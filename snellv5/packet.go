package snellv5

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing-snell/internal/uot"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

const maxUDPResponseHeaderLen = snell.MaxUDPResponseAddressLen

type serverPacketConn struct {
	net.Conn
	service         *Service
	reader          reuse.RecordReader
	readWaitOptions N.ReadWaitOptions
	readAccess      sync.Mutex

	writeAccess sync.Mutex
	writer      reuse.RecordWriter

	clientFIN uot.ClientFINWaiter
}

func (c *serverPacketConn) responseAddrLen(source M.Socksaddr) int {
	return snell.UDPResponseAddressLen(source)
}

func (c *serverPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	record, err := c.reader.NextRecord()
	if err != nil {
		return M.Socksaddr{}, err
	}
	command, err := record.ReadByte()
	if err != nil {
		record.Release()
		return M.Socksaddr{}, err
	}
	if command != snell.UDPCommandForward {
		record.Release()
		return M.Socksaddr{}, E.Extend(snell.ErrUnsupportedCommand, "udp ", command)
	}
	destination, err := c.readRequestPacketDestination(record)
	if err != nil {
		record.Release()
		return M.Socksaddr{}, err
	}
	if record.Len() > buffer.FreeLen() {
		record.Release()
		return M.Socksaddr{}, io.ErrShortBuffer
	}
	_, err = buffer.Write(record.Bytes())
	record.Release()
	if err != nil {
		return M.Socksaddr{}, err
	}
	return destination, nil
}

func (c *serverPacketConn) readRequestPacketDestination(record *buf.Buffer) (M.Socksaddr, error) {
	first, err := record.ReadByte()
	if err != nil {
		return M.Socksaddr{}, err
	}
	if first != 0x00 {
		var host []byte
		host, err = record.ReadBytes(int(first))
		if err != nil {
			return M.Socksaddr{}, err
		}
		var portBytes []byte
		portBytes, err = record.ReadBytes(2)
		if err != nil {
			return M.Socksaddr{}, err
		}
		if record.IsEmpty() {
			return M.Socksaddr{}, snell.ErrEmptyDomainUDPPayload
		}
		return M.ParseSocksaddrHostPort(string(host), binary.BigEndian.Uint16(portBytes)), nil
	}
	addressFamily, err := record.ReadByte()
	if err != nil {
		return M.Socksaddr{}, err
	}
	switch addressFamily {
	case snell.AddressTypeIPv4:
		var addressBytes []byte
		addressBytes, err = record.ReadBytes(4)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var portBytes []byte
		portBytes, err = record.ReadBytes(2)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var address [4]byte
		copy(address[:], addressBytes)
		return M.SocksaddrFrom(netip.AddrFrom4(address), binary.BigEndian.Uint16(portBytes)), nil
	case snell.AddressTypeIPv6:
		var addressBytes []byte
		addressBytes, err = record.ReadBytes(16)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var portBytes []byte
		portBytes, err = record.ReadBytes(2)
		if err != nil {
			return M.Socksaddr{}, err
		}
		var address [16]byte
		copy(address[:], addressBytes)
		return M.SocksaddrFrom(netip.AddrFrom16(address), binary.BigEndian.Uint16(portBytes)).Unwrap(), nil
	default:
		// snell-server v5.0.1: FUN_00140a50 consumes the 0x00 marker and the
		// unknown address-family byte, then forwards the rest as payload with an
		// empty destination instead of aborting the UDP tunnel.
		return M.Socksaddr{}, nil
	}
}

func (c *serverPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.writeAccess.Lock()
	if c.writer == nil {
		err := c.writeTunnelReply()
		if err != nil {
			c.writeAccess.Unlock()
			buffer.Release()
			return err
		}
	}
	recordWriter := c.writer
	c.writeAccess.Unlock()
	header := buf.With(buffer.ExtendHeader(c.responseAddrLen(destination)))
	err := snell.WriteUDPResponseAddress(header, destination)
	if err != nil {
		buffer.Release()
		return err
	}
	if buffer.Len() > maxPayload {
		buffer.Release()
		return snell.ErrPayloadTooLarge
	}
	return recordWriter.WritePacketBuffer(buffer)
}

func (c *serverPacketConn) CreatePacketBatchWriter() (snell.PacketBatchWriter, bool) {
	upstreamWriter, created := bufio.CreateVectorisedWriter(c.Conn)
	if !created {
		return nil, false
	}
	return &serverPacketBatchWriter{conn: c, upstream: upstreamWriter}, true
}

func (c *serverPacketConn) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	writer, created := c.CreatePacketBatchWriter()
	if !created {
		return snell.WritePacketBatchFallback(c, buffers, destinations)
	}
	return writer.WritePacketBatch(buffers, destinations)
}

type serverPacketBatchWriter struct {
	conn     *serverPacketConn
	upstream N.VectorisedWriter

	access sync.Mutex
	writer N.VectorisedWriter
}

func (w *serverPacketBatchWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	w.access.Lock()
	if w.writer == nil {
		w.conn.writeAccess.Lock()
		if w.conn.writer == nil {
			err := w.conn.writeTunnelReply()
			if err != nil {
				w.conn.writeAccess.Unlock()
				w.access.Unlock()
				buf.ReleaseMulti(buffers)
				return err
			}
		}
		w.writer = w.conn.writer.CreatePacketVectorisedWriterFor(w.upstream)
		w.conn.writeAccess.Unlock()
	}
	recordWriter := w.writer
	w.access.Unlock()
	for index, buffer := range buffers {
		header := buf.With(buffer.ExtendHeader(w.conn.responseAddrLen(destinations[index])))
		err := snell.WriteUDPResponseAddress(header, destinations[index])
		if err != nil {
			buf.ReleaseMulti(buffers)
			return err
		}
	}
	return recordWriter.WriteVectorised(buffers)
}

func (c *serverPacketConn) writeTunnelReply() error {
	reply := [1]byte{snell.ReplyTunnel}
	if c.writer != nil {
		_, err := c.writer.Write(reply[:])
		if err != nil {
			return E.Cause(err, "write udp reply")
		}
		return nil
	}
	salt := make([]byte, snell.SaltLen)
	_, err := io.ReadFull(rand.Reader, salt)
	if err != nil {
		return err
	}
	key := snell.DeriveKey(c.service.psk, salt)
	aead, err := snell.NewAEAD(key)
	if err != nil {
		return err
	}
	nonce := make([]byte, snell.NonceLen)
	recordWriter, err := newWriter(c.Conn, aead, nonce)
	if err != nil {
		return err
	}
	err = recordWriter.WriteFirst(salt, reply[:])
	if err != nil {
		return E.Cause(err, "write udp reply")
	}
	c.writer = recordWriter
	return nil
}

func (c *serverPacketConn) FrontHeadroom() int {
	return snell.HeaderCipherLen + maxUDPResponseHeaderLen
}

func (c *serverPacketConn) RearHeadroom() int {
	return snell.AEADTagLen
}

func (c *serverPacketConn) WriterMTU() int {
	return maxPayload - maxUDPResponseHeaderLen
}

func (c *serverPacketConn) Upstream() any {
	return c.Conn
}

func (c *serverPacketConn) InitializeReadWaiter(options N.ReadWaitOptions) (needCopy bool) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	c.readWaitOptions = options
	c.reader.InitializeReadWaiter(options)
	return false
}

func (c *serverPacketConn) WaitReadPacket() (*buf.Buffer, M.Socksaddr, error) {
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	record, err := c.reader.WaitReadBuffer()
	if err != nil {
		return nil, M.Socksaddr{}, err
	}
	command, err := record.ReadByte()
	if err != nil {
		record.Release()
		return nil, M.Socksaddr{}, err
	}
	if command != snell.UDPCommandForward {
		record.Release()
		return nil, M.Socksaddr{}, E.Extend(snell.ErrUnsupportedCommand, "udp ", command)
	}
	destination, err := c.readRequestPacketDestination(record)
	if err != nil {
		record.Release()
		return nil, M.Socksaddr{}, err
	}
	return record, destination, nil
}

func (c *serverPacketConn) Close() error {
	return c.clientFIN.Close(c.Conn, c.waitClientFIN)
}

func (c *serverPacketConn) waitClientFIN(deadline time.Time) {
	c.readAccess.Lock()
	_ = c.Conn.SetReadDeadline(deadline)
	for {
		record, err := c.reader.NextRecord()
		if err != nil {
			break
		}
		record.Release()
	}
	c.readAccess.Unlock()
}

func (c *serverPacketConn) SetDeadline(deadline time.Time) error {
	return c.clientFIN.SetDeadline(c.Conn, deadline)
}

func (c *serverPacketConn) SetReadDeadline(deadline time.Time) error {
	return c.clientFIN.SetReadDeadline(c.Conn, deadline)
}

func (c *serverPacketConn) SetWriteDeadline(deadline time.Time) error {
	return c.Conn.SetWriteDeadline(deadline)
}

var (
	_ N.PacketConn                  = (*serverPacketConn)(nil)
	_ N.PacketReadWaiter            = (*serverPacketConn)(nil)
	_ snell.PacketBatchWriteCreator = (*serverPacketConn)(nil)
	_ snell.PacketBatchWriter       = (*serverPacketConn)(nil)
	_ N.WriterWithMTU               = (*serverPacketConn)(nil)
	_ snell.PacketBatchWriter       = (*serverPacketBatchWriter)(nil)
)
