package test

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

// Exercise CopyPacket itself: fallback writes must preserve batch reads.
func TestPacketBatchFallbackCopy(t *testing.T) {
	for _, mode := range []snell.ObfsMode{snell.ObfsModeNone, snell.ObfsModeHTTP, snell.ObfsModeTLS} {
		t.Run("v4-v5/"+mode.String(), func(t *testing.T) {
			handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
			client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte("test-password"), ObfsMode: mode})
			require.NoError(t, err)
			service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: []byte("test-password"), ObfsMode: mode, Handler: handler})
			require.NoError(t, err)
			testPacketBatchFallbackCopy(t, handler, client.DialPacketConn, service.NewConnection, mode != snell.ObfsModeNone)
		})
	}
	for _, mode := range []snellv6.Mode{snellv6.ModeDefault, snellv6.ModeUnshaped, snellv6.ModeUnsafeRaw} {
		t.Run("v6/"+mode.String(), func(t *testing.T) {
			handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte("test-password"), Mode: mode})
			require.NoError(t, err)
			service, err := snellv6.NewService(snellv6.ServerOptions{PSK: []byte("test-password"), Mode: mode, Handler: handler})
			require.NoError(t, err)
			testPacketBatchFallbackCopy(t, handler, client.DialPacketConn, service.NewConnection, false)
		})
	}
}

func testPacketBatchFallbackCopy(
	t *testing.T,
	handler *captureUoTPacketHandler,
	dial func(net.Conn) (N.NetPacketConn, error),
	serve func(context.Context, net.Conn, M.Socksaddr, N.CloseHandlerFunc) error,
	useTCP bool,
) {
	t.Helper()
	var clientRaw, serverRaw net.Conn
	if useTCP {
		listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, err)
		defer listener.Close()
		require.NoError(t, listener.SetDeadline(time.Now().Add(5*time.Second)))
		clientRaw, err = net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
		require.NoError(t, err)
		t.Cleanup(func() { clientRaw.Close() })
		serverRaw, err = listener.Accept()
		require.NoError(t, err)
	} else {
		clientRaw, serverRaw = net.Pipe()
		t.Cleanup(func() { clientRaw.Close() })
	}
	t.Cleanup(func() { serverRaw.Close() })
	require.NoError(t, clientRaw.SetDeadline(time.Now().Add(5*time.Second)))
	require.NoError(t, serverRaw.SetDeadline(time.Now().Add(5*time.Second)))
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serve(context.Background(), serverRaw, M.ParseSocksaddr("127.0.0.1:12345"), nil)
	}()
	clientConn, err := dial(clientRaw)
	require.NoError(t, err)
	targets := []M.Socksaddr{M.ParseSocksaddr("192.0.2.1:443"), M.ParseSocksaddr("[2001:db8::1]:5353")}
	payloads := [][]byte{bytes.Repeat([]byte("a"), 64), bytes.Repeat([]byte("b"), 128)}
	source := &packetBatchCopySource{payloads: payloads, destinations: targets}
	copyDone := make(chan error, 1)
	go func() {
		_, err := bufio.CopyPacket(clientConn, source)
		copyDone <- err
	}()
	serverConn, _ := waitUoTPacketConn(t, handler, serverDone)
	readPackets := func(conn N.PacketReader) {
		t.Helper()
		for i, payload := range payloads {
			buffer := buf.NewPacket()
			destination, err := conn.ReadPacket(buffer)
			received := append([]byte(nil), buffer.Bytes()...)
			buffer.Release()
			require.NoError(t, err)
			require.Equal(t, targets[i], destination)
			require.Equal(t, payload, received)
		}
	}
	readPackets(serverConn)
	require.ErrorIs(t, <-copyDone, io.EOF)
	require.Equal(t, 2, source.batchReads, "data and EOF must both use the batch reader")
	require.Zero(t, source.singleReads, "fallback writes must not disable batch reads")
	source = &packetBatchCopySource{payloads: payloads, destinations: targets}
	go func() {
		_, err := bufio.CopyPacket(serverConn, source)
		copyDone <- err
	}()
	readPackets(clientConn)
	require.ErrorIs(t, <-copyDone, io.EOF)
	require.Equal(t, 2, source.batchReads)
	require.Zero(t, source.singleReads)
	require.NoError(t, clientRaw.Close())
	require.NoError(t, serverRaw.Close())
}

type packetBatchCopySource struct {
	options      N.ReadWaitOptions
	payloads     [][]byte
	destinations []M.Socksaddr
	index        int
	batchReads   int
	singleReads  int
}

func (s *packetBatchCopySource) InitializeReadWaiter(options N.ReadWaitOptions) bool {
	s.options = options
	return false
}

func (s *packetBatchCopySource) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	s.singleReads++
	if s.index == len(s.payloads) {
		return M.Socksaddr{}, io.EOF
	}
	i := s.index
	s.index++
	_, err := buffer.Write(s.payloads[i])
	return s.destinations[i], err
}

func (s *packetBatchCopySource) WaitReadPackets() ([]*buf.Buffer, []M.Socksaddr, error) {
	s.batchReads++
	if s.index == len(s.payloads) {
		return nil, nil, io.EOF
	}
	var buffers []*buf.Buffer
	destinations := s.destinations[s.index:]
	for ; s.index < len(s.payloads); s.index++ {
		buffer := s.options.NewPacketBuffer()
		_, err := buffer.Write(s.payloads[s.index])
		if err != nil {
			buffer.Release()
			buf.ReleaseMulti(buffers)
			return nil, nil, err
		}
		s.options.PostReturn(buffer)
		buffers = append(buffers, buffer)
	}
	return buffers, destinations, nil
}
