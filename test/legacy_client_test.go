package test

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"testing"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/legacy"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func TestLegacyTCPVersions(t *testing.T) {
	for version := 1; version <= 3; version++ {
		t.Run(string(rune('0'+version)), func(t *testing.T) {
			psk := []byte("legacy-password")
			client, err := legacy.NewClient(psk, version)
			require.NoError(t, err)
			clientRaw, serverRaw := net.Pipe()
			defer clientRaw.Close()
			defer serverRaw.Close()
			server := newLegacyPeerConn(serverRaw, psk, version)
			serverErr := make(chan error, 1)
			go func() {
				request, readErr := snell.ReadRequest(server)
				if readErr != nil {
					serverErr <- readErr
					return
				}
				if request.Destination.String() != "example.com:443" {
					serverErr <- io.ErrUnexpectedEOF
					return
				}
				payload := make([]byte, 5)
				if _, readErr = io.ReadFull(server, payload); readErr != nil {
					serverErr <- readErr
					return
				}
				_, readErr = server.Write(append([]byte{snell.ReplyTunnel}, payload...))
				serverErr <- readErr
			}()
			proxy := client.DialContext(context.Background(), clientRaw, M.ParseSocksaddr("example.com:443"))
			_, err = proxy.Write([]byte("hello"))
			require.NoError(t, err)
			response := make([]byte, 5)
			_, err = io.ReadFull(proxy, response)
			require.NoError(t, err)
			require.Equal(t, []byte("hello"), response)
			require.NoError(t, <-serverErr)
		})
	}
}

func TestLegacyV3UDP(t *testing.T) {
	psk := []byte("legacy-password")
	client, err := legacy.NewClient(psk, 3)
	require.NoError(t, err)
	clientRaw, serverRaw := net.Pipe()
	defer clientRaw.Close()
	defer serverRaw.Close()
	server := newLegacyPeerConn(serverRaw, psk, 3)
	serverErr := make(chan error, 1)
	go func() {
		request, readErr := snell.ReadRequest(server)
		if readErr != nil || request.Command != snell.CommandUDP {
			serverErr <- readErr
			return
		}
		if _, readErr = server.Write([]byte{snell.ReplyTunnel}); readErr != nil {
			serverErr <- readErr
			return
		}
		requestPacket := make([]byte, 1024)
		n, readErr := server.Read(requestPacket)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		buffer := buf.As(requestPacket[:n])
		command, readErr := buffer.ReadByte()
		if readErr != nil || command != snell.UDPCommandForward {
			serverErr <- readErr
			return
		}
		destination, readErr := snell.ReadUDPRequestAddress(buffer)
		if readErr != nil {
			serverErr <- readErr
			return
		}
		response := buf.NewSize(64)
		if readErr = snell.WriteUDPResponseAddress(response, destination); readErr == nil {
			response.Write(buffer.Bytes())
			_, readErr = server.Write(response.Bytes())
		}
		response.Release()
		serverErr <- readErr
	}()
	packetConn, err := client.DialPacketConn(clientRaw)
	require.NoError(t, err)
	destination := M.ParseSocksaddr("127.0.0.1:53")
	_, err = packetConn.WriteTo([]byte("query"), destination)
	require.NoError(t, err)
	response := make([]byte, 16)
	n, source, err := packetConn.ReadFrom(response)
	require.NoError(t, err)
	require.Equal(t, destination.String(), source.String())
	require.Equal(t, []byte("query"), response[:n])
	require.NoError(t, <-serverErr)
}

type legacyPeerConn struct {
	net.Conn
	psk       []byte
	version   int
	reader    *legacyPeerReader
	writer    *legacyPeerWriter
	readOnce  sync.Once
	writeOnce sync.Once
	readErr   error
	writeErr  error
}

func newLegacyPeerConn(conn net.Conn, psk []byte, version int) net.Conn {
	return &legacyPeerConn{Conn: conn, psk: psk, version: version}
}

func (c *legacyPeerConn) Read(p []byte) (int, error) {
	c.readOnce.Do(func() {
		var salt [16]byte
		if _, c.readErr = io.ReadFull(c.Conn, salt[:]); c.readErr != nil {
			return
		}
		var aead cipher.AEAD
		aead, c.readErr = legacyPeerAEAD(c.psk, salt[:], c.version)
		if c.readErr == nil {
			c.reader = &legacyPeerReader{source: c.Conn, aead: aead, nonce: make([]byte, aead.NonceSize())}
		}
	})
	if c.readErr != nil {
		return 0, c.readErr
	}
	return c.reader.Read(p)
}

func (c *legacyPeerConn) Write(p []byte) (int, error) {
	c.writeOnce.Do(func() {
		var salt [16]byte
		if _, c.writeErr = rand.Read(salt[:]); c.writeErr != nil {
			return
		}
		if _, c.writeErr = c.Conn.Write(salt[:]); c.writeErr != nil {
			return
		}
		var aead cipher.AEAD
		aead, c.writeErr = legacyPeerAEAD(c.psk, salt[:], c.version)
		if c.writeErr == nil {
			c.writer = &legacyPeerWriter{destination: c.Conn, aead: aead, nonce: make([]byte, aead.NonceSize())}
		}
	})
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return c.writer.Write(p)
}

func legacyPeerAEAD(psk []byte, salt []byte, version int) (cipher.AEAD, error) {
	key := argon2.IDKey(psk, salt, 3, 8, 1, 32)
	if version == 1 {
		return chacha20poly1305.New(key)
	}
	block, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

type legacyPeerReader struct {
	source io.Reader
	aead   cipher.AEAD
	nonce  []byte
	cache  []byte
}

func (r *legacyPeerReader) Read(p []byte) (int, error) {
	if len(r.cache) > 0 {
		n := copy(p, r.cache)
		r.cache = r.cache[n:]
		return n, nil
	}
	header := make([]byte, 2+r.aead.Overhead())
	if _, err := io.ReadFull(r.source, header); err != nil {
		return 0, err
	}
	header, err := r.aead.Open(header[:0], r.nonce, header, nil)
	if err != nil {
		return 0, err
	}
	legacyIncreaseNonce(r.nonce)
	length := int(binary.BigEndian.Uint16(header))
	if length == 0 {
		return 0, errors.New("snell: zero chunk")
	}
	body := make([]byte, length+r.aead.Overhead())
	if _, err = io.ReadFull(r.source, body); err != nil {
		return 0, err
	}
	body, err = r.aead.Open(body[:0], r.nonce, body, nil)
	if err != nil {
		return 0, err
	}
	legacyIncreaseNonce(r.nonce)
	n := copy(p, body)
	r.cache = body[n:]
	return n, nil
}

type legacyPeerWriter struct {
	destination io.Writer
	aead        cipher.AEAD
	nonce       []byte
	access      sync.Mutex
}

func (w *legacyPeerWriter) Write(p []byte) (int, error) {
	w.access.Lock()
	defer w.access.Unlock()
	header := make([]byte, 2)
	binary.BigEndian.PutUint16(header, uint16(len(p)))
	header = w.aead.Seal(header[:0], w.nonce, header, nil)
	legacyIncreaseNonce(w.nonce)
	body := w.aead.Seal(nil, w.nonce, p, nil)
	legacyIncreaseNonce(w.nonce)
	_, err := w.destination.Write(append(header, body...))
	return len(p), err
}

func legacyIncreaseNonce(nonce []byte) {
	for index := range nonce {
		nonce[index]++
		if nonce[index] != 0 {
			return
		}
	}
}
