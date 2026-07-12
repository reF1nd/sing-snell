package test

import (
	"context"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type captureTCPConnHandler struct {
	connections chan net.Conn
}

func (h *captureTCPConnHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	h.connections <- conn
}

func (*captureTCPConnHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

func TestV5TCPVectorisedWriterSplitsLargeBuffers(t *testing.T) {
	psk := []byte("test-password")
	handler := &captureTCPConnHandler{connections: make(chan net.Conn, 1)}
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk, Handler: handler})
	require.NoError(t, err)
	serviceAddress := startLocalSnellService(t, service)
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: psk})
	require.NoError(t, err)
	clientRaw, err := net.Dial("tcp", serviceAddress)
	require.NoError(t, err)
	t.Cleanup(func() { clientRaw.Close() })
	proxyConn, err := client.DialConn(clientRaw, M.ParseSocksaddr("example.com:443"))
	require.NoError(t, err)
	serverConn := <-handler.connections
	t.Cleanup(func() { serverConn.Close() })

	payload := make([]byte, snell.MaxPayloadLen+1)
	for index := range payload {
		payload[index] = byte(index)
	}
	frontHeadroom := N.CalculateFrontHeadroom(serverConn)
	rearHeadroom := N.CalculateRearHeadroom(serverConn)
	buffer := buf.NewSize(frontHeadroom + len(payload) + rearHeadroom)
	buffer.Resize(frontHeadroom, 0)
	_, err = buffer.Write(payload)
	require.NoError(t, err)
	writer, created := bufio.CreateVectorisedWriter(serverConn)
	require.True(t, created)
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- writer.WriteVectorised([]*buf.Buffer{buffer})
	}()
	received := make([]byte, len(payload))
	_, err = io.ReadFull(proxyConn, received)
	require.NoError(t, err)
	require.NoError(t, <-writeDone)
	require.Equal(t, payload, received)
}
