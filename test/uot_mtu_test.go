package test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type captureUoTPacketHandler struct {
	connections chan N.PacketConn
	users       chan int
}

func (h *captureUoTPacketHandler) NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

func (h *captureUoTPacketHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	if h.users != nil {
		user, loaded := auth.UserFromContext[int](ctx)
		if !loaded {
			user = -1
		}
		h.users <- user
	}
	h.connections <- conn
}

func waitUoTPacketConn(t *testing.T, handler *captureUoTPacketHandler, serverDone <-chan error) (N.PacketConn, bool) {
	t.Helper()
	select {
	case packetConn := <-handler.connections:
		return packetConn, false
	case serverErr := <-serverDone:
		require.NoError(t, serverErr)
		select {
		case packetConn := <-handler.connections:
			return packetConn, true
		default:
			t.Fatal("server closed before creating UoT packet connection")
		}
	case <-time.After(time.Second):
		t.Fatal("server did not create UoT packet connection")
	}
	return nil, false
}

func TestV6UoTAdvertisesRC1PacketMTU(t *testing.T) {
	for _, mode := range []snellv6.Mode{snellv6.ModeDefault, snellv6.ModeUnshaped, snellv6.ModeUnsafeRaw} {
		t.Run(mode.String(), func(t *testing.T) {
			psk := []byte("test-password")
			handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
			service, err := snellv6.NewService(snellv6.ServerOptions{PSK: psk, Mode: mode, Handler: handler})
			require.NoError(t, err)
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: psk, Mode: mode})
			require.NoError(t, err)
			testV6UoTAdvertisesRC1PacketMTU(t, handler, client.DialPacketConn, service.NewConnection)
		})
	}
}

func testV6UoTAdvertisesRC1PacketMTU(
	t *testing.T,
	handler *captureUoTPacketHandler,
	dialPacketConn func(net.Conn) (N.NetPacketConn, error),
	serve func(context.Context, net.Conn, M.Socksaddr, N.CloseHandlerFunc) error,
) {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() {
		clientRaw.Close()
		serverRaw.Close()
	})
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- serve(context.Background(), serverRaw, M.ParseSocksaddr("127.0.0.1:10000"), nil)
	}()
	clientPacketConn, err := dialPacketConn(clientRaw)
	require.NoError(t, err)

	writeOptions := N.NewReadWaitOptions(nil, clientPacketConn)
	payload := writeOptions.NewPacketBuffer()
	payload.Extend(1200)
	writeOptions.PostReturn(payload)
	require.NoError(t, clientPacketConn.WritePacket(payload, M.ParseSocksaddr("example.com:443")))
	serverPacketConn, serverFinished := waitUoTPacketConn(t, handler, serverDone)

	for index, packetConn := range []N.PacketConn{clientPacketConn, serverPacketConn} {
		options := N.NewReadWaitOptions(nil, packetConn)
		if index == 0 {
			require.Equal(t, 0xffff-(1+1+255+2), options.MTU)
		} else {
			require.Equal(t, 0xffff-(1+255+2), options.MTU)
		}
		buffer := options.NewPacketBuffer()
		require.GreaterOrEqual(t, buffer.FreeLen(), 1200)
		buffer.Release()
	}

	require.NoError(t, clientPacketConn.Close())
	require.NoError(t, serverPacketConn.Close())
	if !serverFinished {
		require.NoError(t, <-serverDone)
	}
}
