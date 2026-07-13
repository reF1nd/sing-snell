package test

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type authenticatedEchoHandler struct {
	users chan int
}

func (h authenticatedEchoHandler) record(ctx context.Context) {
	user, loaded := auth.UserFromContext[int](ctx)
	if loaded {
		h.users <- user
	}
}

func (h authenticatedEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.record(ctx)
	localEchoHandler{}.NewConnectionEx(ctx, conn, source, destination, onClose)
}

func (h authenticatedEchoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	h.record(ctx)
	localEchoHandler{}.NewPacketConnectionEx(ctx, conn, source, destination, onClose)
}

func TestV5MultiPSKLoopback(t *testing.T) {
	users, psks := testUsers(16)
	userPSK := psks[len(psks)-1]
	handler := authenticatedEchoHandler{users: make(chan int, 1)}
	service, err := snellv5.NewMultiService[int](snellv5.ServiceOptions{
		Handler:                 handler,
		MultiUserAuthentication: snell.MultiUserAuthenticationPSK,
	})
	require.NoError(t, err)
	require.NoError(t, service.UpdateUsers(users, psks))
	address := startLocalSnellService(t, service)
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: userPSK})
	require.NoError(t, err)
	normalScenario{address: address, client: client}.HalfCloseEcho(t, "v5-multi-psk")
	require.Equal(t, len(users)-1, <-handler.users)
}

func TestV6MultiPSKLoopback(t *testing.T) {
	for name, mode := range map[string]snellv6.Mode{"default": snellv6.ModeDefault, "unshaped": snellv6.ModeUnshaped} {
		t.Run(name, func(t *testing.T) {
			users, psks := testUsers(16)
			userPSK := psks[len(psks)-1]
			handler := authenticatedEchoHandler{users: make(chan int, 1)}
			service, err := snellv6.NewMultiService[int](snellv6.ServerOptions{
				Mode:                    mode,
				Handler:                 handler,
				MultiUserAuthentication: snell.MultiUserAuthenticationPSK,
			})
			require.NoError(t, err)
			require.NoError(t, service.UpdateUsers(users, psks))
			address := startLocalSnellService(t, service)
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: userPSK, Mode: mode})
			require.NoError(t, err)
			serverConn, err := net.Dial("tcp", address)
			require.NoError(t, err)
			proxyConn, err := client.DialConn(serverConn, M.ParseSocksaddrHostPort("127.0.0.1", 443))
			require.NoError(t, err)
			_, err = proxyConn.Write([]byte("hello"))
			require.NoError(t, err)
			require.NoError(t, N.CloseWrite(proxyConn))
			buffer := make([]byte, 5)
			_, err = proxyConn.Read(buffer)
			require.NoError(t, err)
			require.Equal(t, []byte("hello"), buffer)
			require.Equal(t, len(users)-1, <-handler.users)
		})
	}
}

func testUsers(count int) ([]int, [][]byte) {
	users := make([]int, count)
	psks := make([][]byte, count)
	for index := range count {
		users[index] = index
		psks[index] = []byte(fmt.Sprintf("user-%02d-password", index))
	}
	return users, psks
}

func TestV6MultiPSKRejectsUnsafeRaw(t *testing.T) {
	_, err := snellv6.NewMultiService[int](snellv6.ServerOptions{
		Mode:                    snellv6.ModeUnsafeRaw,
		Handler:                 localEchoHandler{},
		MultiUserAuthentication: snell.MultiUserAuthenticationPSK,
	})
	require.Error(t, err)
}

func TestV6ConcurrentUserUpdatesAndAuthentication(t *testing.T) {
	psk := []byte("concurrent-user-password")
	handler := authenticatedEchoHandler{users: make(chan int, 16)}
	service, err := snellv6.NewMultiService[int](snellv6.ServerOptions{
		Mode:                    snellv6.ModeUnshaped,
		Handler:                 handler,
		MultiUserAuthentication: snell.MultiUserAuthenticationPSK,
	})
	require.NoError(t, err)
	require.NoError(t, service.UpdateUsers([]int{0}, [][]byte{psk}))
	address := startLocalSnellService(t, service)
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: psk, Mode: snellv6.ModeUnshaped})
	require.NoError(t, err)

	updateDone := make(chan error, 1)
	go func() {
		for index := range 1000 {
			if updateErr := service.UpdateUsers([]int{index & 1}, [][]byte{psk}); updateErr != nil {
				updateDone <- updateErr
				return
			}
		}
		updateDone <- nil
	}()
	for index := range 16 {
		normalScenario{address: address, client: client}.HalfCloseEcho(t, fmt.Sprintf("v6-concurrent-user-%d", index))
		require.Contains(t, []int{0, 1}, <-handler.users)
	}
	require.NoError(t, <-updateDone)
}

type connectionTypeHandler struct {
	types chan string
}

func (h connectionTypeHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, _ N.CloseHandlerFunc) {
	h.types <- fmt.Sprintf("%T", conn)
	_ = conn.Close()
}

func (connectionTypeHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

func TestV4ClientCommandFollowsReuse(t *testing.T) {
	for _, reuseEnabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("reuse-%t", reuseEnabled), func(t *testing.T) {
			psk := []byte("test-password")
			handler := connectionTypeHandler{types: make(chan string, 1)}
			service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk, Handler: handler})
			require.NoError(t, err)
			client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: psk, Reuse: reuseEnabled})
			require.NoError(t, err)
			clientRaw, serverRaw := net.Pipe()
			defer clientRaw.Close()
			defer serverRaw.Close()
			go func() {
				_ = service.NewConnection(context.Background(), serverRaw, M.ParseSocksaddr("127.0.0.1:10000"), nil)
			}()
			proxyConn, err := client.DialConn(clientRaw, M.ParseSocksaddr("example.com:443"))
			require.NoError(t, err)
			connectionType := <-handler.types
			if reuseEnabled {
				require.True(t, strings.Contains(connectionType, "serverReuseConn"), connectionType)
			} else {
				require.True(t, strings.HasSuffix(connectionType, ".serverConn"), connectionType)
			}
			_ = proxyConn.Close()
			_ = clientRaw.Close()
			_ = serverRaw.Close()
		})
	}
}
