package test

import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing/common/auth"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

type capturePacketConn struct {
	packet []byte
}

func (c *capturePacketConn) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (c *capturePacketConn) Write(p []byte) (int, error) {
	c.packet = append([]byte(nil), p...)
	return len(p), nil
}
func (c *capturePacketConn) Close() error                     { return nil }
func (c *capturePacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *capturePacketConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *capturePacketConn) SetDeadline(time.Time) error      { return nil }
func (c *capturePacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *capturePacketConn) SetWriteDeadline(time.Time) error { return nil }

func quicInitPacket(t *testing.T, psk []byte, userKey []byte) []byte {
	t.Helper()
	conn := new(capturePacketConn)
	_, err := snell.NewQUICProxyPacketConn(conn, psk, userKey, M.ParseSocksaddr("example.com:443"), []byte{0xc0, 1, 2, 3})
	require.NoError(t, err)
	return conn.packet
}

func TestQUICProxyFrameRoundTrip(t *testing.T) {
	psk := []byte("test-password")
	packet := quicInitPacket(t, psk, []byte("alice"))
	destination, userKey, payload, err := snell.DecodeQUICProxyInit(psk, packet)
	require.NoError(t, err)
	require.Equal(t, M.ParseSocksaddr("example.com:443"), destination)
	require.Equal(t, []byte("alice"), userKey)
	require.Equal(t, []byte{0xc0, 1, 2, 3}, payload)
}

func TestQUICProxySessionContext(t *testing.T) {
	session := snell.NewQUICProxySession([]byte("password"), M.ParseSocksaddr("example.com:443"), func(ctx context.Context) context.Context {
		return auth.ContextWithUser(ctx, 7)
	})
	user, loaded := auth.UserFromContext[int](session.Context(context.Background()))
	require.True(t, loaded)
	require.Equal(t, 7, user)
}

func TestQUICProxyUserKeyAuthentication(t *testing.T) {
	psk := []byte("server-password")
	service, err := snellv5.NewMultiService[int](snellv5.ServiceOptions{PSK: psk})
	require.NoError(t, err)
	require.NoError(t, service.UpdateUsers([]int{7}, [][]byte{[]byte("alice")}))
	session, payload, err := service.ParseQUICProxyInit(quicInitPacket(t, psk, []byte("alice")))
	require.NoError(t, err)
	require.Equal(t, []byte{0xc0, 1, 2, 3}, payload)
	user, loaded := auth.UserFromContext[int](session.Context(context.Background()))
	require.True(t, loaded)
	require.Equal(t, 7, user)
}

func TestQUICProxyPSKAuthentication(t *testing.T) {
	users := make([]int, 16)
	psks := make([][]byte, len(users))
	for index := range users {
		users[index] = index
		psks[index] = []byte(fmt.Sprintf("user-%02d-password", index))
	}
	psk := psks[len(psks)-1]
	service, err := snellv5.NewMultiService[int](snellv5.ServiceOptions{MultiUserAuthentication: snell.MultiUserAuthenticationPSK})
	require.NoError(t, err)
	require.NoError(t, service.UpdateUsers(users, psks))
	session, payload, err := service.ParseQUICProxyInit(quicInitPacket(t, psk, nil))
	require.NoError(t, err)
	require.Equal(t, []byte{0xc0, 1, 2, 3}, payload)
	user, loaded := auth.UserFromContext[int](session.Context(context.Background()))
	require.True(t, loaded)
	require.Equal(t, len(users)-1, user)
}

func TestQUICProxyPSKAuthenticationIgnoresClientID(t *testing.T) {
	psk := []byte("user-password")
	service, err := snellv5.NewMultiService[int](snellv5.ServiceOptions{MultiUserAuthentication: snell.MultiUserAuthenticationPSK})
	require.NoError(t, err)
	require.NoError(t, service.UpdateUsers([]int{7}, [][]byte{psk}))
	session, payload, err := service.ParseQUICProxyInit(quicInitPacket(t, psk, []byte("surge-client")))
	require.NoError(t, err)
	require.NotEmpty(t, payload)
	user, loaded := auth.UserFromContext[int](session.Context(context.Background()))
	require.True(t, loaded)
	require.Equal(t, 7, user)
}
