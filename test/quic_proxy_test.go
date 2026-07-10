package test

import (
	"context"
	"encoding/binary"
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
	packet  []byte
	packets [][]byte
}

func (c *capturePacketConn) Read([]byte) (int, error) { return 0, net.ErrClosed }
func (c *capturePacketConn) Write(p []byte) (int, error) {
	c.packet = append([]byte(nil), p...)
	c.packets = append(c.packets, append([]byte(nil), p...))
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
	return quicInitPacketWithPayload(t, psk, userKey, []byte{0xc0, 0, 0, 0, 1, 1, 2, 3})
}

func quicInitPacketWithPayload(t *testing.T, psk []byte, userKey []byte, payload []byte) []byte {
	t.Helper()
	conn := new(capturePacketConn)
	_, err := snell.NewQUICProxyPacketConn(conn, psk, userKey, M.ParseSocksaddr("example.com:443"), payload)
	require.NoError(t, err)
	return conn.packet
}

func quicInitPacketWithoutPayload(t *testing.T, psk []byte, userKey []byte) []byte {
	t.Helper()
	host := []byte("example.com")
	plain := []byte{snell.RequestVersion, byte(len(userKey))}
	plain = append(plain, userKey...)
	plain = append(plain, byte(len(host)))
	plain = append(plain, host...)
	plain = binary.BigEndian.AppendUint16(plain, 443)
	return encodeQUICProxyTestPlaintext(t, psk, plain)
}

func TestQUICProxyFrameRoundTrip(t *testing.T) {
	psk := []byte("test-password")
	packet := quicInitPacket(t, psk, []byte("alice"))
	destination, userKey, payload, err := snell.DecodeQUICProxyInit(psk, packet)
	require.NoError(t, err)
	require.Equal(t, M.ParseSocksaddr("example.com:443"), destination)
	require.Equal(t, []byte("alice"), userKey)
	require.Equal(t, []byte{0xc0, 0, 0, 0, 1, 1, 2, 3}, payload)
}

func TestQUICProxyMultiFrameRoundTrip(t *testing.T) {
	psk := []byte("test-password")
	payload := make([]byte, 4096)
	for index := range payload {
		payload[index] = byte(index)
	}
	packet := quicInitPacketWithPayload(t, psk, []byte("alice"), payload)
	destination, userKey, decodedPayload, err := snell.DecodeQUICProxyInit(psk, packet)
	require.NoError(t, err)
	require.Equal(t, M.ParseSocksaddr("example.com:443"), destination)
	require.Equal(t, []byte("alice"), userKey)
	require.Equal(t, payload, decodedPayload)
}

func TestQUICProxyMultiFrameRejectsTruncationAndTrailingData(t *testing.T) {
	psk := []byte("test-password")
	packet := quicInitPacketWithPayload(t, psk, nil, make([]byte, 4096))
	_, _, _, err := snell.DecodeQUICProxyInit(psk, packet[:len(packet)-1])
	require.Error(t, err)
	_, _, _, err = snell.DecodeQUICProxyInit(psk, append(packet, 0))
	require.Error(t, err)
}

func TestQUICProxyLaterInitialRecreatesSession(t *testing.T) {
	psk := []byte("test-password")
	conn := new(capturePacketConn)
	destination := M.ParseSocksaddr("example.com:443")
	packetConn, err := snell.NewQUICProxyPacketConn(conn, psk, nil, destination, []byte{0xc0, 0, 0, 0, 1})
	require.NoError(t, err)
	initial := []byte{0xd0, 0x6b, 0x33, 0x43, 0xcf, 1, 2, 3}
	written, err := packetConn.WriteTo(initial, destination)
	require.NoError(t, err)
	require.Equal(t, len(initial), written)
	require.Len(t, conn.packets, 2)

	decodedDestination, _, payload, err := snell.DecodeQUICProxyInit(psk, conn.packets[1])
	require.NoError(t, err)
	require.Equal(t, destination, decodedDestination)
	require.Equal(t, initial, payload)
}

func TestQUICProxyRejectsInvalidTargets(t *testing.T) {
	psk := []byte("test-password")
	for _, plain := range [][]byte{
		{snell.RequestVersion, 0, 0, 1, 0},
		append([]byte{snell.RequestVersion, 0, 11}, append([]byte("example.com"), 0, 0)...),
	} {
		_, _, _, err := snell.DecodeQUICProxyInit(psk, encodeQUICProxyTestPlaintext(t, psk, plain))
		require.ErrorContains(t, err, "invalid target")
	}
}

func TestQUICProxyServiceRequiresPayload(t *testing.T) {
	psk := []byte("test-password")
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk})
	require.NoError(t, err)
	_, _, err = service.ParseQUICProxyInit(quicInitPacketWithoutPayload(t, psk, nil))
	require.ErrorContains(t, err, "does not contain a payload")
}

func TestQUICProxyPacketConnRequiresPayload(t *testing.T) {
	_, err := snell.NewQUICProxyPacketConn(new(capturePacketConn), []byte("test-password"), nil, M.ParseSocksaddr("example.com:443"), nil)
	require.ErrorContains(t, err, "initial payload is required")
}

func TestQUICProxyServiceAcceptsNonInitialPayload(t *testing.T) {
	psk := []byte("test-password")
	payload := []byte{0x40, 1, 2, 3}
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk})
	require.NoError(t, err)
	_, decodedPayload, err := service.ParseQUICProxyInit(quicInitPacketWithPayload(t, psk, nil, payload))
	require.NoError(t, err)
	require.Equal(t, payload, decodedPayload)
}

func TestQUICProxyDuplicateInitAllowsNonInitialPayload(t *testing.T) {
	psk := []byte("test-password")
	payload := []byte{0x40, 1, 2, 3}
	session := snell.NewQUICProxySession(psk, M.ParseSocksaddr("example.com:443"), nil)
	decodedPayload, err := session.DecodeDuplicateInit(quicInitPacketWithPayload(t, psk, nil, payload))
	require.NoError(t, err)
	require.Equal(t, payload, decodedPayload)
}

func encodeQUICProxyTestPlaintext(t *testing.T, psk []byte, plain []byte) []byte {
	t.Helper()
	salt := make([]byte, snell.SaltLen)
	aead, err := snell.NewAEAD(snell.DeriveKey(psk, salt))
	require.NoError(t, err)
	nonce := make([]byte, snell.NonceLen)
	header := make([]byte, snell.HeaderPlainLen)
	header[0] = snell.HeaderVersion
	binary.BigEndian.PutUint16(header[5:7], uint16(len(plain)))
	packet := append([]byte(nil), salt...)
	packet = aead.Seal(packet, nonce, header, nil)
	snell.IncreaseNonce(nonce)
	return aead.Seal(packet, nonce, plain, nil)
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
	require.Equal(t, []byte{0xc0, 0, 0, 0, 1, 1, 2, 3}, payload)
	user, loaded := auth.UserFromContext[int](session.Context(context.Background()))
	require.True(t, loaded)
	require.Equal(t, 7, user)
	_, _, err = service.ParseQUICProxyInit(quicInitPacketWithoutPayload(t, psk, []byte("alice")))
	require.ErrorContains(t, err, "does not contain a payload")
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
	require.Equal(t, []byte{0xc0, 0, 0, 0, 1, 1, 2, 3}, payload)
	user, loaded := auth.UserFromContext[int](session.Context(context.Background()))
	require.True(t, loaded)
	require.Equal(t, len(users)-1, user)
	_, _, err = service.ParseQUICProxyInit(quicInitPacketWithoutPayload(t, psk, nil))
	require.ErrorContains(t, err, "does not contain a payload")
}

func TestQUICInitialDetection(t *testing.T) {
	require.True(t, snell.IsQUICInitial([]byte{0xc0, 0, 0, 0, 1}))
	require.True(t, snell.IsQUICInitial([]byte{0xd0, 0x6b, 0x33, 0x43, 0xcf}))
	require.False(t, snell.IsQUICInitial([]byte{0xe0, 0, 0, 0, 1}))
	require.False(t, snell.IsQUICInitial([]byte{0xc0, 0, 0, 0, 0}))
	require.False(t, snell.IsQUICInitial([]byte{0xc0, 1, 2, 3}))
}

func TestV5ConcurrentUserUpdatesAndQUICAuthentication(t *testing.T) {
	psk := []byte("concurrent-user-password")
	service, err := snellv5.NewMultiService[int](snellv5.ServiceOptions{
		MultiUserAuthentication: snell.MultiUserAuthenticationPSK,
	})
	require.NoError(t, err)
	require.NoError(t, service.UpdateUsers([]int{0}, [][]byte{psk}))
	packet := quicInitPacket(t, psk, nil)

	done := make(chan error, 2)
	go func() {
		for index := range 1000 {
			if updateErr := service.UpdateUsers([]int{index & 1}, [][]byte{psk}); updateErr != nil {
				done <- updateErr
				return
			}
		}
		done <- nil
	}()
	go func() {
		for range 1000 {
			session, _, parseErr := service.ParseQUICProxyInit(packet)
			if parseErr != nil {
				done <- parseErr
				return
			}
			user, loaded := auth.UserFromContext[int](session.Context(context.Background()))
			if !loaded || user != 0 && user != 1 {
				done <- fmt.Errorf("unexpected authenticated user: %d", user)
				return
			}
		}
		done <- nil
	}()
	require.NoError(t, <-done)
	require.NoError(t, <-done)
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
