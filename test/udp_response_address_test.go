package test

import (
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestUDPResponseAddressRoundTrip(t *testing.T) {
	for _, destination := range []M.Socksaddr{
		M.ParseSocksaddr("example.com:443"),
		M.ParseSocksaddr("127.0.0.1:53"),
		M.ParseSocksaddr("[2001:db8::1]:853"),
	} {
		t.Run(destination.String(), func(t *testing.T) {
			buffer := buf.New()
			defer buffer.Release()

			require.NoError(t, snell.WriteUDPResponseAddress(buffer, destination))
			require.Equal(t, snell.UDPResponseAddressLen(destination), buffer.Len())

			actual, err := snell.ReadUDPResponseAddress(buffer)
			require.NoError(t, err)
			require.Equal(t, destination.String(), actual.String())
		})
	}
}

func TestUDPResponseAddressRejectsInvalidDomain(t *testing.T) {
	buffer := buf.New()
	defer buffer.Release()

	err := snell.WriteUDPResponseAddress(buffer, M.Socksaddr{Fqdn: strings.Repeat("a", 256), Port: 443})
	require.Error(t, err)
}

func TestUDPResponseAddressPreservesMappedIPv4ForV6(t *testing.T) {
	source := M.ParseSocksaddr("[::ffff:192.0.2.1]:443")
	buffer := buf.New()
	defer buffer.Release()

	require.NoError(t, snell.WriteUDPResponseAddressPreserveMapped(buffer, source))
	require.Equal(t, 1+16+2, buffer.Len())
	require.Equal(t, byte(snell.AddressTypeIPv6), buffer.Bytes()[0])
	require.Equal(t, snell.UDPResponseAddressLenPreserveMapped(source), buffer.Len())

	decoded, err := snell.ReadUDPResponseAddress(buffer)
	require.NoError(t, err)
	require.Equal(t, "192.0.2.1:443", decoded.String())
}

func TestServerUDPDomainResponseLoopback(t *testing.T) {
	psk := []byte("domain-response-password")
	destination := M.ParseSocksaddr("example.com:443")

	v5Handler := domainPacketEchoHandler{initialDestinations: make(chan M.Socksaddr, 1)}
	v5Service, err := snellv5.NewService(snellv5.ServiceOptions{
		PSK:     psk,
		Handler: v5Handler,
	})
	require.NoError(t, err)
	v4Client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: psk})
	require.NoError(t, err)
	t.Run("v5", func(t *testing.T) {
		testServerUDPDomainResponseLoopback(t, destination, v5Handler.initialDestinations, v4Client.DialPacketConn, v5Service.NewConnection)
	})

	for name, mode := range v6Modes {
		t.Run("v6-"+name, func(t *testing.T) {
			handler := domainPacketEchoHandler{initialDestinations: make(chan M.Socksaddr, 1)}
			v6Service, err := snellv6.NewService(snellv6.ServerOptions{
				PSK:     psk,
				Mode:    mode,
				Handler: handler,
			})
			require.NoError(t, err)
			v6Client, err := snellv6.NewClient(snellv6.ClientOptions{
				PSK:  psk,
				Mode: mode,
			})
			require.NoError(t, err)
			testServerUDPDomainResponseLoopback(t, destination, handler.initialDestinations, v6Client.DialPacketConn, v6Service.NewConnection)
		})
	}
}

func TestServerUDPDomainResponseLoopbackMultiPSK(t *testing.T) {
	destination := M.ParseSocksaddr("example.com:443")

	t.Run("v5", func(t *testing.T) {
		users, psks := testUsers(16)
		userPSK := psks[len(psks)-1]
		handler := domainPacketEchoHandler{initialDestinations: make(chan M.Socksaddr, 1), users: make(chan int, 1)}
		service, err := snellv5.NewMultiService[int](snellv5.ServiceOptions{
			Handler:                 handler,
			MultiUserAuthentication: snell.MultiUserAuthenticationPSK,
		})
		require.NoError(t, err)
		require.NoError(t, service.UpdateUsers(users, psks))
		client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: userPSK})
		require.NoError(t, err)
		testServerUDPDomainResponseLoopback(t, destination, handler.initialDestinations, client.DialPacketConn, service.NewConnection)
		require.Equal(t, len(users)-1, <-handler.users)
	})

	for name, mode := range v6Modes {
		t.Run("v6-"+name, func(t *testing.T) {
			if mode == snellv6.ModeUnsafeRaw {
				t.Skip("psk multi-user authentication is unavailable in unsafe-raw mode")
			}
			users, psks := testUsers(16)
			userPSK := psks[len(psks)-1]
			handler := domainPacketEchoHandler{initialDestinations: make(chan M.Socksaddr, 1), users: make(chan int, 1)}
			service, err := snellv6.NewMultiService[int](snellv6.ServerOptions{
				Mode:                    mode,
				Handler:                 handler,
				MultiUserAuthentication: snell.MultiUserAuthenticationPSK,
			})
			require.NoError(t, err)
			require.NoError(t, service.UpdateUsers(users, psks))
			client, err := snellv6.NewClient(snellv6.ClientOptions{
				PSK:  userPSK,
				Mode: mode,
			})
			require.NoError(t, err)
			testServerUDPDomainResponseLoopback(t, destination, handler.initialDestinations, client.DialPacketConn, service.NewConnection)
			require.Equal(t, len(users)-1, <-handler.users)
		})
	}
}

type domainPacketEchoHandler struct {
	initialDestinations chan M.Socksaddr
	users               chan int
}

func (domainPacketEchoHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	err := conn.Close()
	if onClose != nil {
		onClose(err)
	}
}

func (h domainPacketEchoHandler) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	if h.initialDestinations != nil {
		h.initialDestinations <- destination
	}
	if h.users != nil {
		user, loaded := auth.UserFromContext[int](ctx)
		if loaded {
			h.users <- user
		} else {
			h.users <- -1
		}
	}
	go func() {
		var closeErr error
		defer func() {
			if err := conn.Close(); closeErr == nil {
				closeErr = err
			}
			if onClose != nil {
				onClose(closeErr)
			}
		}()

		buffer := buf.NewSize(N.CalculateFrontHeadroom(conn) + 1024 + N.CalculateRearHeadroom(conn))
		buffer.Resize(N.CalculateFrontHeadroom(conn), 0)
		packetDestination, err := conn.ReadPacket(buffer)
		if err != nil {
			buffer.Release()
			closeErr = err
			return
		}
		closeErr = conn.WritePacket(buffer, packetDestination)
	}()
}

func testServerUDPDomainResponseLoopback(
	t *testing.T,
	destination M.Socksaddr,
	initialDestinations <-chan M.Socksaddr,
	dialPacketConn func(net.Conn) (N.NetPacketConn, error),
	serve func(context.Context, net.Conn, M.Socksaddr, N.CloseHandlerFunc) error,
) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	serverErr := make(chan error, 1)
	serverClosed := make(chan error, 1)
	go func() {
		serverErr <- serve(context.Background(), serverConn, M.ParseSocksaddr("127.0.0.1:12345"), func(err error) {
			serverClosed <- err
		})
	}()

	packetConn, err := dialPacketConn(clientConn)
	require.NoError(t, err)
	defer packetConn.Close()

	payload := []byte("query")
	request := buf.NewSize(N.CalculateFrontHeadroom(packetConn) + len(payload) + N.CalculateRearHeadroom(packetConn))
	request.Resize(N.CalculateFrontHeadroom(packetConn), 0)
	_, err = request.Write(payload)
	require.NoError(t, err)
	err = packetConn.WritePacket(request, destination)
	require.NoError(t, err)

	response := buf.NewSize(1024)
	defer response.Release()
	require.NoError(t, packetConn.SetReadDeadline(time.Now().Add(time.Second)))
	source, err := packetConn.ReadPacket(response)
	require.NoError(t, err)
	require.Equal(t, payload, response.Bytes())
	require.Equal(t, destination.String(), source.String())
	select {
	case initialDestination := <-initialDestinations:
		require.Equal(t, destination.String(), initialDestination.String())
	default:
		t.Fatal("packet handler did not receive initial destination")
	}
	require.NoError(t, <-serverErr)

	require.NoError(t, packetConn.Close())
	select {
	case err = <-serverClosed:
		if err != nil && !errors.Is(err, io.ErrClosedPipe) && !errors.Is(err, net.ErrClosed) {
			require.NoError(t, err)
		}
	case <-time.After(time.Second):
		t.Fatal("server packet handler did not close")
	}
}
