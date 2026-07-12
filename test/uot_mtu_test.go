package test

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type captureUoTPacketHandler struct {
	connections chan N.PacketConn
	users       chan int
}

type closeNotifyConn struct {
	net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *closeNotifyConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
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

func TestV5UoTAdvertisesProtocolMTU(t *testing.T) {
	psk := []byte("test-password")
	handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk, Handler: handler})
	require.NoError(t, err)
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: psk})
	require.NoError(t, err)

	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() {
		clientRaw.Close()
		serverRaw.Close()
	})
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- service.NewConnection(context.Background(), serverRaw, M.ParseSocksaddr("127.0.0.1:10000"), nil)
	}()
	clientPacketConn, err := client.DialPacketConn(clientRaw)
	require.NoError(t, err)

	payload := buf.NewSize(2048)
	payload.Resize(512, 0)
	payload.Extend(1200)
	require.NoError(t, clientPacketConn.WritePacket(payload, M.ParseSocksaddr("example.com:443")))
	serverPacketConn, serverFinished := waitUoTPacketConn(t, handler, serverDone)
	t.Cleanup(func() { serverPacketConn.Close() })

	for index, packetConn := range []N.PacketConn{clientPacketConn, serverPacketConn} {
		options := N.NewReadWaitOptions(nil, packetConn)
		if index == 0 {
			require.Equal(t, 0x3fff-(1+1+255+2), options.MTU)
		} else {
			require.Equal(t, 0x3fff-snell.MaxUDPResponseAddressLen, options.MTU)
		}
		buffer := options.NewPacketBuffer()
		require.GreaterOrEqual(t, buffer.FreeLen(), 1200)
		buffer.Release()
	}

	require.NoError(t, clientPacketConn.Close())
	if !serverFinished {
		require.NoError(t, <-serverDone)
	}
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
			require.Equal(t, 0xffff-snell.MaxUDPResponseAddressLen, options.MTU)
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

func TestV6MultiUserUoTRC1PacketMode(t *testing.T) {
	for _, authentication := range []snell.MultiUserAuthentication{
		snell.MultiUserAuthenticationUserKey,
		snell.MultiUserAuthenticationPSK,
	} {
		t.Run(map[snell.MultiUserAuthentication]string{
			snell.MultiUserAuthenticationUserKey: "userkey",
			snell.MultiUserAuthenticationPSK:     "psk",
		}[authentication], func(t *testing.T) {
			for _, testCase := range []struct {
				name string
				run  func(*testing.T, *captureUoTPacketHandler, *snellv6.Client, *snellv6.MultiService[int])
			}{
				{
					name: "mtu",
					run: func(t *testing.T, handler *captureUoTPacketHandler, client *snellv6.Client, service *snellv6.MultiService[int]) {
						testV6UoTAdvertisesRC1PacketMTU(t, handler, client.DialPacketConn, service.NewConnection)
					},
				},
				{
					name: "large-datagram",
					run: func(t *testing.T, handler *captureUoTPacketHandler, client *snellv6.Client, service *snellv6.MultiService[int]) {
						testUoTLargeDatagram(t, handler, 0xffff-9, client.DialPacketConn, func(conn net.Conn) error {
							return service.NewConnection(context.Background(), conn, M.ParseSocksaddr("127.0.0.1:10000"), nil)
						})
					},
				},
				{
					name: "packet-batch",
					run: func(t *testing.T, handler *captureUoTPacketHandler, client *snellv6.Client, service *snellv6.MultiService[int]) {
						testUoTPacketBatch(t, handler, client.DialPacketConn, func(conn net.Conn) error {
							return service.NewConnection(context.Background(), conn, M.ParseSocksaddr("127.0.0.1:10000"), nil)
						})
					},
				},
				{
					name: "oversize-rejection",
					run: func(t *testing.T, handler *captureUoTPacketHandler, client *snellv6.Client, service *snellv6.MultiService[int]) {
						testUoTServerPacketBatchRejection(t, handler, 0x10000, client.DialPacketConn, func(conn net.Conn) error {
							return service.NewConnection(context.Background(), conn, M.ParseSocksaddr("127.0.0.1:10000"), nil)
						})
					},
				},
			} {
				t.Run(testCase.name, func(t *testing.T) {
					handler, client, service, expectedUser := newV6MultiUserUoTFixture(t, authentication)
					testCase.run(t, handler, client, service)
					require.Equal(t, expectedUser, <-handler.users)
				})
			}
		})
	}
}

func newV6MultiUserUoTFixture(
	t *testing.T,
	authentication snell.MultiUserAuthentication,
) (*captureUoTPacketHandler, *snellv6.Client, *snellv6.MultiService[int], int) {
	t.Helper()
	users, credentials := testUsers(16)
	expectedUser := users[len(users)-1]
	selectedCredential := credentials[len(credentials)-1]
	handler := &captureUoTPacketHandler{
		connections: make(chan N.PacketConn, 1),
		users:       make(chan int, 1),
	}
	serverOptions := snellv6.ServerOptions{
		Mode:                    snellv6.ModeDefault,
		Handler:                 handler,
		MultiUserAuthentication: authentication,
	}
	clientOptions := snellv6.ClientOptions{Mode: snellv6.ModeDefault}
	if authentication == snell.MultiUserAuthenticationPSK {
		clientOptions.PSK = selectedCredential
	} else {
		serverOptions.PSK = []byte(testPSK)
		clientOptions.PSK = serverOptions.PSK
		clientOptions.UserKey = selectedCredential
	}
	service, err := snellv6.NewMultiService[int](serverOptions)
	require.NoError(t, err)
	require.NoError(t, service.UpdateUsers(users, credentials))
	client, err := snellv6.NewClient(clientOptions)
	require.NoError(t, err)
	return handler, client, service, expectedUser
}

func TestV5UoTServerWaitsForClientFIN(t *testing.T) {
	psk := []byte("test-password")
	handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk, Handler: handler})
	require.NoError(t, err)
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: psk})
	require.NoError(t, err)

	clientRaw, serverPipe := net.Pipe()
	serverRaw := &closeNotifyConn{Conn: serverPipe, closed: make(chan struct{})}
	t.Cleanup(func() {
		clientRaw.Close()
		serverRaw.Close()
	})
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- service.NewConnection(context.Background(), serverRaw, M.ParseSocksaddr("127.0.0.1:10000"), nil)
	}()
	clientPacketConn, err := client.DialPacketConn(clientRaw)
	require.NoError(t, err)

	payload := buf.NewSize(2048)
	payload.Resize(512, 0)
	payload.Extend(1200)
	require.NoError(t, clientPacketConn.WritePacket(payload, M.ParseSocksaddr("example.com:443")))
	serverPacketConn := <-handler.connections
	require.NoError(t, serverPacketConn.Close())
	require.NoError(t, serverPacketConn.SetReadDeadline(time.Now().Add(-time.Second)))
	require.Never(t, func() bool {
		select {
		case <-serverRaw.closed:
			return true
		default:
			return false
		}
	}, 50*time.Millisecond, time.Millisecond)

	require.NoError(t, clientPacketConn.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	readBuffer := buf.NewSize(2048)
	_, readErr := clientPacketConn.ReadPacket(readBuffer)
	readBuffer.Release()
	var netErr net.Error
	require.ErrorAs(t, readErr, &netErr)
	require.True(t, netErr.Timeout())

	require.NoError(t, clientPacketConn.Close())
	select {
	case <-serverRaw.closed:
	case <-time.After(time.Second):
		t.Fatal("server did not close UoT stream after client FIN")
	}
	require.NoError(t, <-serverDone)
}

func TestV6UoTServerWaitsForClientFIN(t *testing.T) {
	for _, mode := range []snellv6.Mode{snellv6.ModeDefault, snellv6.ModeUnshaped, snellv6.ModeUnsafeRaw} {
		t.Run(mode.String(), func(t *testing.T) {
			testV6UoTServerWaitsForClientFIN(t, mode)
		})
	}
}

func testV6UoTServerWaitsForClientFIN(t *testing.T, mode snellv6.Mode) {
	psk := []byte("test-password")
	handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
	service, err := snellv6.NewService(snellv6.ServerOptions{PSK: psk, Mode: mode, Handler: handler})
	require.NoError(t, err)
	client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: psk, Mode: mode})
	require.NoError(t, err)

	clientRaw, serverPipe := net.Pipe()
	serverRaw := &closeNotifyConn{Conn: serverPipe, closed: make(chan struct{})}
	t.Cleanup(func() {
		clientRaw.Close()
		serverRaw.Close()
	})
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- service.NewConnection(context.Background(), serverRaw, M.ParseSocksaddr("127.0.0.1:10000"), nil)
	}()
	clientPacketConn, err := client.DialPacketConn(clientRaw)
	require.NoError(t, err)

	payload := buf.NewSize(4096)
	payload.Resize(2048, 0)
	payload.Extend(1200)
	require.NoError(t, clientPacketConn.WritePacket(payload, M.ParseSocksaddr("example.com:443")))
	serverPacketConn := <-handler.connections

	require.NoError(t, serverPacketConn.Close())
	require.NoError(t, serverPacketConn.SetReadDeadline(time.Now().Add(-time.Second)))
	require.Never(t, func() bool {
		select {
		case <-serverRaw.closed:
			return true
		default:
			return false
		}
	}, 50*time.Millisecond, time.Millisecond)

	require.NoError(t, clientPacketConn.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
	readBuffer := buf.NewSize(2048)
	_, readErr := clientPacketConn.ReadPacket(readBuffer)
	readBuffer.Release()
	var netErr net.Error
	require.ErrorAs(t, readErr, &netErr)
	require.True(t, netErr.Timeout())

	require.NoError(t, clientPacketConn.Close())
	select {
	case <-serverRaw.closed:
	case <-time.After(time.Second):
		t.Fatal("server did not close UoT stream after client FIN")
	}
	require.NoError(t, <-serverDone)
}

func TestV5UoTLargeDatagramUsesSingleFrame(t *testing.T) {
	psk := []byte("test-password")
	handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk, Handler: handler})
	require.NoError(t, err)
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: psk})
	require.NoError(t, err)
	testUoTLargeDatagram(t, handler, 0x3fff-9, client.DialPacketConn, func(conn net.Conn) error {
		return service.NewConnection(context.Background(), conn, M.ParseSocksaddr("127.0.0.1:10000"), nil)
	})
}

func TestV6UoTLargeDatagramUsesSingleFrame(t *testing.T) {
	for _, mode := range []snellv6.Mode{snellv6.ModeDefault, snellv6.ModeUnshaped, snellv6.ModeUnsafeRaw} {
		t.Run(mode.String(), func(t *testing.T) {
			psk := []byte("test-password")
			handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
			service, err := snellv6.NewService(snellv6.ServerOptions{PSK: psk, Mode: mode, Handler: handler})
			require.NoError(t, err)
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: psk, Mode: mode})
			require.NoError(t, err)
			testUoTLargeDatagram(t, handler, 0xffff-9, client.DialPacketConn, func(conn net.Conn) error {
				return service.NewConnection(context.Background(), conn, M.ParseSocksaddr("127.0.0.1:10000"), nil)
			})
		})
	}
}

func TestV5UoTPacketBatchUsesSingleFrames(t *testing.T) {
	psk := []byte("test-password")
	handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk, Handler: handler})
	require.NoError(t, err)
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: psk})
	require.NoError(t, err)
	testUoTPacketBatch(t, handler, client.DialPacketConn, func(conn net.Conn) error {
		return service.NewConnection(context.Background(), conn, M.ParseSocksaddr("127.0.0.1:10000"), nil)
	})
}

func TestV6UoTPacketBatchUsesSingleFrames(t *testing.T) {
	for _, mode := range []snellv6.Mode{snellv6.ModeDefault, snellv6.ModeUnshaped, snellv6.ModeUnsafeRaw} {
		t.Run(mode.String(), func(t *testing.T) {
			psk := []byte("test-password")
			handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
			service, err := snellv6.NewService(snellv6.ServerOptions{PSK: psk, Mode: mode, Handler: handler})
			require.NoError(t, err)
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: psk, Mode: mode})
			require.NoError(t, err)
			testUoTPacketBatch(t, handler, client.DialPacketConn, func(conn net.Conn) error {
				return service.NewConnection(context.Background(), conn, M.ParseSocksaddr("127.0.0.1:10000"), nil)
			})
		})
	}
}

func TestV5UoTServerPacketBatchRejectsOversizeWithoutCorruptingState(t *testing.T) {
	psk := []byte("test-password")
	handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
	service, err := snellv5.NewService(snellv5.ServiceOptions{PSK: psk, Handler: handler})
	require.NoError(t, err)
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: psk})
	require.NoError(t, err)
	testUoTServerPacketBatchRejection(t, handler, 0x3fff, client.DialPacketConn, func(conn net.Conn) error {
		return service.NewConnection(context.Background(), conn, M.ParseSocksaddr("127.0.0.1:10000"), nil)
	})
}

func TestV6UoTServerPacketBatchRejectsOversizeWithoutCorruptingState(t *testing.T) {
	for _, mode := range []snellv6.Mode{snellv6.ModeDefault, snellv6.ModeUnshaped, snellv6.ModeUnsafeRaw} {
		t.Run(mode.String(), func(t *testing.T) {
			psk := []byte("test-password")
			handler := &captureUoTPacketHandler{connections: make(chan N.PacketConn, 1)}
			service, err := snellv6.NewService(snellv6.ServerOptions{PSK: psk, Mode: mode, Handler: handler})
			require.NoError(t, err)
			client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: psk, Mode: mode})
			require.NoError(t, err)
			testUoTServerPacketBatchRejection(t, handler, 0x10000, client.DialPacketConn, func(conn net.Conn) error {
				return service.NewConnection(context.Background(), conn, M.ParseSocksaddr("127.0.0.1:10000"), nil)
			})
		})
	}
}

func testUoTServerPacketBatchRejection(
	t *testing.T,
	handler *captureUoTPacketHandler,
	oversizedPayloadLen int,
	dialPacketConn func(net.Conn) (N.NetPacketConn, error),
	serve func(net.Conn) error,
) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		serverDone <- serve(conn)
	}()
	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { clientRaw.Close() })
	clientPacketConn, err := dialPacketConn(clientRaw)
	require.NoError(t, err)
	target := M.ParseSocksaddr("1.1.1.1:443")
	clientOptions := N.NewReadWaitOptions(nil, clientPacketConn)
	first := clientOptions.NewPacketBuffer()
	first.Extend(1)[0] = 1
	clientOptions.PostReturn(first)
	require.NoError(t, clientPacketConn.WritePacket(first, target))
	serverPacketConn, serverFinished := waitUoTPacketConn(t, handler, serverDone)

	firstRead := buf.NewSize(1)
	firstDestination, err := serverPacketConn.ReadPacket(firstRead)
	require.NoError(t, err)
	require.Equal(t, target, firstDestination)
	firstRead.Release()
	newServerBuffer := func(size int) *buf.Buffer {
		frontHeadroom := N.CalculateFrontHeadroom(serverPacketConn)
		rearHeadroom := N.CalculateRearHeadroom(serverPacketConn)
		buffer := buf.NewSize(frontHeadroom + size + rearHeadroom)
		buffer.Resize(frontHeadroom, 0)
		buffer.Extend(size)
		return buffer
	}
	batchWriter, created := bufio.CreatePacketBatchWriter(serverPacketConn)
	require.True(t, created)
	require.ErrorIs(t, batchWriter.WritePacketBatch(
		[]*buf.Buffer{newServerBuffer(1), newServerBuffer(oversizedPayloadLen)},
		[]M.Socksaddr{target, target},
	), snell.ErrPayloadTooLarge)

	writeDone := make(chan error, 1)
	go func() {
		response := newServerBuffer(1)
		response.Bytes()[0] = 2
		writeDone <- serverPacketConn.WritePacket(response, target)
	}()
	response := buf.NewSize(1)
	responseSource, err := clientPacketConn.ReadPacket(response)
	require.NoError(t, err)
	require.NoError(t, <-writeDone)
	require.Equal(t, target, responseSource)
	require.Equal(t, []byte{2}, response.Bytes())
	response.Release()

	require.NoError(t, clientPacketConn.Close())
	require.NoError(t, serverPacketConn.Close())
	if !serverFinished {
		require.NoError(t, <-serverDone)
	}
}

func TestV4UoTRejectsEmptyDomainPayloadBeforeHandshake(t *testing.T) {
	psk := []byte("test-password")
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: psk})
	require.NoError(t, err)
	for _, batch := range []bool{false, true} {
		t.Run(map[bool]string{false: "single", true: "batch"}[batch], func(t *testing.T) {
			listener, listenErr := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, listenErr)
			defer listener.Close()
			serverRawDone := make(chan net.Conn, 1)
			go func() {
				serverRaw, acceptErr := listener.Accept()
				if acceptErr == nil {
					serverRawDone <- serverRaw
				}
			}()
			clientRaw, dialErr := net.Dial("tcp", listener.Addr().String())
			require.NoError(t, dialErr)
			defer clientRaw.Close()
			serverRaw := <-serverRawDone
			defer serverRaw.Close()
			packetConn, dialErr := client.DialPacketConn(clientRaw)
			require.NoError(t, dialErr)
			empty := buf.NewSize(N.CalculateFrontHeadroom(packetConn) + N.CalculateRearHeadroom(packetConn))
			empty.Resize(N.CalculateFrontHeadroom(packetConn), 0)
			destination := M.ParseSocksaddr("example.com:443")
			if batch {
				batchWriter, created := bufio.CreatePacketBatchWriter(packetConn)
				require.True(t, created)
				dialErr = batchWriter.WritePacketBatch([]*buf.Buffer{empty}, []M.Socksaddr{destination})
			} else {
				dialErr = packetConn.WritePacket(empty, destination)
			}
			require.ErrorIs(t, dialErr, snell.ErrEmptyDomainUDPPayload)
			require.NoError(t, serverRaw.SetReadDeadline(time.Now().Add(20*time.Millisecond)))
			_, readErr := serverRaw.Read(make([]byte, 1))
			var netErr net.Error
			require.ErrorAs(t, readErr, &netErr)
			require.True(t, netErr.Timeout())
		})
	}
}

func testUoTPacketBatch(
	t *testing.T,
	handler *captureUoTPacketHandler,
	dialPacketConn func(net.Conn) (N.NetPacketConn, error),
	serve func(net.Conn) error,
) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	serverDone := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverDone <- acceptErr
			return
		}
		serverDone <- serve(conn)
	}()
	clientRaw, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	t.Cleanup(func() { clientRaw.Close() })
	clientPacketConn, err := dialPacketConn(clientRaw)
	require.NoError(t, err)

	targets := []M.Socksaddr{
		M.ParseSocksaddr("1.1.1.1:443"),
		M.ParseSocksaddr("[2606:4700:4700::1111]:443"),
	}
	payloads := [][]byte{make([]byte, 4096), make([]byte, 8192)}
	for payloadIndex, payload := range payloads {
		for index := range payload {
			payload[index] = byte(index + payloadIndex)
		}
	}
	clientBuffers := make([]*buf.Buffer, len(payloads))
	clientOptions := N.NewReadWaitOptions(nil, clientPacketConn)
	for index, payload := range payloads {
		clientBuffers[index] = clientOptions.NewPacketBuffer()
		_, err = clientBuffers[index].Write(payload)
		require.NoError(t, err)
		clientOptions.PostReturn(clientBuffers[index])
	}
	clientBatchWriter, created := bufio.CreatePacketBatchWriter(clientPacketConn)
	require.True(t, created)
	require.NoError(t, clientBatchWriter.WritePacketBatch(clientBuffers, targets))

	serverPacketConn, serverFinished := waitUoTPacketConn(t, handler, serverDone)
	serverOptions := N.NewReadWaitOptions(nil, serverPacketConn)
	serverBuffers := make([]*buf.Buffer, len(payloads))
	for index, payload := range payloads {
		serverBuffers[index] = serverOptions.NewPacketBuffer()
		destination, readErr := serverPacketConn.ReadPacket(serverBuffers[index])
		require.NoError(t, readErr)
		serverOptions.PostReturn(serverBuffers[index])
		require.Equal(t, targets[index], destination)
		require.Equal(t, payload, serverBuffers[index].Bytes())
	}
	serverBatchWriter, created := bufio.CreatePacketBatchWriter(serverPacketConn)
	require.True(t, created)
	require.NoError(t, serverBatchWriter.WritePacketBatch(serverBuffers, targets))

	for index, payload := range payloads {
		response := buf.NewSize(len(payload) + 64)
		source, readErr := clientPacketConn.ReadPacket(response)
		require.NoError(t, readErr)
		require.Equal(t, targets[index], source)
		require.Equal(t, payload, response.Bytes())
		response.Release()
	}
	require.NoError(t, clientPacketConn.Close())
	require.NoError(t, serverPacketConn.Close())
	if !serverFinished {
		select {
		case serverErr := <-serverDone:
			require.NoError(t, serverErr)
		case <-time.After(time.Second):
			t.Fatal("server did not finish UoT connection")
		}
	}
}

func testUoTLargeDatagram(
	t *testing.T,
	handler *captureUoTPacketHandler,
	payloadSize int,
	dialPacketConn func(net.Conn) (N.NetPacketConn, error),
	serve func(net.Conn) error,
) {
	t.Helper()
	clientRaw, serverRaw := net.Pipe()
	t.Cleanup(func() {
		clientRaw.Close()
		serverRaw.Close()
	})
	serverDone := make(chan error, 1)
	go func() { serverDone <- serve(serverRaw) }()
	clientPacketConn, err := dialPacketConn(clientRaw)
	require.NoError(t, err)
	target := M.ParseSocksaddr("1.1.1.1:443")
	payloadBytes := make([]byte, payloadSize)
	for index := range payloadBytes {
		payloadBytes[index] = byte(index)
	}
	writeOptions := N.NewReadWaitOptions(nil, clientPacketConn)
	writeBuffer := buf.NewSize(payloadSize + writeOptions.FrontHeadroom + writeOptions.RearHeadroom)
	if writeOptions.FrontHeadroom > 0 {
		writeBuffer.Resize(writeOptions.FrontHeadroom, 0)
	}
	if writeOptions.RearHeadroom > 0 {
		writeBuffer.Reserve(writeOptions.RearHeadroom)
	}
	written, err := writeBuffer.Write(payloadBytes)
	require.NoError(t, err)
	require.Equal(t, payloadSize, written)
	writeOptions.PostReturn(writeBuffer)
	require.NoError(t, clientPacketConn.WritePacket(writeBuffer, target))

	serverPacketConn, serverFinished := waitUoTPacketConn(t, handler, serverDone)
	serverWriteOptions := N.NewReadWaitOptions(nil, serverPacketConn)
	serverBuffer := buf.NewSize(payloadSize + serverWriteOptions.FrontHeadroom + serverWriteOptions.RearHeadroom)
	if serverWriteOptions.FrontHeadroom > 0 {
		serverBuffer.Resize(serverWriteOptions.FrontHeadroom, 0)
	}
	if serverWriteOptions.RearHeadroom > 0 {
		serverBuffer.Reserve(serverWriteOptions.RearHeadroom)
	}
	packetDestination, err := serverPacketConn.ReadPacket(serverBuffer)
	require.NoError(t, err)
	serverWriteOptions.PostReturn(serverBuffer)
	require.Equal(t, target, packetDestination)
	require.Equal(t, payloadBytes, serverBuffer.Bytes())
	writeDone := make(chan error, 1)
	go func() { writeDone <- serverPacketConn.WritePacket(serverBuffer, packetDestination) }()

	readBuffer := buf.NewSize(65535)
	responseSource, err := clientPacketConn.ReadPacket(readBuffer)
	require.NoError(t, err)
	require.NoError(t, <-writeDone)
	require.Equal(t, target, responseSource)
	require.Equal(t, payloadBytes, readBuffer.Bytes())
	readBuffer.Release()
	require.NoError(t, clientPacketConn.Close())
	require.NoError(t, serverPacketConn.Close())
	if !serverFinished {
		require.NoError(t, <-serverDone)
	}
}
