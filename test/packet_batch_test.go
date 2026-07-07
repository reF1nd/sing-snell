package test

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestPacketBatchCreator(t *testing.T) {
	tests := []struct {
		name   string
		client func(net.Conn) (N.NetPacketConn, error)
	}{
		{
			name: "v4",
			client: func(conn net.Conn) (N.NetPacketConn, error) {
				client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte("test-password")})
				if err != nil {
					return nil, err
				}
				return client.DialPacketConn(conn)
			},
		},
		{
			name: "v6",
			client: func(conn net.Conn) (N.NetPacketConn, error) {
				client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte("test-password"), Mode: snellv6.ModeDefault})
				if err != nil {
					return nil, err
				}
				return client.DialPacketConn(conn)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Run("pipe", func(t *testing.T) {
				clientConn, serverConn := net.Pipe()
				defer clientConn.Close()
				defer serverConn.Close()
				packetConn, err := test.client(clientConn)
				require.NoError(t, err)
				writer, created := bufio.CreatePacketBatchWriter(packetConn)
				require.True(t, created)
				require.NotNil(t, writer)
			})
			t.Run("tcp", func(t *testing.T) {
				listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
				require.NoError(t, err)
				defer listener.Close()
				require.NoError(t, listener.SetDeadline(time.Now().Add(time.Second)))
				clientConn, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
				require.NoError(t, err)
				defer clientConn.Close()
				serverConn, err := listener.Accept()
				require.NoError(t, err)
				defer serverConn.Close()
				packetConn, err := test.client(clientConn)
				require.NoError(t, err)
				writer, created := bufio.CreatePacketBatchWriter(packetConn)
				require.True(t, created)
				require.NotNil(t, writer)
			})
		})
	}
}
