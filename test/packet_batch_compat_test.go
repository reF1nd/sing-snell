package test

import (
	"net"
	"testing"

	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

func TestPacketBatchCreatorCompatibility(t *testing.T) {
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
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()
			packetConn, err := test.client(clientConn)
			require.NoError(t, err)
			_, created := bufio.CreatePacketBatchWriter(packetConn)
			require.True(t, created)
		})
	}
}
