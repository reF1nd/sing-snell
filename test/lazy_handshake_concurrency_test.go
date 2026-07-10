package test

import (
	"io"
	"net"
	"sync"
	"testing"

	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestConcurrentLazyHandshakeWrites(t *testing.T) {
	v4Client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte("test-password")})
	require.NoError(t, err)
	v6Client, err := snellv6.NewClient(snellv6.ClientOptions{PSK: []byte("test-password"), Mode: snellv6.ModeDefault})
	require.NoError(t, err)
	for name, dial := range map[string]func(net.Conn) net.Conn{
		"v4": func(conn net.Conn) net.Conn {
			return v4Client.DialEarlyConn(conn, M.ParseSocksaddr("example.com:443"))
		},
		"v6": func(conn net.Conn) net.Conn {
			return v6Client.DialEarlyConn(conn, M.ParseSocksaddr("example.com:443"))
		},
	} {
		t.Run(name, func(t *testing.T) {
			for range 64 {
				clientRaw, serverRaw := net.Pipe()
				proxyConn := dial(clientRaw)
				drainDone := make(chan struct{})
				go func() {
					_, _ = io.Copy(io.Discard, serverRaw)
					close(drainDone)
				}()
				start := make(chan struct{})
				var group sync.WaitGroup
				group.Add(2)
				for range 2 {
					go func() {
						defer group.Done()
						<-start
						_, writeErr := proxyConn.Write([]byte("x"))
						require.NoError(t, writeErr)
					}()
				}
				close(start)
				group.Wait()
				require.NoError(t, clientRaw.Close())
				<-drainDone
				require.NoError(t, serverRaw.Close())
			}
		})
	}
}
