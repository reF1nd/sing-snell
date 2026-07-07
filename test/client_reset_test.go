package test

import (
	"testing"

	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type resettableReuseTCPClient interface {
	reuseTCPClient
	Reset()
}

func TestClientResetDropsIdleReuseSessions(t *testing.T) {
	t.Run("v4-v5", func(t *testing.T) {
		service, err := snellv5.NewService(snellv5.ServiceOptions{
			PSK:     []byte(testPSK),
			Handler: localEchoHandler{},
		})
		require.NoError(t, err)
		serviceAddress := startLocalSnellService(t, service)
		var proxy countingTCPProxy
		proxy.Start(t, serviceAddress)
		client, err := snellv4.NewClient(snellv4.ClientOptions{
			PSK:    []byte(testPSK),
			Reuse:  true,
			Dialer: N.SystemDialer,
			Server: M.ParseSocksaddr(proxy.address),
		})
		require.NoError(t, err)
		verifyClientResetDropsIdleReuseSession(t, client, &proxy)
	})

	for _, testCase := range []struct {
		name string
		mode snellv6.Mode
	}{
		{"default", snellv6.ModeDefault},
		{"unshaped", snellv6.ModeUnshaped},
		{"unsafe-raw", snellv6.ModeUnsafeRaw},
	} {
		t.Run("v6-"+testCase.name, func(t *testing.T) {
			service, err := snellv6.NewService(snellv6.ServerOptions{
				PSK:     []byte(testPSK),
				Mode:    testCase.mode,
				Handler: localEchoHandler{},
			})
			require.NoError(t, err)
			serviceAddress := startLocalSnellService(t, service)
			var proxy countingTCPProxy
			proxy.Start(t, serviceAddress)
			client, err := snellv6.NewClient(snellv6.ClientOptions{
				PSK:    []byte(testPSK),
				Mode:   testCase.mode,
				Reuse:  true,
				Dialer: N.SystemDialer,
				Server: M.ParseSocksaddr(proxy.address),
			})
			require.NoError(t, err)
			verifyClientResetDropsIdleReuseSession(t, client, &proxy)
		})
	}
}

func verifyClientResetDropsIdleReuseSession(t *testing.T, client resettableReuseTCPClient, proxy *countingTCPProxy) {
	t.Helper()
	t.Cleanup(func() { require.NoError(t, client.Close()) })
	scenario := reuseScenario{client: client, destination: M.ParseSocksaddrHostPort("127.0.0.1", 443)}
	scenario.RoundTrip(t, "before-reset-1")
	scenario.RoundTrip(t, "before-reset-2")
	require.Equal(t, int32(1), proxy.count.Load())
	client.Reset()
	scenario.RoundTrip(t, "after-reset")
	require.Equal(t, int32(2), proxy.count.Load())
}
