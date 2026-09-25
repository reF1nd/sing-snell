package test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestReuseEOFPersistsAcrossReadMethods(t *testing.T) {
	t.Parallel()
	for _, protocol := range []struct {
		name string
		v5   bool
		mode snellv6.Mode
	}{
		{name: "v5", v5: true},
		{name: "v6-default", mode: snellv6.ModeDefault},
		{name: "v6-unshaped", mode: snellv6.ModeUnshaped},
		{name: "v6-unsafe-raw", mode: snellv6.ModeUnsafeRaw},
	} {
		for _, method := range []string{"Read", "ReadBuffer", "WaitReadBuffer"} {
			t.Run(protocol.name+"/"+method, func(t *testing.T) {
				t.Parallel()
				results := make(chan error, 1)
				handler := eofAfterSniffHandler{method: method, results: results}
				var service snell.Service
				var err error
				if protocol.v5 {
					service, err = snellv5.NewService(snellv5.ServiceOptions{PSK: []byte(testPSK), Handler: handler})
				} else {
					service, err = snellv6.NewService(snellv6.ServerOptions{PSK: []byte(testPSK), Mode: protocol.mode, Handler: handler})
				}
				require.NoError(t, err)
				var proxy countingTCPProxy
				proxy.Start(t, startLocalSnellService(t, service))
				var client reuseTCPClient
				if protocol.v5 {
					client, err = snellv4.NewClient(snellv4.ClientOptions{
						PSK: []byte(testPSK), Reuse: true, Dialer: N.SystemDialer, Server: M.ParseSocksaddr(proxy.address),
					})
				} else {
					client, err = snellv6.NewClient(snellv6.ClientOptions{
						PSK: []byte(testPSK), Mode: protocol.mode, Reuse: true, Dialer: N.SystemDialer, Server: M.ParseSocksaddr(proxy.address),
					})
				}
				require.NoError(t, err)
				defer client.Close()
				// Reuse the same transport after both an empty upload and an upload
				// with data. Each new logical connection must start with a fresh EOF state.
				for _, payload := range [][]byte{nil, bytes.Repeat([]byte("request"), 1024), nil} {
					conn, err := client.DialContext(context.Background(), M.ParseSocksaddr("example.com:80"))
					require.NoError(t, err)
					t.Cleanup(func() { conn.Close() })
					require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
					if len(payload) > 0 {
						_, err = conn.Write(payload)
						require.NoError(t, err)
					}
					require.NoError(t, N.CloseWrite(conn))
					var response []byte
					for {
						chunk, readErr := readReuseChunk(conn, method)
						response = append(response, chunk...)
						if errors.Is(readErr, io.EOF) {
							break
						}
						require.NoError(t, readErr)
					}
					require.Equal(t, append([]byte("response:"), payload...), response)
					require.NoError(t, conn.SetReadDeadline(time.Now().Add(-time.Second)))
					for _, nextMethod := range []string{"Read", "ReadBuffer", "WaitReadBuffer"} {
						chunk, readErr := readReuseChunk(conn, nextMethod)
						require.Empty(t, chunk)
						require.ErrorIs(t, readErr, io.EOF, nextMethod)
					}
					require.NoError(t, conn.Close())
					select {
					case serverErr := <-results:
						require.NoError(t, serverErr)
					case <-time.After(5 * time.Second):
						t.Fatal("server handler did not finish")
					}
				}
				require.Equal(t, int32(1), proxy.count.Load(), "logical EOF must preserve transport reuse")
			})
		}
	}
}

type eofAfterSniffHandler struct {
	localEchoHandler
	method  string
	results chan<- error
}

func (h eofAfterSniffHandler) NewConnectionEx(_ context.Context, conn net.Conn, _, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	go func() {
		var result error
		defer func() {
			result = errors.Join(result, conn.Close())
			if onClose != nil {
				onClose(result)
			}
			h.results <- result
		}()
		result = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		if result != nil {
			return
		}
		// Model the EOF consumed during sniffing, before the relay starts reading.
		payload, err := io.ReadAll(conn)
		if err != nil {
			result = err
			return
		}
		// An expired deadline makes an accidental transport read fail immediately.
		result = conn.SetReadDeadline(time.Now().Add(-time.Second))
		if result != nil {
			return
		}
		chunk, err := readReuseChunk(conn, h.method)
		if !errors.Is(err, io.EOF) || len(chunk) != 0 {
			result = fmt.Errorf("read after sniff EOF: %d bytes, %v", len(chunk), err)
			return
		}
		result = conn.SetReadDeadline(time.Time{})
		if result != nil {
			return
		}
		_, result = conn.Write(append([]byte("response:"), payload...))
	}()
}

func readReuseChunk(conn net.Conn, method string) ([]byte, error) {
	switch method {
	case "Read":
		buffer := make([]byte, 2048)
		n, err := conn.Read(buffer)
		return buffer[:n], err
	case "ReadBuffer":
		buffer := buf.New()
		defer buffer.Release()
		err := conn.(N.ExtendedReader).ReadBuffer(buffer)
		return bytes.Clone(buffer.Bytes()), err
	case "WaitReadBuffer":
		waiter, ok := bufio.CreateReadWaiter(conn)
		if !ok {
			return nil, errors.New("missing read waiter")
		}
		waiter.InitializeReadWaiter(N.ReadWaitOptions{})
		buffer, err := waiter.WaitReadBuffer()
		if buffer == nil {
			return nil, err
		}
		defer buffer.Release()
		return bytes.Clone(buffer.Bytes()), err
	default:
		return nil, fmt.Errorf("unknown read method: %s", method)
	}
}
