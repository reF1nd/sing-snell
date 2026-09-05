package snellv4

import (
	"context"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	M "github.com/sagernet/sing/common/metadata"
)

func TestKeepSessionSurvivesCloseOnce(t *testing.T) {
	for _, testCase := range []struct {
		name       string
		keep       bool
		readClosed bool
	}{
		{name: "drain-kept", keep: true},
		{name: "drain-not-kept"},
		{name: "eof-kept", keep: true, readClosed: true},
		{name: "eof-not-kept", readClosed: true},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			upstream := newCaptureConn()
			client, err := NewClient(ClientOptions{
				PSK:    []byte("keep-session-test-psk"),
				Reuse:  true,
				Dialer: captureDialer{conn: upstream},
				Server: M.ParseSocksaddr("127.0.0.1:1"),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { client.Close() })
			client.SetKeepIdleConnections(false)
			ctx := context.Background()
			if testCase.keep {
				ctx = snell.ContextWithKeepSession(ctx)
			}
			destination := M.ParseSocksaddr("example.com:443")
			conn, err := client.DialContext(ctx, destination)
			if err != nil {
				t.Fatal(err)
			}
			c := conn.(*reuseConn)
			// Model a successful reply with its EOF still unread on the drain path.
			c.session.reader = &reader{upstream: upstream, psk: client.psk}
			c.replyRead.Store(true)
			c.readClosed.Store(testCase.readClosed)
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(time.Second)
			for reuse.State(c.session.state.Load()) == reuse.StateWaiting && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			want := reuse.StateClosed
			if testCase.keep {
				want = reuse.StateReady
			}
			if got := reuse.State(c.session.state.Load()); got != want {
				t.Fatalf("session state after close = %v, want %v", got, want)
			}
			if !testCase.keep {
				return
			}
			// The exemption must not survive into the next unmarked connection.
			next, err := client.DialContext(context.Background(), destination)
			if err != nil {
				t.Fatal(err)
			}
			nextConn := next.(*reuseConn)
			if nextConn.session != c.session {
				t.Fatal("kept session was not reused")
			}
			nextConn.replyRead.Store(true)
			nextConn.readClosed.Store(true)
			if err := nextConn.Close(); err != nil {
				t.Fatal(err)
			}
			if got := reuse.State(c.session.state.Load()); got != reuse.StateClosed {
				t.Fatalf("unmarked reuse remained open: state %v", got)
			}
		})
	}
}
