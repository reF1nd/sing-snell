package snellv6

import (
	"context"
	"io"
	"net"
	"sync"
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
			// Model a successful reply with its EOF still unread on the drain path,
			// over a transport that stays open while the session is idle.
			c.session.transport.Conn = &idleConn{Conn: c.session.transport.Conn, closed: make(chan struct{})}
			c.session.reader = newRawReader(eofReader{})
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

type eofReader struct{}

func (eofReader) Read([]byte) (int, error) {
	return 0, io.EOF
}

// idleConn blocks reads until it is closed, like an open transport with no
// pending data, so the idle watch of a pooled session does not end it.
type idleConn struct {
	net.Conn
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *idleConn) Read([]byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}

func (c *idleConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}
