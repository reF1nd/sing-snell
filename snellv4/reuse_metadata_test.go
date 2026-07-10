package snellv4

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/internal/reuse"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func TestReuseMetadataDuringHandshake(t *testing.T) {
	t.Parallel()
	for _, mode := range []struct{ name string }{{"v4-v5"}} {
		for _, reused := range []bool{false, true} {
			for _, operation := range []string{"read", "write", "buffer"} {
				t.Run(fmt.Sprintf("%s/reused=%v/%s", mode.name, reused, operation), func(t *testing.T) {
					t.Parallel()
					client, err := NewClient(ClientOptions{PSK: []byte("metadata-race-test-password"), UserKey: []byte("user"), Reuse: true})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { client.Close() })
					upstream := &metadataBlockingConn{captureConn: newCaptureConn()}
					t.Cleanup(func() { upstream.Close() })
					session := client.newReuseSession(upstream)
					session.state.Store(uint32(reuse.StateActive))
					destination := M.ParseSocksaddr("example.com:443")
					if reused {
						first, err := session.DialConn(destination)
						if err != nil {
							t.Fatal(err)
						}
						if _, err = first.Write(nil); err != nil {
							t.Fatal(err)
						}
						// Model a completed logical connection returning the established session.
						session.Release(true)
						taken, found, closed := client.pool.Take()
						if !found || closed || taken != session {
							t.Fatal("session not reusable")
						}
					}
					raw, err := session.DialConn(destination)
					if err != nil {
						t.Fatal(err)
					}
					conn := raw.(*reuseConn)
					recordHeadroom, saltHeadroom, rear, mtu := snell.HeaderCipherLen, snell.SaltLen+maxInitialPaddingLen, snell.AEADTagLen, maxPayload
					request := snell.Request{Command: snell.CommandConnectV2, ClientID: client.userKey, Destination: destination}
					initial := request.Len() + recordHeadroom
					if !reused {
						initial += saltHeadroom
					}
					metadata := func() [3]int { return [3]int{conn.FrontHeadroom(), conn.RearHeadroom(), conn.WriterMTU()} }
					if got := metadata(); got != [3]int{initial, rear, mtu} {
						t.Fatalf("initial metadata = %v", got)
					}
					upstream.entered, upstream.release = make(chan struct{}), make(chan struct{})
					done := make(chan error, 1)
					go func() {
						switch operation {
						case "read":
							_, err := conn.Read(make([]byte, 1))
							if errors.Is(err, io.EOF) {
								err = nil
							}
							done <- err
						case "write":
							_, err := conn.Write([]byte("payload"))
							done <- err
						case "buffer":
							buffer := buf.NewSize(initial + 7 + rear)
							buffer.Resize(initial, 0)
							_, _ = buffer.Write([]byte("payload"))
							done <- conn.WriteBuffer(buffer)
						}
					}()
					select {
					case <-upstream.entered:
					case <-time.After(5 * time.Second):
						t.Fatal("handshake did not reach upstream")
					}
					// Queries must return while the handshake holds its lock in network I/O.
					queried := make(chan [3]int, 1)
					go func() { queried <- metadata() }()
					select {
					case got := <-queried:
						if got != [3]int{initial, rear, mtu} {
							t.Errorf("pending metadata = %v, want %v", got, [3]int{initial, rear, mtu})
						}
					case <-time.After(5 * time.Second):
						t.Fatal("metadata query blocked on handshake")
					}
					// Keep querying across writer publication. Do not synchronize each query
					// with handshake completion: that would hide the original data race.
					started, stopped := make(chan struct{}), make(chan struct{})
					stop := make(chan struct{})
					go func() {
						defer close(stopped)
						close(started)
						for {
							got := metadata()
							if (got[0] != initial && got[0] != recordHeadroom) || got[1] != rear || got[2] != mtu {
								t.Errorf("concurrent metadata = %v", got)
								return
							}
							select {
							case <-stop:
								return
							default:
								runtime.Gosched()
							}
						}
					}()
					<-started
					upstream.unblock()
					select {
					case err := <-done:
						if err != nil {
							t.Error(err)
						}
					case <-time.After(5 * time.Second):
						t.Error("handshake did not complete")
					}
					close(stop)
					<-stopped
					if got := metadata(); got != [3]int{recordHeadroom, rear, mtu} {
						t.Errorf("established metadata = %v", got)
					}
				})
			}
		}
	}
}

type metadataBlockingConn struct {
	*captureConn
	entered     chan struct{}
	release     chan struct{}
	enterOnce   sync.Once
	releaseOnce sync.Once
}

func (c *metadataBlockingConn) Write(p []byte) (int, error) {
	if c.entered != nil {
		c.enterOnce.Do(func() { close(c.entered) })
		<-c.release
	}
	return c.captureConn.Write(p)
}

func (c *metadataBlockingConn) unblock() {
	c.releaseOnce.Do(func() {
		if c.release != nil {
			close(c.release)
		}
	})
}

func (c *metadataBlockingConn) Close() error {
	c.unblock()
	return c.captureConn.Close()
}
