package snellv5

import (
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func TestReuseReadEOF(t *testing.T) {
	t.Parallel()
	for _, side := range []struct {
		name     string
		newReads func(io.Reader) ([]eofReadOperation, func())
	}{
		{"server", func(upstream io.Reader) ([]eofReadOperation, func()) {
			conn := &serverReuseConn[struct{}]{session: &serverReuseSession[struct{}]{reader: &reader{upstream: upstream}}}
			return eofReadOperations(conn, conn), nil
		}},
	} {
		for _, first := range []int{0, 1, 2} {
			for _, readErr := range []error{io.EOF, fmt.Errorf("wrapped: %w", io.EOF), io.ErrUnexpectedEOF} {
				t.Run(fmt.Sprintf("%s/%d/%v", side.name, first, readErr), func(t *testing.T) {
					t.Parallel()
					upstream := &eofCountingReader{err: readErr}
					reads, closeRead := side.newReads(upstream)
					if err := reads[first].read(); !errors.Is(err, readErr) {
						t.Fatalf("initial %s: %v, want %v", reads[first].name, err, readErr)
					}
					firstCalls := upstream.calls
					// The next access would fail differently: EOF must belong to the
					// logical connection, while other errors must not latch EOF.
					upstream.err = io.ErrNoProgress
					for _, read := range reads {
						want := io.ErrNoProgress
						if errors.Is(readErr, io.EOF) {
							want = io.EOF
						}
						if err := read.read(); !errors.Is(err, want) {
							t.Errorf("subsequent %s: %v, want %v", read.name, err, want)
						}
					}
					if errors.Is(readErr, io.EOF) {
						if upstream.calls != firstCalls {
							t.Errorf("read after EOF touched upstream: calls %d -> %d", firstCalls, upstream.calls)
						}
					} else if upstream.calls <= firstCalls {
						t.Error("non-EOF error prevented subsequent reads")
					}
					if closeRead != nil {
						closeRead()
						for _, read := range reads {
							if err := read.read(); !errors.Is(err, net.ErrClosed) {
								t.Errorf("closed %s: %v, want net.ErrClosed", read.name, err)
							}
						}
					}
				})
			}
		}
	}
}

type eofReadOperation struct {
	name string
	read func() error
}

func eofReadOperations(reader N.ExtendedReader, waiter N.ReadWaiter) []eofReadOperation {
	waiter.InitializeReadWaiter(N.ReadWaitOptions{})
	return []eofReadOperation{
		{"Read", func() error {
			n, err := reader.Read(make([]byte, 1))
			if n != 0 {
				return fmt.Errorf("unexpected data: %d bytes", n)
			}
			return err
		}},
		{"ReadBuffer", func() error {
			buffer := buf.New()
			defer buffer.Release()
			err := reader.ReadBuffer(buffer)
			if !buffer.IsEmpty() {
				return fmt.Errorf("unexpected data: %d bytes", buffer.Len())
			}
			return err
		}},
		{"WaitReadBuffer", func() error {
			buffer, err := waiter.WaitReadBuffer()
			if buffer != nil {
				buffer.Release()
				return errors.New("unexpected buffer")
			}
			return err
		}},
	}
}

type eofCountingReader struct {
	calls int
	err   error
}

func (r *eofCountingReader) Read([]byte) (int, error) {
	r.calls++
	return 0, r.err
}
