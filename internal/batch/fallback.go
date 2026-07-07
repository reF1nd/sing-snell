package batch

import (
	"errors"
	"os"

	snell "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// FallbackPacketWriter writes a packet batch one datagram at a time for
// connections without a vectorised writer. Like the vectorised batch writers,
// it drops only datagrams above the record payload maximum, writes the rest,
// and then reports snell.ErrPayloadTooLarge. WritePacket owns each buffer, so
// a failed buffer is not released again.
type FallbackPacketWriter struct {
	Writer N.PacketWriter
}

func (w FallbackPacketWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	var payloadTooLargeErr error
	for index, buffer := range buffers {
		err := w.Writer.WritePacket(buffer, destinations[index])
		if err == nil {
			continue
		}
		if errors.Is(err, snell.ErrPayloadTooLarge) {
			payloadTooLargeErr = err
			continue
		}
		buf.ReleaseMulti(buffers[index+1:])
		return err
	}
	return payloadTooLargeErr
}
