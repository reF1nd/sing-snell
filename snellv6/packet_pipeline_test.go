package snellv6

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"

	snell "github.com/sagernet/sing-snell"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestClientPacketConnPipelinesFirstDatagram(t *testing.T) {
	const message = "UDP is disabled by server configuration"
	psk := []byte("udp-pipeline-test-psk")
	destination := M.ParseSocksaddr("192.0.2.1:443")
	payload := []byte("first datagram")
	for _, mode := range []Mode{ModeDefault, ModeUnshaped, ModeUnsafeRaw} {
		t.Run(mode.String(), func(t *testing.T) {
			clientSide, serverSide := net.Pipe()
			defer clientSide.Close()
			defer serverSide.Close()
			deadline := time.Now().Add(time.Second)
			if err := clientSide.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err := serverSide.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}

			var profile *Profile
			if mode == ModeDefault {
				profile = NewProfile(psk)
			}
			serverDone := make(chan error, 1)
			go func() {
				// The tunnel reply is withheld until the first datagram arrives.
				reader, request, err := readFirstRecord(serverSide, mode, psk, profile, N.ReadWaitOptions{})
				if err != nil {
					serverDone <- err
					return
				}
				request.Release()
				record, err := reader.NextRecord()
				if err != nil {
					serverDone <- E.Cause(err, "read first datagram")
					return
				}
				command, err := record.ReadByte()
				if err != nil || command != snell.UDPCommandForward {
					record.Release()
					serverDone <- E.New("unexpected udp command ", command, ": ", err)
					return
				}
				packetDestination, err := snell.ReadUDPRequestAddress(record)
				if err != nil {
					record.Release()
					serverDone <- err
					return
				}
				received := bytes.Clone(record.Bytes())
				record.Release()
				if packetDestination != destination || !bytes.Equal(received, payload) {
					serverDone <- E.New("unexpected datagram to ", packetDestination, ": ", string(received))
					return
				}
				reply := append([]byte{snell.ReplyError, 0x01, byte(len(message))}, message...)
				_, err = writeFirstRecord(serverSide, mode, psk, profile, reply)
				serverDone <- err
			}()

			client, err := NewClient(ClientOptions{PSK: psk, Mode: mode})
			if err != nil {
				t.Fatal(err)
			}
			packetConn, err := client.DialPacketConn(clientSide)
			if err != nil {
				t.Fatal(err)
			}
			_, err = packetConn.WriteTo(payload, destination.UDPAddr())
			if err != nil {
				t.Fatal(err)
			}

			_, _, err = packetConn.ReadFrom(make([]byte, 64))
			var responseErr *snell.ServerResponseError
			if !errors.As(err, &responseErr) || responseErr.Message != message {
				t.Fatalf("ReadFrom error = %v, want server error %q", err, message)
			}
			if err = <-serverDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
