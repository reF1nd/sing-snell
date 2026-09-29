package snell

import (
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
)

func TestReadServerResponseError(t *testing.T) {
	t.Parallel()
	for _, testCase := range []struct {
		code      byte
		message   string
		remoteEOF bool
	}{
		{101, "Remote EOF", true},
		{101, "Other failure", false},
		{1, "Remote EOF", false},
		{1, "Connection refused", false},
	} {
		t.Run(fmt.Sprintf("%d/%s", testCase.code, testCase.message), func(t *testing.T) {
			t.Parallel()
			record := buf.As(append([]byte{testCase.code, byte(len(testCase.message))}, testCase.message...))
			err := ReadServerError(record)
			want := fmt.Sprintf("snell: server error %d: %s", testCase.code, testCase.message)
			if err == nil || err.Error() != want {
				t.Fatalf("error = %v, want %q", err, want)
			}
			var response *ServerResponseError
			if !errors.As(fmt.Errorf("read reply: %w", err), &response) {
				t.Fatal("wrapped reply lost its structured error")
			}
			if response.Code != testCase.code || response.Message != testCase.message || response.IsRemoteEOF() != testCase.remoteEOF {
				t.Fatalf("unexpected response: %#v", response)
			}
			if errors.Is(err, io.EOF) || E.IsClosedOrCanceled(err) {
				t.Fatal("server error was reclassified as normal stream completion")
			}
		})
	}
}

func TestMalformedServerResponseIsNotRemoteEOF(t *testing.T) {
	t.Parallel()
	for name, payload := range map[string][]byte{
		"missing-code":      nil,
		"missing-length":    {101},
		"truncated-message": {101, 10, 'R'},
		"trailing-data":     append([]byte{101, 10}, []byte("Remote EOF!")...),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := ReadServerError(buf.As(payload))
			var response *ServerResponseError
			if err == nil || errors.As(err, &response) {
				t.Fatalf("malformed reply decoded as server response: %v", err)
			}
		})
	}
}
