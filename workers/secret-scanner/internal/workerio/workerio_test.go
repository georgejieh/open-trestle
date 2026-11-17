package workerio

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
)

func requestFrame(t *testing.T, id byte) []byte {
	t.Helper()
	frame, err := protocol.EncodeRequestFrame(protocol.Request{
		SchemaVersion: 1,
		RequestID:     strings.Repeat(string(id), 64),
		Sources:       []protocol.Source{{Ordinal: 0, Content: []byte("text")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func TestReadRequestRequiresExactlyOneFrame(t *testing.T) {
	frame := requestFrame(t, 'a')
	request, read, err := ReadRequest(bytes.NewReader(frame))
	if err != nil || request.RequestID != strings.Repeat("a", 64) || !bytes.Equal(read, frame) {
		t.Fatalf("one frame: %v", err)
	}
	for name, input := range map[string][]byte{
		"empty":          nil,
		"short prefix":   frame[:3],
		"short payload":  frame[:len(frame)-1],
		"trailing byte":  append(append([]byte(nil), frame...), 0),
		"second frame":   append(append([]byte(nil), frame...), frame...),
		"zero length":    {0, 0, 0, 0},
		"oversized":      {0, 0x30, 0, 1},
		"invalid json":   {0, 0, 0, 1, '{'},
		"unknown fields": append([]byte{0, 0, 0, 2}, "{}"...),
	} {
		if _, _, err := ReadRequest(bytes.NewReader(input)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestReadSessionRequestEndsOnlyAtAFrameBoundary(t *testing.T) {
	first, second := requestFrame(t, 'a'), requestFrame(t, 'b')
	input := bytes.NewReader(append(append([]byte(nil), first...), second...))
	for _, want := range []byte{'a', 'b'} {
		request, _, err := ReadSessionRequest(input)
		if err != nil || request.RequestID != strings.Repeat(string(want), 64) {
			t.Fatalf("frame %c: %v", want, err)
		}
	}
	if _, _, err := ReadSessionRequest(input); !errors.Is(err, io.EOF) {
		t.Fatalf("end at boundary = %v, want io.EOF", err)
	}
	for name, cut := range map[string][]byte{"prefix": first[:2], "payload": first[:10]} {
		if _, _, err := ReadSessionRequest(bytes.NewReader(cut)); err == nil || errors.Is(err, io.EOF) {
			t.Errorf("end inside the %s = %v, want a non-EOF error", name, err)
		}
	}
}

func TestWriteAllAndClearRequest(t *testing.T) {
	var output bytes.Buffer
	if err := WriteAll(&output, []byte("frame")); err != nil || output.String() != "frame" {
		t.Fatalf("WriteAll: %v", err)
	}
	content := []byte("secret")
	request := protocol.Request{SchemaVersion: 1, Sources: []protocol.Source{{Content: content}}}
	ClearRequest(&request)
	if !bytes.Equal(content, make([]byte, len(content))) || request.Sources != nil {
		t.Fatal("request was not cleared")
	}
	ClearRequest(nil)
}
