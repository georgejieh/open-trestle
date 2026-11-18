package workerio

import (
	"bytes"
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
