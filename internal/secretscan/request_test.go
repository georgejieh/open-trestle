package secretscan

import (
	"bytes"
	"crypto/sha256"
	"strings"
	"testing"
)

func TestRequestEncoderMatchesCanonicalProtocolWithoutTemporaryJSON(t *testing.T) {
	request := Request{
		SchemaVersion: 1,
		RequestID:     strings.Repeat("01", sha256.Size),
		Sources:       []Source{{Ordinal: 0, Content: make([]byte, 0)}, {Ordinal: 1, Content: []byte("\u03c0\r\n")}},
	}
	got, err := encodeClientRequestFrame(request)
	if err != nil {
		t.Fatal(err)
	}
	want, err := EncodeRequestFrame(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("request encoding differs from protocol")
	}
	clear(got)
}

func TestSourceInputBounds(t *testing.T) {
	tooMany := make([][]byte, maxSources+1)
	for index := range tooMany {
		tooMany[index] = []byte{}
	}
	aggregate := make([][]byte, maxAggregateSourceBytes/maxSourceBytes+1)
	for index := range aggregate {
		aggregate[index] = make([]byte, maxSourceBytes)
	}
	for name, sources := range map[string][][]byte{
		"no source":       {},
		"nil source":      {nil},
		"invalid UTF-8":   {{0xff}},
		"source count":    tooMany,
		"source bytes":    {make([]byte, maxSourceBytes+1)},
		"aggregate bytes": aggregate,
	} {
		if validateSourceInputs(sources) {
			t.Errorf("%s: accepted", name)
		}
	}
	if !validateSourceInputs([][]byte{{}, []byte("clean")}) {
		t.Fatal("an empty and a short source were refused")
	}
}
