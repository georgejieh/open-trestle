package bpe

import (
	"bytes"
	"flag"
	"os"
	"testing"

	"github.com/betterleaks/betterleaks/detect"
)

var update = flag.Bool("update", false, "rewrite cl100k_base.bin from Betterleaks' embedded BPE file")

// TestFlatTableEqualsUpstreamRanks compares the embedded table with the ranks
// Betterleaks' own loader reads from the upstream cl100k_base file.
func TestFlatTableEqualsUpstreamRanks(t *testing.T) {
	upstream, err := (&detect.TiktokenLoader{}).LoadTiktokenBpe("https://openaipublic.blob.core.windows.net/encodings/" + encodingFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(upstream) != 100256 {
		t.Fatalf("upstream table has %d ranks", len(upstream))
	}
	encoded, err := Encode(upstream)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := os.WriteFile("cl100k_base.bin", encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Skip("rewrote cl100k_base.bin; run again without -update to check the embedded table")
	}
	committed, err := os.ReadFile("cl100k_base.bin")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(committed, encoded) || table != string(committed) {
		t.Fatal("cl100k_base.bin is not the canonical encoding of the upstream ranks; rerun with -update")
	}
	flat, err := (Loader{}).LoadTiktokenBpe("https://openaipublic.blob.core.windows.net/encodings/" + encodingFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(flat) != len(upstream) {
		t.Fatalf("flat table has %d ranks, upstream %d", len(flat), len(upstream))
	}
	for token, rank := range upstream {
		if got, ok := flat[token]; !ok || got != rank {
			t.Fatalf("rank of token %q is %d (present %v), upstream %d", token, got, ok, rank)
		}
	}
}

func TestDecodeRejectsMalformedTables(t *testing.T) {
	valid, err := Encode(map[string]int{"a": 0, "bc": 1, "d": 7})
	if err != nil {
		t.Fatal(err)
	}
	if ranks, err := Decode(string(valid)); err != nil || len(ranks) != 3 || ranks["d"] != 7 {
		t.Fatalf("valid table: %v %v", ranks, err)
	}
	for name, encoded := range map[string][]byte{
		"empty":            {},
		"truncated":        valid[:len(valid)-1],
		"trailing":         append(append([]byte(nil), valid...), 0),
		"count too large":  {0xff, 0xff, 0xff, 0x7f},
		"zero length":      {1, 0, 0},
		"length past end":  {1, 9, 'a', 0},
		"repeated rank":    {2, 1, 'a', 3, 1, 'b', 3},
		"decreasing rank":  {2, 1, 'a', 3, 1, 'b', 2},
		"duplicate token":  {2, 1, 'a', 0, 1, 'a', 1},
		"overlong uvarint": {0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x01},
	} {
		if _, err := Decode(string(encoded)); err == nil {
			t.Errorf("%s table accepted", name)
		}
	}
	if _, err := Encode(map[string]int{"a": 1, "b": 1}); err == nil {
		t.Error("repeated rank encoded")
	}
}
