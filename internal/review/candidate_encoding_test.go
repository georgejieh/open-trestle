package review

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestCandidateBatchEncodingRoundTripsAdmittedFindings(t *testing.T) {
	response, snapshot, items := candidateFixture(t, validCandidateDocument())
	batch, err := ParseCandidateBatch(response, snapshot, items)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeCandidateBatch(batch)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEncodedCandidateBatch(encoded)
	if err != nil || parsed.Identity() != batch.Identity() || parsed.ResponseIdentity() != batch.ResponseIdentity() || parsed.SnapshotIdentity() != batch.SnapshotIdentity() || len(parsed.Findings()) != 1 || parsed.Validate() != nil {
		t.Fatalf("parsed candidate batch = (%#v, %v)", parsed, err)
	}
	reencoded, _ := EncodeCandidateBatch(parsed)
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("candidate batch encoding was not canonical")
	}
	for _, malformed := range [][]byte{
		append(append([]byte(nil), encoded...), '\n'),
		bytes.Replace(encoded, []byte(batch.Identity()), []byte(strings.Repeat("f", 64)), 1),
		bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1),
	} {
		if parsed, err := ParseEncodedCandidateBatch(malformed); !errors.Is(err, ErrInvalidCandidateBatchEncoding) || parsed.Identity() != "" {
			t.Fatalf("malformed candidate batch = (%#v, %v)", parsed, err)
		}
	}
}

func TestCandidateBatchEncodingPreservesExplicitEmptySet(t *testing.T) {
	response, snapshot, _ := candidateFixture(t, `{"schema_version":1,"candidates":[]}`)
	batch, _ := ParseCandidateBatch(response, snapshot, nil)
	encoded, err := EncodeCandidateBatch(batch)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEncodedCandidateBatch(encoded)
	if err != nil || parsed.Findings() != nil || parsed.Identity() != batch.Identity() {
		t.Fatalf("parsed empty batch = (%#v, %v)", parsed, err)
	}
}
