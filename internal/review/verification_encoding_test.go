package review

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestVerificationBatchEncodingRoundTripsCompleteVerdicts(t *testing.T) {
	_, candidates, items := verificationFixture(t, `{"schema_version":1,"verdicts":[]}`)
	response, candidates, items := verificationFixture(t, validVerificationDocument(candidates.Findings()[0].Identity()))
	batch, err := ParseVerificationBatch(response, candidates, items)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeVerificationBatch(batch)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEncodedVerificationBatch(encoded)
	if err != nil || parsed.Identity() != batch.Identity() || parsed.CandidateBatchIdentity() != candidates.Identity() || len(parsed.Results()) != 1 || parsed.Validate() != nil {
		t.Fatalf("parsed batch=(%#v,%v)", parsed, err)
	}
	reencoded, _ := EncodeVerificationBatch(parsed)
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("verification encoding was not canonical")
	}
	for _, malformed := range [][]byte{
		append(append([]byte(nil), encoded...), '\n'),
		bytes.Replace(encoded, []byte(batch.Identity()), []byte(strings.Repeat("f", 64)), 1),
		bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1),
	} {
		if parsed, err := ParseEncodedVerificationBatch(malformed); !errors.Is(err, ErrInvalidVerificationBatchEncoding) || parsed.Identity() != "" {
			t.Fatalf("malformed=(%#v,%v)", parsed, err)
		}
	}
}
