package review

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestVerifiedFindingSetEncodingRoundTripsPromotedFindings(t *testing.T) {
	generationContext, candidates, candidateOutput, verificationContext, verification, verificationOutput, independence := independentVerificationFixture(t, "verified")
	receipt, _ := NewIndependentVerificationReceipt(IndependentVerificationArtifacts{GenerationContext: generationContext, Candidates: candidates, CandidateOutput: candidateOutput, VerificationContext: verificationContext, Verification: verification, VerificationOutput: verificationOutput, RouteIndependence: independence})
	set, err := PromoteVerifiedCandidates(receipt, candidates, verification)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeVerifiedFindingSet(set)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEncodedVerifiedFindingSet(encoded)
	if err != nil || parsed.Identity() != set.Identity() || len(parsed.Findings()) != 1 || parsed.Findings()[0].Fingerprint() != set.Findings()[0].Fingerprint() || parsed.Validate() != nil {
		t.Fatalf("parsed=(%#v,%v)", parsed, err)
	}
	reencoded, _ := EncodeVerifiedFindingSet(parsed)
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("verified set encoding was not canonical")
	}
	for _, malformed := range [][]byte{append(append([]byte(nil), encoded...), '\n'), bytes.Replace(encoded, []byte(set.Identity()), []byte(strings.Repeat("f", 64)), 1)} {
		if parsed, err := ParseEncodedVerifiedFindingSet(malformed); !errors.Is(err, ErrInvalidVerifiedFindingSetEncoding) || parsed.Identity() != "" {
			t.Fatalf("malformed=(%#v,%v)", parsed, err)
		}
	}
}
