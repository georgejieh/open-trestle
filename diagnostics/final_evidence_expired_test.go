package diagnostics

import (
	"bytes"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
)

// A result recorded after its evidence expired carries no evidence part, is
// bound into the identity, survives parsing, and can never be completed.
func TestFinalSetEvidenceExpired(t *testing.T) {
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-evidence-expired")
	if err != nil {
		t.Fatal(err)
	}
	for _, outcome := range []FinalOutcome{FinalOutcomeFailed, FinalOutcomeCanceled, FinalOutcomeInconclusive} {
		bare, err := NewFinalReviewSet(scope, "", "", outcome, Set{}, Set{})
		if err != nil {
			t.Fatal(err)
		}
		expired, err := bare.WithEvidenceExpired()
		if err != nil || !expired.EvidenceExpired() || expired.Identity() == bare.Identity() || expired.Validate() != nil {
			t.Fatalf("%s: expired set err=%v", outcome, err)
		}
		encoded, err := EncodeSet(expired)
		if err != nil || !bytes.Contains(encoded, []byte(`"evidence_expired":true`)) {
			t.Fatalf("%s: encoded=%s err=%v", outcome, encoded, err)
		}
		parsed, err := ParseSet(encoded)
		if err != nil || !parsed.EvidenceExpired() || parsed.Identity() != expired.Identity() {
			t.Fatalf("%s: parsed err=%v", outcome, err)
		}
		if _, err := ParseSet(bytes.Replace(encoded, []byte(`,"evidence_expired":true`), nil, 1)); err == nil {
			t.Fatalf("%s: dropped flag kept the identity", outcome)
		}
		if _, err := expired.WithEvidenceExpired(); err == nil {
			t.Fatal("expired twice")
		}
	}
	refused, err := NewFinalReviewSet(scope, "", "", FinalOutcomeFailed, Set{}, Set{})
	if err != nil {
		t.Fatal(err)
	}
	if refused, err = refused.WithContextRefusal(testContextShortfall); err != nil {
		t.Fatal(err)
	}
	both, err := refused.WithEvidenceExpired()
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeSet(both)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, err := ParseSet(encoded); err != nil || !parsed.EvidenceExpired() || parsed.Identity() != both.Identity() {
		t.Fatalf("refused expired parse: %v", err)
	}
	deterministic, err := deterministicSetAtCount(t, "run-expired-with-evidence", 1)
	if err != nil {
		t.Fatal(err)
	}
	withEvidence, err := NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), FinalOutcomeFailed, deterministic, Set{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := withEvidence.WithEvidenceExpired(); err == nil {
		t.Fatal("expired flag accepted beside evidence")
	}
	if _, err := deterministic.WithEvidenceExpired(); err == nil {
		t.Fatal("expired flag accepted on a non-final set")
	}
	// The schema admits exactly the encodings the runtime produces.
	assertFinalSetValidates(t, encoded)
	bare, err := NewFinalReviewSet(scope, "", "", FinalOutcomeInconclusive, Set{}, Set{})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := bare.WithEvidenceExpired()
	if err != nil {
		t.Fatal(err)
	}
	plain, err := EncodeSet(expired)
	if err != nil {
		t.Fatal(err)
	}
	assertFinalSetValidates(t, plain)
	withParts, err := EncodeSet(withEvidence)
	if err != nil {
		t.Fatal(err)
	}
	assertFinalSetValidates(t, withParts)
	for name, forged := range map[string][]byte{
		"false flag":         bytes.Replace(plain, []byte(`"evidence_expired":true`), []byte(`"evidence_expired":false`), 1),
		"completed":          bytes.Replace(plain, []byte(`"outcome":"inconclusive"`), []byte(`"outcome":"completed"`), 1),
		"beside evidence":    bytes.Replace(withParts, []byte(`"outcome":"failed"`), []byte(`"outcome":"failed","evidence_expired":true`), 1),
		"refusal not failed": bytes.Replace(encoded, []byte(`"outcome":"failed"`), []byte(`"outcome":"canceled"`), 1),
	} {
		assertFinalSetRefused(t, name, forged)
	}
}
