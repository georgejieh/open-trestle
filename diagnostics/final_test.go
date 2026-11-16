package diagnostics

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
)

func TestFullReviewFinalV7KeepsObservationAndVerifiedFindingDistinct(t *testing.T) {
	deterministic, err := deterministicSetAtCount(t, "run-full-final", 1)
	if err != nil {
		t.Fatal(err)
	}
	finding, err := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue", "Verified by independent route.", SeverityError, "verified.go", 4, 4, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := NewSetWithDeterministicChecks(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []Finding{finding})
	if err != nil {
		t.Fatal(err)
	}
	store, err := NewFileStore(filepath.Join(t.TempDir(), "diagnostics"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = store.PutDiagnosticSet(context.Background(), deterministic); err != nil {
		t.Fatal(err)
	}
	if _, err = store.PutDiagnosticSet(context.Background(), verified); !errors.Is(err, ErrSetConflict) {
		t.Fatalf("V6->V5 collision must be RED: %v", err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	final, err := NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), FinalOutcomeCompleted, deterministic, verified)
	if err != nil || final.SchemaVersion() != 7 || final.Outcome() != FinalOutcomeCompleted || len(final.DeterministicObservations()) != 1 || len(final.Findings()) != 1 {
		t.Fatalf("final=%#v err=%v", final, err)
	}
	encoded, err := EncodeSet(final)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"observations"`)) || !bytes.Contains(encoded, []byte(`"findings"`)) || !bytes.Contains(encoded, []byte(`"outcome":"completed"`)) {
		t.Fatalf("encoded=%s", encoded)
	}
	parsed, err := ParseSet(encoded)
	if err != nil || parsed.Identity() != final.Identity() || !bytes.Equal(encoded, mustEncodeSet(t, parsed)) {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	store, err = NewFileStore(filepath.Join(t.TempDir(), "final"))
	if err != nil {
		t.Fatal(err)
	}
	if created, err := store.PutDiagnosticSet(context.Background(), final); !created || err != nil {
		t.Fatalf("put=(%v,%v)", created, err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(filepath.Join(filepath.Dir(store.root), "final"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	readback, err := reopened.GetDiagnosticSet(context.Background(), deterministic.Scope())
	if err != nil || readback.Identity() != final.Identity() || readback.SchemaVersion() != 7 || readback.VerifiedSetIdentity() != verified.VerifiedSetIdentity() || readback.AnalysisResultIdentity() != deterministic.AnalysisResultIdentity() {
		t.Fatalf("readback=%#v err=%v", readback, err)
	}
	if created, err := reopened.PutDiagnosticSet(context.Background(), final); created || err != nil {
		t.Fatalf("replay=(%t,%v)", created, err)
	}
}

func TestFullReviewPhysicalSnapshotAndSelectedReviewSnapshotAreDistinct(t *testing.T) {
	deterministic, err := deterministicSetAtCount(t, "run-snapshot-domains", 1)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := NewSetWithDeterministicChecks(deterministic.Scope(), strings.Repeat("9", 64), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 0, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), nil)
	if err != nil {
		t.Fatal(err)
	}
	final, err := NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), FinalOutcomeCompleted, deterministic, verified)
	if err != nil || final.SnapshotIdentity() != deterministic.SnapshotIdentity() || final.ReviewSnapshotIdentity() != verified.SnapshotIdentity() || final.VerifiedSetIdentity() != verified.VerifiedSetIdentity() {
		t.Fatalf("different snapshot domains rejected: %#v %v", final, err)
	}
	encoded, err := EncodeSet(final)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSet(encoded)
	if err != nil || parsed.Identity() != final.Identity() || parsed.ReviewSnapshotIdentity() != verified.SnapshotIdentity() || !bytes.Equal(encoded, mustEncodeSet(t, parsed)) {
		t.Fatalf("roundtrip=%#v err=%v", parsed, err)
	}
}

func TestFullReviewFailedWithoutEvidenceCannotAppearClean(t *testing.T) {
	deterministic, err := deterministicSetAtCount(t, "run-failed-final", 1)
	if err != nil {
		t.Fatal(err)
	}
	final, err := NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), FinalOutcomeFailed, Set{}, Set{})
	if err != nil || final.SchemaVersion() != 7 || final.Outcome() != FinalOutcomeFailed || len(final.DeterministicChecks()) != 0 || len(final.Findings()) != 0 {
		t.Fatalf("failed final=%#v err=%v", final, err)
	}
	if _, err := NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), FinalOutcomeCompleted, Set{}, Set{}); err == nil {
		t.Fatal("completed without verification admitted")
	}
	for _, outcome := range []FinalOutcome{FinalOutcomeFailed, FinalOutcomeCanceled, FinalOutcomeAbstained, FinalOutcomeInconclusive} {
		early, err := NewFinalReviewSet(deterministic.Scope(), "", "", outcome, Set{}, Set{})
		if err != nil || early.Validate() != nil || early.VerifiedSetIdentity() != "" || early.AnalysisResultIdentity() != "" {
			t.Fatalf("early %s=%#v err=%v", outcome, early, err)
		}
		encoded, err := EncodeSet(early)
		if err != nil || bytes.Contains(encoded, []byte(`"verified"`)) || bytes.Contains(encoded, []byte(`"deterministic"`)) {
			t.Fatalf("early=%s err=%v", encoded, err)
		}
		parsed, err := ParseSet(encoded)
		if err != nil || parsed.Identity() != early.Identity() {
			t.Fatalf("early parse=%#v err=%v", parsed, err)
		}
	}
}

func TestFullReviewV7RefusesCrossScopeEvidenceAndTampering(t *testing.T) {
	deterministic, err := deterministicSetAtCount(t, "run-cross-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	other, err := deterministicSetAtCount(t, "run-cross-b", 1)
	if err != nil {
		t.Fatal(err)
	}
	if set, err := NewFinalReviewSet(other.Scope(), other.SnapshotIdentity(), other.HeadRevision(), FinalOutcomeFailed, deterministic, Set{}); err == nil || set.Identity() != "" {
		t.Fatalf("cross scope admitted: %#v %v", set, err)
	}
	if set, err := NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), strings.Repeat("2", 40), FinalOutcomeFailed, deterministic, Set{}); err == nil || set.Identity() != "" {
		t.Fatalf("cross revision admitted: %#v %v", set, err)
	}
	final, err := NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), FinalOutcomeAbstained, deterministic, Set{})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeSet(final)
	if err != nil {
		t.Fatal(err)
	}
	for _, tampered := range [][]byte{
		bytes.Replace(encoded, []byte(`"outcome":"abstained"`), []byte(`"outcome":"completed"`), 1),
		bytes.Replace(encoded, []byte(`"analysis_result_identity":"`), []byte(`"analysis_result_identity":"0`), 1),
		bytes.Replace(encoded, []byte(`"deterministic":{`), []byte(`"deterministic":{"unexpected":1,`), 1),
	} {
		if parsed, err := ParseSet(tampered); err == nil || parsed.Identity() != "" {
			t.Fatalf("tampered parsed=%#v err=%v", parsed, err)
		}
	}
}

func BenchmarkFullReviewV7EncodeParse(b *testing.B) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "bench-full-review")
	checkSource := DeterministicCheck{changeIdentity: strings.Repeat("7", 64), state: CheckFailed, applicableFiles: 1, applicableRanges: 1, checkedFiles: 1, checkedRanges: 1, matches: 1}
	check, _ := NewDeterministicCheck(deriveSourceDeterministicCheckIdentity(checkSource), strings.Repeat("8", 64), strings.Repeat("7", 64), CheckFailed, 1, 1, 1, 1, 1)
	observation, _ := NewDeterministicObservation(strings.Repeat("6", 64), strings.Repeat("5", 64), strings.Repeat("8", 64), check.Identity(), "Debug output left in source", "Exact changed range; human review required.", SeverityWarning, "main.go", 6, 6, []string{strings.Repeat("4", 64)})
	deterministic, _ := NewSetWithDeterministicObservations(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("8", 64), []DeterministicCheck{check}, []DeterministicObservation{observation})
	finding, _ := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue", "Verified by independent route.", SeverityError, "main.go", 4, 4, []string{strings.Repeat("c", 64)})
	verified, _ := NewSetWithDeterministicChecks(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []Finding{finding})
	final, _ := NewFinalReviewSet(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), FinalOutcomeCompleted, deterministic, verified)
	encoded, _ := EncodeSet(final)
	b.ResetTimer()
	b.ReportMetric(float64(len(encoded)), "bytes/set")
	for i := 0; i < b.N; i++ {
		value, err := EncodeSet(final)
		if err != nil {
			b.Fatal(err)
		}
		_, err = ParseSet(value)
		if err != nil {
			b.Fatal(err)
		}
	}
}
