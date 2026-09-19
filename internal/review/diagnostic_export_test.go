package review

import (
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"strings"
	"testing"
)

func TestExportDiagnosticSetPreservesVerifiedLineage(t *testing.T) {
	receipt, set := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	exported, err := ExportDiagnosticSet(scope, strings.Repeat("1", 40), receipt, set)
	if err != nil || exported.Validate() != nil || exported.SchemaVersion() != 2 || exported.VerifiedSetIdentity() != set.Identity() || exported.CandidateCount() != 1 || exported.VerifiedCount() != 1 || exported.RejectedCount() != 0 || exported.InconclusiveCount() != 0 || len(exported.Findings()) != 1 {
		t.Fatalf("export=(%#v,%v)", exported, err)
	}
	finding := exported.Findings()[0]
	if finding.SourceIdentity() != set.Findings()[0].Identity() || finding.Severity() != diagnostics.SeverityError {
		t.Fatalf("finding=%#v", finding)
	}
}

func TestExportDiagnosticSetPreservesRejectedAndInconclusiveCoverage(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	for _, test := range []struct {
		outcome      string
		rejected     uint16
		inconclusive uint16
	}{{"rejected", 1, 0}, {"inconclusive", 0, 1}} {
		receipt, set := verifiedSetFixture(t, test.outcome, gateway.RouteIndependenceDistinctProvider)
		exported, err := ExportDiagnosticSet(scope, strings.Repeat("1", 40), receipt, set)
		if err != nil || exported.SchemaVersion() != 2 || exported.CandidateCount() != 1 || exported.VerifiedCount() != 0 || exported.RejectedCount() != test.rejected || exported.InconclusiveCount() != test.inconclusive || len(exported.Findings()) != 0 {
			t.Fatalf("%s export=%#v err=%v", test.outcome, exported, err)
		}
	}
}

func TestMaterializeDiagnosticSetPersistsExactLineageIdempotently(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "inconclusive", gateway.RouteIndependenceDistinctProvider)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	store := diagnostics.NewMemoryStore()
	headRevision := strings.Repeat("1", 40)

	first, created, err := MaterializeDiagnosticSet(context.Background(), store, scope, headRevision, receipt, verified)
	if err != nil || !created {
		t.Fatalf("first materialization=(%#v,%t,%v)", first, created, err)
	}
	second, created, err := MaterializeDiagnosticSet(context.Background(), store, scope, headRevision, receipt, verified)
	if err != nil || created || second.Identity() != first.Identity() {
		t.Fatalf("second materialization=(%#v,%t,%v)", second, created, err)
	}
	persisted, err := store.GetDiagnosticSet(context.Background(), scope)
	if err != nil || persisted.Identity() != first.Identity() || persisted.SchemaVersion() != 2 ||
		persisted.Scope().Identity() != scope.Identity() || persisted.HeadRevision() != headRevision ||
		persisted.SnapshotIdentity() != receipt.SnapshotIdentity() || persisted.VerifiedSetIdentity() != verified.Identity() ||
		persisted.CandidateCount() != 1 || persisted.VerifiedCount() != 0 || persisted.RejectedCount() != 0 || persisted.InconclusiveCount() != 1 {
		t.Fatalf("persisted=(%#v,%v)", persisted, err)
	}
}

func TestMaterializeDiagnosticSetRejectsUnavailableOrConflictingStore(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	headRevision := strings.Repeat("1", 40)
	var unavailable *diagnostics.MemoryStore
	if _, _, err := MaterializeDiagnosticSet(context.Background(), unavailable, scope, headRevision, receipt, verified); !errors.Is(err, diagnostics.ErrInvalidStore) {
		t.Fatalf("typed nil store err=%v", err)
	}

	store := diagnostics.NewMemoryStore()
	if _, created, err := MaterializeDiagnosticSet(context.Background(), store, scope, headRevision, receipt, verified); err != nil || !created {
		t.Fatalf("initial materialization=(%t,%v)", created, err)
	}
	otherReceipt, otherVerified := verifiedSetFixture(t, "rejected", gateway.RouteIndependenceDistinctProvider)
	if _, created, err := MaterializeDiagnosticSet(context.Background(), store, scope, headRevision, otherReceipt, otherVerified); !errors.Is(err, diagnostics.ErrSetConflict) || created {
		t.Fatalf("conflicting materialization=(%t,%v)", created, err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, created, err := MaterializeDiagnosticSet(canceled, store, scope, headRevision, receipt, verified); !errors.Is(err, diagnostics.ErrStoreContextDone) || created {
		t.Fatalf("canceled materialization=(%t,%v)", created, err)
	}
}

func TestExportDiagnosticSetPreservesSourceCoverage(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	coverage, _ := newContextSourceCoverage(receipt.VerificationContextIdentity(), scope.Identity(), receipt.SnapshotIdentity(), receipt.CandidateBatchIdentity(), 173, 1, 172, nil)
	exported, err := ExportDiagnosticSetWithSourceCoverage(scope, strings.Repeat("1", 40), receipt, verified, coverage)
	if err != nil || exported.Validate() != nil || exported.SchemaVersion() != 3 || exported.VerificationContextIdentity() != receipt.VerificationContextIdentity() || exported.SourceAnalyzedCount() != 173 || exported.SourceSelectedCount() != 1 || exported.SourceOmittedCount() != 172 || exported.VerifiedSetIdentity() != verified.Identity() {
		t.Fatalf("exported=(%#v,%v)", exported, err)
	}
	otherCoverage, _ := newContextSourceCoverage(strings.Repeat("f", 64), scope.Identity(), receipt.SnapshotIdentity(), receipt.CandidateBatchIdentity(), 173, 1, 172, nil)
	if crossed, err := ExportDiagnosticSetWithSourceCoverage(scope, strings.Repeat("1", 40), receipt, verified, otherCoverage); err == nil || crossed.Identity() != "" {
		t.Fatalf("crossed coverage=(%#v,%v)", crossed, err)
	}
	store := diagnostics.NewMemoryStore()
	first, created, err := MaterializeDiagnosticSetWithSourceCoverage(context.Background(), store, scope, strings.Repeat("1", 40), receipt, verified, coverage)
	if err != nil || !created || first.Identity() != exported.Identity() {
		t.Fatalf("first materialization=(%#v,%t,%v)", first, created, err)
	}
	second, created, err := MaterializeDiagnosticSetWithSourceCoverage(context.Background(), store, scope, strings.Repeat("1", 40), receipt, verified, coverage)
	if err != nil || created || second.Identity() != first.Identity() {
		t.Fatalf("second materialization=(%#v,%t,%v)", second, created, err)
	}
}

func TestExportDiagnosticSetPreservesOmissionReasons(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	unsupported, _ := newContextSourceOmissionSummary(ContextOmissionUnsupported, 2)
	selection, _ := newContextSourceOmissionSummary(ContextOmissionSelectionLimit, 170)
	coverage, _ := newContextSourceCoverage(receipt.VerificationContextIdentity(), scope.Identity(), receipt.SnapshotIdentity(), receipt.CandidateBatchIdentity(), 173, 1, 172, []ContextSourceOmissionSummary{unsupported, selection})
	exported, err := ExportDiagnosticSetWithOmissionReasons(scope, strings.Repeat("1", 40), receipt, verified, coverage)
	if err != nil || exported.Validate() != nil || exported.SchemaVersion() != 4 || len(exported.OmissionSummaries()) != 2 || exported.OmissionSummaries()[0].Reason() != diagnostics.OmissionSelectionLimit || exported.OmissionSummaries()[0].Count() != 170 {
		t.Fatalf("exported=(%#v,%v)", exported, err)
	}
	store := diagnostics.NewMemoryStore()
	first, created, err := MaterializeDiagnosticSetWithOmissionReasons(context.Background(), store, scope, strings.Repeat("1", 40), receipt, verified, coverage)
	if err != nil || !created || first.Identity() != exported.Identity() {
		t.Fatalf("materialized=(%#v,%t,%v)", first, created, err)
	}
}

func TestExportDiagnosticSetPreservesDeterministicCheck(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	selection, _ := newContextSourceOmissionSummary(ContextOmissionSelectionLimit, 172)
	coverage, _ := newContextSourceCoverage(receipt.VerificationContextIdentity(), scope.Identity(), receipt.SnapshotIdentity(), receipt.CandidateBatchIdentity(), 173, 1, 172, []ContextSourceOmissionSummary{selection})
	check, _ := diagnostics.NewDeterministicCheck("7d14e06842bbf9ba2db3c600f146d2e497bcaacd1664a1bdcb02b52e7b3d1a96", strings.Repeat("8", 64), strings.Repeat("a", 64), diagnostics.CheckPassed, 2, 3, 2, 3, 0)
	exported, err := ExportDiagnosticSetWithDeterministicChecks(scope, strings.Repeat("1", 40), receipt, verified, coverage, []diagnostics.DeterministicCheck{check})
	if err != nil || exported.Validate() != nil || exported.SchemaVersion() != 5 || len(exported.DeterministicChecks()) != 1 || exported.DeterministicChecks()[0].Identity() != check.Identity() {
		t.Fatalf("exported=(%#v,%v)", exported, err)
	}
	store := diagnostics.NewMemoryStore()
	materialized, created, err := MaterializeDiagnosticSetWithDeterministicChecks(context.Background(), store, scope, strings.Repeat("1", 40), receipt, verified, coverage, []diagnostics.DeterministicCheck{check})
	if err != nil || !created || materialized.Identity() != exported.Identity() {
		t.Fatalf("materialized=(%#v,%t,%v)", materialized, created, err)
	}
}
