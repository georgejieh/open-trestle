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

// exportTestCoverage is a source coverage of one selected source bound to the
// receipt, with no omissions.
func exportTestCoverage(t *testing.T, scope audit.ReviewScope, receipt IndependentVerificationReceipt) ContextSourceCoverage {
	t.Helper()
	coverage, err := newContextSourceCoverage(receipt.VerificationContextIdentity(), scope.Identity(), receipt.SnapshotIdentity(), receipt.CandidateBatchIdentity(), 1, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	return coverage
}

func exportTestCheck(t *testing.T) diagnostics.DeterministicCheck {
	t.Helper()
	check, err := diagnostics.NewDeterministicCheck("7d14e06842bbf9ba2db3c600f146d2e497bcaacd1664a1bdcb02b52e7b3d1a96", strings.Repeat("8", 64), strings.Repeat("a", 64), diagnostics.CheckPassed, 2, 3, 2, 3, 0)
	if err != nil {
		t.Fatal(err)
	}
	return check
}

func materializeTestSet(ctx context.Context, t *testing.T, store diagnostics.Store, scope audit.ReviewScope, receipt IndependentVerificationReceipt, verified VerifiedFindingSet) (diagnostics.Set, bool, error) {
	t.Helper()
	return MaterializeDiagnosticSetWithDeterministicChecks(ctx, store, scope, strings.Repeat("1", 40), receipt, verified, exportTestCoverage(t, scope, receipt), []diagnostics.DeterministicCheck{exportTestCheck(t)})
}

func TestExportDiagnosticSetPreservesVerifiedLineage(t *testing.T) {
	receipt, set := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	exported, err := ExportDiagnosticSetWithDeterministicChecks(scope, strings.Repeat("1", 40), receipt, set, exportTestCoverage(t, scope, receipt), []diagnostics.DeterministicCheck{exportTestCheck(t)})
	if err != nil || exported.Validate() != nil || exported.SchemaVersion() != 5 || exported.VerifiedSetIdentity() != set.Identity() || exported.CandidateCount() != 1 || exported.VerifiedCount() != 1 || exported.RejectedCount() != 0 || exported.InconclusiveCount() != 0 || len(exported.Findings()) != 1 {
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
		exported, err := ExportDiagnosticSetWithDeterministicChecks(scope, strings.Repeat("1", 40), receipt, set, exportTestCoverage(t, scope, receipt), []diagnostics.DeterministicCheck{exportTestCheck(t)})
		if err != nil || exported.CandidateCount() != 1 || exported.VerifiedCount() != 0 || exported.RejectedCount() != test.rejected || exported.InconclusiveCount() != test.inconclusive || len(exported.Findings()) != 0 {
			t.Fatalf("%s export=%#v err=%v", test.outcome, exported, err)
		}
	}
}

func TestMaterializeDiagnosticSetPersistsExactLineageIdempotently(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "inconclusive", gateway.RouteIndependenceDistinctProvider)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	store := diagnostics.NewMemoryStore()
	headRevision := strings.Repeat("1", 40)

	first, created, err := materializeTestSet(context.Background(), t, store, scope, receipt, verified)
	if err != nil || !created {
		t.Fatalf("first materialization=(%#v,%t,%v)", first, created, err)
	}
	second, created, err := materializeTestSet(context.Background(), t, store, scope, receipt, verified)
	if err != nil || created || second.Identity() != first.Identity() {
		t.Fatalf("second materialization=(%#v,%t,%v)", second, created, err)
	}
	persisted, err := store.GetDiagnosticSet(context.Background(), scope)
	if err != nil || persisted.Identity() != first.Identity() || persisted.SchemaVersion() != 5 ||
		persisted.Scope().Identity() != scope.Identity() || persisted.HeadRevision() != headRevision ||
		persisted.SnapshotIdentity() != receipt.SnapshotIdentity() || persisted.VerifiedSetIdentity() != verified.Identity() ||
		persisted.CandidateCount() != 1 || persisted.VerifiedCount() != 0 || persisted.RejectedCount() != 0 || persisted.InconclusiveCount() != 1 {
		t.Fatalf("persisted=(%#v,%v)", persisted, err)
	}
}

func TestMaterializeDiagnosticSetRejectsUnavailableOrConflictingStore(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	var unavailable *diagnostics.MemoryStore
	if _, _, err := materializeTestSet(context.Background(), t, unavailable, scope, receipt, verified); !errors.Is(err, diagnostics.ErrInvalidStore) {
		t.Fatalf("typed nil store err=%v", err)
	}

	store := diagnostics.NewMemoryStore()
	if _, created, err := materializeTestSet(context.Background(), t, store, scope, receipt, verified); err != nil || !created {
		t.Fatalf("initial materialization=(%t,%v)", created, err)
	}
	otherReceipt, otherVerified := verifiedSetFixture(t, "rejected", gateway.RouteIndependenceDistinctProvider)
	if _, created, err := materializeTestSet(context.Background(), t, store, scope, otherReceipt, otherVerified); !errors.Is(err, diagnostics.ErrSetConflict) || created {
		t.Fatalf("conflicting materialization=(%t,%v)", created, err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, created, err := materializeTestSet(canceled, t, store, scope, receipt, verified); !errors.Is(err, diagnostics.ErrStoreContextDone) || created {
		t.Fatalf("canceled materialization=(%t,%v)", created, err)
	}
}

func TestExportDiagnosticSetPreservesSourceCoverage(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	selection, _ := newContextSourceOmissionSummary(ContextOmissionSelectionLimit, 172)
	coverage, _ := newContextSourceCoverage(receipt.VerificationContextIdentity(), scope.Identity(), receipt.SnapshotIdentity(), receipt.CandidateBatchIdentity(), 173, 1, 172, []ContextSourceOmissionSummary{selection})
	checks := []diagnostics.DeterministicCheck{exportTestCheck(t)}
	exported, err := ExportDiagnosticSetWithDeterministicChecks(scope, strings.Repeat("1", 40), receipt, verified, coverage, checks)
	if err != nil || exported.Validate() != nil || exported.VerificationContextIdentity() != receipt.VerificationContextIdentity() || exported.SourceAnalyzedCount() != 173 || exported.SourceSelectedCount() != 1 || exported.SourceOmittedCount() != 172 || exported.VerifiedSetIdentity() != verified.Identity() {
		t.Fatalf("exported=(%#v,%v)", exported, err)
	}
	otherCoverage, _ := newContextSourceCoverage(strings.Repeat("f", 64), scope.Identity(), receipt.SnapshotIdentity(), receipt.CandidateBatchIdentity(), 173, 1, 172, []ContextSourceOmissionSummary{selection})
	if crossed, err := ExportDiagnosticSetWithDeterministicChecks(scope, strings.Repeat("1", 40), receipt, verified, otherCoverage, checks); err == nil || crossed.Identity() != "" {
		t.Fatalf("crossed coverage=(%#v,%v)", crossed, err)
	}
}

func TestExportDiagnosticSetPreservesOmissionReasons(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	unsupported, _ := newContextSourceOmissionSummary(ContextOmissionUnsupported, 2)
	selection, _ := newContextSourceOmissionSummary(ContextOmissionSelectionLimit, 170)
	coverage, _ := newContextSourceCoverage(receipt.VerificationContextIdentity(), scope.Identity(), receipt.SnapshotIdentity(), receipt.CandidateBatchIdentity(), 173, 1, 172, []ContextSourceOmissionSummary{unsupported, selection})
	exported, err := ExportDiagnosticSetWithDeterministicChecks(scope, strings.Repeat("1", 40), receipt, verified, coverage, []diagnostics.DeterministicCheck{exportTestCheck(t)})
	if err != nil || exported.Validate() != nil || len(exported.OmissionSummaries()) != 2 || exported.OmissionSummaries()[0].Reason() != diagnostics.OmissionSelectionLimit || exported.OmissionSummaries()[0].Count() != 170 {
		t.Fatalf("exported=(%#v,%v)", exported, err)
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

func TestExportDiagnosticSetRecordsABaseSideFindingOnlyInVersion8(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	// Relabel the fixture finding as a categorized finding on removed base
	// lines, with its covering evidence on the same side.
	finding := verified.findings[0]
	finding.category, finding.side = CandidateCategoryCorrectness, LineSideBase
	finding.evidenceBindings = append([]candidateEvidenceBinding(nil), finding.evidenceBindings...)
	for index := range finding.evidenceBindings {
		finding.evidenceBindings[index].side = LineSideBase
	}
	finding.fingerprint = deriveVerifiedFindingFingerprint(finding)
	finding.identity = deriveVerifiedFindingIdentity(finding)
	verified.findings = []VerifiedFinding{finding}
	verified.identity = deriveVerifiedFindingSetIdentity(verified)
	if err := verified.Validate(); err != nil {
		t.Fatal(err)
	}
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	selection, _ := newContextSourceOmissionSummary(ContextOmissionSelectionLimit, 172)
	coverage, _ := newContextSourceCoverage(receipt.VerificationContextIdentity(), scope.Identity(), receipt.SnapshotIdentity(), receipt.CandidateBatchIdentity(), 173, 1, 172, []ContextSourceOmissionSummary{selection})
	check, _ := diagnostics.NewDeterministicCheck("7d14e06842bbf9ba2db3c600f146d2e497bcaacd1664a1bdcb02b52e7b3d1a96", strings.Repeat("8", 64), strings.Repeat("a", 64), diagnostics.CheckPassed, 2, 3, 2, 3, 0)
	exported, err := ExportDiagnosticSetWithDeterministicChecks(scope, strings.Repeat("1", 40), receipt, verified, coverage, []diagnostics.DeterministicCheck{check})
	if err != nil || exported.SchemaVersion() != 8 || len(exported.Findings()) != 1 || exported.Findings()[0].Side() != diagnostics.LineSideBase || exported.Findings()[0].SourceIdentity() != finding.Identity() {
		t.Fatalf("exported=(%#v,%v)", exported, err)
	}
}
