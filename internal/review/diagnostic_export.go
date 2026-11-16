package review

import (
	"context"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	"reflect"
)

// MaterializeDiagnosticSet exports and idempotently persists one verified diagnostic set.
func MaterializeDiagnosticSet(
	ctx context.Context,
	store diagnostics.Store,
	scope audit.ReviewScope,
	headRevision string,
	receipt IndependentVerificationReceipt,
	set VerifiedFindingSet,
) (diagnostics.Set, bool, error) {
	if ctx == nil {
		return diagnostics.Set{}, false, diagnostics.ErrInvalidStoreContext
	}
	if store == nil || reflect.ValueOf(store).Kind() == reflect.Pointer && reflect.ValueOf(store).IsNil() {
		return diagnostics.Set{}, false, diagnostics.ErrInvalidStore
	}
	exported, err := ExportDiagnosticSet(scope, headRevision, receipt, set)
	if err != nil {
		return diagnostics.Set{}, false, err
	}
	created, err := store.PutDiagnosticSet(ctx, exported)
	if err != nil {
		return diagnostics.Set{}, false, err
	}
	return exported, created, nil
}

// MaterializeDiagnosticSetWithSourceCoverage exports and idempotently persists version 3 diagnostics.
func MaterializeDiagnosticSetWithSourceCoverage(
	ctx context.Context,
	store diagnostics.Store,
	scope audit.ReviewScope,
	headRevision string,
	receipt IndependentVerificationReceipt,
	set VerifiedFindingSet,
	coverage ContextSourceCoverage,
) (diagnostics.Set, bool, error) {
	if ctx == nil {
		return diagnostics.Set{}, false, diagnostics.ErrInvalidStoreContext
	}
	if store == nil || reflect.ValueOf(store).Kind() == reflect.Pointer && reflect.ValueOf(store).IsNil() {
		return diagnostics.Set{}, false, diagnostics.ErrInvalidStore
	}
	exported, err := ExportDiagnosticSetWithSourceCoverage(scope, headRevision, receipt, set, coverage)
	if err != nil {
		return diagnostics.Set{}, false, err
	}
	created, err := store.PutDiagnosticSet(ctx, exported)
	if err != nil {
		return diagnostics.Set{}, false, err
	}
	return exported, created, nil
}

// MaterializeDiagnosticSetWithDeterministicChecks exports and idempotently persists version 5 or 8 diagnostics.
func MaterializeDiagnosticSetWithDeterministicChecks(
	ctx context.Context,
	store diagnostics.Store,
	scope audit.ReviewScope,
	headRevision string,
	receipt IndependentVerificationReceipt,
	set VerifiedFindingSet,
	coverage ContextSourceCoverage,
	checks []diagnostics.DeterministicCheck,
) (diagnostics.Set, bool, error) {
	if ctx == nil {
		return diagnostics.Set{}, false, diagnostics.ErrInvalidStoreContext
	}
	if store == nil || reflect.ValueOf(store).Kind() == reflect.Pointer && reflect.ValueOf(store).IsNil() {
		return diagnostics.Set{}, false, diagnostics.ErrInvalidStore
	}
	exported, err := ExportDiagnosticSetWithDeterministicChecks(scope, headRevision, receipt, set, coverage, checks)
	if err != nil {
		return diagnostics.Set{}, false, err
	}
	created, err := store.PutDiagnosticSet(ctx, exported)
	if err != nil {
		return diagnostics.Set{}, false, err
	}
	return exported, created, nil
}

// MaterializeDiagnosticSetWithOmissionReasons exports and idempotently persists version 4 diagnostics.
func MaterializeDiagnosticSetWithOmissionReasons(
	ctx context.Context,
	store diagnostics.Store,
	scope audit.ReviewScope,
	headRevision string,
	receipt IndependentVerificationReceipt,
	set VerifiedFindingSet,
	coverage ContextSourceCoverage,
) (diagnostics.Set, bool, error) {
	if ctx == nil {
		return diagnostics.Set{}, false, diagnostics.ErrInvalidStoreContext
	}
	if store == nil || reflect.ValueOf(store).Kind() == reflect.Pointer && reflect.ValueOf(store).IsNil() {
		return diagnostics.Set{}, false, diagnostics.ErrInvalidStore
	}
	exported, err := ExportDiagnosticSetWithOmissionReasons(scope, headRevision, receipt, set, coverage)
	if err != nil {
		return diagnostics.Set{}, false, err
	}
	created, err := store.PutDiagnosticSet(ctx, exported)
	if err != nil {
		return diagnostics.Set{}, false, err
	}
	return exported, created, nil
}

// ExportDiagnosticSet converts independently verified findings into the version 2 editor contract.
func ExportDiagnosticSet(scope audit.ReviewScope, headRevision string, receipt IndependentVerificationReceipt, set VerifiedFindingSet) (diagnostics.Set, error) {
	findings, err := exportDiagnosticFindings(scope, receipt, set)
	if err != nil {
		return diagnostics.Set{}, err
	}
	return diagnostics.NewSetWithCoverage(scope, set.SnapshotIdentity(), headRevision, set.Identity(), uint16(set.CandidateCount()), uint16(set.RejectedCount()), uint16(set.InconclusiveCount()), findings)
}

// ExportDiagnosticSetWithSourceCoverage adds exact source-selection accounting to version 3 diagnostics.
func ExportDiagnosticSetWithSourceCoverage(scope audit.ReviewScope, headRevision string, receipt IndependentVerificationReceipt, set VerifiedFindingSet, coverage ContextSourceCoverage) (diagnostics.Set, error) {
	findings, err := exportDiagnosticFindings(scope, receipt, set)
	validCoverage := coverage.Validate() == nil && coverage.VerificationContextIdentity() == receipt.VerificationContextIdentity() && coverage.ReviewScopeIdentity() == scope.Identity() && coverage.SnapshotIdentity() == receipt.SnapshotIdentity() && coverage.CandidateBatchIdentity() == receipt.CandidateBatchIdentity()
	if err != nil || !validCoverage {
		return diagnostics.Set{}, ErrVerifiedFindingBindingMismatch
	}
	return diagnostics.NewSetWithSourceCoverage(scope, set.SnapshotIdentity(), headRevision, set.Identity(), coverage.VerificationContextIdentity(), uint16(set.CandidateCount()), uint16(set.RejectedCount()), uint16(set.InconclusiveCount()), coverage.AnalyzedCount(), coverage.SelectedCount(), coverage.OmittedCount(), findings)
}

// ExportDiagnosticSetWithDeterministicChecks adds exact content-free checks to
// version 5 diagnostics, or version 8 when a verified finding is on removed
// base lines.
func ExportDiagnosticSetWithDeterministicChecks(scope audit.ReviewScope, headRevision string, receipt IndependentVerificationReceipt, set VerifiedFindingSet, coverage ContextSourceCoverage, checks []diagnostics.DeterministicCheck) (diagnostics.Set, error) {
	findings, summaries, err := exportDiagnosticFindingsWithOmissions(scope, receipt, set, coverage)
	if err != nil {
		return diagnostics.Set{}, err
	}
	return diagnostics.NewSetWithDeterministicChecks(scope, set.SnapshotIdentity(), headRevision, set.Identity(), coverage.VerificationContextIdentity(), uint16(set.CandidateCount()), uint16(set.RejectedCount()), uint16(set.InconclusiveCount()), coverage.AnalyzedCount(), coverage.SelectedCount(), coverage.OmittedCount(), summaries, checks, findings)
}

// ExportDiagnosticSetWithOmissionReasons adds bounded aggregate omission reasons to version 4 diagnostics.
func ExportDiagnosticSetWithOmissionReasons(scope audit.ReviewScope, headRevision string, receipt IndependentVerificationReceipt, set VerifiedFindingSet, coverage ContextSourceCoverage) (diagnostics.Set, error) {
	findings, summaries, err := exportDiagnosticFindingsWithOmissions(scope, receipt, set, coverage)
	if err != nil {
		return diagnostics.Set{}, err
	}
	return diagnostics.NewSetWithOmissionReasons(scope, set.SnapshotIdentity(), headRevision, set.Identity(), coverage.VerificationContextIdentity(), uint16(set.CandidateCount()), uint16(set.RejectedCount()), uint16(set.InconclusiveCount()), coverage.AnalyzedCount(), coverage.SelectedCount(), coverage.OmittedCount(), summaries, findings)
}

// exportDiagnosticFindingsWithOmissions exports verified findings and the
// exact aggregate omission reasons of a coverage bound to the same receipt.
func exportDiagnosticFindingsWithOmissions(scope audit.ReviewScope, receipt IndependentVerificationReceipt, set VerifiedFindingSet, coverage ContextSourceCoverage) ([]diagnostics.Finding, []diagnostics.OmissionSummary, error) {
	findings, err := exportDiagnosticFindings(scope, receipt, set)
	if err != nil {
		return nil, nil, err
	}
	validCoverage := coverage.Validate() == nil && coverage.VerificationContextIdentity() == receipt.VerificationContextIdentity() && coverage.ReviewScopeIdentity() == scope.Identity() && coverage.SnapshotIdentity() == receipt.SnapshotIdentity() && coverage.CandidateBatchIdentity() == receipt.CandidateBatchIdentity()
	contextSummaries := coverage.OmissionSummaries()
	summaryTotal := uint64(0)
	summaries := make([]diagnostics.OmissionSummary, len(contextSummaries))
	for index, value := range contextSummaries {
		summaryTotal += uint64(value.Count())
		reason, reasonErr := diagnosticOmissionReason(value.Reason())
		if reasonErr != nil {
			return nil, nil, ErrVerifiedFindingBindingMismatch
		}
		summaries[index], err = diagnostics.NewOmissionSummary(reason, value.Count())
		if err != nil {
			return nil, nil, err
		}
	}
	if !validCoverage || summaryTotal != uint64(coverage.OmittedCount()) || (coverage.OmittedCount() == 0) != (len(summaries) == 0) {
		return nil, nil, ErrVerifiedFindingBindingMismatch
	}
	return findings, summaries, nil
}

func diagnosticOmissionReason(value ContextSourceOmissionCategory) (diagnostics.OmissionReason, error) {
	switch value {
	case ContextOmissionAuthorization:
		return diagnostics.OmissionAuthorization, nil
	case ContextOmissionResourceLimit:
		return diagnostics.OmissionResourceLimit, nil
	case ContextOmissionUnsupported:
		return diagnostics.OmissionUnsupported, nil
	case ContextOmissionAnalysisFailure:
		return diagnostics.OmissionAnalysisFailure, nil
	case ContextOmissionDuplicate:
		return diagnostics.OmissionDuplicate, nil
	case ContextOmissionSelectionLimit:
		return diagnostics.OmissionSelectionLimit, nil
	default:
		return 0, ErrVerifiedFindingBindingMismatch
	}
}

func exportDiagnosticFindings(scope audit.ReviewScope, receipt IndependentVerificationReceipt, set VerifiedFindingSet) ([]diagnostics.Finding, error) {
	if scope.Validate() != nil || receipt.Validate() != nil || set.Validate() != nil || receipt.ReviewScopeIdentity() != scope.Identity() || set.IndependentReceiptIdentity() != receipt.Identity() || set.SnapshotIdentity() != receipt.SnapshotIdentity() {
		return nil, ErrVerifiedFindingBindingMismatch
	}
	findings := make([]diagnostics.Finding, 0, set.VerifiedCount())
	for _, finding := range set.Findings() {
		sourceRange := finding.SourceRange()
		// Only a set version that records sides accepts a base-side finding;
		// the earlier versions refuse it rather than relabel base lines as head.
		value, err := diagnostics.NewFinding(finding.Identity(), finding.Fingerprint(), finding.Title(), finding.Claim(), diagnosticSeverity(finding.Severity()), sourceRange.Path(), uint32(sourceRange.StartLine()), uint32(sourceRange.EndLine()), finding.EvidenceIDs())
		if finding.Side() == LineSideBase {
			value, err = diagnostics.NewBaseSideFinding(finding.Identity(), finding.Fingerprint(), finding.Title(), finding.Claim(), diagnosticSeverity(finding.Severity()), sourceRange.Path(), uint32(sourceRange.StartLine()), uint32(sourceRange.EndLine()), uint32(finding.HeadLine()), finding.EvidenceIDs())
		}
		if err != nil {
			return nil, err
		}
		findings = append(findings, value)
	}
	return findings, nil
}
func diagnosticSeverity(severity Severity) diagnostics.Severity {
	switch severity {
	case SeverityCritical, SeverityHigh:
		return diagnostics.SeverityError
	case SeverityMedium:
		return diagnostics.SeverityWarning
	default:
		return diagnostics.SeverityInformation
	}
}
