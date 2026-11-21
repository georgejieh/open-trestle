package review

import (
	"context"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	"reflect"
)

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
		// A base-side finding keeps its base lines and records its side.
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
