package testsupport

import (
	"context"
	"strings"

	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

// CleanPublicationScanner is deterministic test authority for content-free clean receipts.
type CleanPublicationScanner struct{}

func NewCleanPublicationScanner() CleanPublicationScanner { return CleanPublicationScanner{} }
func (CleanPublicationScanner) Identity() string {
	return review.PublicationContentScannerIdentity(cleanPublicationScannerProfile())
}
func (CleanPublicationScanner) Scan(_ context.Context, independent review.IndependentVerificationReceipt, set review.VerifiedFindingSet, verificationContext review.PublicationVerificationContext, selection review.PublicationSelection) (review.PublicationContentScanReceipt, error) {
	fieldCount, scannedBytes := 0, 0
	for _, finding := range append(selection.InlineFindings(), selection.SummaryOnlyFindings()...) {
		fieldCount += 3
		scannedBytes += len(finding.Title()) + len(finding.Claim()) + len(finding.SourceRange().Path())
	}
	profile := cleanPublicationScannerProfile()
	initial := review.ScanCompletion{Complete: true, FieldCount: fieldCount, ScannedByteCount: scannedBytes}
	residual := review.ScanCompletion{Complete: true, FieldCount: fieldCount, ScannedByteCount: scannedBytes}
	return review.NewPublicationContentScanReceipt(independent, set, verificationContext, selection, profile, initial, residual)
}

func cleanPublicationScannerProfile() review.ScannerProfile {
	return review.ScannerProfile{WorkerProtocol: 1, Scanner: secretscan.ScannerName, ScannerVersion: secretscan.ScannerVersion, ScannerCommit: secretscan.ScannerCommit, RulesetIdentity: secretscan.RulesetIdentity, RulesetRuleCount: secretscan.RulesetRuleCount, BuildProfile: secretscan.BuildProfile, LauncherSHA256: strings.Repeat("a", 64), WorkerSHA256: strings.Repeat("b", 64)}
}
