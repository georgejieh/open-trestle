package publication

import (
	"context"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/review"
)

// BuildFinalDiagnosticParts reconstitutes evidence through exact, scoped artifact
// references. Missing IDs mean the corresponding operation was not completed;
// missing artifacts for supplied IDs are errors, not clean or verified results.
func BuildFinalDiagnosticParts(ctx context.Context, store artifact.Store, scope audit.ReviewScope, analysisID, changeID, verificationID string, at time.Time) (diagnostics.Set, diagnostics.Set, error) {
	var zero diagnostics.Set
	if ctx == nil || nilInterface(store) || scope.Validate() != nil || at.IsZero() || (analysisID == "") != (changeID == "") || verificationID != "" && analysisID == "" {
		return zero, zero, ErrInvalidReadinessResult
	}
	if analysisID == "" {
		return zero, zero, nil
	}
	changeArtifact, err := store.Get(ctx, scope, changeID, at)
	if err != nil {
		return zero, zero, err
	}
	baseID, headID, err := changehandler.ResultArtifactReferences(changeArtifact)
	if err != nil {
		return zero, zero, err
	}
	baseArtifact, err := store.Get(ctx, scope, baseID, at)
	if err != nil {
		return zero, zero, err
	}
	headArtifact, err := store.Get(ctx, scope, headID, at)
	if err != nil {
		return zero, zero, err
	}
	change, err := changehandler.ParseResultArtifact(changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return zero, zero, err
	}
	if _, err = sourcehandler.ParseSnapshotArtifact(headArtifact); err != nil {
		return zero, zero, err
	}
	analysisArtifact, err := store.Get(ctx, scope, analysisID, at)
	if err != nil {
		return zero, zero, err
	}
	analysis, err := analysishandler.ParseResultArtifact(analysisArtifact, changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return zero, zero, err
	}
	if analysisArtifact.Classification() != changeArtifact.Classification() || analysisArtifact.Protection() != changeArtifact.Protection() {
		return zero, zero, ErrInvalidReadinessResult
	}
	checks := analysis.Checks()
	if len(checks) != 1 {
		return zero, zero, ErrInvalidReadinessResult
	}
	deterministic, err := analysishandler.BuildDiagnosticSet(scope, change, analysis, checks[0], analysis.Observations())
	if err != nil {
		return zero, zero, err
	}
	if verificationID == "" {
		return deterministic, zero, nil
	}
	verificationArtifact, err := store.Get(ctx, scope, verificationID, at)
	if err != nil {
		return zero, zero, err
	}
	if verificationArtifact.Classification() != analysisArtifact.Classification() || verificationArtifact.Protection() != analysisArtifact.Protection() {
		return zero, zero, ErrInvalidReadinessResult
	}
	generationID, err := modelhandler.VerificationResultReferences(verificationArtifact)
	if err != nil {
		return zero, zero, err
	}
	generationArtifact, err := store.Get(ctx, scope, generationID, at)
	if err != nil {
		return zero, zero, err
	}
	inputID, contextID, err := modelhandler.GenerationResultReferences(generationArtifact)
	if err != nil {
		return zero, zero, err
	}
	inputArtifact, err := store.Get(ctx, scope, inputID, at)
	if err != nil {
		return zero, zero, err
	}
	contextArtifact, err := store.Get(ctx, scope, contextID, at)
	if err != nil {
		return zero, zero, err
	}
	verification, err := modelhandler.ParseStoredVerificationResultArtifact(ctx, store, at, verificationArtifact, generationArtifact, inputArtifact, contextArtifact)
	if err != nil {
		return zero, zero, ErrInvalidReadinessResult
	}
	if !contains(contextArtifact.Provenance(), analysisArtifact.Identity()) || !contains(contextArtifact.Provenance(), changeArtifact.Identity()) || !contains(contextArtifact.Provenance(), headArtifact.Identity()) {
		return zero, zero, ErrInvalidReadinessResult
	}
	verified, err := review.ExportDiagnosticSetWithDeterministicChecks(scope, change.HeadRevision().Digest(), verification.IndependentReceipt(), verification.VerifiedFindings(), verification.VerificationContext().SourceCoverage(), deterministic.DeterministicChecks())
	if err != nil {
		return zero, zero, err
	}
	if deterministic.HeadRevision() != verified.HeadRevision() {
		return zero, zero, ErrInvalidReadinessResult
	}
	return deterministic, verified, nil
}
