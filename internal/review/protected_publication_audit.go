package review

import (
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"time"
)

var ErrProtectedPublicationPrerequisite = errors.New("invalid protected publication prerequisite")

type ProtectedPublicationAuditReceipt struct{ source, context, readiness audit.Event }

func (r ProtectedPublicationAuditReceipt) SourceEvent() audit.Event    { return r.source }
func (r ProtectedPublicationAuditReceipt) ContextEvent() audit.Event   { return r.context }
func (r ProtectedPublicationAuditReceipt) ReadinessEvent() audit.Event { return r.readiness }

// RecordProtectedPublicationPrerequisites records source, context, and readiness lineage before effect authorization.
func RecordProtectedPublicationPrerequisites(ctx context.Context, ledger audit.Ledger, scope audit.ReviewScope, binding ProtectedSourceBinding, readiness PublicationReadiness, at time.Time) (ProtectedPublicationAuditReceipt, error) {
	if isNilModelAuditLedger(ledger) || scope.Validate() != nil || binding.Validate() != nil || readiness.Validate() != nil || binding.ReviewScopeIdentity() != scope.Identity() || readiness.ReviewScopeIdentity() != scope.Identity() || binding.PipelineSnapshotIdentity() != readiness.snapshotIdentity || binding.ContextIdentity() != readiness.GenerationContextIdentity() {
		return ProtectedPublicationAuditReceipt{}, ErrProtectedPublicationPrerequisite
	}
	sourceParents := []string{binding.headSnapshotArtifactIdentity, binding.headSnapshotIdentity, binding.headManifestIdentity, binding.changeArtifactIdentity, binding.changeIdentity, binding.evidenceArtifactIdentity}
	sourceEvent, err := appendUniqueModelAuditEvent(ctx, ledger, scope, modelAuditEventSpecification{kind: audit.EventReviewSnapshotBound, subject: binding.SourceIdentity(), parents: sourceParents}, at)
	if err != nil {
		return ProtectedPublicationAuditReceipt{}, err
	}
	contextParents := []string{binding.SourceIdentity(), sourceEvent.Identity(), binding.contextArtifactIdentity, binding.contextIdentity, binding.evidenceArtifactIdentity}
	contextEvent, err := appendUniqueModelAuditEvent(ctx, ledger, scope, modelAuditEventSpecification{kind: audit.EventContextAcquisitionBound, subject: binding.ContextBindingIdentity(), parents: contextParents}, at)
	if err != nil {
		return ProtectedPublicationAuditReceipt{}, err
	}
	readinessParents := []string{readiness.VerificationReceiptIdentity(), readiness.VerifiedFindingSetIdentity(), readiness.PolicyIdentity()}
	readinessEvent, err := appendUniqueModelAuditEvent(ctx, ledger, scope, modelAuditEventSpecification{kind: audit.EventPublicationReadinessEvaluated, subject: readiness.Identity(), parents: readinessParents}, at)
	if err != nil {
		return ProtectedPublicationAuditReceipt{}, err
	}
	return ProtectedPublicationAuditReceipt{sourceEvent, contextEvent, readinessEvent}, nil
}
