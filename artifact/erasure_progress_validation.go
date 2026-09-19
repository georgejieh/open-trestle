package artifact

import (
	"bytes"
	"time"
)

func validateProgressOriginal(o ErasureProgressOptions, admitted, prepared erasurePolicySnapshot) error {
	op, a, g := o.Operation, o.Admission, o.OriginalAuthorization
	if op.LegacyReceiptIdentity() != "" || g.LegacyReceiptIdentity() != "" {
		return ErrErasureLegacyInventoryRequired
	}
	grant, err := EncodeErasureAuthorizationV2(g)
	if err != nil {
		return err
	}
	if a.Scope() != op.Scope() || g.Scope() != op.Scope() || a.NamespaceIdentity() != o.Namespace.Identity() ||
		op.NamespaceIdentity() != o.Namespace.Identity() || op.ArtifactIdentity() != a.ArtifactIdentity() ||
		op.AdmissionIdentity() != a.Identity() || op.OriginalAuthorizationIdentity() != g.Identity() ||
		op.AuthorizationDocumentDigest() != hashBytes(grant) || op.PolicyIdentity() != g.PolicyIdentity() ||
		op.ProtectedPolicyIdentity() != prepared.Identity || op.PolicyIdentity() != prepared.ErasurePolicyIdentity ||
		op.Ownership() != prepared.Ownership || op.ErasureProtocol() != prepared.Protocol ||
		g.FenceRetentionPolicyIdentity() != prepared.FenceRetentionPolicyIdentity || g.Ownership() != prepared.Ownership ||
		a.Protection() != ProtectionEnvelopeEncrypted || !admitted.matchesNamespace(o.Namespace) || !prepared.matchesNamespace(o.Namespace) ||
		!bytes.Equal(o.AdmissionPolicyBytes, o.OperationPolicyBytes) || !admitted.allows(a.AdmittedAt()) ||
		op.PreparedAt().Before(a.AdmittedAt()) || o.OperationAcceptedAt.Before(op.PreparedAt()) ||
		!prepared.allows(op.PreparedAt()) || !prepared.allows(o.OperationAcceptedAt) ||
		!g.AllowsAdmission(a, op.PreparedAt()) || !g.AllowsAdmission(a, o.OperationAcceptedAt) {
		return ErrErasureBindingMismatch
	}
	if o.ConfirmedVersion != "" && (o.ConfirmedAt.Before(a.AdmittedAt()) || !o.ConfirmedAt.Before(a.ExpiresAt()) || !admitted.allows(o.ConfirmedAt)) {
		return ErrErasureBindingMismatch
	}
	return nil
}

func validateProgressAllowance(o ErasureProgressOptions, s ErasureAllowanceSnapshot, original, policy erasurePolicySnapshot) error {
	a, usage := s.Allowance, s.Usage
	if !a.AllowsOperation(o.Operation, s.AcceptedAt) || s.AcceptedAt.Before(o.OperationAcceptedAt) ||
		a.PrincipalIdentity() != o.OriginalAuthorization.PrincipalIdentity() || a.ProtectedPolicyIdentity() != policy.Identity ||
		a.RecoveryPolicyIdentity() != policy.RecoveryPolicyIdentity || !policy.matchesNamespace(o.Namespace) ||
		!original.stableEqual(policy) || !policy.allows(s.AcceptedAt) || usage.AllowanceIdentity != a.Identity() ||
		!validProgressSpending(usage.Spent) || !progressBudgetWithin(usage.Spent, a.Maximum()) || usage.Spent != s.TotalCost ||
		s.AttemptCount != uint64(usage.Spent.Requests) || usage.NextSequence != uint64(usage.Spent.Requests)+1 {
		return ErrErasureBindingMismatch
	}
	return nil
}

// Aggregate costs must still be possible when only part of history is selected.
func validProgressSpending(b ResumeBudget) bool {
	reads, lists, creates, deletes := uint64(b.Reads), uint64(b.Lists), uint64(b.Creates), uint64(b.Deletes)
	mutations := creates + deletes
	if uint64(b.Requests) != reads+lists+mutations || uint64(b.Mutations) != mutations || b.Pages != b.Lists ||
		uint64(b.Versions) < lists || uint64(b.Versions) > 256*lists ||
		b.ListBytes < 4097*lists || b.ListBytes > 1048577*lists || b.WriteBytes < creates || b.WriteBytes > 16384*creates {
		return false
	}
	base := b.ListBytes + 4097*mutations
	if base < b.ListBytes || b.ResponseBytes < base {
		return false
	}
	readBytes := b.ResponseBytes - base
	return readBytes >= 4097*reads && readBytes <= 33554433*reads
}

func progressBudgetVector(b ResumeBudget) [11]uint64 {
	return [11]uint64{uint64(b.Requests), uint64(b.Mutations), uint64(b.Reads), uint64(b.Lists), uint64(b.Creates),
		uint64(b.Deletes), uint64(b.Pages), uint64(b.Versions), b.ResponseBytes, b.ListBytes, b.WriteBytes}
}
func progressBudgetWithin(a, b ResumeBudget) bool {
	x, y := progressBudgetVector(a), progressBudgetVector(b)
	for i := range x {
		if x[i] > y[i] {
			return false
		}
	}
	return true
}
func addProgressBudget(a, b ResumeBudget) (ResumeBudget, bool) {
	x, y := progressBudgetVector(a), progressBudgetVector(b)
	for i := range x {
		if y[i] > ^uint64(0)-x[i] {
			return ResumeBudget{}, false
		}
		x[i] += y[i]
		if i < 8 && x[i] > uint64(^uint32(0)) {
			return ResumeBudget{}, false
		}
	}
	return ResumeBudget{Requests: uint32(x[0]), Mutations: uint32(x[1]), Reads: uint32(x[2]), Lists: uint32(x[3]),
		Creates: uint32(x[4]), Deletes: uint32(x[5]), Pages: uint32(x[6]), Versions: uint32(x[7]),
		ResponseBytes: x[8], ListBytes: x[9], WriteBytes: x[10]}, true
}
func progressAttemptCost(r AttemptRequest) ResumeBudget {
	cost := ResumeBudget{Requests: 1, ResponseBytes: uint64(r.MaximumResponseBytes()) + 1}
	switch r.Kind() {
	case AttemptCurrentRead, AttemptIntentRead, AttemptAttestationRead:
		cost.Reads = 1
	case AttemptVersionList:
		cost.Lists, cost.Pages, cost.Versions, cost.ListBytes = 1, 1, uint32(r.PageLimit()), cost.ResponseBytes
	case AttemptIntentCreate, AttemptFenceCreate, AttemptAttestationCreate:
		cost.Mutations, cost.Creates, cost.WriteBytes = 1, 1, uint64(r.BodyBytes())
	case AttemptVersionDelete:
		cost.Mutations, cost.Deletes = 1, 1
	}
	return cost
}
func progressArtifactKey(o ErasureProgressOptions) string {
	return o.Namespace.Prefix() + "/artifacts/" + o.Operation.Scope().Identity() + "/" + o.Operation.ArtifactIdentity()
}
func progressDeletionStem(o ErasureProgressOptions) string {
	return o.Namespace.Prefix() + "/deletions/" + o.Operation.Scope().Identity() + "/" + o.Operation.ArtifactIdentity()
}
func progressRequestKey(o ErasureProgressOptions, r AttemptRequest) bool {
	stem := progressDeletionStem(o)
	switch r.Kind() {
	case AttemptCurrentRead, AttemptVersionList, AttemptFenceCreate, AttemptVersionDelete:
		return r.Key() == progressArtifactKey(o)
	case AttemptIntentRead:
		return r.Key() == stem+".intent-v2" || r.Key() == stem+".intent"
	case AttemptAttestationRead:
		return r.Key() == stem+".attestation-v2" || r.Key() == stem+".receipt"
	case AttemptIntentCreate:
		return r.Key() == stem+".intent-v2"
	case AttemptAttestationCreate:
		return r.Key() == stem+".attestation-v2"
	}
	return false
}

func validateProgressAttempt(o ErasureProgressOptions, a ErasureAttempt, s ErasureAllowanceSnapshot, policy erasurePolicySnapshot) error {
	r := a.Request()
	if !progressRequestKey(o, r) || a.Sequence() >= s.Usage.NextSequence || a.ReservedAt().Before(s.AcceptedAt) ||
		!s.Allowance.AllowsOperation(o.Operation, a.ReservedAt()) || !policy.allows(a.ReservedAt()) ||
		!progressBudgetWithin(progressAttemptCost(r), s.Usage.Spent) {
		return ErrErasureBindingMismatch
	}
	key, err := NewExactObjectKey(o.Namespace.Identity(), r.Key())
	if err != nil {
		return err
	}
	var version ObjectVersion
	if r.Kind() == AttemptVersionDelete {
		version, err = NewObjectVersion(o.Namespace.Identity(), r.Key(), r.VersionKind(), r.VersionID())
		if err != nil {
			return err
		}
	}
	expected, err := NewAttemptRequest(AttemptRequestOptions{ReservationIdentity: r.ReservationIdentity(), Operation: o.Operation,
		Allowance: s.Allowance, Kind: r.Kind(), Key: key, Version: version,
		Cursor: VersionCursor{KeyMarker: r.KeyMarker(), VersionIDMarker: r.VersionIDMarker()}, PageLimit: r.PageLimit(),
		MaximumResponseBytes: r.MaximumResponseBytes(), BodyDigest: r.BodyDigest(), BodyBytes: r.BodyBytes(), ObservationIdentity: r.ObservationIdentity()})
	if err != nil {
		return err
	}
	left, err := EncodeAttemptRequest(r)
	if err != nil {
		return err
	}
	right, err := EncodeAttemptRequest(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(left, right) {
		return ErrErasureBindingMismatch
	}
	return nil
}

func (g *erasureProgressGraph) attemptWindow(a ErasureAttempt, times ...time.Time) error {
	s, exists := g.snapshots[a.Request().AllowanceIdentity()]
	if !exists {
		return ErrInvalidErasureContract
	}
	p, exists := g.policies[s.Allowance.ProtectedPolicyIdentity()]
	if !exists {
		return ErrInvalidErasureContract
	}
	for _, at := range times {
		if !s.Allowance.AllowsOperation(g.o.Operation, at) || !p.allows(at) || at.Before(s.AcceptedAt) {
			return ErrErasureBindingMismatch
		}
	}
	return nil
}
