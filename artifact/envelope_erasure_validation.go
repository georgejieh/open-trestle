package artifact

import (
	"bytes"
	"time"
)

func validateResumeOriginal(m *envelopeErasureMode, ref ErasureOperationRef, allowance ResumeAllowance, p ErasureProgress) error {
	if err := p.Validate(); err != nil {
		return err
	}
	o := p.data.options
	if o.Operation.Ref() != ref || o.Namespace.Identity() != m.namespace.Identity() ||
		o.Namespace != m.namespace || allowance.Scope() != o.Operation.Scope() ||
		allowance.OperationIdentity() != o.Operation.Identity() || allowance.ArtifactIdentity() != o.Operation.ArtifactIdentity() ||
		allowance.AdmissionIdentity() != o.Operation.AdmissionIdentity() ||
		allowance.OriginalAuthorizationIdentity() != o.Operation.OriginalAuthorizationIdentity() ||
		allowance.AuthorizationDocumentDigest() != o.Operation.AuthorizationDocumentDigest() ||
		allowance.PrincipalIdentity() != o.OriginalAuthorization.PrincipalIdentity() {
		return ErrErasureBindingMismatch
	}
	original, err := parseErasurePolicySnapshot(o.OperationPolicyBytes)
	if err != nil {
		return err
	}
	current, err := parseErasurePolicySnapshot(m.policy.Bytes())
	if err != nil {
		return err
	}
	if !original.stableEqual(current) || !current.matchesNamespace(o.Namespace) ||
		current.DatabaseAuthorityIdentity != m.journal.DatabaseAuthorityIdentity() {
		return ErrErasureBindingMismatch
	}
	return nil
}

func resumeProgressGraph(p ErasureProgress) (*erasureProgressGraph, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	g := &erasureProgressGraph{o: p.data.options, attempts: make(map[string]ErasureAttempt),
		snapshots: make(map[string]ErasureAllowanceSnapshot), policies: make(map[string]erasurePolicySnapshot),
		evidence: make(map[string]ErasureEvidence), slots: make(map[string]ErasureEvidence)}
	for _, raw := range p.AcceptedPolicyBytes() {
		policy, err := parseErasurePolicySnapshot(raw)
		if err != nil {
			return nil, err
		}
		g.policies[policy.Identity] = policy
	}
	for _, s := range g.o.AllowanceSnapshots {
		g.snapshots[s.Allowance.Identity()] = s
	}
	for _, a := range g.o.Attempts {
		g.attempts[a.Identity()] = a
	}
	for _, e := range g.o.Evidence {
		g.evidence[e.Identity()], g.slots[e.Slot()] = e, e
	}
	if err := g.validate(); err != nil {
		return nil, err
	}
	return g, nil
}

// resultFromProgress is private and historical. It rechecks full originals,
// policies, totals, request/attempt preimages, evidence edges and chronology.
// A candidate, boolean, or metadata Valid call alone never yields Certified.
func resultFromProgress(p ErasureProgress) (ErasureResult, error) {
	g, err := resumeProgressGraph(p)
	if err != nil {
		return ErasureResult{}, err
	}
	r := ErasureResult{state: ErasureStatePrepared, operation: p.Operation(), unknown: p.HasUnknownHistory()}
	usages := p.AllowanceUsages()
	if len(usages) > 1 {
		return ErasureResult{}, ErrErasureBindingMismatch
	}
	if len(usages) == 1 {
		r.usage, r.hasUsage = usages[0], true
	}
	if len(g.o.AllowanceSnapshots) != 0 || len(g.o.Attempts) != 0 || len(g.o.Evidence) != 0 {
		r.state = ErasureStatePending
	}
	if r.unknown {
		r.state = ErasureStateUnknown
	}
	published := g.slots["published"]
	if published.Identity() == "" {
		return r, nil
	}
	candidate, fence := g.slots["candidate"], g.slots["fence"]
	if candidate.Identity() == "" || fence.Identity() == "" {
		return ErasureResult{}, ErrInvalidErasureContract
	}
	if err := g.validateFence(fence); err != nil {
		return ErasureResult{}, err
	}
	parents := candidate.ParentIdentities()
	if len(parents) != 1 {
		return ErasureResult{}, ErrInvalidErasureContract
	}
	verification, exists := g.evidence[parents[0]]
	if !exists || verification.Kind() != "verification" {
		return ErasureResult{}, ErrInvalidErasureContract
	}
	if err := g.validateVerification(verification); err != nil {
		return ErasureResult{}, err
	}
	if err := g.validateCandidate(candidate); err != nil {
		return ErasureResult{}, err
	}
	if err := g.validatePublished(published); err != nil {
		return ErasureResult{}, err
	}
	attestation, err := ParseErasureAttestationV2(candidate.RecordBytes(), p.Operation().Scope())
	if err != nil {
		return ErasureResult{}, err
	}
	r.state, r.attestation = ErasureStateCertified, attestation
	return r, nil
}

func (i *resumeInvocation) validateResumeRequestDependencies(r AttemptRequest, q resumeRequest, at time.Time) error {
	if err := r.Validate(); err != nil {
		return err
	}
	if i.progress.data == nil || !progressRequestKey(i.progress.data.options, r) ||
		r.Scope() != i.ref.Scope() || r.NamespaceIdentity() != i.ref.NamespaceIdentity() ||
		q.key.Key() != r.Key() || q.key.NamespaceIdentity() != r.NamespaceIdentity() ||
		q.kind != r.Kind() || r.OperationIdentity() != i.operation.Identity() || r.AllowanceIdentity() != i.allowance.Identity() ||
		r.ExpectedBucketOwner() != i.allowance.ExpectedBucketOwner() || !i.allowance.AllowsOperation(i.operation, at) ||
		!i.mode.policy.AllowsAt(at) {
		return ErrErasureBindingMismatch
	}
	stem := progressDeletionStem(i.progress.data.options)
	legacy := r.Kind() == AttemptIntentRead && r.Key() == stem+".intent" ||
		r.Kind() == AttemptAttestationRead && r.Key() == stem+".receipt"
	if legacy != q.legacy {
		return ErrErasureBindingMismatch
	}
	switch r.Kind() {
	case AttemptCurrentRead, AttemptIntentRead, AttemptAttestationRead, AttemptVersionList:
		if q.observation != nil || len(q.body) != 0 {
			return ErrErasureBindingMismatch
		}
		if r.Kind() == AttemptVersionList && (i.fence.Identity() == "" || at.Before(i.fence.ObservedAt())) {
			return ErrErasureBindingMismatch
		}
		return nil
	}
	if q.observation == nil {
		return ErrErasureBindingMismatch
	}
	observed := q.observation
	parsed, err := ParseAttemptResponseEvidence(observed.evidence, observed.attempt)
	if err != nil {
		return err
	}
	expected, err := NewAttemptResponseEvidence(observed.response)
	if err != nil {
		return err
	}
	if err := equalProgressEvidence(expected, observed.evidence); err != nil {
		return err
	}
	parent := observed.attempt.Request()
	if observed.evidence.Ref() != i.ref || observed.evidence.ObservedAt().After(at) ||
		parent.Key() != r.Key() || parent.NamespaceIdentity() != r.NamespaceIdentity() ||
		r.ObservationIdentity() != observed.evidence.Identity() {
		return ErrErasureBindingMismatch
	}
	switch r.Kind() {
	case AttemptIntentCreate, AttemptFenceCreate, AttemptAttestationCreate:
		readKind := AttemptIntentRead
		var body []byte
		switch r.Kind() {
		case AttemptIntentCreate:
			body, err = EncodeErasureOperation(i.operation)
		case AttemptFenceCreate:
			readKind = AttemptCurrentRead
			var fence ErasureFence
			fence, err = NewErasureFence(i.operation)
			if err == nil {
				body, err = EncodeErasureFence(fence)
			}
			if i.pinned.Identity() != "" {
				return ErrErasureConflict
			}
		case AttemptAttestationCreate:
			readKind = AttemptAttestationRead
			if i.candidate.Kind() != "candidate" || at.Before(i.candidate.ObservedAt()) {
				return ErrErasureBindingMismatch
			}
			body = i.candidate.RecordBytes()
		}
		if err != nil {
			return err
		}
		if parent.Kind() != readKind || parsed.Code != AttemptResponseAbsent ||
			parsed.ContentKind != "" && !(r.Kind() == AttemptFenceCreate && parsed.ContentKind == "delete_marker") ||
			!bytes.Equal(q.body, body) || r.BodyBytes() != uint32(len(body)) || r.BodyDigest() != hashBytes(body) {
			return ErrErasureBindingMismatch
		}
	case AttemptVersionDelete:
		if q.version.Validate() != nil || q.version.Key() != r.Key() || q.version.NamespaceIdentity() != r.NamespaceIdentity() ||
			q.version.VersionID() != r.VersionID() || q.version.Kind() != r.VersionKind() ||
			i.pinned.Identity() != "" && q.version.VersionID() == i.pinned.VersionID() {
			return ErrErasureBindingMismatch
		}
		if parsed.Code != AttemptResponsePresent {
			return ErrErasureBindingMismatch
		}
		switch parent.Kind() {
		case AttemptCurrentRead:
			if parsed.ContentKind != "ciphertext" || parsed.Version.Kind() != ObjectVersionData || parsed.Version != q.version {
				return ErrErasureBindingMismatch
			}
		case AttemptVersionList:
			if i.fence.Identity() == "" || observed.attempt.ReservedAt().Before(i.fence.ObservedAt()) {
				return ErrErasureBindingMismatch
			}
			found := false
			for _, entry := range parsed.Page.Entries {
				if entry.Version == q.version {
					found = true
				}
			}
			if !found {
				return ErrErasureBindingMismatch
			}
		default:
			return ErrErasureBindingMismatch
		}
	default:
		return ErrErasureBindingMismatch
	}
	return nil
}
