package artifact

import "bytes"

type erasureProgressGraph struct {
	o         ErasureProgressOptions
	attempts  map[string]ErasureAttempt
	snapshots map[string]ErasureAllowanceSnapshot
	policies  map[string]erasurePolicySnapshot
	evidence  map[string]ErasureEvidence
	slots     map[string]ErasureEvidence
}

func equalProgressEvidence(a, b ErasureEvidence) error {
	x, err := EncodeErasureEvidence(a)
	if err != nil {
		return err
	}
	y, err := EncodeErasureEvidence(b)
	if err != nil {
		return err
	}
	if !bytes.Equal(x, y) {
		return ErrErasureBindingMismatch
	}
	return nil
}

func (g *erasureProgressGraph) response(e ErasureEvidence) (AttemptResponseOptions, error) {
	a, exists := g.attempts[e.AttemptIdentity()]
	if !exists {
		return AttemptResponseOptions{}, ErrInvalidErasureContract
	}
	return ParseAttemptResponseEvidence(e, a)
}

func (g *erasureProgressGraph) validate() error {
	// Each root is walked independently, so a shared ancestor reached through a
	// longer path cannot hide a seventh edge behind a shorter cached traversal.
	for _, e := range g.o.Evidence {
		if err := g.walk(e.Identity(), 0, make(map[string]bool)); err != nil {
			return err
		}
	}
	for _, a := range g.o.Attempts {
		if id := a.Request().ObservationIdentity(); id != "" {
			if err := g.walk(id, 1, make(map[string]bool)); err != nil {
				return err
			}
		}
	}
	for _, e := range g.o.Evidence {
		if err := g.validateEvidence(e); err != nil {
			return err
		}
	}
	for _, a := range g.o.Attempts {
		if err := g.validateObservation(a); err != nil {
			return err
		}
		response := g.slots["response:"+a.Identity()]
		unknown := g.slots["unknown:"+a.Identity()]
		if response.Identity() == "" && !g.o.UnresolvedExists {
			return ErrErasureBindingMismatch
		}
		if unknown.Identity() != "" && !g.o.UnknownExists {
			return ErrErasureBindingMismatch
		}
	}
	return nil
}

func (g *erasureProgressGraph) walk(id string, depth int, path map[string]bool) error {
	if depth > 6 || path[id] {
		return ErrInvalidErasureContract
	}
	e, exists := g.evidence[id]
	if !exists {
		return ErrInvalidErasureContract
	}
	path[id] = true
	defer delete(path, id)
	for _, parent := range e.record.ParentIdentities {
		if err := g.walk(parent, depth+1, path); err != nil {
			return err
		}
	}
	if e.AttemptIdentity() != "" {
		a, exists := g.attempts[e.AttemptIdentity()]
		if !exists {
			return ErrInvalidErasureContract
		}
		if observation := a.Request().ObservationIdentity(); observation != "" {
			if err := g.walk(observation, depth+1, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *erasureProgressGraph) validateEvidence(e ErasureEvidence) error {
	if e.ObservedAt().Before(g.o.Operation.PreparedAt()) {
		return ErrErasureBindingMismatch
	}
	switch e.Kind() {
	case "response":
		r, err := g.response(e)
		if err != nil {
			return err
		}
		if r.Code == AttemptResponseUnavailable || r.Code == AttemptResponseMalformed {
			if g.slots["unknown:"+e.AttemptIdentity()].Identity() == "" {
				return ErrInvalidErasureContract
			}
		}
		if r.Code != AttemptResponsePresent {
			return nil
		}
		request := r.Attempt.Request()
		switch r.ContentKind {
		case "operation":
			expected, err := EncodeErasureOperation(g.o.Operation)
			if err != nil {
				return err
			}
			if request.Key() != progressDeletionStem(g.o)+".intent-v2" || !bytes.Equal(expected, r.CanonicalRecord) {
				return ErrErasureBindingMismatch
			}
		case "fence":
			parsed, err := responseFromEvidence(e)
			if err != nil {
				return err
			}
			if err := exactFenceResponse(g.o.Operation, parsed); err != nil {
				return err
			}
		case "attestation":
			candidate := g.slots["candidate"]
			if candidate.Identity() == "" {
				return ErrInvalidErasureContract
			}
			if request.Key() != progressDeletionStem(g.o)+".attestation-v2" ||
				!bytes.Equal(candidate.RecordBytes(), r.CanonicalRecord) || r.Attempt.ReservedAt().Before(candidate.ObservedAt()) {
				return ErrErasureBindingMismatch
			}
		}
		return nil
	case "unknown":
		a, exists := g.attempts[e.AttemptIdentity()]
		if !exists {
			return ErrInvalidErasureContract
		}
		expected, err := NewAttemptUnknownEvidence(a, e.ObservedAt())
		if err != nil {
			return err
		}
		return equalProgressEvidence(e, expected)
	case "fence":
		return g.validateFence(e)
	case "verification":
		return g.validateVerification(e)
	case "candidate":
		return g.validateCandidate(e)
	case "published":
		return g.validatePublished(e)
	}
	return ErrInvalidErasureContract
}

func (g *erasureProgressGraph) validateFence(e ErasureEvidence) error {
	parent := g.evidence[e.record.ParentIdentities[0]]
	response, err := g.response(parent)
	if err != nil {
		return err
	}
	version, err := ParseObjectVersion(e.RecordBytes())
	if err != nil {
		return err
	}
	request := response.Attempt.Request()
	if parent.Kind() != "response" || request.Kind() != AttemptCurrentRead || request.Key() != progressArtifactKey(g.o) ||
		version.Key() != request.Key() || version.NamespaceIdentity() != g.o.Namespace.Identity() {
		return ErrErasureBindingMismatch
	}
	key, err := NewExactObjectKey(g.o.Namespace.Identity(), progressArtifactKey(g.o))
	if err != nil {
		return err
	}
	expected, err := NewFenceObservationEvidence(g.o.Operation, key, parent, e.ObservedAt())
	if err != nil {
		return err
	}
	return equalProgressEvidence(e, expected)
}

func (g *erasureProgressGraph) validateVerification(e ErasureEvidence) error {
	v, err := ParseErasureVerification(e.RecordBytes(), g.o.Operation.Ref())
	if err != nil {
		return err
	}
	fence := g.evidence[v.FenceEvidenceIdentity()]
	list := g.evidence[v.ListResponseIdentities()[0]]
	current := g.evidence[v.CurrentResponseIdentity()]
	if fence.Identity() == "" || list.Identity() == "" || current.Identity() == "" {
		return ErrInvalidErasureContract
	}
	if fence.Identity() != g.slots["fence"].Identity() {
		return ErrErasureBindingMismatch
	}
	lr, err := g.response(list)
	if err != nil {
		return err
	}
	cr, err := g.response(current)
	if err != nil {
		return err
	}
	la, ca := lr.Attempt, cr.Attempt
	request := la.Request()
	fenceRead := g.evidence[fence.record.ParentIdentities[0]]
	if request.Kind() != AttemptVersionList || request.KeyMarker() != "" || request.VersionIDMarker() != "" || request.PageLimit() != 2 ||
		request.Key() != progressArtifactKey(g.o) || ca.Request().Kind() != AttemptCurrentRead || ca.Request().Key() != request.Key() ||
		la.Identity() == ca.Identity() || la.Request().ReservationIdentity() == ca.Request().ReservationIdentity() ||
		la.Identity() == fenceRead.AttemptIdentity() || ca.Identity() == fenceRead.AttemptIdentity() ||
		la.ReservedAt().Before(fence.ObservedAt()) || ca.ReservedAt().Before(list.ObservedAt()) {
		return ErrErasureBindingMismatch
	}
	if err := g.attemptWindow(la, la.ReservedAt(), list.ObservedAt(), v.VerifiedAt(), v.CompletedAt()); err != nil {
		return err
	}
	if err := g.attemptWindow(ca, ca.ReservedAt(), current.ObservedAt(), v.VerifiedAt(), v.CompletedAt()); err != nil {
		return err
	}
	expected, err := NewErasureVerification(g.o.Operation, fence, []ErasureEvidence{list}, current, v.CompletedAt())
	if err != nil {
		return err
	}
	canonical, err := EncodeErasureVerification(expected)
	if err != nil {
		return err
	}
	if !bytes.Equal(canonical, e.RecordBytes()) {
		return ErrErasureBindingMismatch
	}
	rebuilt, err := NewVerificationEvidence(expected)
	if err != nil {
		return err
	}
	return equalProgressEvidence(e, rebuilt)
}

func (g *erasureProgressGraph) validateCandidate(e ErasureEvidence) error {
	candidate, err := ParseErasureAttestationV2(e.RecordBytes(), g.o.Operation.Scope())
	if err != nil {
		return err
	}
	parent := g.evidence[e.record.ParentIdentities[0]]
	if parent.Identity() == "" {
		return ErrInvalidErasureContract
	}
	if parent.Kind() != "verification" {
		return ErrErasureBindingMismatch
	}
	v, err := ParseErasureVerification(parent.RecordBytes(), g.o.Operation.Ref())
	if err != nil {
		return err
	}
	current := g.evidence[v.CurrentResponseIdentity()]
	list := g.evidence[v.ListResponseIdentities()[0]]
	ca, caExists := g.attempts[current.AttemptIdentity()]
	la, laExists := g.attempts[list.AttemptIdentity()]
	if !caExists || !laExists {
		return ErrInvalidErasureContract
	}
	selected := g.snapshots[ca.Request().AllowanceIdentity()]
	policy, exists := g.policies[selected.Allowance.ProtectedPolicyIdentity()]
	if !exists {
		return ErrInvalidErasureContract
	}
	// Terminal decisions use the policy selected by their actual reservations,
	// not a loaded value forged from historical bytes.
	if la.Request().ProtectedPolicyIdentity() != policy.Identity || candidate.ResumePolicyIdentity() != policy.Identity {
		return ErrErasureBindingMismatch
	}
	if err := g.attemptWindow(ca, v.VerifiedAt(), v.CompletedAt()); err != nil {
		return err
	}
	if err := g.attemptWindow(la, v.VerifiedAt(), v.CompletedAt()); err != nil {
		return err
	}
	op := g.o.Operation
	fence, err := NewErasureFence(op)
	if err != nil {
		return err
	}
	expected := erasureAttestationV2Record{Contract: erasureAttestationV2Contract, SchemaVersion: 2,
		NamespaceIdentity: op.NamespaceIdentity(), ScopeIdentity: op.Scope().Identity(), ArtifactIdentity: op.ArtifactIdentity(),
		PayloadDigest: g.o.Admission.PayloadDigest(), AdmissionIdentity: op.AdmissionIdentity(), OperationIdentity: op.Identity(),
		OriginalAuthorizationIdentity: op.OriginalAuthorizationIdentity(), AuthorizationDocumentDigest: op.AuthorizationDocumentDigest(),
		ErasureProtocol: op.ErasureProtocol(), PolicyIdentity: op.PolicyIdentity(), ProtectedPolicyIdentity: op.ProtectedPolicyIdentity(),
		ResumePolicyIdentity: policy.Identity, ConfigurationEvidenceIdentity: policy.ConfigurationEvidenceIdentity,
		FenceIdentity: fence.Identity(), FenceVersionIdentity: v.FenceVersionIdentity(), VerificationIdentity: v.Identity(),
		PreparedAtMilliseconds: op.PreparedAt().UnixMilli(), VerifiedAtMilliseconds: v.VerifiedAt().UnixMilli(), CompletedAtMilliseconds: v.CompletedAt().UnixMilli(),
		ProofScope: "all_versions_at_exact_key", RemainingDataVersions: 1, RemainingDeleteMarkers: 0, RemainingRecord: "content_free_fence", LegacyReceiptIdentity: ""}
	expected.Identity = attestationV2RecordIdentity(expected)
	raw, err := erasureMetadataEncode(expected, maxEncodedErasureAttestationV2Bytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(raw, e.RecordBytes()) || !e.ObservedAt().Equal(v.CompletedAt()) {
		return ErrErasureBindingMismatch
	}
	return nil
}

func (g *erasureProgressGraph) validatePublished(e ErasureEvidence) error {
	candidate := g.evidence[e.record.ParentIdentities[0]]
	read := g.evidence[e.record.ParentIdentities[1]]
	if candidate.Identity() == "" || read.Identity() == "" {
		return ErrInvalidErasureContract
	}
	if candidate.Identity() != g.slots["candidate"].Identity() {
		return ErrErasureBindingMismatch
	}
	response, err := g.response(read)
	if err != nil {
		return err
	}
	a := response.Attempt
	if a.Request().Kind() != AttemptAttestationRead || a.Request().Key() != progressDeletionStem(g.o)+".attestation-v2" ||
		a.ReservedAt().Before(candidate.ObservedAt()) {
		return ErrErasureBindingMismatch
	}
	if err := g.attemptWindow(a, a.ReservedAt(), read.ObservedAt(), e.ObservedAt()); err != nil {
		return err
	}
	expected, err := NewAttestationPublicationEvidence(candidate, read, e.ObservedAt())
	if err != nil {
		return err
	}
	return equalProgressEvidence(e, expected)
}

func (g *erasureProgressGraph) validateObservation(a ErasureAttempt) error {
	request := a.Request()
	if request.ObservationIdentity() == "" {
		return nil
	}
	observation, exists := g.evidence[request.ObservationIdentity()]
	if !exists {
		return ErrInvalidErasureContract
	}
	response, err := g.response(observation)
	if err != nil {
		return err
	}
	observedRequest := response.Attempt.Request()
	if observation.Kind() != "response" || observation.ObservedAt().After(a.ReservedAt()) || response.Attempt.Identity() == a.Identity() ||
		observedRequest.Key() != request.Key() || observedRequest.NamespaceIdentity() != request.NamespaceIdentity() {
		return ErrErasureBindingMismatch
	}
	switch request.Kind() {
	case AttemptIntentCreate, AttemptFenceCreate, AttemptAttestationCreate:
		kind := AttemptIntentRead
		if request.Kind() == AttemptFenceCreate {
			kind = AttemptCurrentRead
		}
		if request.Kind() == AttemptAttestationCreate {
			kind = AttemptAttestationRead
		}
		if observedRequest.Kind() != kind || response.Code != AttemptResponseAbsent {
			return ErrErasureBindingMismatch
		}
		if request.Kind() == AttemptAttestationCreate {
			candidate := g.slots["candidate"]
			if candidate.Identity() == "" {
				return ErrInvalidErasureContract
			}
			body := candidate.RecordBytes()
			if request.BodyBytes() != uint32(len(body)) || request.BodyDigest() != hashBytes(body) || a.ReservedAt().Before(candidate.ObservedAt()) {
				return ErrErasureBindingMismatch
			}
		}
	case AttemptVersionDelete:
		if fence := g.slots["fence"]; fence.Identity() != "" {
			pinned, err := ParseObjectVersion(fence.RecordBytes())
			if err != nil {
				return err
			}
			if request.VersionID() == pinned.VersionID() {
				return ErrErasureBindingMismatch
			}
		}
		if response.Code != AttemptResponsePresent {
			return ErrErasureBindingMismatch
		}
		switch observedRequest.Kind() {
		case AttemptCurrentRead:
			if response.ContentKind != "ciphertext" || response.Version.Kind() != ObjectVersionData ||
				request.VersionKind() != response.Version.Kind() || request.VersionID() != response.Version.VersionID() {
				return ErrErasureBindingMismatch
			}
		case AttemptVersionList:
			fence := g.slots["fence"]
			if fence.Identity() == "" {
				return ErrInvalidErasureContract
			}
			pinned, err := ParseObjectVersion(fence.RecordBytes())
			if err != nil {
				return err
			}
			if response.Attempt.ReservedAt().Before(fence.ObservedAt()) || request.VersionID() == pinned.VersionID() {
				return ErrErasureBindingMismatch
			}
			found := false
			for _, entry := range response.Page.Entries {
				if entry.Version.Kind() == request.VersionKind() && entry.Version.VersionID() == request.VersionID() {
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
