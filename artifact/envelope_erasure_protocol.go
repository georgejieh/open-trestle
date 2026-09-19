package artifact

import (
	"bytes"
)

// Read/page ceilings are conservative prepaid selections, not mandatory greedy
// use of the transport maxima. A refused larger response authorizes no deletion.
const (
	resumeCurrentReadMaximum uint32 = 32 << 20
	resumeRecordReadMaximum  uint32 = 16384
	resumeListMaximum        uint32 = 64 << 10
	resumePurgePageLimit     uint16 = 16
)

func erasureIntentObjectKey(n StorageNamespace, op ErasureOperation) (ExactObjectKey, error) {
	return NewExactObjectKey(n.Identity(), n.Prefix()+"/deletions/"+op.Scope().Identity()+"/"+op.ArtifactIdentity()+".intent-v2")
}
func erasureAttestationObjectKey(n StorageNamespace, op ErasureOperation) (ExactObjectKey, error) {
	return NewExactObjectKey(n.Identity(), n.Prefix()+"/deletions/"+op.Scope().Identity()+"/"+op.ArtifactIdentity()+".attestation-v2")
}

func (i *resumeInvocation) read(kind AttemptKind, key ExactObjectKey, expected []byte, legacy bool) (resumeObservation, error) {
	maximum := resumeRecordReadMaximum
	if kind == AttemptCurrentRead {
		if i.pinned.Identity() != "" {
			maximum = 4096
		} else {
			var err error
			maximum, err = i.currentReadMaximum()
			if err != nil {
				return resumeObservation{}, err
			}
		}
	}
	return i.reserveAndDispatch(resumeRequest{kind: kind, key: key, maximum: maximum, expected: expected, legacy: legacy})
}
func (i *resumeInvocation) create(kind AttemptKind, key ExactObjectKey, body []byte, observation resumeObservation) (resumeObservation, error) {
	return i.reserveAndDispatch(resumeRequest{kind: kind, key: key, maximum: 4096, body: body, observation: &observation})
}
func (i *resumeInvocation) deleteVersion(key ExactObjectKey, version ObjectVersion, observation resumeObservation) error {
	// Compare the provider's raw token before kind/content labels. A forged label
	// can never turn the required fence's token into an erasure target.
	if i.pinned.Identity() != "" && version.VersionID() == i.pinned.VersionID() {
		return ErrErasureConflict
	}
	_, err := i.reserveAndDispatch(resumeRequest{kind: AttemptVersionDelete, key: key, version: version, maximum: 4096, observation: &observation})
	return err
}

func (i *resumeInvocation) complete() error {
	n, op := i.progress.data.options.Namespace, i.operation
	key, err := NewExactObjectKey(n.Identity(), progressArtifactKey(i.progress.data.options))
	if err != nil {
		return err
	}
	stem := progressDeletionStem(i.progress.data.options)
	for _, legacy := range []struct {
		suffix string
		kind   AttemptKind
	}{{".intent", AttemptIntentRead}, {".receipt", AttemptAttestationRead}} {
		oldKey, err := NewExactObjectKey(n.Identity(), stem+legacy.suffix)
		if err != nil {
			return err
		}
		if _, err := i.read(legacy.kind, oldKey, nil, true); err != nil {
			return err
		}
	}
	intentKey, err := erasureIntentObjectKey(n, op)
	if err != nil {
		return err
	}
	intentBody, err := EncodeErasureOperation(op)
	if err != nil {
		return err
	}
	intent, err := i.read(AttemptIntentRead, intentKey, intentBody, false)
	if err != nil {
		return err
	}
	if intent.response.Code == AttemptResponseAbsent {
		if _, err := i.create(AttemptIntentCreate, intentKey, intentBody, intent); err != nil {
			return err
		}
		intent, err = i.read(AttemptIntentRead, intentKey, intentBody, false)
		if err != nil {
			return err
		}
	}
	if intent.response.Code != AttemptResponsePresent || !bytes.Equal(intent.response.CanonicalRecord, intentBody) {
		return ErrErasureConflict
	}
	fenceValue, err := NewErasureFence(op)
	if err != nil {
		return err
	}
	fenceBody, err := EncodeErasureFence(fenceValue)
	if err != nil {
		return err
	}
	if err := i.acquireFence(key, fenceBody); err != nil {
		return err
	}
	if err := i.purge(key); err != nil {
		return err
	}
	// Discovery and terminal verification always use different reservations.
	terminalScan := &versionScan{required: i.pinned}
	terminal, err := i.reserveAndDispatch(resumeRequest{kind: AttemptVersionList, key: key, limit: 2, maximum: resumeListMaximum, scan: terminalScan})
	if err != nil {
		return err
	}
	if err := validateTerminalFencePage(terminal, key, i.pinned); err != nil {
		return err
	}
	current, err := i.read(AttemptCurrentRead, key, fenceBody, false)
	if err != nil {
		return err
	}
	if current.response.Code != AttemptResponsePresent || current.response.ContentKind != "fence" || current.response.Version != i.pinned ||
		!bytes.Equal(current.response.CanonicalRecord, fenceBody) || current.attempt.Identity() == terminal.attempt.Identity() ||
		current.attempt.ReservedAt().Before(terminal.evidence.ObservedAt()) {
		return ErrErasureConflict
	}
	completed, err := i.sample(true)
	if err != nil {
		return err
	}
	verification, err := NewErasureVerification(op, i.fence, []ErasureEvidence{terminal.evidence}, current.evidence, completed)
	if err != nil {
		return err
	}
	verificationEvidence, err := NewVerificationEvidence(verification)
	if err != nil {
		return err
	}
	if _, err := i.record(verificationEvidence); err != nil {
		return err
	}
	if _, err := i.sample(true); err != nil {
		return err
	}
	proposed, err := NewAttestationCandidateEvidence(op, i.progress.Admission(), i.mode.policy, verification)
	if err != nil {
		return err
	}
	selected, err := i.record(proposed)
	if err != nil {
		return err
	}
	// Adopt the actual CAS winner with its historical policy and original times.
	if err := i.reload(); err != nil {
		return err
	}
	if i.candidate.Identity() != selected.Identity() {
		return ErrErasureConflict
	}
	proofKey, err := erasureAttestationObjectKey(n, op)
	if err != nil {
		return err
	}
	body := i.candidate.RecordBytes()
	proof, err := i.read(AttemptAttestationRead, proofKey, body, false)
	if err != nil {
		return err
	}
	if proof.response.Code == AttemptResponseAbsent {
		if _, err := i.create(AttemptAttestationCreate, proofKey, body, proof); err != nil {
			return err
		}
	}
	// Create's bool supplies no version. Even an existing proof is separately
	// read in full for this publication decision; no old response is replayed.
	proof, err = i.read(AttemptAttestationRead, proofKey, body, false)
	if err != nil {
		return err
	}
	if proof.response.Code != AttemptResponsePresent || !bytes.Equal(proof.response.CanonicalRecord, body) {
		return ErrErasureConflict
	}
	at, err := i.sample(true)
	if err != nil {
		return err
	}
	publication, err := NewAttestationPublicationEvidence(i.candidate, proof.evidence, at)
	if err != nil {
		return err
	}
	if _, err := i.record(publication); err != nil {
		return err
	}
	return nil
}

func (i *resumeInvocation) acquireFence(key ExactObjectKey, body []byte) error {
	// Every iteration spends a request before dispatch, so this loop is also
	// bounded when an admitted delayed Create repeatedly wins a vacated gap.
	readback := false
	for {
		var current resumeObservation
		var err error
		if readback {
			current, err = i.reserveAndDispatch(resumeRequest{kind: AttemptCurrentRead, key: key, maximum: 4096, expected: body})
		} else {
			current, err = i.read(AttemptCurrentRead, key, nil, false)
		}
		if err != nil {
			return err
		}
		if current.response.Code == AttemptResponsePresent && current.response.ContentKind == "fence" {
			at, err := i.sample(true)
			if err != nil {
				return err
			}
			proposed, err := NewFenceObservationEvidence(i.operation, key, current.evidence, at)
			if err != nil {
				return err
			}
			selected, err := i.record(proposed)
			if err != nil {
				return err
			}
			pinned, err := ParseObjectVersion(selected.RecordBytes())
			if err != nil {
				return err
			}
			if pinned != current.response.Version || pinned.Key() != key.Key() || pinned.Kind() != ObjectVersionData {
				return ErrErasureConflict
			}
			i.fence, i.pinned = selected, pinned
			return nil
		}
		if i.pinned.Identity() != "" {
			return ErrErasureConflict
		}
		switch current.response.Code {
		case AttemptResponsePresent:
			if current.response.ContentKind != "ciphertext" {
				return ErrErasureConflict
			}
			if err := i.deleteVersion(key, current.response.Version, current); err != nil {
				return err
			}
		case AttemptResponseAbsent:
			// Strict absence or a typed current marker permits only conditional create.
			created, err := i.create(AttemptFenceCreate, key, body, current)
			if err != nil {
				return err
			}
			readback = created.response.Code == AttemptResponseCreated
		default:
			return ErrErasureConflict
		}
		// A separate full read after either mutation observes any newly current
		// ciphertext and any delayed payload winner before a fence token is pinned.
	}
}

func (i *resumeInvocation) purge(key ExactObjectKey) error {
	scan := &versionScan{required: i.pinned}
	cursor := VersionCursor{}
	for {
		page, err := i.reserveAndDispatch(resumeRequest{kind: AttemptVersionList, key: key, cursor: cursor,
			limit: resumePurgePageLimit, maximum: resumeListMaximum, scan: scan})
		if err != nil {
			return err
		}
		var target ObjectVersion
		for _, entry := range page.response.Page.Entries {
			if entry.Version.VersionID() == i.pinned.VersionID() {
				if entry.Version != i.pinned || !entry.IsLatest {
					return ErrErasureConflict
				}
				continue
			}
			if target.Identity() == "" {
				target = entry.Version
			}
		}
		if target.Identity() != "" {
			if err := i.deleteVersion(key, target, page); err != nil {
				return err
			}
			// Never reuse a continuation across deletion, including not-found replies.
			cursor, scan = VersionCursor{}, &versionScan{required: i.pinned}
			continue
		}
		if !page.response.Page.Truncated {
			if !scan.versions[i.pinned.VersionID()] {
				return ErrErasureConflict
			}
			return nil
		}
		cursor = page.response.Page.Next
	}
}
