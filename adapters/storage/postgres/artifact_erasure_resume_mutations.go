package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

func (j *artifactResumeJournal) freshAllowance(a artifact.ResumeAllowance, at, captured time.Time, r *resumeResolver) error {
	if !validErasureInstant(at) || !validErasureInstant(captured) || at.After(captured) {
		return artifact.ErrInvalidErasureContract
	}
	if a.ValidateProtected(j.policy) != nil {
		return artifact.ErrErasureAuthorityRequired
	}
	p, err := parsePersistedErasurePolicy(j.policy.Bytes())
	if err != nil || !resumeStablePolicy(p, r.originalPolicy) || a.PrincipalIdentity() != r.options.OriginalAuthorization.PrincipalIdentity() {
		return artifact.ErrErasureBindingMismatch
	}
	op := r.options.Operation
	if a.Scope() != op.Scope() || a.NamespaceIdentity() != op.NamespaceIdentity() || a.ArtifactIdentity() != op.ArtifactIdentity() || a.AdmissionIdentity() != op.AdmissionIdentity() || a.OperationIdentity() != op.Identity() || a.OriginalAuthorizationIdentity() != op.OriginalAuthorizationIdentity() || a.AuthorizationDocumentDigest() != op.AuthorizationDocumentDigest() {
		return artifact.ErrErasureBindingMismatch
	}
	if !a.AllowsOperation(op, at) || !a.AllowsOperation(op, captured) || !j.policy.AllowsAt(at) || !j.policy.AllowsAt(captured) {
		return artifact.ErrErasureAllowanceExpired
	}
	return nil
}
func resumeKnownError(outcome erasureCommitOutcome, err, reason error) error {
	if outcome == erasureCommitUnknown {
		return artifact.ErrErasureUnknownOutcome
	}
	if outcome == erasureKnownAbort && err == artifact.ErrErasureConflict && reason != nil {
		return reason
	}
	return err
}
func (j *artifactResumeJournal) AdmitResumeAllowance(ctx context.Context, ref artifact.ErasureOperationRef, a artifact.ResumeAllowance, at time.Time) (artifact.AllowanceUsage, error) {
	if err := j.validateResume(ctx, ref); err != nil {
		return artifact.AllowanceUsage{}, err
	}
	if err := a.Validate(); err != nil {
		return artifact.AllowanceUsage{}, err
	}
	if err := a.ValidateProtected(j.policy); err != nil {
		return artifact.AllowanceUsage{}, err
	}
	captured := j.clock.Now()
	var result artifact.AllowanceUsage
	var reason error
	outcome, err := j.index.store.retryErasureMutation(ctx, ref.Scope().TenantID(), func(tx *sql.Tx) error {
		result = artifact.AllowanceUsage{}
		reason = nil
		if err := lockScopeTransaction(ctx, tx, "artifact:"+ref.Scope().Identity()+":"+a.ArtifactIdentity()); err != nil {
			return err
		}
		r := newResumeResolver(j, ctx, tx, ref)
		found, err := r.original()
		if err != nil {
			return err
		}
		if !found {
			return artifact.ErrErasureAdmissionMissing
		}
		if err := j.freshAllowance(a, at, captured, r); err != nil {
			if err == artifact.ErrErasureAllowanceExpired {
				reason = err
				return artifact.ErrErasureConflict
			}
			return err
		}
		row, found, err := r.allowance(a.Identity(), true)
		if err != nil {
			return err
		}
		if found {
			raw, _ := artifact.EncodeResumeAllowance(a)
			stored, _ := artifact.EncodeResumeAllowance(row.Allowance)
			if !bytes.Equal(raw, stored) || !bytes.Equal(row.AcceptedPolicyBytes, j.policy.Bytes()) || a.ProtectedDocumentDigest() != erasureDigest(raw) {
				return artifact.ErrErasureConflict
			}
			result = row.Usage
			return nil
		}
		args, err := resumeAllowanceCells(r.options.Operation, a, j.policy.Bytes(), at, artifact.ResumeBudget{})
		if err != nil {
			return err
		}
		if err := execErasureOne(ctx, tx, resumeSQLAllowanceInsert, args...); err != nil {
			return err
		}
		result = artifact.AllowanceUsage{AllowanceIdentity: a.Identity(), NextSequence: 1}
		return nil
	})
	err = resumeKnownError(outcome, err, reason)
	if outcome != erasureKnownCommit || err != nil {
		return artifact.AllowanceUsage{}, err
	}
	return result, nil
}
func (j *artifactResumeJournal) ReserveErasureAttempt(ctx context.Context, ref artifact.ErasureOperationRef, a artifact.ResumeAllowance, request artifact.AttemptRequest, at time.Time) (artifact.ErasureAttempt, bool, error) {
	if err := j.validateResume(ctx, ref); err != nil {
		return artifact.ErasureAttempt{}, false, err
	}
	if err := a.Validate(); err != nil {
		return artifact.ErasureAttempt{}, false, err
	}
	if err := request.Validate(); err != nil {
		return artifact.ErasureAttempt{}, false, err
	}
	if err := a.ValidateProtected(j.policy); err != nil {
		return artifact.ErasureAttempt{}, false, err
	}
	captured := j.clock.Now()
	var result artifact.ErasureAttempt
	inserted := false
	var reason error
	outcome, err := j.index.store.retryErasureMutation(ctx, ref.Scope().TenantID(), func(tx *sql.Tx) error {
		result = artifact.ErasureAttempt{}
		inserted = false
		reason = nil
		if err := lockScopeTransaction(ctx, tx, "artifact:"+ref.Scope().Identity()+":"+a.ArtifactIdentity()); err != nil {
			return err
		}
		r := newResumeResolver(j, ctx, tx, ref)
		found, err := r.original()
		if err != nil {
			return err
		}
		if !found {
			return artifact.ErrErasureAdmissionMissing
		}
		if err := j.freshAllowance(a, at, captured, r); err != nil {
			if err == artifact.ErrErasureAllowanceExpired {
				reason = err
				return artifact.ErrErasureConflict
			}
			return err
		}
		row, found, err := r.allowance(a.Identity(), true)
		if err != nil {
			return err
		}
		if !found {
			return artifact.ErrErasureConflict
		}
		raw, _ := artifact.EncodeResumeAllowance(a)
		stored, _ := artifact.EncodeResumeAllowance(row.Allowance)
		if !bytes.Equal(raw, stored) || !bytes.Equal(row.AcceptedPolicyBytes, j.policy.Bytes()) || at.Before(row.AcceptedAt) {
			return artifact.ErrErasureConflict
		}
		prior, found, err := r.attempt(request.ReservationIdentity(), true, 0)
		if err != nil {
			return err
		}
		if found {
			want, _ := artifact.EncodeAttemptRequest(request)
			got, _ := artifact.EncodeAttemptRequest(prior.Request())
			if !bytes.Equal(want, got) {
				return artifact.ErrErasureConflict
			}
			if err := r.globals(); err != nil {
				return err
			}
			if _, err := r.progress(); err != nil {
				return err
			}
			result = prior
			return nil
		}
		if err := r.validateRequest(request, a, at, 0); err != nil {
			if err == ErrCorruptRecord {
				return artifact.ErrErasureBindingMismatch
			}
			return err
		}
		if id := request.ObservationIdentity(); id != "" {
			if err := r.evidenceDepth(r.evidence[id], 1); err != nil {
				return err
			}
		}
		requestRaw, _ := artifact.EncodeAttemptRequest(request)
		if err := r.charge("request", request.Identity(), requestRaw); err != nil {
			return err
		}
		if err := r.globals(); err != nil {
			return err
		}
		if _, err := r.progress(); err != nil {
			return err
		}
		max, spent, cost := journalResumeBudgetVector(a.Maximum()), journalResumeBudgetVector(row.Usage.Spent), journalResumeBudgetVector(resumeRequestCost(request))
		for i := range max {
			if spent[i] > max[i] || cost[i] > max[i]-spent[i] {
				reason = artifact.ErrErasureAllowanceExhausted
				return artifact.ErrErasureConflict
			}
		}
		if row.Usage.NextSequence < 1 || row.Usage.NextSequence > 4096 {
			reason = artifact.ErrErasureAllowanceExhausted
			return artifact.ErrErasureConflict
		}
		candidate, err := artifact.NewErasureAttempt(request, row.Usage.NextSequence, at)
		if err != nil {
			return err
		}
		args := resumeArgs(ref, a.Identity())
		args = append(args, resumeBudgetCells(resumeRequestCost(request))...)
		spending, err := tx.ExecContext(ctx, resumeSQLAllowanceSpend, args...)
		if err != nil {
			return classifyTransactionError(err)
		}
		affected, err := spending.RowsAffected()
		if err != nil {
			return classifyTransactionError(err)
		}
		if affected == 0 {
			reason = artifact.ErrErasureAllowanceExhausted
			return artifact.ErrErasureConflict
		}
		if affected != 1 {
			return ErrCorruptRecord
		}
		args, err = resumeAttemptCells(r.options.Operation, candidate)
		if err != nil {
			return err
		}
		if err := execErasureOne(ctx, tx, resumeSQLAttemptInsert, args...); err != nil {
			return err
		}
		result = candidate
		inserted = true
		return nil
	})
	err = resumeKnownError(outcome, err, reason)
	if outcome != erasureKnownCommit || err != nil {
		return artifact.ErasureAttempt{}, false, err
	}
	return result, inserted, nil
}
func resumeSameEvidence(a, b artifact.ErasureEvidence) bool {
	x, err := artifact.EncodeErasureEvidence(a)
	if err != nil {
		return false
	}
	y, err := artifact.EncodeErasureEvidence(b)
	return err == nil && bytes.Equal(x, y)
}
func (r *resumeResolver) incoming(e artifact.ErasureEvidence, captured time.Time) error {
	if e.Ref() != r.ref || !validErasureInstant(captured) || e.ObservedAt().After(captured) || e.ObservedAt().Before(r.options.Operation.PreparedAt()) {
		return artifact.ErrErasureBindingMismatch
	}
	if err := e.Validate(); err != nil {
		return err
	}
	if e.AttemptIdentity() != "" {
		a, found, err := r.attempt(e.AttemptIdentity(), false, 0)
		if err != nil {
			return err
		}
		if !found {
			return artifact.ErrErasureBindingMismatch
		}
		if e.ObservedAt().Before(a.ReservedAt()) {
			return artifact.ErrErasureBindingMismatch
		}
		if e.Kind() == "response" {
			response, err := artifact.ParseAttemptResponseEvidence(e, a)
			if err != nil {
				return err
			}
			if r.legacyRead(a.Request()) && (response.Code == artifact.AttemptResponsePresent || response.ContentKind != "") {
				return artifact.ErrErasureBindingMismatch
			}
		}
	}
	parents := make([]artifact.ErasureEvidence, 0, len(e.ParentIdentities()))
	for _, id := range e.ParentIdentities() {
		p, found, err := r.evidenceRead(id, false, 1)
		if err != nil {
			return err
		}
		if !found {
			return artifact.ErrErasureBindingMismatch
		}
		parents = append(parents, p)
	}
	op := r.options.Operation
	current := r.options.Namespace.Prefix() + "/artifacts/" + op.Scope().Identity() + "/" + op.ArtifactIdentity()
	key, err := artifact.NewExactObjectKey(op.NamespaceIdentity(), current)
	if err != nil {
		return err
	}
	var expected artifact.ErasureEvidence
	switch e.Kind() {
	case "unknown":
		a := r.attempts[e.AttemptIdentity()]
		expected, err = artifact.NewAttemptUnknownEvidence(a, e.ObservedAt())
	case "response":
		return nil
	case "fence":
		parent := parents[0]
		a, found, loadErr := r.attempt(parent.AttemptIdentity(), false, 1)
		if loadErr != nil {
			return loadErr
		}
		if !found || a.Request().Kind() != artifact.AttemptCurrentRead || a.Request().Key() != current {
			return artifact.ErrErasureBindingMismatch
		}
		expected, err = artifact.NewFenceObservationEvidence(op, key, parent, e.ObservedAt())
	case "verification":
		selected, found, loadErr := r.evidenceRead("fence", true, 1)
		if loadErr != nil {
			return loadErr
		}
		if !found || selected.Identity() != parents[0].Identity() {
			return artifact.ErrErasureBindingMismatch
		}
		list, found, loadErr := r.attempt(parents[1].AttemptIdentity(), false, 1)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return artifact.ErrErasureBindingMismatch
		}
		read, found, loadErr := r.attempt(parents[2].AttemptIdentity(), false, 1)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return artifact.ErrErasureBindingMismatch
		}
		lr, rr := list.Request(), read.Request()
		if lr.Kind() != artifact.AttemptVersionList || lr.Key() != current || lr.PageLimit() != 2 || lr.KeyMarker() != "" || lr.VersionIDMarker() != "" || rr.Kind() != artifact.AttemptCurrentRead || rr.Key() != current || list.Identity() == read.Identity() || list.ReservedAt().Before(selected.ObservedAt()) || read.ReservedAt().Before(parents[1].ObservedAt()) {
			return artifact.ErrErasureBindingMismatch
		}
		if !r.j.policy.AllowsAt(e.ObservedAt()) || !r.j.policy.AllowsAt(captured) {
			return artifact.ErrErasureAllowanceExpired
		}
		for _, a := range []artifact.ErasureAttempt{list, read} {
			s := r.allowances[a.Request().AllowanceIdentity()]
			p, parseErr := parsePersistedErasurePolicy(s.AcceptedPolicyBytes)
			if parseErr != nil || !s.Allowance.AllowsOperation(op, e.ObservedAt()) || !p.allows(e.ObservedAt()) {
				return artifact.ErrErasureBindingMismatch
			}
			if !s.Allowance.AllowsOperation(op, captured) || !p.allows(captured) {
				return artifact.ErrErasureAllowanceExpired
			}
		}
		verification, buildErr := artifact.NewErasureVerification(op, selected, []artifact.ErasureEvidence{parents[1]}, parents[2], e.ObservedAt())
		if buildErr != nil {
			return buildErr
		}
		expected, err = artifact.NewVerificationEvidence(verification)
	case "candidate":
		verification, parseErr := artifact.ParseErasureVerification(parents[0].RecordBytes(), r.ref)
		if parseErr != nil {
			return parseErr
		}
		if !r.j.policy.AllowsAt(captured) {
			return artifact.ErrErasureAllowanceExpired
		}
		expected, err = artifact.NewAttestationCandidateEvidence(op, r.options.Admission, r.j.policy, verification)
		readEvidence, found, loadErr := r.evidenceRead(verification.CurrentResponseIdentity(), false, 2)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return artifact.ErrErasureBindingMismatch
		}
		read, found, loadErr := r.attempt(readEvidence.AttemptIdentity(), false, 2)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return artifact.ErrErasureBindingMismatch
		}
		snapshot := r.allowances[read.Request().AllowanceIdentity()]
		if !bytes.Equal(snapshot.AcceptedPolicyBytes, r.j.policy.Bytes()) || !snapshot.Allowance.AllowsOperation(op, captured) {
			return artifact.ErrErasureAllowanceExpired
		}
	case "published":
		selected, found, loadErr := r.evidenceRead("candidate", true, 1)
		if loadErr != nil {
			return loadErr
		}
		if !found || selected.Identity() != parents[0].Identity() {
			return artifact.ErrErasureBindingMismatch
		}
		read, found, loadErr := r.attempt(parents[1].AttemptIdentity(), false, 1)
		if loadErr != nil {
			return loadErr
		}
		if !found {
			return artifact.ErrErasureBindingMismatch
		}
		proof := r.options.Namespace.Prefix() + "/deletions/" + op.Scope().Identity() + "/" + op.ArtifactIdentity() + ".attestation-v2"
		if read.Request().Kind() != artifact.AttemptAttestationRead || read.Request().Key() != proof || read.ReservedAt().Before(selected.ObservedAt()) {
			return artifact.ErrErasureBindingMismatch
		}
		snapshot := r.allowances[read.Request().AllowanceIdentity()]
		policy, parseErr := parsePersistedErasurePolicy(snapshot.AcceptedPolicyBytes)
		if parseErr != nil || !snapshot.Allowance.AllowsOperation(op, parents[1].ObservedAt()) || !policy.allows(parents[1].ObservedAt()) ||
			!snapshot.Allowance.AllowsOperation(op, e.ObservedAt()) || !policy.allows(e.ObservedAt()) {
			return artifact.ErrErasureBindingMismatch
		}
		expected, err = artifact.NewAttestationPublicationEvidence(selected, parents[1], e.ObservedAt())
	default:
		return artifact.ErrInvalidErasureContract
	}
	if err != nil {
		return err
	}
	if !resumeSameEvidence(expected, e) {
		return artifact.ErrErasureBindingMismatch
	}
	return nil
}
func (j *artifactResumeJournal) RecordErasureEvidence(ctx context.Context, ref artifact.ErasureOperationRef, e artifact.ErasureEvidence) (artifact.ErasureEvidence, bool, error) {
	if err := j.validateResume(ctx, ref); err != nil {
		return artifact.ErasureEvidence{}, false, err
	}
	if err := e.Validate(); err != nil {
		return artifact.ErasureEvidence{}, false, err
	}
	if e.Ref() != ref {
		return artifact.ErasureEvidence{}, false, artifact.ErrErasureBindingMismatch
	}
	captured := j.clock.Now()
	var result artifact.ErasureEvidence
	inserted := false
	var reason error
	outcome, err := j.index.store.retryErasureMutation(ctx, ref.Scope().TenantID(), func(tx *sql.Tx) error {
		result = artifact.ErasureEvidence{}
		inserted = false
		reason = nil
		before := newResumeResolver(j, ctx, tx, ref)
		found, err := before.original()
		if err != nil {
			return err
		}
		if !found {
			return artifact.ErrErasureAdmissionMissing
		}
		op := before.options.Operation
		if err := lockScopeTransaction(ctx, tx, "artifact:"+ref.Scope().Identity()+":"+op.ArtifactIdentity()); err != nil {
			return err
		}
		r := newResumeResolver(j, ctx, tx, ref)
		r.points = before.points
		found, err = r.original()
		if err != nil {
			return err
		}
		if !found || r.options.Operation.Identity() != op.Identity() || r.options.Operation.ArtifactIdentity() != op.ArtifactIdentity() {
			return ErrCorruptRecord
		}
		if err := r.globals(); err != nil {
			return err
		}
		if e.AttemptIdentity() != "" {
			for _, kind := range []string{"response", "unknown"} {
				if _, _, err := r.evidenceRead(kind+":"+e.AttemptIdentity(), true, 0); err != nil {
					return err
				}
			}
		}
		winner, present, err := r.evidenceRead(e.Slot(), true, 0)
		if err != nil {
			return err
		}
		if present && resumeSameEvidence(winner, e) {
			if _, err := r.progress(); err != nil {
				return err
			}
			result = winner
			return nil
		}
		raw, err := artifact.EncodeErasureEvidence(e)
		if err != nil {
			return err
		}
		if err := r.charge("evidence", e.Identity(), raw); err != nil {
			return err
		}
		if err := r.incoming(e, captured); err != nil {
			if err == artifact.ErrErasureAllowanceExpired {
				reason = err
				return artifact.ErrErasureConflict
			}
			return err
		}
		if err := r.evidenceDepth(e, 0); err != nil {
			return err
		}
		if _, err := r.progress(); err != nil {
			return err
		}
		if present {
			adopt := resumeSameEvidence(winner, e)
			switch e.Kind() {
			case "unknown":
				adopt = winner.AttemptIdentity() == e.AttemptIdentity()
			case "fence":
				adopt = bytes.Equal(winner.RecordBytes(), e.RecordBytes())
			case "candidate":
				adopt = true
			case "published":
				// Both proof bodies were validated against the selected candidate.
				previous, proposed := winner.ParentIdentities(), e.ParentIdentities()
				adopt = len(previous) == 2 && len(proposed) == 2 && previous[0] == proposed[0]
			}
			if !adopt {
				return artifact.ErrErasureConflict
			}
			result = winner
			return nil
		}
		if e.Kind() == "response" {
			a, found, err := r.attempt(e.AttemptIdentity(), false, 0)
			if err != nil {
				return err
			}
			if !found {
				return artifact.ErrErasureBindingMismatch
			}
			response, err := artifact.ParseAttemptResponseEvidence(e, a)
			if err != nil {
				return err
			}
			if response.Code == artifact.AttemptResponseUnavailable || response.Code == artifact.AttemptResponseMalformed {
				_, exists, err := r.evidenceRead("unknown:"+a.Identity(), true, 0)
				if err != nil {
					return err
				}
				if !exists {
					if len(r.evidence) >= 384 {
						return ErrCorruptRecord
					}
					unknown, err := artifact.NewAttemptUnknownEvidence(a, e.ObservedAt())
					if err != nil {
						return err
					}
					unknownRaw, err := artifact.EncodeErasureEvidence(unknown)
					if err != nil {
						return err
					}
					if err := r.charge("evidence", unknown.Identity(), unknownRaw); err != nil {
						return err
					}
					args, err := resumeEvidenceCells(op, unknown)
					if err != nil {
						return err
					}
					if err := execErasureOne(ctx, tx, resumeSQLEvidenceInsert, args...); err != nil {
						return err
					}
				}
			}
		}
		args, err := resumeEvidenceCells(op, e)
		if err != nil {
			return err
		}
		if err := execErasureOne(ctx, tx, resumeSQLEvidenceInsert, args...); err != nil {
			return err
		}
		result = e
		inserted = true
		return nil
	})
	err = resumeKnownError(outcome, err, reason)
	if outcome != erasureKnownCommit || err != nil {
		return artifact.ErasureEvidence{}, false, err
	}
	return result, inserted, nil
}
