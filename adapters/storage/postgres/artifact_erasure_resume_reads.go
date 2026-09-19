package postgres

import (
	"context"
	"database/sql"
	"sort"

	"github.com/georgejieh/open-trestle/artifact"
)

// subset retains every dependency reachable from the selected page roots.
// The complete lookahead shares the same snapshot and lookup budget.
func (r *resumeResolver) subset(roots []artifact.ErasureAttempt) *resumeResolver {
	s := *r
	s.attempts = map[string]artifact.ErasureAttempt{}
	s.evidence = map[string]artifact.ErasureEvidence{}
	s.allowances = map[string]artifact.ErasureAllowanceSnapshot{}
	s.slots = map[string]string{}
	s.reservations = map[string]string{}
	var attempt func(string)
	var evidence func(string)
	attempt = func(id string) {
		if _, ok := s.attempts[id]; ok {
			return
		}
		a, ok := r.attempts[id]
		if !ok {
			return
		}
		s.attempts[id] = a
		s.reservations[a.Request().ReservationIdentity()] = id
		if value, ok := r.allowances[a.Request().AllowanceIdentity()]; ok {
			s.allowances[a.Request().AllowanceIdentity()] = value
		}
		if observation := a.Request().ObservationIdentity(); observation != "" {
			evidence(observation)
		}
		for _, e := range r.evidence {
			if e.AttemptIdentity() == id {
				evidence(e.Identity())
			}
		}
	}
	evidence = func(id string) {
		if _, ok := s.evidence[id]; ok {
			return
		}
		e, ok := r.evidence[id]
		if !ok {
			return
		}
		s.evidence[id] = e
		s.slots[e.Slot()] = id
		if e.AttemptIdentity() != "" {
			attempt(e.AttemptIdentity())
		}
		for _, parent := range e.ParentIdentities() {
			evidence(parent)
		}
	}
	for _, slot := range []string{"fence", "candidate", "published"} {
		if id, ok := r.slots[slot]; ok {
			evidence(id)
		}
	}
	for _, a := range roots {
		attempt(a.Identity())
	}
	if id := r.options.RequestedAllowanceIdentity; id != "" {
		if value, ok := r.allowances[id]; ok {
			s.allowances[id] = value
		}
	}
	return &s
}
func (j *artifactResumeJournal) ReadErasureAttempt(ctx context.Context, ref artifact.ErasureOperationRef, reservation string) (artifact.ErasureAttempt, []artifact.ErasureEvidence, bool, error) {
	if err := j.validateResume(ctx, ref); err != nil {
		return artifact.ErasureAttempt{}, nil, false, err
	}
	if !validDigest(reservation) {
		return artifact.ErasureAttempt{}, nil, false, artifact.ErrInvalidErasureContract
	}
	var result artifact.ErasureAttempt
	var evidence []artifact.ErasureEvidence
	found := false
	err := j.readSnapshot(ctx, ref.Scope(), func(tx *sql.Tx) error {
		r := newResumeResolver(j, ctx, tx, ref)
		present, err := r.original()
		if err != nil || !present {
			return err
		}
		a, present, err := r.attempt(reservation, true, 0)
		if err != nil || !present {
			return err
		}
		if err := r.globals(); err != nil {
			return err
		}
		if _, err := r.progress(); err != nil {
			return err
		}
		result = a
		found = true
		for _, e := range r.evidence {
			if e.AttemptIdentity() == a.Identity() {
				evidence = append(evidence, e)
			}
		}
		sort.Slice(evidence, func(i, j int) bool { return evidence[i].Slot() < evidence[j].Slot() })
		return nil
	})
	if err != nil {
		return artifact.ErasureAttempt{}, nil, false, err
	}
	return result, evidence, found, nil
}
func (j *artifactResumeJournal) ReadAllowanceAttempts(ctx context.Context, ref artifact.ErasureOperationRef, allowance string, after uint64, limit uint16) (artifact.AttemptPage, error) {
	if err := j.validateResume(ctx, ref); err != nil {
		return artifact.AttemptPage{}, err
	}
	if !validDigest(allowance) || after > 4096 || limit < 1 || limit > 64 {
		return artifact.AttemptPage{}, artifact.ErrInvalidErasureContract
	}
	var result artifact.AttemptPage
	err := j.readSnapshot(ctx, ref.Scope(), func(tx *sql.Tx) error {
		r := newResumeResolver(j, ctx, tx, ref)
		present, err := r.original()
		if err != nil {
			return err
		}
		if !present {
			return artifact.ErrErasureConflict
		}
		_, present, err = r.allowance(allowance, false)
		if err != nil {
			return err
		}
		if !present {
			return artifact.ErrErasureConflict
		}
		r.options.RequestedAllowanceIdentity = allowance
		if err := r.globals(); err != nil {
			return err
		}
		args := append(resumeArgs(ref, allowance), int64(after), int64(limit)+1)
		rows, err := r.rows(resumeSQLAttemptPage, 27, int(limit)+1, true, args...)
		if err != nil {
			return err
		}
		attempts := make([]artifact.ErasureAttempt, 0, len(rows))
		last := after
		for _, row := range rows {
			a, err := resumeDecodeAttempt(row, r.options.Operation)
			if err != nil {
				return err
			}
			if a.Request().AllowanceIdentity() != allowance || a.Sequence() <= last {
				return ErrCorruptRecord
			}
			last = a.Sequence()
			if err := r.includeAttempt(a, false, 0); err != nil {
				return err
			}
			attempts = append(attempts, a)
		}
		more := len(attempts) > int(limit)
		if more {
			lookahead := r.subset(attempts[int(limit):])
			if _, err := lookahead.progress(); err != nil {
				return err
			}
			attempts = attempts[:limit]
		}
		retained := r.subset(attempts)
		if _, err := retained.progress(); err != nil {
			return err
		}
		result = artifact.AttemptPage{Attempts: append([]artifact.ErasureAttempt(nil), attempts...), After: after, More: more}
		if len(attempts) > 0 {
			result.After = attempts[len(attempts)-1].Sequence()
		}
		return nil
	})
	if err != nil {
		return artifact.AttemptPage{}, err
	}
	return result, nil
}
func (j *artifactResumeJournal) ReadErasureProgress(ctx context.Context, ref artifact.ErasureOperationRef, allowance string) (artifact.ErasureProgress, bool, error) {
	if err := j.validateResume(ctx, ref); err != nil {
		return artifact.ErasureProgress{}, false, err
	}
	if allowance != "" && !validDigest(allowance) {
		return artifact.ErasureProgress{}, false, artifact.ErrInvalidErasureContract
	}
	var result artifact.ErasureProgress
	found := false
	err := j.readSnapshot(ctx, ref.Scope(), func(tx *sql.Tx) error {
		r := newResumeResolver(j, ctx, tx, ref)
		present, err := r.original()
		if err != nil || !present {
			return err
		}
		r.options.RequestedAllowanceIdentity = allowance
		if allowance != "" {
			_, present, err := r.allowance(allowance, false)
			if err != nil {
				return err
			}
			if !present {
				return artifact.ErrErasureConflict
			}
		}
		if err := r.globals(); err != nil {
			return err
		}
		rows, err := r.rows(resumeSQLUnrecordedUncertaintyPage, 27, 65, true, append(erasureReadArgs(ref.Scope(), ref.NamespaceIdentity(), ref.OperationIdentity()), "", int64(65))...)
		if err != nil {
			return err
		}
		roots := make([]artifact.ErasureAttempt, 0, len(rows))
		last := ""
		for _, row := range rows {
			a, err := resumeDecodeAttempt(row, r.options.Operation)
			if err != nil {
				return err
			}
			if a.Identity() <= last {
				return ErrCorruptRecord
			}
			last = a.Identity()
			if err := r.includeAttempt(a, true, 0); err != nil {
				return err
			}
			roots = append(roots, a)
		}
		more := len(roots) == 65
		if more {
			lookahead := r.subset(roots[64:])
			lookahead.options.UnrecordedUncertainty = roots[64:]
			if _, err := lookahead.progress(); err != nil {
				return err
			}
			roots = roots[:64]
		}
		retained := r.subset(roots)
		retained.options.UnrecordedUncertainty = roots
		retained.options.UncertaintyBookkeepingMore = more
		result, err = retained.progress()
		if err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		return artifact.ErasureProgress{}, false, err
	}
	return result, found, nil
}
