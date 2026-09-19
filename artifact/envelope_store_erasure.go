package artifact

import (
	"context"
	"fmt"
	"time"
)

// EnvelopeErasureOptions requires the owned erasure interface and a DB-only journal.
type EnvelopeErasureOptions struct {
	Backend ErasureObjectBackend
	Keys    EnvelopeKeyProvider
	Journal ResumeJournal
	Policy  ProtectedErasurePolicy
	Clock   ErasureClock
}

type envelopeErasureMode struct {
	backend   ErasureObjectBackend
	journal   ResumeJournal
	policy    ProtectedErasurePolicy
	namespace StorageNamespace
	clock     ErasureClock
}

func (envelopeErasureMode) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("artifact erasure mode{redacted}"))
}

// NewEnvelopeStoreWithErasure installs both immutable modes before publication.
// Construction performs local checks only, with no clock or external I/O.
func NewEnvelopeStoreWithErasure(o EnvelopeErasureOptions) (*EnvelopeStore, error) {
	s, err := NewEnvelopeStoreWithAdmissionPreparation(EnvelopeAdmissionPreparationOptions{
		Backend: o.Backend, Keys: o.Keys, Journal: o.Journal, Policy: o.Policy, Clock: o.Clock,
	})
	if err != nil {
		return nil, err
	}
	if o.Backend.ValidateErasure() != nil {
		return nil, ErrErasureBackendUnsupported
	}
	s.resume = &envelopeErasureMode{backend: o.Backend, journal: o.Journal,
		policy: o.Policy, namespace: s.admission.namespace, clock: o.Clock}
	return s, nil
}

func (s *EnvelopeStore) erasureMode(ctx context.Context, ref ErasureOperationRef) (*envelopeErasureMode, error) {
	if s == nil || s.resume == nil {
		return nil, ErrErasureJournalRequired
	}
	if err := validateContext(ctx); err != nil {
		return nil, err
	}
	if err := ref.Validate(); err != nil {
		return nil, err
	}
	m := s.resume
	if nilErasureDependency(m.journal) || nilErasureDependency(m.clock) {
		return nil, ErrErasureJournalRequired
	}
	if m.policy.Validate() != nil {
		return nil, ErrErasureAuthorityRequired
	}
	if m.namespace.Validate() != nil || m.namespace.Identity() != ref.NamespaceIdentity() ||
		m.policy.NamespaceIdentity() != ref.NamespaceIdentity() || m.policy.DatabaseAuthorityIdentity() != m.journal.DatabaseAuthorityIdentity() {
		return nil, ErrErasureBindingMismatch
	}
	return m, nil
}

// ReadErasure reads historical evidence. It never samples time or dispatches work.
func (s *EnvelopeStore) ReadErasure(ctx context.Context, ref ErasureOperationRef) (ErasureResult, bool, error) {
	m, err := s.erasureMode(ctx, ref)
	if err != nil {
		return ErasureResult{}, false, err
	}
	p, found, err := m.journal.ReadErasureProgress(ctx, ref, "")
	if err != nil {
		return ErasureResult{}, false, resumePublicError(err)
	}
	if !found {
		return ErasureResult{}, false, nil
	}
	if p.Operation().Ref() != ref {
		return ErasureResult{}, false, ErrErasureBindingMismatch
	}
	r, err := resultFromProgress(p)
	if err != nil {
		return ErasureResult{}, false, err
	}
	return r, true, nil
}

type resumeInvocation struct {
	mode                  *envelopeErasureMode
	ctx                   context.Context
	ref                   ErasureOperationRef
	allowance             ResumeAllowance
	progress              ErasureProgress
	operation             ErasureOperation
	start, last, deadline time.Time
	spent                 ResumeBudget
	usage                 AllowanceUsage
	admitted              bool
	fenceCreates          uint32
	fence                 ErasureEvidence
	pinned                ObjectVersion
	candidate             ErasureEvidence
}

func (*resumeInvocation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("artifact erasure invocation{redacted}"))
}

// ResumeErasure executes one bounded convergence attempt. Recovery always uses
// new reservations; historical records cannot restore a spent dispatch permit.
func (s *EnvelopeStore) ResumeErasure(ctx context.Context, ref ErasureOperationRef, allowance ResumeAllowance) (ErasureResult, error) {
	m, err := s.erasureMode(ctx, ref)
	if err != nil {
		return ErasureResult{}, err
	}
	if err := allowance.Validate(); err != nil {
		return ErasureResult{}, err
	}
	if err := allowance.ValidateProtected(m.policy); err != nil {
		return ErasureResult{}, err
	}
	if allowance.Scope() != ref.Scope() || allowance.NamespaceIdentity() != ref.NamespaceIdentity() || allowance.OperationIdentity() != ref.OperationIdentity() {
		return ErasureResult{}, ErrErasureBindingMismatch
	}
	if nilErasureDependency(m.backend) || m.backend.ValidateErasure() != nil || m.backend.ConfigurationIdentity() != m.namespace.BackendConfigurationIdentity() {
		return ErasureResult{}, ErrErasureBackendUnsupported
	}
	i := &resumeInvocation{mode: m, ctx: ctx, ref: ref, allowance: allowance}
	now, err := i.sample(false)
	if err != nil {
		return ErasureResult{}, err
	}
	i.start = now
	i.deadline = now.Add(90 * time.Second)
	for _, end := range []time.Time{allowance.NotAfter(), m.policy.NotAfter()} {
		if end.Before(i.deadline) {
			i.deadline = end
		}
	}
	if end, ok := ctx.Deadline(); ok && end.Before(i.deadline) {
		i.deadline = end
	}
	p, found, err := m.journal.ReadErasureProgress(ctx, ref, "")
	if err != nil {
		return ErasureResult{}, resumePublicError(err)
	}
	if !found {
		return ErasureResult{}, ErrErasureAdmissionMissing
	}
	if err := validateResumeOriginal(m, ref, allowance, p); err != nil {
		return ErasureResult{}, err
	}
	i.progress, i.operation = p, p.Operation()
	if now.Before(i.operation.PreparedAt()) || now.Before(p.data.options.OperationAcceptedAt) {
		return ErasureResult{}, ErrInvalidErasureContract
	}
	now, err = i.sample(true)
	if err != nil {
		return ErasureResult{}, err
	}
	usage, err := m.journal.AdmitResumeAllowance(ctx, ref, allowance, now)
	if err != nil {
		return ErasureResult{}, resumePublicError(err)
	}
	if !validResumeUsage(usage, allowance) {
		return ErasureResult{}, ErrErasureBindingMismatch
	}
	i.usage, i.admitted = usage, true
	// Bookkeeping has priority over any provider observation or result adoption.
	for _, attempt := range p.UnrecordedUncertainty() {
		at, err := i.sample(false)
		if err != nil {
			return ErasureResult{}, err
		}
		unknown, err := NewAttemptUnknownEvidence(attempt, at)
		if err != nil {
			return ErasureResult{}, err
		}
		if _, err := i.record(unknown); err != nil {
			return ErasureResult{}, err
		}
	}
	if p.UncertaintyBookkeepingMore() {
		return ErasureResult{}, ErrErasureUnknownOutcome
	}
	if err := i.reload(); err != nil {
		return ErasureResult{}, err
	}
	if _, published := i.progress.Published(); published {
		if _, err := i.sample(true); err != nil {
			return i.failure(err)
		}
		return resultFromProgress(i.progress)
	}
	if err := i.complete(); err != nil {
		return i.failure(err)
	}
	if err := i.reload(); err != nil {
		return ErasureResult{}, err
	}
	if _, err := i.sample(true); err != nil {
		return i.failure(err)
	}
	result, err := resultFromProgress(i.progress)
	if err != nil {
		return ErasureResult{}, err
	}
	if result.State() != ErasureStateCertified {
		return ErasureResult{}, ErrErasureUnknownOutcome
	}
	return result, nil
}

func (i *resumeInvocation) reload() error {
	p, found, err := i.mode.journal.ReadErasureProgress(i.ctx, i.ref, i.allowance.Identity())
	if err != nil {
		return resumePublicError(err)
	}
	if !found {
		return ErrErasureConflict
	}
	if err := validateResumeOriginal(i.mode, i.ref, i.allowance, p); err != nil {
		return err
	}
	usages := p.AllowanceUsages()
	if len(usages) != 1 || !validResumeUsage(usages[0], i.allowance) {
		return ErrErasureBindingMismatch
	}
	i.progress, i.usage = p, usages[0]
	i.fence, _ = p.Fence()
	i.candidate, _ = p.Candidate()
	if i.fence.Identity() != "" {
		pinned, err := ParseObjectVersion(i.fence.RecordBytes())
		if err != nil {
			return err
		}
		i.pinned = pinned
	}
	return nil
}
