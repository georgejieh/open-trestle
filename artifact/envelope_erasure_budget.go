package artifact

import (
	"errors"
	"time"
)

var resumeInvocationMaximum = ResumeBudget{
	Requests: 256, Mutations: 160, Reads: 128, Lists: 64, Creates: 16,
	Deletes: 128, Pages: 64, Versions: 4096, ResponseBytes: 64 << 20,
	ListBytes: 8 << 20, WriteBytes: 128 << 10,
}

func validResumeUsage(u AllowanceUsage, a ResumeAllowance) bool {
	return u.AllowanceIdentity == a.Identity() && validProgressSpending(u.Spent) &&
		progressBudgetWithin(u.Spent, a.Maximum()) && u.NextSequence == uint64(u.Spent.Requests)+1 && u.NextSequence <= 4097
}

// Samples are taken only on the live stack, never in a SQL retry callback.
func (i *resumeInvocation) sample(active bool) (time.Time, error) {
	if err := validateContext(i.ctx); err != nil {
		return time.Time{}, err
	}
	at := i.mode.clock.Now()
	if !validErasureAuthorizationV2Time(at) || !i.last.IsZero() && at.Before(i.last) ||
		i.operation.Identity() != "" && at.Before(i.operation.PreparedAt()) {
		return time.Time{}, ErrInvalidErasureContract
	}
	i.last = at
	if active {
		if !i.mode.policy.AllowsAt(at) || at.Before(i.allowance.NotBefore()) || !at.Before(i.allowance.NotAfter()) ||
			!i.deadline.IsZero() && !at.Before(i.deadline) {
			return time.Time{}, ErrErasureAllowanceExpired
		}
		if i.operation.Identity() != "" && !i.allowance.AllowsOperation(i.operation, at) {
			return time.Time{}, ErrErasureBindingMismatch
		}
	}
	return at, nil
}

// Both ceilings are checked before Reserve. The journal independently serializes
// durable totals against concurrent callers. Neither counter is refunded.
func (i *resumeInvocation) precharge(r AttemptRequest) error {
	cost := progressAttemptCost(r)
	next, ok := addProgressBudget(i.spent, cost)
	if !ok || !progressBudgetWithin(next, resumeInvocationMaximum) ||
		r.Kind() == AttemptFenceCreate && i.fenceCreates >= 8 {
		return ErrErasureAllowanceExhausted
	}
	durable, ok := addProgressBudget(i.usage.Spent, cost)
	if !ok || !progressBudgetWithin(durable, i.allowance.Maximum()) {
		return ErrErasureAllowanceExhausted
	}
	i.spent = next
	if r.Kind() == AttemptFenceCreate {
		i.fenceCreates++
	}
	return nil
}

func resumePublicError(err error) error {
	if err == nil {
		return nil
	}
	for _, fixed := range []error{
		ErrErasureUnknownOutcome, ErrErasureAllowanceExhausted, ErrErasureAllowanceExpired,
		ErrErasureBlocked, ErrErasureConflict, ErrErasureBindingMismatch,
		ErrErasureIdentityMismatch, ErrInvalidErasureContract, ErrErasureAuthorityRequired,
		ErrErasureJournalRequired, ErrErasureJournalUnavailable, ErrErasureAdmissionMissing,
		ErrErasureNamespaceUnsupported, ErrErasureBackendUnsupported,
		ErrErasureLegacyInventoryRequired, ErrInvalidStoreContext, ErrStoreContextDone,
	} {
		if errors.Is(err, fixed) {
			return fixed
		}
	}
	return ErrErasureJournalUnavailable
}

func (i *resumeInvocation) failure(cause error) (ErasureResult, error) {
	err := resumePublicError(cause)
	// Unknown commits and possibly transmitted requests release no values.
	if errors.Is(err, ErrErasureUnknownOutcome) || !i.admitted {
		return ErasureResult{}, err
	}
	state := ErasureState(0)
	switch err {
	case ErrErasureAllowanceExhausted, ErrErasureAllowanceExpired:
		state = ErasureStatePending
	case ErrErasureBlocked, ErrErasureConflict, ErrErasureLegacyInventoryRequired:
		state = ErasureStateBlocked
	default:
		return ErasureResult{}, err
	}
	// Read actual totals, including concurrent spending. A failed read overrides
	// a local refusal; cached spending cannot stand in for a known DB snapshot.
	if readErr := i.reload(); readErr != nil {
		return ErasureResult{}, readErr
	}
	r, readErr := resultFromProgress(i.progress)
	if readErr != nil {
		return ErasureResult{}, readErr
	}
	r.state, r.attestation = state, ErasureAttestationV2{}
	return r, err
}

// The first unknown current body can use the full 32 MiB transport ceiling.
// Later reads use the remaining prepaid capacity, leaving a bounded tail for
// fence verification/publication. A larger refused body is never deletion
// authority; the next explicit invocation again starts with a full-size option.
func (i *resumeInvocation) currentReadMaximum() (uint32, error) {
	local := resumeInvocationMaximum.ResponseBytes
	durable := i.allowance.Maximum().ResponseBytes
	if i.spent.ResponseBytes > local || i.usage.Spent.ResponseBytes > durable {
		return 0, ErrErasureAllowanceExhausted
	}
	remaining := local - i.spent.ResponseBytes
	if other := durable - i.usage.Spent.ResponseBytes; other < remaining {
		remaining = other
	}
	if remaining < 4097 {
		return 0, ErrErasureAllowanceExhausted
	}
	tail := remaining / 4
	if tail > 2<<20 {
		tail = 2 << 20
	}
	maximum := remaining - tail - 1
	if maximum < 4096 {
		maximum = remaining - 1
	}
	if maximum > uint64(resumeCurrentReadMaximum) {
		maximum = uint64(resumeCurrentReadMaximum)
	}
	return uint32(maximum), nil
}
