package artifact

import (
	"context"
	"errors"
	"time"
)

var (
	ErrErasureAllowanceExhausted = errors.New("erasure allowance exhausted")
	ErrErasureAllowanceExpired   = errors.New("erasure allowance expired")
)

// AllowanceUsage reports durable spending, not dispatch permission.
type AllowanceUsage struct {
	AllowanceIdentity string
	Spent             ResumeBudget
	NextSequence      uint64
}

// AttemptPage contains reservation metadata in increasing sequence order.
type AttemptPage struct {
	Attempts []ErasureAttempt
	After    uint64
	More     bool
}

// ResumeJournal extends admission with durable budgets and evidence history.
type ResumeJournal interface {
	AdmissionPreparationJournal
	AdmitResumeAllowance(context.Context, ErasureOperationRef, ResumeAllowance, time.Time) (AllowanceUsage, error)
	ReserveErasureAttempt(context.Context, ErasureOperationRef, ResumeAllowance, AttemptRequest, time.Time) (ErasureAttempt, bool, error)
	ReadErasureAttempt(context.Context, ErasureOperationRef, string) (ErasureAttempt, []ErasureEvidence, bool, error)
	ReadAllowanceAttempts(context.Context, ErasureOperationRef, string, uint64, uint16) (AttemptPage, error)
	ReadErasureProgress(context.Context, ErasureOperationRef, string) (ErasureProgress, bool, error)
	RecordErasureEvidence(context.Context, ErasureOperationRef, ErasureEvidence) (ErasureEvidence, bool, error)
}
