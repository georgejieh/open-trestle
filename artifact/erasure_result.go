package artifact

import (
	"context"
	"fmt"
)

// ErasureState describes protocol evidence, not provider-media destruction.
// Prepared means no later progress is visible in the bounded historical closure;
// it does not assert that no allowance, spending, or resolved work ever existed.
type ErasureState uint8

const (
	ErasureStatePrepared  ErasureState = 1
	ErasureStatePending   ErasureState = 2
	ErasureStateUnknown   ErasureState = 3
	ErasureStateBlocked   ErasureState = 4
	ErasureStateCertified ErasureState = 5
)

// ErasureResult can be constructed only by the owner after journal validation.
// The zero value carries no operation, spending, or attestation.
type ErasureResult struct {
	state       ErasureState
	operation   ErasureOperation
	attestation ErasureAttestationV2
	unknown     bool
	usage       AllowanceUsage
	hasUsage    bool
}

func (r ErasureResult) State() ErasureState         { return r.state }
func (r ErasureResult) Operation() ErasureOperation { return r.operation }
func (r ErasureResult) Attestation() (ErasureAttestationV2, bool) {
	if r.state != ErasureStateCertified {
		return ErasureAttestationV2{}, false
	}
	return r.attestation, true
}
func (r ErasureResult) HasUnknownHistory() bool       { return r.unknown }
func (r ErasureResult) Usage() (AllowanceUsage, bool) { return r.usage, r.hasUsage }
func (ErasureResult) String() string                  { return "artifact erasure result" }
func (ErasureResult) GoString() string                { return "artifact.ErasureResult{<redacted>}" }
func (ErasureResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("artifact erasure result{redacted}"))
}

// BudgetedErasureStore adds explicit, prepaid erasure to admission/preparation.
type BudgetedErasureStore interface {
	AdmissionPreparationStore
	ResumeErasure(context.Context, ErasureOperationRef, ResumeAllowance) (ErasureResult, error)
	ReadErasure(context.Context, ErasureOperationRef) (ErasureResult, bool, error)
}

var _ BudgetedErasureStore = (*EnvelopeStore)(nil)
