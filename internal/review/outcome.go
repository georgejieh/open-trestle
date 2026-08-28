package review

import (
	"errors"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// Outcome identifies the truth state of a local review.
type Outcome string

const (
	// OutcomeVerified means the adapter produced evidence for its finding.
	OutcomeVerified Outcome = "verified"
	// OutcomeBlocked means policy rejected an otherwise understood request.
	OutcomeBlocked Outcome = "blocked"
	// OutcomeFailed means the review input or operation was invalid.
	OutcomeFailed Outcome = "failed"
	// OutcomeInconclusive means the adapter could not produce a finding.
	OutcomeInconclusive Outcome = "inconclusive"
)

// OutcomeError carries a non-success review outcome.
type OutcomeError struct {
	outcome Outcome
	cause   error
}

func newOutcomeError(outcome Outcome, cause error) *OutcomeError {
	return &OutcomeError{outcome: outcome, cause: cause}
}

// Error returns the underlying failure message.
func (e *OutcomeError) Error() string {
	return e.cause.Error()
}

// Unwrap returns the underlying error.
func (e *OutcomeError) Unwrap() error {
	return e.cause
}

// Outcome returns the review truth state.
func (e *OutcomeError) Outcome() Outcome {
	return e.outcome
}

// ErrorOutcome returns an error's declared outcome or failed by default.
func ErrorOutcome(err error) Outcome {
	var outcomeError *OutcomeError
	if errors.As(err, &outcomeError) {
		return outcomeError.Outcome()
	}
	return OutcomeFailed
}

// LocalResult is the immutable output of a local review.
type LocalResult struct {
	fixtureIdentity string
	outcome         Outcome
	reason          string
	finding         Finding
	evidence        evidence.EvidenceItem
}

// FixtureIdentity returns the reviewed fixture identity.
func (r LocalResult) FixtureIdentity() string {
	return r.fixtureIdentity
}

// Outcome returns the review truth state.
func (r LocalResult) Outcome() Outcome {
	return r.outcome
}

// Reason returns the explanation for an inconclusive result.
func (r LocalResult) Reason() string {
	return r.reason
}

// Finding returns the verified finding.
func (r LocalResult) Finding() Finding {
	return r.finding
}

// Evidence returns the finding's immutable evidence.
func (r LocalResult) Evidence() evidence.EvidenceItem {
	return r.evidence
}
