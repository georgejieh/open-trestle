package review

import (
	"errors"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// ErrModelOutputInvalid marks a candidate or verification parse failure that
// the model's answer itself caused: a reply that did not stop normally with
// exactly one JSON document, a document that is malformed or has the wrong
// shape, or one the review rules refuse (for example a location or evidence
// the request does not allow). A host input that fails its own check is never
// marked. The specific error stays reachable with errors.Is.
var ErrModelOutputInvalid = errors.New("model answer is not a valid review document")

// ModelOutputProblem is the closed, content-free class of an answer marked
// ErrModelOutputInvalid. It never carries the answer's text.
type ModelOutputProblem string

const (
	ModelOutputNotJSON              ModelOutputProblem = "not_json"
	ModelOutputRefusal              ModelOutputProblem = "refusal"
	ModelOutputWrongShape           ModelOutputProblem = "wrong_shape"
	ModelOutputInvalidValue         ModelOutputProblem = "invalid_value"
	ModelOutputUnknownCandidate     ModelOutputProblem = "unknown_candidate"
	ModelOutputCandidateSetMismatch ModelOutputProblem = "candidate_set_mismatch"
	ModelOutputUnknownEvidence      ModelOutputProblem = "unknown_evidence"
	ModelOutputEvidenceMismatch     ModelOutputProblem = "evidence_mismatch"
)

// modelOutputProblems maps each document error the parsers mark to its class.
var modelOutputProblems = map[error]ModelOutputProblem{
	ErrInvalidCandidateDocumentJSON:      ModelOutputWrongShape,
	ErrDuplicateCandidateDocumentKey:     ModelOutputWrongShape,
	ErrInvalidCandidateDocumentShape:     ModelOutputWrongShape,
	ErrInvalidCandidateSchemaVersion:     ModelOutputWrongShape,
	ErrInvalidVerificationDocumentJSON:   ModelOutputWrongShape,
	ErrDuplicateVerificationDocumentKey:  ModelOutputWrongShape,
	ErrInvalidVerificationDocumentShape:  ModelOutputWrongShape,
	ErrInvalidVerificationSchemaVersion:  ModelOutputWrongShape,
	ErrTooManyCandidateFindings:          ModelOutputInvalidValue,
	ErrInvalidCandidateText:              ModelOutputInvalidValue,
	ErrInvalidCandidateSeverity:          ModelOutputInvalidValue,
	ErrInvalidCandidateCategory:          ModelOutputInvalidValue,
	ErrInvalidCandidateFix:               ModelOutputInvalidValue,
	ErrDuplicateCandidateFinding:         ModelOutputInvalidValue,
	ErrInvalidVerificationOutcome:        ModelOutputInvalidValue,
	ErrInvalidVerificationSeverity:       ModelOutputInvalidValue,
	ErrInvalidVerificationRationale:      ModelOutputInvalidValue,
	ErrVerificationCandidateNotAllowed:   ModelOutputUnknownCandidate,
	ErrDuplicateVerificationCandidate:    ModelOutputCandidateSetMismatch,
	ErrVerificationCandidateSetMismatch:  ModelOutputCandidateSetMismatch,
	ErrInvalidCandidateEvidenceSet:       ModelOutputUnknownEvidence,
	ErrInvalidCandidateReference:         ModelOutputUnknownEvidence,
	ErrDuplicateCandidateEvidence:        ModelOutputUnknownEvidence,
	ErrCandidateEvidenceNotAllowed:       ModelOutputUnknownEvidence,
	ErrVerificationEvidenceNotAllowed:    ModelOutputUnknownEvidence,
	ErrCandidateRangeNotSupported:        ModelOutputEvidenceMismatch,
	ErrCandidateEvidenceRangeMismatch:    ModelOutputEvidenceMismatch,
	ErrVerificationEvidenceRangeMismatch: ModelOutputEvidenceMismatch,
}

type modelOutputError struct {
	cause   error
	problem ModelOutputProblem
}

func (e modelOutputError) Error() string   { return e.cause.Error() }
func (e modelOutputError) Unwrap() []error { return []error{e.cause, ErrModelOutputInvalid} }

// modelOutputFailure marks err, an error of the answer's document, as caused
// by the model's answer. A document error without its own class is
// wrong_shape.
func modelOutputFailure(err error) error {
	if err == nil {
		return nil
	}
	problem := ModelOutputWrongShape
	for target, class := range modelOutputProblems {
		if errors.Is(err, target) {
			problem = class
			break
		}
	}
	return modelOutputError{cause: err, problem: problem}
}

// envelopeFailure marks envelope, the error of a reply that is not one JSON
// document, by what the reply holds instead: a refusal, or text.
func envelopeFailure(envelope error, parts []provider.ResponsePart) error {
	problem := ModelOutputNotJSON
	for _, part := range parts {
		if part.Kind() == provider.ResponsePartRefusal {
			problem = ModelOutputRefusal
		}
	}
	return modelOutputError{cause: envelope, problem: problem}
}

// ModelOutputProblemOf returns the class of an error marked
// ErrModelOutputInvalid, or false for any other error.
func ModelOutputProblemOf(err error) (ModelOutputProblem, bool) {
	var marked modelOutputError
	if !errors.As(err, &marked) {
		return "", false
	}
	return marked.problem, true
}
