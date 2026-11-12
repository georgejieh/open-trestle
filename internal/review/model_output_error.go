package review

import "errors"

// ErrModelOutputInvalid marks a candidate or verification parse failure that
// the model's answer itself caused: a reply that did not stop normally with
// exactly one JSON document, a document that is malformed or has the wrong
// shape, or one the review rules refuse (for example a location or evidence
// the request does not allow). A host input that fails its own check is never
// marked. The specific error stays reachable with errors.Is.
var ErrModelOutputInvalid = errors.New("model answer is not a valid review document")

type modelOutputError struct{ cause error }

func (e modelOutputError) Error() string   { return e.cause.Error() }
func (e modelOutputError) Unwrap() []error { return []error{e.cause, ErrModelOutputInvalid} }

// modelOutputFailure marks err as caused by the model's answer.
func modelOutputFailure(err error) error {
	if err == nil {
		return nil
	}
	return modelOutputError{cause: err}
}
