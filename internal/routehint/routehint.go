// Package routehint holds the fixed host words that explain a recorded route
// refusal. Every surface that shows one uses this text, so the local review,
// the daemon's CLI results, and the web console stay identical.
package routehint

import (
	"fmt"

	"github.com/georgejieh/open-trestle/internal/gateway"
)

const (
	// RouteContextInsufficient explains the route_context_insufficient reason.
	RouteContextInsufficient = "the review request needs more context than the route declares"
	// NoEligibleRoute explains the no_eligible_route reason.
	NoEligibleRoute = "no configured route met the runtime policy for this request"
)

// ContextShortfall is the hint for a route_context_insufficient refusal: the
// byte-based reservation, its input and output parts, the route's declared
// context, and the context length to raise. The web console renders the same
// text from the same counts.
func ContextShortfall(required uint64, input, output, declared uint32) string {
	return fmt.Sprintf("the review needs up to %d tokens (a byte-based upper bound: %d input plus %d output) but the route declares max_context_tokens %d; raise max_context_tokens on the route and the model server's context length to at least %d (docs/named-local-runtimes.md#context-length)", required, input, output, declared, required)
}

// providerRefusal is the content-free detail and fixed words of one refusal a
// provider answered with, or of a provider reply the adapter refused: a
// console label, what the refusal means, and what the operator can do. None
// ever carries the provider's own message or names a field of its reply. The
// detail is also the model task's failure reason token.
type providerRefusal struct{ detail, label, text, action string }

func (r providerRefusal) hint() string { return r.text + ": " + r.action }

var providerRefusals = map[gateway.RouteFailureClass]providerRefusal{
	gateway.RouteFailurePaymentRequired:  {"provider_payment_required", "Provider payment required", "the provider refused the request for billing", "add credit or a subscription to the provider account, or choose another route"},
	gateway.RouteFailureModelUnavailable: {"provider_model_unavailable", "Provider model unavailable", "the provider does not serve this model at this endpoint", "check the model name and endpoint, choose a model the provider lists as available, and re-run setup"},
	gateway.RouteFailureModelRetired:     {"provider_model_retired", "Provider model retired", "the provider no longer serves this model", "choose a model the provider lists as available and re-run setup"},
	gateway.RouteFailureAuthentication:   {"provider_authentication_failed", "Provider authentication failed", "the provider did not accept the credential", "check the API key the route names (for ollama-signin, run `ollama signin`), then retry"},
	gateway.RouteFailureAuthorization:    {"provider_authorization_denied", "Provider authorization denied", "the provider refused this account access to the model or endpoint", "check the account's access, or choose another route"},
	gateway.RouteFailureRateLimited:      {"provider_rate_limited", "Provider rate limited", "the provider rate-limited the request on its last attempt", "wait and run the review again, or choose another route"},
	gateway.RouteFailureInvalidResponse:  {"provider_response_invalid", "Provider reply refused", "the provider answered, but its reply did not match what Open Trestle accepts, for example malformed or truncated output, an unrecognized field or an unexpected HTTP status", "run the review again; if it repeats, choose another model or route and report it"},
	gateway.RouteFailureRequestRejected:  {"provider_request_rejected", "Provider request rejected", "the provider rejected the request as invalid, for example an unknown model ID or a parameter the model or endpoint does not accept", "check the model ID, the endpoint and its transport, and that the model and endpoint accept structured output and the requested output allowance; then re-run setup"},
}

// ModelOutputInvalid is the failure detail, and the model task's failure
// reason token, of a reply that stopped normally but whose answer was not a
// valid review document.
const ModelOutputInvalid = "model_output_invalid"

// modelOutputInvalid has the fixed words of ModelOutputInvalid. They describe
// the answer's form only and never quote it.
var modelOutputInvalid = providerRefusal{ModelOutputInvalid, "Model answer not a review document", "the model's answer was not a valid review document (for example malformed JSON, the wrong shape or a refusal)", "run the review again; if it repeats, choose another model"}

// modelOutputProblems are the fixed words of each class of invalid answer
// (review.ModelOutputProblem). They describe the answer's form only.
var modelOutputProblems = map[string]string{
	"not_json":               "the answer was not one JSON document",
	"refusal":                "the model refused to answer",
	"wrong_shape":            "the JSON did not have the required fields and structure",
	"invalid_value":          "a field had a value the output rules do not allow",
	"unknown_candidate":      "a verdict named a candidate label that is not in the request",
	"candidate_set_mismatch": "the verdicts did not answer every candidate exactly once",
	"unknown_evidence":       "it cited a source ID that is not in the request",
	"evidence_mismatch":      "the cited evidence does not cover the reported lines",
}

// ModelOutputInvalidHint is the hint of ModelOutputInvalid, naming the class
// of invalid answer when problem is a known one.
func ModelOutputInvalidHint(problem string) string {
	words, ok := modelOutputProblems[problem]
	if !ok {
		return modelOutputInvalid.hint()
	}
	return "the model's answer was not a valid review document (" + problem + ": " + words + "): " + modelOutputInvalid.action
}

// ProviderRefusal returns the failure detail and one-line hint for a route
// attempt the provider refused, or whose reply the adapter refused
// (invalid_response), from its closed failure class alone. Any other class
// returns ok false. The caller decides that the provider answered: a
// credential that could not be read, or a request that could not be built, is
// not a provider refusal.
func ProviderRefusal(failure gateway.RouteFailureClass) (detail, hint string, ok bool) {
	refusal, ok := providerRefusals[failure]
	if !ok {
		return "", "", false
	}
	return refusal.detail, refusal.hint(), true
}

// ProviderRefusalHint returns the hint of a provider refusal detail, or "".
func ProviderRefusalHint(detail string) string {
	if _, text, action, ok := ProviderRefusalWords(detail); ok {
		return text + ": " + action
	}
	return ""
}

// ProviderRefusalWords returns the console label, the explanation and the
// operator action of a provider refusal detail, of ModelOutputInvalid, or of
// the task failure reason token of either. Its hint is the explanation, a
// colon and the action.
func ProviderRefusalWords(detail string) (label, text, action string, ok bool) {
	if detail == modelOutputInvalid.detail {
		return modelOutputInvalid.label, modelOutputInvalid.text, modelOutputInvalid.action, true
	}
	for _, refusal := range providerRefusals {
		if refusal.detail == detail {
			return refusal.label, refusal.text, refusal.action, true
		}
	}
	return "", "", "", false
}
