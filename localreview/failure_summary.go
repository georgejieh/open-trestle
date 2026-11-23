package localreview

import "github.com/georgejieh/open-trestle/internal/routehint"

// FailureDetailModelOutputExhausted records that a model route finished with
// a length stop and no complete answer: the model spent its whole output
// allowance, typically on reasoning, before it finished the requested
// document.
const FailureDetailModelOutputExhausted = "model_output_exhausted"

// Provider refusal details record that the last model request a provider
// answered was refused, from the HTTP status class alone: billing (402),
// credential (401), account access (403), model or endpoint not served (404),
// model retired (410), rate limit (429), or the request itself rejected as
// invalid (400, 405, 415 or 422, for example an unknown model ID or a
// parameter the model or endpoint does not accept). They never carry
// provider text.
const (
	FailureDetailProviderPaymentRequired      = "provider_payment_required"
	FailureDetailProviderModelUnavailable     = "provider_model_unavailable"
	FailureDetailProviderModelRetired         = "provider_model_retired"
	FailureDetailProviderAuthenticationFailed = "provider_authentication_failed"
	FailureDetailProviderAuthorizationDenied  = "provider_authorization_denied"
	FailureDetailProviderRateLimited          = "provider_rate_limited"
	FailureDetailProviderRequestRejected      = "provider_request_rejected"
)

// FailureDetailProviderResponseInvalid records that the provider answered the
// last model request but the adapter refused its reply: malformed, truncated,
// empty or oversized, with an unrecognized field, or with an HTTP status it
// does not classify. The run failure stays internal; the detail tells the
// operator that the provider's reply, not an internal check, ended the run.
// It never carries the reply or names any of its fields.
const FailureDetailProviderResponseInvalid = "provider_response_invalid"

// FailureDetailModelOutputInvalid records that the provider's reply was
// accepted and stopped normally, but the model's answer was not a valid review
// document: malformed JSON (for example wrapped in chat-template tokens or
// with a raw control character in a string), the wrong shape, a refusal, or
// a document the review rules refuse. The run failure stays internal; the
// detail tells the operator that the model's answer, not an internal check,
// ended the run. It never carries the answer or names any of its fields; the
// result's model_output_problem names the answer's class (for example
// unknown_candidate), and the hint explains it.
const FailureDetailModelOutputInvalid = routehint.ModelOutputInvalid

// FailureDetailProviderNoAllowedEndpoint records that OpenRouter answered the
// last request with HTTP 404: it serves no endpoint for the model that the
// request may use. With zero data retention required, by Open Trestle on
// every request or by the OpenRouter account or key, a model without a
// zero-data-retention endpoint is refused this way.
const FailureDetailProviderNoAllowedEndpoint = "provider_no_allowed_endpoint"

// FailureDetailSpendingLimitReached records that a review was refused before
// it started, before any credential was read for model dispatch, because the
// local usage ledger records spend at or over a spending limit of an API key
// the review's routes use. The ledger is an upper-bound estimate, not a bill,
// and the limit is best effort; the provider's own limit is the guarantee.
const FailureDetailSpendingLimitReached = "spending_limit_reached"

// LimitationOpenRouterZDRNotRequired marks a result whose policy has an
// OpenRouter route that does not require zero data retention. It claims
// neither that a provider retains prompts nor that it does not.
const LimitationOpenRouterZDRNotRequired = "openrouter_zero_data_retention_not_required"

// ZeroDataRetentionNotRequiredText is the text line, shown by default, of a
// result that carries LimitationOpenRouterZDRNotRequired: a privacy fact a
// person needs even when the limitations list is left out.
const ZeroDataRetentionNotRequiredText = "zero data retention: not required on an OpenRouter route this review used (no claim either way about what the provider keeps)\n"

// failureHints are plain-language explanations of each run failure class.
// They describe what the class usually means; they are not diagnoses.
var failureHints = map[string]string{
	"policy":         "a runtime policy, authorization or budget rule refused the work",
	"resource_limit": "a configured size, token, time or cost limit was reached",
	"transient":      "the model route failed temporarily (network, rate limit or provider error); a later retry may succeed",
	"invalid_input":  "a recorded input did not match its expected shape or identity",
	"canceled":       "the run was canceled or its time limit expired",
	"dependency":     "a task this one depends on did not complete",
	"internal":       "a model response could not be accepted (for example malformed or truncated output) or an internal check failed",
}

// taskFailureHints refine a class hint for a specific failing task.
var taskFailureHints = map[[2]string]string{
	{"policy", "context"}:         "usually no changed source could be supplied to the model (every source was omitted, unsupported, or not authorized); see the context task's source omissions",
	{"resource_limit", "context"}: "usually the changed source did not fit the context packet budget",
}

var failureDetailHints = map[string]string{
	FailureDetailModelOutputExhausted:      "the model used its whole output allowance, usually on reasoning, before finishing its answer; choose a non-reasoning model for this role or raise the review output allowance (setup bootstrap init --max-output-tokens)",
	FailureDetailProviderNoAllowedEndpoint: "OpenRouter has no endpoint for this model that the request may use: if zero data retention is required (by this setup or by your OpenRouter account or key settings), choose a model with zero-data-retention endpoints and run trestle init again (https://openrouter.ai/docs/guides/features/zdr); otherwise check the model ID",
	FailureDetailSpendingLimitReached:      "the spend recorded for an API key this review uses has reached its spending limit for the current period, so the review was not started and nothing was sent: run trestle usage to see it, then raise or clear the limit (trestle usage set, trestle usage clear) or wait for the next period; the figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill, and the limit is best effort, so your provider's own limit is the guarantee",
}

// failureTask returns the key of the first task, in plan order, that failed.
func (r Result) failureTask() string {
	for _, task := range r.wire.Tasks {
		if task.Status == "failed" {
			return task.Key
		}
	}
	return ""
}

// failureSummary returns the failure class, failing task and one-line hint of
// a run that did not succeed. It is empty for a run without a recorded failure.
func (r Result) failureSummary() (class, task, detail, hint string) {
	if r.wire.RunStatus == "succeeded" || r.wire.Failure == "" {
		return "", "", "", ""
	}
	class, task, detail = r.wire.Failure, r.failureTask(), r.wire.FailureDetail
	hint = failureHints[class]
	if value, ok := taskFailureHints[[2]string{class, task}]; ok {
		hint = value
	}
	if value, ok := failureDetailHints[detail]; ok {
		hint = value
	}
	if value := routehint.ProviderRefusalHint(detail); value != "" {
		hint = value
	}
	if detail == FailureDetailRouteContextInsufficient && r.wire.ContextShortfall != nil {
		hint = contextShortfallHint(*r.wire.ContextShortfall)
	}
	if detail == FailureDetailModelOutputInvalid {
		hint = routehint.ModelOutputInvalidHint(r.wire.ModelOutputProblem)
	}
	return class, task, detail, hint
}

// FailureLine renders "class (task key)" with the detail when one was
// observed, for example "internal (task verification): model_output_exhausted".
func FailureLine(class, task, detail string) string {
	line := class
	if task != "" {
		line += " (task " + task + ")"
	}
	if detail != "" {
		line += ": " + detail
	}
	return line
}
