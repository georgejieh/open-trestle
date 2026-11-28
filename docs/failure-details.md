# Failure details

A review that did not succeed prints a `failure:` line and a `hint:` line. This
page explains what each `failure_detail` value means and what Open Trestle
suggests.

The JSON result carries the same facts as `failure` and `failure_detail`, and a
review set repeats them for each member. `failure` is one of seven classes
(`policy`, `resource_limit`, `transient`, `invalid_input`, `canceled`,
`dependency`, `internal`). When Open Trestle could observe why the review failed,
`failure_detail` adds one of the values below.

```text
status: refused
ci: blocked
run: failed
failure: policy (task candidates): provider_payment_required
hint: the provider refused the request for billing: add credit or a subscription to the provider account, or choose another route
```

A detail never carries a provider's message, a model's answer or any source,
and the field is absent when no value applies. For the process exit status, see
[exit codes](exit-codes.md). For the full output, see
[local model review](local-model-review.md#results-and-limits).

| `failure_detail` | Run failure, exit | What it means | Hint printed |
| --- | --- | --- | --- |
| `provider_payment_required` | `policy`, `4` | The provider answered HTTP 402: no credit or quota. | the provider refused the request for billing: add credit or a subscription to the provider account, or choose another route |
| `provider_authentication_failed` | `policy`, `4` | HTTP 401: the provider did not accept the key. | the provider did not accept the credential: check the API key the route names (for ollama-signin, run `ollama signin`), then retry |
| `provider_authorization_denied` | `policy`, `4` | HTTP 403: the account may not use the model or endpoint. | the provider refused this account access to the model or endpoint: check the account's access, or choose another route |
| `provider_model_unavailable` | `policy`, `4` | HTTP 404: the provider does not serve this model at this endpoint. | the provider does not serve this model at this endpoint: check the model name and endpoint, choose a model the provider lists as available, and re-run setup |
| `provider_no_allowed_endpoint` | `policy`, `4` | OpenRouter answered 404: it has no endpoint for the model that the request may use. With zero data retention required, a model without a zero-data-retention endpoint is refused this way. | OpenRouter has no endpoint for this model that the request may use: if zero data retention is required (by this setup or by your OpenRouter account or key settings), choose a model with zero-data-retention endpoints and run trestle init again (https://openrouter.ai/docs/guides/features/zdr); otherwise check the model ID |
| `provider_model_retired` | `policy`, `4` | HTTP 410: the model is retired. | the provider no longer serves this model: choose a model the provider lists as available and re-run setup |
| `provider_request_rejected` | `policy`, `4` | HTTP 400, 405, 415 or 422: the provider rejected the request itself, for example an unknown model ID or a parameter the endpoint does not accept. | the provider rejected the request as invalid, for example an unknown model ID or a parameter the model or endpoint does not accept: check the model ID, the endpoint and its transport, and that the model and endpoint accept structured output and the requested output allowance; then re-run setup |
| `provider_rate_limited` | `transient`, `1` | HTTP 429, or 503 with a `Retry-After` in seconds, on the last of up to two retries. | the provider rate-limited the request on its last attempt: wait and run the review again, or choose another route |
| `provider_response_invalid` | `internal`, `1` | The provider answered, but the reply was malformed, truncated, empty, oversized, had an unrecognized field, or came with an unclassified HTTP status. | the provider answered, but its reply did not match what Open Trestle accepts, for example malformed or truncated output, an unrecognized field or an unexpected HTTP status: run the review again; if it repeats, choose another model or route and report it |
| `model_output_invalid` | `internal`, `1` | The reply ended normally, but the model's answer was not a valid review document, also on the one retry that `trestle review` sends for any class but `refusal`. The JSON result adds `model_output_problem` with the class of the last answer (see below). | the model's answer was not a valid review document (CLASS: WORDS): run the review again; if it repeats, choose another model |
| `model_output_exhausted` | `internal`, `1` | The model used its whole output allowance, usually on reasoning, before finishing. This applies to the last answer that `trestle review` received, after its one retry. | the model used its whole output allowance, usually on reasoning, before finishing its answer; choose a non-reasoning model for this role, or set up again with a larger output allowance (trestle init --directory NEW_FOLDER --max-output-tokens N) |
| `route_context_insufficient` | `policy`, `4` | No configured route declares a context large enough for the request. The JSON result adds `context_shortfall` with the counts. | the review needs up to N tokens (a byte-based upper bound: I input plus O output) but the route declares max_context_tokens D; raise max_context_tokens on the route and the model server's context length to at least N (docs/named-local-runtimes.md#context-length) |
| `spending_limit_reached` | `policy`, `4` | The recorded spend for a key the review uses is at or over its limit, so nothing was sent. The run status is `not_opened`. | the spend recorded for an API key this review uses has reached its spending limit for the current period, so the review was not started and nothing was sent: run trestle usage to see it, then raise or clear the limit (trestle usage set, trestle usage clear) or wait for the next period; the figures are Open Trestle's upper-bound estimate at the highest pinned price, not a bill, and the limit is best effort, so your provider's own limit is the guarantee |

`model_output_problem` names what was wrong with the answer but never quotes
it.

| `model_output_problem` | Words in the hint |
| --- | --- |
| `not_json` | the answer was not one JSON document |
| `refusal` | the model refused to answer |
| `wrong_shape` | the JSON did not have the required fields and structure |
| `invalid_value` | a field had a value the output rules do not allow |
| `unknown_candidate` | a verdict named a candidate label that is not in the request |
| `candidate_set_mismatch` | the verdicts did not answer every candidate exactly once |
| `unknown_evidence` | it cited a source ID that is not in the request |
| `evidence_mismatch` | the cited evidence does not cover the reported lines |

`trestle review` and `trestle local-git model-review` record the class, while
a daemon run records only `model_output_invalid`.

`trestle review` sends a request once more after an answer that ends as
`model_output_invalid` (any class but `refusal`) or `model_output_exhausted`,
once for the finder and once for the checker. A review that then completes
carries `model_answer_retried` in `limitations` and prints
`answer retried: a model answer was not usable, so its request was sent once more`.
Both requests count toward its tokens and cost. A daemon run sends no such
retry.

A class with no detail still has a one-line hint:

| Run failure | Hint |
| --- | --- |
| `policy` | a runtime policy, authorization or budget rule refused the work |
| `resource_limit` | a configured size, token, time or cost limit was reached |
| `transient` | the model route failed temporarily (network, rate limit or provider error); a later retry may succeed |
| `invalid_input` | a recorded input did not match its expected shape or identity |
| `canceled` | the run was canceled or its time limit expired |
| `dependency` | a task this one depends on did not complete |
| `internal` | a model response could not be accepted (for example malformed or truncated output) or an internal check failed |

For the context task, the `policy` hint adds that usually no changed source
could be supplied to the model, and the `resource_limit` hint adds that usually
the changed source did not fit the context packet budget.

[Troubleshooting](troubleshooting.md) has common fixes for each value. The HTTP
status mapping and retry rules are in
[provider refusals](local-model-review.md#provider-refusals).
