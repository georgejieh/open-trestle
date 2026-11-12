package controlplane

import "errors"

// ErrInvalidTaskFailureReason identifies an unknown or misplaced failure reason.
var ErrInvalidTaskFailureReason = errors.New("invalid task failure reason")

// TaskFailureReason is a closed, content-free refinement of one failed task
// attempt. It names why a task refused and never carries forge, provider, or
// repository text. Source acquisition, context assembly and the two model
// tasks record reasons.
type TaskFailureReason uint8

const (
	// TaskFailureReasonNoMergeBase records that the requested base and the
	// head share no history, so there is no merge base to review from.
	TaskFailureReasonNoMergeBase TaskFailureReason = iota + 1
	// TaskFailureReasonNothingToReview records that the head equals the
	// requested base or is already contained in it.
	TaskFailureReasonNothingToReview
	// TaskFailureReasonMergeBaseUnavailable records that the forge did not
	// report a usable merge base.
	TaskFailureReasonMergeBaseUnavailable
	// TaskFailureReasonRouteContextInsufficient records that a context task's
	// model request reservation, a byte-based upper bound on its input tokens
	// plus the output allowance, exceeds every candidate route's declared
	// context. It always carries a TaskFailureContextShortfall.
	TaskFailureReasonRouteContextInsufficient
	// TaskFailureReasonNoEligibleRoute records that no candidate route was
	// eligible for a context task's model request for another reason.
	TaskFailureReasonNoEligibleRoute
	// The provider refusal reasons record that the provider answered a model
	// task's request with a refusal, named from the HTTP status alone: billing
	// or quota (402), a model or endpoint it does not serve (404), a retired
	// model (410), a credential it did not accept (401), an account it refused
	// access (403) and a rate limit (429). The first five are policy failures
	// and the rate limit a transient one.
	TaskFailureReasonProviderPaymentRequired
	TaskFailureReasonProviderModelUnavailable
	TaskFailureReasonProviderModelRetired
	TaskFailureReasonProviderAuthenticationFailed
	TaskFailureReasonProviderAuthorizationDenied
	TaskFailureReasonProviderRateLimited
	// TaskFailureReasonProviderResponseInvalid records that the provider
	// answered a model task's request but the adapter refused the reply:
	// malformed, truncated, empty or oversized, with an unrecognized field, or
	// with an HTTP status it does not classify. It is an internal failure and
	// names neither the reply nor any of its fields.
	TaskFailureReasonProviderResponseInvalid
	// TaskFailureReasonModelOutputInvalid records that the provider's reply
	// was accepted and stopped normally, but the model's answer in it was not
	// a valid review document: malformed JSON, the wrong shape, a refusal, or
	// a document the review rules refuse. It is an internal failure and names
	// neither the answer nor any of its fields.
	TaskFailureReasonModelOutputInvalid
)

// TaskFailureContextShortfall carries the counts of a
// route_context_insufficient refusal: the reservation, its input and output
// parts, and the largest declared context among the routes too small. It is
// content-free; the zero value is absent.
type TaskFailureContextShortfall struct {
	RequiredTokens        uint64
	EstimatedInputTokens  uint32
	MaxOutputTokens       uint32
	DeclaredContextTokens uint32
}

// Present reports whether the shortfall carries counts.
func (s TaskFailureContextShortfall) Present() bool { return s != TaskFailureContextShortfall{} }

func (s TaskFailureContextShortfall) valid() bool {
	return s.EstimatedInputTokens != 0 && s.MaxOutputTokens != 0 && s.RequiredTokens == uint64(s.EstimatedInputTokens)+uint64(s.MaxOutputTokens) && s.DeclaredContextTokens != 0 && uint64(s.DeclaredContextTokens) < s.RequiredTokens
}

// taskFailureShortfallRecord is the wire form of a TaskFailureContextShortfall.
type taskFailureShortfallRecord struct {
	RequiredTokens        uint64 `json:"required_tokens"`
	EstimatedInputTokens  uint32 `json:"estimated_input_tokens"`
	MaxOutputTokens       uint32 `json:"max_output_tokens"`
	DeclaredContextTokens uint32 `json:"declared_context_tokens"`
}

func taskFailureShortfallToRecord(s TaskFailureContextShortfall) *taskFailureShortfallRecord {
	if !s.Present() {
		return nil
	}
	return &taskFailureShortfallRecord{s.RequiredTokens, s.EstimatedInputTokens, s.MaxOutputTokens, s.DeclaredContextTokens}
}

func taskFailureShortfallFromRecord(r *taskFailureShortfallRecord) TaskFailureContextShortfall {
	if r == nil {
		return TaskFailureContextShortfall{}
	}
	return TaskFailureContextShortfall{r.RequiredTokens, r.EstimatedInputTokens, r.MaxOutputTokens, r.DeclaredContextTokens}
}

func (r TaskFailureReason) String() string {
	switch r {
	case TaskFailureReasonNoMergeBase:
		return "no_merge_base"
	case TaskFailureReasonNothingToReview:
		return "nothing_to_review"
	case TaskFailureReasonMergeBaseUnavailable:
		return "merge_base_unavailable"
	case TaskFailureReasonRouteContextInsufficient:
		return "route_context_insufficient"
	case TaskFailureReasonNoEligibleRoute:
		return "no_eligible_route"
	case TaskFailureReasonProviderPaymentRequired:
		return "provider_payment_required"
	case TaskFailureReasonProviderModelUnavailable:
		return "provider_model_unavailable"
	case TaskFailureReasonProviderModelRetired:
		return "provider_model_retired"
	case TaskFailureReasonProviderAuthenticationFailed:
		return "provider_authentication_failed"
	case TaskFailureReasonProviderAuthorizationDenied:
		return "provider_authorization_denied"
	case TaskFailureReasonProviderRateLimited:
		return "provider_rate_limited"
	case TaskFailureReasonProviderResponseInvalid:
		return "provider_response_invalid"
	case TaskFailureReasonModelOutputInvalid:
		return "model_output_invalid"
	default:
		return ""
	}
}

func (r TaskFailureReason) Validate() error {
	if r.String() == "" {
		return ErrInvalidTaskFailureReason
	}
	return nil
}

// ParseTaskFailureReason accepts one exact reason token; the empty token is no reason.
func ParseTaskFailureReason(value string) (TaskFailureReason, error) {
	if value == "" {
		return 0, nil
	}
	for reason := TaskFailureReasonNoMergeBase; reason <= TaskFailureReasonModelOutputInvalid; reason++ {
		if reason.String() == value {
			return reason, nil
		}
	}
	return 0, ErrInvalidTaskFailureReason
}

// contextRefusalReason reports a route refusal reason of a context task.
func contextRefusalReason(reason TaskFailureReason) bool {
	return reason == TaskFailureReasonRouteContextInsufficient || reason == TaskFailureReasonNoEligibleRoute
}

// taskFailureReasonAllowed reports whether a task of kind may record reason
// with shortfall: source reasons on source acquisition, route refusals on
// context assembly, and counts exactly for route_context_insufficient.
func taskFailureReasonAllowed(kind TaskKind, reason TaskFailureReason, shortfall TaskFailureContextShortfall) bool {
	switch reason {
	case TaskFailureReasonNoMergeBase, TaskFailureReasonNothingToReview, TaskFailureReasonMergeBaseUnavailable:
		return kind == TaskAcquireSource && !shortfall.Present()
	case TaskFailureReasonRouteContextInsufficient:
		return kind == TaskAssembleContext && shortfall.valid()
	case TaskFailureReasonNoEligibleRoute:
		return kind == TaskAssembleContext && !shortfall.Present()
	}
	if _, provider := providerRefusalFailure(reason); provider {
		return (kind == TaskGenerateCandidates || kind == TaskVerifyCandidates) && !shortfall.Present()
	}
	return false
}

// providerRefusalFailure returns the one run failure a model task reason (a
// provider refusal, a refused reply or an invalid model answer) is recorded
// with, and whether reason is one.
func providerRefusalFailure(reason TaskFailureReason) (RunFailure, bool) {
	switch reason {
	case TaskFailureReasonProviderPaymentRequired, TaskFailureReasonProviderModelUnavailable, TaskFailureReasonProviderModelRetired,
		TaskFailureReasonProviderAuthenticationFailed, TaskFailureReasonProviderAuthorizationDenied:
		return RunFailurePolicy, true
	case TaskFailureReasonProviderRateLimited:
		return RunFailureTransient, true
	case TaskFailureReasonProviderResponseInvalid, TaskFailureReasonModelOutputInvalid:
		return RunFailureInternal, true
	}
	return 0, false
}

// taskFailureReasonFailureAllowed reports whether failure may carry reason:
// a provider refusal names exactly one run failure, and the other reasons
// keep the failure their constructor chose.
func taskFailureReasonFailureAllowed(reason TaskFailureReason, failure RunFailure) bool {
	if expected, provider := providerRefusalFailure(reason); provider {
		return failure == expected
	}
	return true
}

// NewModelTaskFailureWithReason binds a failed candidate generation or
// verification attempt and the provider refusal, refused reply or invalid
// model answer that ended it to one plan and task. The failure must be the one the reason names.
func NewModelTaskFailureWithReason(failure RunFailure, reason TaskFailureReason, plan ReviewRunPlan, task TaskDefinition) (TaskCompletion, error) {
	expected, provider := providerRefusalFailure(reason)
	if !provider || failure != expected || plan.Validate() != nil || task.Validate() != nil || !taskFailureReasonAllowed(task.Kind(), reason, TaskFailureContextShortfall{}) {
		return TaskCompletion{}, ErrInvalidTaskCompletion
	}
	canonical, exists := plan.Task(task.Key())
	if !exists || canonical.Identity() != task.Identity() {
		return TaskCompletion{}, ErrInvalidTaskCompletion
	}
	completion := TaskCompletion{status: TaskCompletionFailed, failure: failure, reason: reason, planIdentity: plan.Identity(), taskIdentity: task.Identity()}
	completion.identity = deriveTaskCompletionIdentity(completion)
	return completion, nil
}

// NewSourceTaskFailureWithReason binds a failed source acquisition and its
// content-free reason to one plan and task.
func NewSourceTaskFailureWithReason(failure RunFailure, reason TaskFailureReason, plan ReviewRunPlan, task TaskDefinition) (TaskCompletion, error) {
	if failure.String() == "" || reason.Validate() != nil || plan.Validate() != nil || task.Validate() != nil || task.Kind() != TaskAcquireSource || !taskFailureReasonAllowed(task.Kind(), reason, TaskFailureContextShortfall{}) {
		return TaskCompletion{}, ErrInvalidTaskCompletion
	}
	canonical, exists := plan.Task(task.Key())
	if !exists || canonical.Identity() != task.Identity() {
		return TaskCompletion{}, ErrInvalidTaskCompletion
	}
	completion := TaskCompletion{status: TaskCompletionFailed, failure: failure, reason: reason, planIdentity: plan.Identity(), taskIdentity: task.Identity()}
	completion.identity = deriveTaskCompletionIdentity(completion)
	return completion, nil
}

// NewContextTaskRefusal binds a context task's policy refusal before any model
// effect, with its content-free route reason and, for
// route_context_insufficient, its counts, to one plan and task.
func NewContextTaskRefusal(reason TaskFailureReason, shortfall TaskFailureContextShortfall, plan ReviewRunPlan, task TaskDefinition) (TaskCompletion, error) {
	if reason.Validate() != nil || plan.Validate() != nil || task.Validate() != nil || task.Kind() != TaskAssembleContext || !taskFailureReasonAllowed(task.Kind(), reason, shortfall) {
		return TaskCompletion{}, ErrInvalidTaskCompletion
	}
	canonical, exists := plan.Task(task.Key())
	if !exists || canonical.Identity() != task.Identity() {
		return TaskCompletion{}, ErrInvalidTaskCompletion
	}
	completion := TaskCompletion{status: TaskCompletionFailed, failure: RunFailurePolicy, reason: reason, shortfall: shortfall, planIdentity: plan.Identity(), taskIdentity: task.Identity()}
	completion.identity = deriveTaskCompletionIdentity(completion)
	return completion, nil
}
