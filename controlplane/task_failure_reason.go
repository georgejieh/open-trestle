package controlplane

import "errors"

// ErrInvalidTaskFailureReason identifies an unknown or misplaced failure reason.
var ErrInvalidTaskFailureReason = errors.New("invalid task failure reason")

// TaskFailureReason is a closed, content-free refinement of one failed task
// attempt. It names why a task refused and never carries forge, provider, or
// repository text. Only source acquisition records a reason.
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
	for reason := TaskFailureReasonNoMergeBase; reason <= TaskFailureReasonNoEligibleRoute; reason++ {
		if reason.String() == value {
			return reason, nil
		}
	}
	return 0, ErrInvalidTaskFailureReason
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
	return false
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
