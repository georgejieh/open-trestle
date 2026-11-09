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
)

func (r TaskFailureReason) String() string {
	switch r {
	case TaskFailureReasonNoMergeBase:
		return "no_merge_base"
	case TaskFailureReasonNothingToReview:
		return "nothing_to_review"
	case TaskFailureReasonMergeBaseUnavailable:
		return "merge_base_unavailable"
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
	for reason := TaskFailureReasonNoMergeBase; reason <= TaskFailureReasonMergeBaseUnavailable; reason++ {
		if reason.String() == value {
			return reason, nil
		}
	}
	return 0, ErrInvalidTaskFailureReason
}

func taskFailureReasonAllowed(kind TaskKind) bool { return kind == TaskAcquireSource }

// NewSourceTaskFailureWithReason binds a failed source acquisition and its
// content-free reason to one plan and task.
func NewSourceTaskFailureWithReason(failure RunFailure, reason TaskFailureReason, plan ReviewRunPlan, task TaskDefinition) (TaskCompletion, error) {
	if failure.String() == "" || reason.Validate() != nil || plan.Validate() != nil || task.Validate() != nil || !taskFailureReasonAllowed(task.Kind()) {
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
