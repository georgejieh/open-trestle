package controlplane

// TaskAttemptPolicy fixes the shared default planner recipe. Model and publication
// claims are never replayed automatically; deterministic handlers may retry.
type TaskAttemptPolicy struct {
	attempts     uint8
	retry, lease uint32
}

func (p TaskAttemptPolicy) MaximumAttempts() uint8            { return p.attempts }
func (p TaskAttemptPolicy) RetryDelayMilliseconds() uint32    { return p.retry }
func (p TaskAttemptPolicy) LeaseDurationMilliseconds() uint32 { return p.lease }
func DefaultTaskAttemptPolicy(kind TaskKind) (TaskAttemptPolicy, error) {
	if err := kind.Validate(); err != nil {
		return TaskAttemptPolicy{}, err
	}
	attempts := uint8(3)
	switch kind {
	case TaskAssembleContext, TaskGenerateCandidates, TaskVerifyCandidates, TaskPublishResult:
		attempts = 1
	}
	return TaskAttemptPolicy{attempts, 1000, 30000}, nil
}
