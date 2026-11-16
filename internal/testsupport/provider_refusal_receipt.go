package testsupport

import (
	"context"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// ProviderRefusalReceipt returns the receipt of a one-attempt run whose
// candidates task failed because the provider refused it with reason, after
// its source, change and context tasks succeeded, so a surface test can render
// a recorded provider refusal.
func ProviderRefusalReceipt(scope audit.ReviewScope, reason controlplane.TaskFailureReason) (controlplane.ReviewRunReceipt, error) {
	ctx := context.Background()
	chain := []controlplane.TaskDefinition{}
	for index, step := range []struct {
		key  string
		kind controlplane.TaskKind
	}{{"source", controlplane.TaskAcquireSource}, {"change", controlplane.TaskBuildChange}, {"context", controlplane.TaskAssembleContext}, {"candidates", controlplane.TaskGenerateCandidates}} {
		var dependencies []string
		if index > 0 {
			dependencies = []string{chain[index-1].Key()}
		}
		definition, err := controlplane.NewTaskDefinition(step.key, step.kind, strings.Repeat("a", 64), strings.Repeat("d", 64), dependencies, 1, 0, 30_000, true)
		if err != nil {
			return controlplane.ReviewRunReceipt{}, err
		}
		chain = append(chain, definition)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), strings.Repeat("c", 64), controlplane.ReviewRunAdvisory, chain)
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	coordinator, err := controlplane.NewCoordinator(controlplane.NewMemoryRunJournal())
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	at := time.UnixMilli(100)
	if _, err := coordinator.Open(ctx, plan, at); err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	for _, task := range chain {
		at = at.Add(time.Millisecond)
		if _, err := coordinator.Advance(ctx, plan, at); err != nil {
			return controlplane.ReviewRunReceipt{}, err
		}
		lease, _, err := coordinator.ClaimTask(ctx, plan, task.Key(), task.HandlerIdentity(), "worker", at)
		if err != nil {
			return controlplane.ReviewRunReceipt{}, err
		}
		completion, err := controlplane.NewTaskSuccess(strings.Repeat("e", 64))
		if task.Kind() == controlplane.TaskGenerateCandidates {
			failure := controlplane.RunFailurePolicy
			switch reason {
			case controlplane.TaskFailureReasonProviderRateLimited:
				failure = controlplane.RunFailureTransient
			case controlplane.TaskFailureReasonProviderResponseInvalid, controlplane.TaskFailureReasonModelOutputInvalid:
				failure = controlplane.RunFailureInternal
			}
			completion, err = controlplane.NewModelTaskFailureWithReason(failure, reason, plan, task)
		}
		if err != nil {
			return controlplane.ReviewRunReceipt{}, err
		}
		if _, err := coordinator.CompleteTask(ctx, plan, lease, completion, at); err != nil {
			return controlplane.ReviewRunReceipt{}, err
		}
	}
	state, err := coordinator.Advance(ctx, plan, at.Add(time.Millisecond))
	if err != nil {
		return controlplane.ReviewRunReceipt{}, err
	}
	return controlplane.NewReviewRunReceipt(state)
}
