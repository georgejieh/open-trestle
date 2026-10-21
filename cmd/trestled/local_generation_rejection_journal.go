package main

import (
	"errors"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

var errGenerationRejectionJournal = errors.New("generation rejection journal proof refused")

// validateGenerationRejectionJournal proves only the supplied replay and closed
// candidate-failure suffix. It does not prove physical bytes or current enrollment.
func validateGenerationRejectionJournal(fact controlplane.HistoricalContextPacketFact, events []controlplane.RunEvent, auditEvents []audit.Event, now time.Time) error {
	fail := func() error { return errGenerationRejectionJournal }
	plan := fact.Plan()
	if !recordedV4PlanShape(plan) || len(auditEvents) != 5 || len(events) == 0 || now.UnixMilli() <= 0 {
		return fail()
	}
	linked, ok := fact.LinkedInputEvent()
	if !ok {
		return fail()
	}
	settled, ok := fact.TaskSettlementEvent()
	if !ok || settled.Kind() != controlplane.RunEventContextInputSettled || settled.PreviousIdentity() != linked.Identity() || settled.OutputIdentity() != linked.InputDescriptor().Input.ArtifactIdentity {
		return fail()
	}
	terminal, ok := fact.TerminalEvent()
	if !ok || terminal.Kind() != controlplane.RunEventFailed || terminal.Failure() != controlplane.RunFailureInternal || terminal.Identity() != fact.FinalHeadIdentity() || terminal.Identity() != events[len(events)-1].Identity() || fact.FinalRunStatus() != controlplane.ReviewRunFailed {
		return fail()
	}
	state, err := controlplane.ReplayReviewRun(plan, events)
	if err != nil || state.Status() != controlplane.ReviewRunFailed || state.Failure() != controlplane.RunFailureInternal || state.Revision() != fact.FinalRevision() || state.HeadIdentity() != fact.FinalHeadIdentity() {
		return fail()
	}
	var boundary int
	for i, event := range events {
		if event.OccurredAt().After(now) {
			return fail()
		}
		if event.Identity() == settled.Identity() {
			boundary = i + 1
		}
	}
	if boundary == 0 || boundary >= len(events) {
		return fail()
	}
	before, err := controlplane.ReplayReviewRun(plan, events[:boundary])
	if err != nil || before.Status() != controlplane.ReviewRunActive {
		return fail()
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context"} {
		task, ok := before.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeSucceeded || task.OutputIdentity() == "" {
			return fail()
		}
	}
	for _, key := range []string{"candidates", "verification", "readiness"} {
		task, ok := before.Task(key)
		if !ok || task.Attempts() != 0 || task.OutputIdentity() != "" || task.Status() != controlplane.TaskRuntimePending {
			return fail()
		}
	}
	tail := events[boundary:]
	if len(tail) < 6 || tail[0].Kind() != controlplane.RunEventTaskAvailable || tail[0].TaskKey() != "candidates" || tail[1].Kind() != controlplane.RunEventTaskLeased || tail[1].TaskKey() != "candidates" || tail[1].Attempt() != 1 {
		return fail()
	}
	claim := tail[1]
	index := 2
	for index < len(tail) && tail[index].Kind() == controlplane.RunEventTaskLeaseRenewed {
		renewal := tail[index]
		if renewal.TaskKey() != "candidates" || renewal.Attempt() != claim.Attempt() || renewal.LeaseTokenIdentity() != claim.LeaseTokenIdentity() || renewal.WorkerIdentity() != claim.WorkerIdentity() {
			return fail()
		}
		index++
	}
	if len(tail)-index != 4 {
		return fail()
	}
	failed := tail[index]
	if failed.Kind() != controlplane.RunEventTaskFailed || failed.TaskKey() != "candidates" || failed.Failure() != controlplane.RunFailureInternal || failed.OutputIdentity() != "" || failed.Attempt() != 1 || failed.LeaseTokenIdentity() != claim.LeaseTokenIdentity() || !failed.RetryAt().IsZero() {
		return fail()
	}
	for i, key := range []string{"verification", "readiness"} {
		event := tail[index+1+i]
		if event.Kind() != controlplane.RunEventTaskSkipped || event.TaskKey() != key || event.Failure() != controlplane.RunFailureDependency || event.Attempt() != 0 || event.OutputIdentity() != "" {
			return fail()
		}
		task, ok := state.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeSkipped || task.Attempts() != 0 || task.OutputIdentity() != "" || task.Failure() != controlplane.RunFailureDependency {
			return fail()
		}
	}
	if tail[index+3].Identity() != terminal.Identity() {
		return fail()
	}
	candidate, ok := state.Task("candidates")
	if !ok || candidate.Status() != controlplane.TaskRuntimeFailed || candidate.Attempts() != 1 || candidate.Failure() != controlplane.RunFailureInternal || candidate.OutputIdentity() != "" || candidate.LastEventIdentity() != failed.Identity() {
		return fail()
	}
	if auditEvents[0].OccurredAtUnixMilliseconds() > linked.OccurredAt().UnixMilli() || auditEvents[1].OccurredAtUnixMilliseconds() < claim.OccurredAt().UnixMilli() {
		return fail()
	}
	previous := int64(0)
	for i, event := range auditEvents {
		if event.Validate() != nil || event.Scope() != plan.Scope() || event.Sequence() != uint64(i+1) || event.OccurredAtUnixMilliseconds() < previous || event.OccurredAtUnixMilliseconds() > failed.OccurredAt().UnixMilli() {
			return fail()
		}
		previous = event.OccurredAtUnixMilliseconds()
	}
	if auditEvents[4].Kind() != audit.EventGenerationRejected {
		return fail()
	}
	return nil
}
