package main

import (
	"errors"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
)

var errTerminalModelExpiry = errors.New("terminal model lease expiry proof refused")

type terminalModelExpiry struct {
	task                             string
	claim, latestLease, failed       controlplane.RunEvent
	candidateClaim, candidateSuccess controlplane.RunEvent
}

// This recognizes exhausted leases, not handler completions with the same failure.
func validateTerminalModelExpiryJournal(fact controlplane.HistoricalContextPacketFact, now time.Time) (terminalModelExpiry, error) {
	fail := func() (terminalModelExpiry, error) { return terminalModelExpiry{}, errTerminalModelExpiry }
	plan, events := fact.Plan(), fact.ReplayEvents()
	if !recordedV4PlanShape(plan) || len(events) == 0 || now.UnixMilli() <= 0 {
		return fail()
	}
	linked, linkedOK := fact.LinkedInputEvent()
	settled, settledOK := fact.TaskSettlementEvent()
	terminal, terminalOK := fact.TerminalEvent()
	if !linkedOK || !settledOK || !terminalOK || settled.Kind() != controlplane.RunEventContextInputSettled || settled.PreviousIdentity() != linked.Identity() || settled.OutputIdentity() != linked.InputDescriptor().Input.ArtifactIdentity || terminal.Kind() != controlplane.RunEventFailed || terminal.Failure() != controlplane.RunFailureResourceLimit || terminal.Identity() != fact.FinalHeadIdentity() || terminal.Identity() != events[len(events)-1].Identity() {
		return fail()
	}
	state, err := controlplane.ReplayReviewRun(plan, events)
	if err != nil || state.Status() != controlplane.ReviewRunFailed || state.Failure() != terminal.Failure() || state.Revision() != fact.FinalRevision() || state.HeadIdentity() != fact.FinalHeadIdentity() || fact.FinalRunStatus() != state.Status() {
		return fail()
	}
	boundary := 0
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
		if !ok || task.Status() != controlplane.TaskRuntimePending || task.Attempts() != 0 || task.OutputIdentity() != "" {
			return fail()
		}
	}
	tail, index := events[boundary:], 0
	proof := terminalModelExpiry{}
	for _, key := range []string{"candidates", "verification"} {
		definition, _ := plan.Task(key)
		if definition.MaxAttempts() != 1 || index+2 >= len(tail) || tail[index].Kind() != controlplane.RunEventTaskAvailable || tail[index].TaskKey() != key {
			return fail()
		}
		index++
		claim := tail[index]
		if claim.Kind() != controlplane.RunEventTaskLeased || claim.TaskKey() != key || claim.Attempt() != 1 {
			return fail()
		}
		latest := claim
		index++
		for index < len(tail) && tail[index].Kind() == controlplane.RunEventTaskLeaseRenewed {
			renewal := tail[index]
			if renewal.TaskKey() != key || renewal.Attempt() != claim.Attempt() || renewal.LeaseTokenIdentity() != claim.LeaseTokenIdentity() || renewal.WorkerIdentity() != claim.WorkerIdentity() {
				return fail()
			}
			latest = renewal
			index++
		}
		if index >= len(tail) {
			return fail()
		}
		result := tail[index]
		index++
		if key == "candidates" {
			proof.candidateClaim = claim
		}
		if result.Kind() == controlplane.RunEventTaskSucceeded && key == "candidates" {
			if result.TaskKey() != key || result.Attempt() != 1 || result.LeaseTokenIdentity() != claim.LeaseTokenIdentity() || result.OutputIdentity() == "" || result.OccurredAt().After(latest.LeaseExpiresAt()) {
				return fail()
			}
			proof.candidateSuccess = result
			continue
		}
		if result.Kind() != controlplane.RunEventTaskFailed || result.TaskKey() != key || result.Attempt() != 1 || result.LeaseTokenIdentity() != latest.LeaseTokenIdentity() || result.Failure() != controlplane.RunFailureResourceLimit || result.OutputIdentity() != "" || !result.RetryAt().IsZero() || result.OccurredAt().Before(latest.LeaseExpiresAt()) {
			return fail()
		}
		proof.task, proof.claim, proof.latestLease, proof.failed = key, claim, latest, result
		break
	}
	if proof.task == "" {
		return fail()
	}
	skipped := []string{"readiness"}
	if proof.task == "candidates" {
		skipped = []string{"verification", "readiness"}
	}
	for _, key := range skipped {
		if index >= len(tail) {
			return fail()
		}
		event := tail[index]
		if event.Kind() != controlplane.RunEventTaskSkipped || event.TaskKey() != key || event.Failure() != controlplane.RunFailureDependency || event.Attempt() != 0 || event.OutputIdentity() != "" {
			return fail()
		}
		runtime, ok := state.Task(key)
		if !ok || runtime.Status() != controlplane.TaskRuntimeSkipped || runtime.Attempts() != 0 || runtime.OutputIdentity() != "" {
			return fail()
		}
		index++
	}
	if index != len(tail)-1 || tail[index].Identity() != terminal.Identity() {
		return fail()
	}
	finalTask, ok := state.Task(proof.task)
	if !ok || finalTask.Status() != controlplane.TaskRuntimeFailed || finalTask.Attempts() != 1 || finalTask.OutputIdentity() != "" || finalTask.LastEventIdentity() != proof.failed.Identity() {
		return fail()
	}
	preterminal, err := controlplane.ReplayReviewRun(plan, events[:len(events)-1])
	if err != nil {
		return fail()
	}
	completion, ready, err := preterminal.TerminalCompletion()
	if err != nil || !ready || completion.Failure() != terminal.Failure() {
		return fail()
	}
	return proof, nil
}
