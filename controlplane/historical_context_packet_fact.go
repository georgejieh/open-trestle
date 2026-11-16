// Historical context packet facts are read-only journal metadata, not startup authority.
package controlplane

import (
	"slices"
)

const maxStartupHistoricalPacketFacts = 1024

// ContextPacketExpiryTail describes only a closed event suffix. It does not
// prove plan eligibility, physical bytes, absent route effects or startup safety.
type ContextPacketExpiryTail uint8

const (
	ContextPacketExpiryTailUnknown ContextPacketExpiryTail = iota
	// ContextPacketExpiryTailActiveExactV4 means the latest v4 is the exact head,
	// without making a claim about the current clock or lease expiry.
	ContextPacketExpiryTailActiveExactV4
	// ContextPacketExpiryTailExpiredV4PolicyTerminated includes active interrupted
	// cleanup prefixes. It does not mean the run itself is terminal.
	ContextPacketExpiryTailExpiredV4PolicyTerminated
	// ContextPacketExpiryTailRefusedV4PolicyTerminated is the exact v4 settled
	// within its lease as a recorded route refusal, with the same closed cleanup
	// suffix. It does not mean the run itself is terminal.
	ContextPacketExpiryTailRefusedV4PolicyTerminated
)

// HistoricalContextPacketFact describes one replay-validated v4 event. It does
// not attest physical artifact bytes or authorize dispatch or startup.
type HistoricalContextPacketFact struct {
	plan          *ReviewRunPlan // one independently owned plan per retained scope
	replay        *[]RunEvent    // one private event snapshot per retained scope
	prepared      RunEvent
	lease         RunEvent
	upstream      []RunEvent
	transitive    []RunEvent
	linked        RunEvent
	hasLinked     bool
	settlement    RunEvent
	hasSettlement bool
	terminal      RunEvent
	hasTerminal   bool
	status        ReviewRunStatus
	revision      uint64
	head          string
	expiryTail    ContextPacketExpiryTail
}

func cloneHistoricalPlan(plan ReviewRunPlan) ReviewRunPlan {
	plan.tasks = append([]TaskDefinition(nil), plan.tasks...)
	for i := range plan.tasks {
		plan.tasks[i].dependencies = append([]string(nil), plan.tasks[i].dependencies...)
	}
	return plan
}

func cloneHistoricalEvent(event RunEvent) RunEvent {
	event.preparedArtifact = append([]byte(nil), event.preparedArtifact...)
	event.packetDescriptor = clonePacketDescriptor(event.packetDescriptor)
	event.inputDescriptor = cloneContextInputDescriptor(event.inputDescriptor)
	return event
}

func (f HistoricalContextPacketFact) Plan() ReviewRunPlan {
	if f.plan == nil {
		return ReviewRunPlan{}
	}
	return cloneHistoricalPlan(*f.plan)
}

// ReplayEvents returns independent copies of the fully replayed stream that
// produced this fact. Rooted observations remain provisional until their outer
// physical postchecks succeed. These events grant no startup authority.
func (f HistoricalContextPacketFact) ReplayEvents() []RunEvent {
	if f.replay == nil {
		return nil
	}
	result := make([]RunEvent, len(*f.replay))
	for i, event := range *f.replay {
		result[i] = cloneHistoricalEvent(event)
	}
	return result
}

func (f HistoricalContextPacketFact) PreparedEvent() RunEvent {
	return cloneHistoricalEvent(f.prepared)
}

// LeaseEvent returns the exact claim or renewal referenced by the packet.
func (f HistoricalContextPacketFact) LeaseEvent() RunEvent {
	return cloneHistoricalEvent(f.lease)
}
func (f HistoricalContextPacketFact) UpstreamSuccessEvents() []RunEvent {
	result := make([]RunEvent, len(f.upstream))
	for i, event := range f.upstream {
		result[i] = cloneHistoricalEvent(event)
	}
	return result
}

// TransitiveDependencySuccessEvents returns the available latest ancestor
// successes at v4, sorted by task key. Ancestors without a recorded success are
// omitted, including failed or skipped tasks behind optional dependencies.
// This is not a complete ancestor inventory or proof of physical artifact bytes.
func (f HistoricalContextPacketFact) TransitiveDependencySuccessEvents() []RunEvent {
	result := make([]RunEvent, len(f.transitive))
	for i, event := range f.transitive {
		result[i] = cloneHistoricalEvent(event)
	}
	return result
}

func (f HistoricalContextPacketFact) LinkedInputEvent() (RunEvent, bool) {
	if !f.hasLinked {
		return RunEvent{}, false
	}
	return cloneHistoricalEvent(f.linked), true
}
func (f HistoricalContextPacketFact) TaskSettlementEvent() (RunEvent, bool) {
	if !f.hasSettlement {
		return RunEvent{}, false
	}
	return cloneHistoricalEvent(f.settlement), true
}
func (f HistoricalContextPacketFact) TerminalEvent() (RunEvent, bool) {
	if !f.hasTerminal {
		return RunEvent{}, false
	}
	return cloneHistoricalEvent(f.terminal), true
}

// ExpiryTail returns suffix metadata even for non-nine-task plans. Callers must
// independently validate the exact recipe, current enrollment and all effects.
func (f HistoricalContextPacketFact) ExpiryTail() ContextPacketExpiryTail { return f.expiryTail }

func (f HistoricalContextPacketFact) FinalRunStatus() ReviewRunStatus { return f.status }
func (f HistoricalContextPacketFact) FinalRevision() uint64           { return f.revision }
func (f HistoricalContextPacketFact) FinalHeadIdentity() string       { return f.head }

// historicalFactsForStream scans only a fully replayed stream. It retains at
// most remaining facts, and indexes no events after the diagnostic limit.
func historicalFactsForStream(plan ReviewRunPlan, events []RunEvent, state ReviewRunState, remaining int) ([]HistoricalContextPacketFact, bool, error) {
	type checkpoint struct {
		index          int
		identity       string
		linkedIdentity string
	}
	latest := make(map[string]RunEvent)
	leases := make(map[string]RunEvent)
	active := make(map[string]checkpoint)
	facts := make([]HistoricalContextPacketFact, 0)
	var owned *ReviewRunPlan
	var replay *[]RunEvent
	var terminal RunEvent
	overflow := false
	tailIndex, skipIndex := -1, 0
	tail := ContextPacketExpiryTailUnknown
	tailFinal := false
	for _, event := range events {
		if tailIndex >= 0 {
			switch {
			case tail == ContextPacketExpiryTailActiveExactV4 && packetExpiryFailure(facts[tailIndex], event):
				tail = ContextPacketExpiryTailExpiredV4PolicyTerminated
			case tail == ContextPacketExpiryTailActiveExactV4 && packetRefusalFailure(facts[tailIndex], event):
				tail = ContextPacketExpiryTailRefusedV4PolicyTerminated
			case (tail == ContextPacketExpiryTailExpiredV4PolicyTerminated || tail == ContextPacketExpiryTailRefusedV4PolicyTerminated) && !tailFinal && packetExpirySkip(plan, event, skipIndex):
				skipIndex++
			case (tail == ContextPacketExpiryTailExpiredV4PolicyTerminated || tail == ContextPacketExpiryTailRefusedV4PolicyTerminated) && !tailFinal && skipIndex == 3 && event.Kind() == RunEventFailed && event.Failure() == RunFailurePolicy:
				tailFinal = true
			default:
				tail = ContextPacketExpiryTailUnknown
			}
		}
		switch event.Kind() {
		case RunEventTaskLeased, RunEventTaskLeaseRenewed:
			if !overflow {
				leases[event.TaskKey()] = event
			}
		case RunEventTaskSucceeded:
			if !overflow {
				latest[event.TaskKey()] = event
			}
		case RunEventContextPacketPrepared:
			if len(facts) >= remaining {
				overflow = true
				// No new facts, plans, or indices are retained after overflow.
				latest = nil
				leases = nil
				active = nil
				tailIndex = -1
				tail = ContextPacketExpiryTailUnknown
				continue
			}
			task, found := plan.Task(event.TaskKey())
			if !found || task.Identity() != event.TaskIdentity() {
				return nil, false, ErrInvalidStartupInventoryEntry
			}
			lease, hasLease := leases[event.TaskKey()]
			descriptor := event.PacketDescriptor()
			expectedLease := TaskLease{planIdentity: plan.Identity(), taskKey: task.Key(), taskIdentity: task.Identity(), handlerIdentity: task.HandlerIdentity(), workerIdentity: lease.WorkerIdentity(), tokenIdentity: lease.LeaseTokenIdentity(), eventIdentity: lease.Identity(), attempt: lease.Attempt(), expiresAtMillis: lease.leaseExpiresAtMillis}
			if !hasLease || lease.Identity() != descriptor.LeaseEventIdentity || lease.TaskIdentity() != event.TaskIdentity() || lease.Attempt() != event.Attempt() || lease.LeaseTokenIdentity() != event.LeaseTokenIdentity() || descriptor.LeaseIdentity != deriveTaskLeaseIdentity(expectedLease) {
				return nil, false, ErrInvalidStartupInventoryEntry
			}
			keys := task.Dependencies()
			// Plan validation guarantees sorted direct dependency task keys.
			upstream := make([]RunEvent, 0, len(keys))
			outputs := make([]string, 0, len(keys))
			for _, key := range keys {
				success, ok := latest[key]
				dependency, exists := plan.Task(key)
				if !ok || !exists || success.Kind() != RunEventTaskSucceeded || success.TaskKey() != key ||
					success.TaskIdentity() != dependency.Identity() || success.Sequence() >= event.Sequence() ||
					!validControlPlaneDigest(success.Identity()) || !validControlPlaneDigest(success.OutputIdentity()) {
					return nil, false, ErrInvalidStartupInventoryEntry
				}
				upstream = append(upstream, cloneHistoricalEvent(success))
				outputs = append(outputs, success.OutputIdentity())
			}
			slices.Sort(outputs)
			outputs = slices.Compact(outputs)
			if !slices.Equal(outputs, event.PacketDescriptor().DependencyIdentities) {
				return nil, false, ErrInvalidStartupInventoryEntry
			}
			transitive, err := historicalAncestorSuccesses(plan, task, event, latest)
			if err != nil {
				return nil, false, err
			}
			if owned == nil {
				cloned := cloneHistoricalPlan(plan)
				owned = &cloned
				copied := make([]RunEvent, len(events))
				for i, event := range events {
					copied[i] = cloneHistoricalEvent(event)
				}
				replay = &copied
			}
			facts = append(facts, HistoricalContextPacketFact{plan: owned, replay: replay, prepared: cloneHistoricalEvent(event), lease: cloneHistoricalEvent(lease), upstream: upstream, transitive: transitive})
			active[event.TaskKey()] = checkpoint{index: len(facts) - 1, identity: event.Identity()}
			tailIndex, skipIndex = len(facts)-1, 0
			tail = ContextPacketExpiryTailActiveExactV4
			tailFinal = false
		case RunEventContextInputPrepared:
			if overflow {
				continue
			}
			record, found := active[event.TaskKey()]
			if !found || record.identity != event.InputDescriptor().PacketPreparedEventIdentity || record.linkedIdentity != "" ||
				facts[record.index].prepared.TaskIdentity() != event.TaskIdentity() ||
				facts[record.index].prepared.Attempt() != event.Attempt() ||
				facts[record.index].prepared.LeaseTokenIdentity() != event.LeaseTokenIdentity() {
				return nil, false, ErrInvalidStartupInventoryEntry
			}
			facts[record.index].linked = cloneHistoricalEvent(event)
			facts[record.index].hasLinked = true
			record.linkedIdentity = event.Identity()
			active[event.TaskKey()] = record
		case RunEventTaskFailed, RunEventContextInputSettled:
			if overflow {
				continue
			}
			record, found := active[event.TaskKey()]
			if !found {
				continue
			}
			if event.TaskIdentity() != facts[record.index].prepared.TaskIdentity() ||
				event.Attempt() != facts[record.index].prepared.Attempt() ||
				event.LeaseTokenIdentity() != facts[record.index].prepared.LeaseTokenIdentity() {
				return nil, false, ErrInvalidStartupInventoryEntry
			}
			// ReplayReviewRun verified the live prepared checkpoint and exact
			// prepared-event identity; global predecessors may be other tasks.
			facts[record.index].settlement = cloneHistoricalEvent(event)
			facts[record.index].hasSettlement = true
			delete(active, event.TaskKey())
		case RunEventSucceeded, RunEventFailed, RunEventCanceled:
			terminal = event
		}
	}
	if tailIndex >= 0 {
		facts[tailIndex].expiryTail = tail
	}
	for i := range facts {
		if terminal.Kind() != 0 {
			facts[i].terminal = cloneHistoricalEvent(terminal)
			facts[i].hasTerminal = true
		}
		facts[i].status = state.Status()
		facts[i].revision = state.Revision()
		facts[i].head = state.HeadIdentity()
	}
	return facts, overflow, nil
}

func historicalAncestorSuccesses(plan ReviewRunPlan, task TaskDefinition, prepared RunEvent, latest map[string]RunEvent) ([]RunEvent, error) {
	seen := make(map[string]bool)
	keys := make([]string, 0, plan.TaskCount()-1)
	discover := func(key string) error {
		if key == task.Key() {
			return ErrInvalidStartupInventoryEntry
		}
		if seen[key] {
			return nil
		}
		if _, exists := plan.Task(key); !exists || len(keys) >= plan.TaskCount()-1 {
			return ErrInvalidStartupInventoryEntry
		}
		seen[key] = true
		keys = append(keys, key)
		return nil
	}
	for _, key := range task.Dependencies() {
		if err := discover(key); err != nil {
			return nil, err
		}
	}
	for index := 0; index < len(keys); index++ {
		ancestor, _ := plan.Task(keys[index])
		for _, key := range ancestor.Dependencies() {
			if err := discover(key); err != nil {
				return nil, err
			}
		}
	}
	slices.Sort(keys)
	result := make([]RunEvent, 0, len(keys))
	for _, key := range keys {
		ancestor, _ := plan.Task(key)
		success, exists := latest[key]
		if !exists {
			continue
		}
		if success.Kind() != RunEventTaskSucceeded || success.TaskKey() != key || success.TaskIdentity() != ancestor.Identity() || success.PlanIdentity() != plan.Identity() || success.Scope().Identity() != plan.Scope().Identity() || success.Sequence() >= prepared.Sequence() || success.Validate() != nil || !validControlPlaneDigest(success.OutputIdentity()) {
			return nil, ErrInvalidStartupInventoryEntry
		}
		result = append(result, cloneHistoricalEvent(success))
	}
	return result, nil
}

func packetExpiryFailure(f HistoricalContextPacketFact, event RunEvent) bool {
	prepared, lease := f.prepared, f.lease
	return event.Kind() == RunEventTaskFailed && event.PlanIdentity() == prepared.PlanIdentity() && event.Scope() == prepared.Scope() && event.TaskKey() == prepared.TaskKey() && event.TaskIdentity() == prepared.TaskIdentity() && event.Attempt() == prepared.Attempt() && event.LeaseTokenIdentity() == prepared.LeaseTokenIdentity() && event.PreviousIdentity() == prepared.Identity() && event.Sequence() == prepared.Sequence()+1 && event.Failure() == RunFailurePolicy && event.FailureReason() == 0 && event.OutputIdentity() == "" && event.RetryAt().IsZero() && !event.OccurredAt().Before(lease.LeaseExpiresAt())
}

// packetRefusalFailure is the lease holder's in-lease route refusal of the exact v4.
func packetRefusalFailure(f HistoricalContextPacketFact, event RunEvent) bool {
	prepared, lease := f.prepared, f.lease
	return event.Kind() == RunEventTaskFailed && event.PlanIdentity() == prepared.PlanIdentity() && event.Scope() == prepared.Scope() && event.TaskKey() == prepared.TaskKey() && event.TaskIdentity() == prepared.TaskIdentity() && event.Attempt() == prepared.Attempt() && event.LeaseTokenIdentity() == prepared.LeaseTokenIdentity() && event.PreviousIdentity() == prepared.Identity() && event.Sequence() == prepared.Sequence()+1 && event.Failure() == RunFailurePolicy && contextRefusalReason(event.FailureReason()) && event.OutputIdentity() == "" && event.RetryAt().IsZero() && !event.OccurredAt().After(lease.LeaseExpiresAt())
}

func packetExpirySkip(plan ReviewRunPlan, event RunEvent, index int) bool {
	// These names define the closed cleanup protocol, not a plan-shape validator.
	keys := [...]string{"candidates", "verification", "readiness"}
	kinds := [...]TaskKind{TaskGenerateCandidates, TaskVerifyCandidates, TaskEvaluatePublication}
	if index >= len(keys) || event.Kind() != RunEventTaskSkipped || event.TaskKey() != keys[index] || event.Failure() != RunFailureDependency {
		return false
	}
	task, ok := plan.Task(keys[index])
	return ok && task.Kind() == kinds[index] && event.TaskIdentity() == task.Identity()
}
