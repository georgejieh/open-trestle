// Historical context packet facts are read-only journal metadata, not startup authority.
package controlplane

import (
	"slices"
)

const maxStartupHistoricalPacketFacts = 1024

// HistoricalContextPacketFact describes one replay-validated v4 event. It does
// not attest physical artifact bytes or authorize dispatch or startup.
type HistoricalContextPacketFact struct {
	plan          *ReviewRunPlan // one independently owned plan per retained scope
	prepared      RunEvent
	upstream      []RunEvent
	linked        RunEvent
	hasLinked     bool
	settlement    RunEvent
	hasSettlement bool
	terminal      RunEvent
	hasTerminal   bool
	status        ReviewRunStatus
	revision      uint64
	head          string
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
func (f HistoricalContextPacketFact) PreparedEvent() RunEvent {
	return cloneHistoricalEvent(f.prepared)
}
func (f HistoricalContextPacketFact) UpstreamSuccessEvents() []RunEvent {
	result := make([]RunEvent, len(f.upstream))
	for i, event := range f.upstream {
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
	active := make(map[string]checkpoint)
	facts := make([]HistoricalContextPacketFact, 0)
	var owned *ReviewRunPlan
	var terminal RunEvent
	overflow := false
	for _, event := range events {
		switch event.Kind() {
		case RunEventTaskSucceeded:
			if !overflow {
				latest[event.TaskKey()] = event
			}
		case RunEventContextPacketPrepared:
			if len(facts) >= remaining {
				overflow = true
				// No new facts, plans, or indices are retained after overflow.
				latest = nil
				active = nil
				continue
			}
			task, found := plan.Task(event.TaskKey())
			if !found || task.Identity() != event.TaskIdentity() {
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
			if owned == nil {
				cloned := cloneHistoricalPlan(plan)
				owned = &cloned
			}
			facts = append(facts, HistoricalContextPacketFact{plan: owned, prepared: cloneHistoricalEvent(event), upstream: upstream})
			active[event.TaskKey()] = checkpoint{index: len(facts) - 1, identity: event.Identity()}
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
		case RunEventTaskFailed:
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
