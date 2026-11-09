package controlplane

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"
)

var ErrPreparedContextPacket = errors.New("invalid or unresolved prepared context packet")

// ContextPacketDescriptor records artifact metadata and upstream identities, never payload bytes.
// A later input checkpoint must advance this exact packet and lease atomically.
type ContextPacketDescriptor struct {
	ArtifactIdentity      string   `json:"artifact_identity"`
	LeaseIdentity         string   `json:"lease_identity"`
	LeaseEventIdentity    string   `json:"lease_event_identity"`
	PayloadDigest         string   `json:"payload_digest"`
	Classification        string   `json:"classification"`
	Protection            string   `json:"protection"`
	Provenance            []string `json:"provenance"`
	SourceRootIdentity    string   `json:"source_root_identity"`
	SnapshotIdentity      string   `json:"snapshot_identity"`
	DependencyIdentities  []string `json:"dependency_identities"`
	CreatedAtMilliseconds int64    `json:"created_at_milliseconds"`
	ExpiresAtMilliseconds int64    `json:"expires_at_milliseconds"`
}

func packetArtifactIdentity(scope interface{ Identity() string }, d ContextPacketDescriptor) string {
	return hashControlPlaneValue(struct {
		ScopeIdentity         string   `json:"scope_identity"`
		Kind                  string   `json:"kind"`
		MediaType             string   `json:"media_type"`
		Classification        string   `json:"classification"`
		Origin                string   `json:"origin"`
		Protection            string   `json:"protection"`
		Provenance            []string `json:"provenance"`
		PayloadDigest         string   `json:"payload_digest"`
		CreatedAtMilliseconds int64    `json:"created_at_milliseconds"`
		ExpiresAtMilliseconds int64    `json:"expires_at_milliseconds"`
	}{scope.Identity(), "context_packet", "application/json", d.Classification, "host", d.Protection, d.Provenance, d.PayloadDigest, d.CreatedAtMilliseconds, d.ExpiresAtMilliseconds})
}
func validPacketDigests(values []string, limit int) bool {
	if len(values) == 0 || len(values) > limit {
		return false
	}
	for i, value := range values {
		if !validControlPlaneDigest(value) || i > 0 && values[i-1] >= value {
			return false
		}
	}
	return true
}
func (d ContextPacketDescriptor) valid(scope interface{ Identity() string }) bool {
	return validControlPlaneDigest(d.ArtifactIdentity) && validControlPlaneDigest(d.LeaseIdentity) && validControlPlaneDigest(d.LeaseEventIdentity) && validControlPlaneDigest(d.PayloadDigest) &&
		(d.Classification == "public" || d.Classification == "internal" || d.Classification == "confidential" || d.Classification == "restricted") &&
		(d.Protection == "process_private" || d.Protection == "envelope_encrypted") &&
		validPacketDigests(d.Provenance, 32) && validControlPlaneDigest(d.SourceRootIdentity) &&
		validControlPlaneDigest(d.SnapshotIdentity) && validPacketDigests(d.DependencyIdentities, 32) &&
		d.CreatedAtMilliseconds > 0 && d.ExpiresAtMilliseconds > d.CreatedAtMilliseconds &&
		d.ExpiresAtMilliseconds <= maxRunEventUnixMilliseconds && d.ExpiresAtMilliseconds-d.CreatedAtMilliseconds <= int64((10*365*24*time.Hour)/time.Millisecond) &&
		packetArtifactIdentity(scope, d) == d.ArtifactIdentity && packetDependenciesInProvenance(d)
}
func packetDependenciesInProvenance(d ContextPacketDescriptor) bool {
	for _, identity := range d.DependencyIdentities {
		if !slices.Contains(d.Provenance, identity) {
			return false
		}
	}
	return true
}

func clonePacketDescriptor(d ContextPacketDescriptor) ContextPacketDescriptor {
	d.Provenance = append([]string(nil), d.Provenance...)
	d.DependencyIdentities = append([]string(nil), d.DependencyIdentities...)
	return d
}

// PreparedContextPacket is a replayable content-free intent, not dispatch authority.
type PreparedContextPacket struct{ event RunEvent }

func (p PreparedContextPacket) Identity() string { return p.event.Identity() }
func (p PreparedContextPacket) Descriptor() ContextPacketDescriptor {
	return clonePacketDescriptor(p.event.packetDescriptor)
}

func exactPacketDependencies(state ReviewRunState, runtime TaskRuntimeState, descriptor ContextPacketDescriptor) bool {
	expected := make([]string, 0, len(runtime.Definition().Dependencies()))
	for _, dependency := range runtime.Definition().Dependencies() {
		upstream, found := state.Task(dependency)
		if !found || upstream.Status() != TaskRuntimeSucceeded || !validControlPlaneDigest(upstream.OutputIdentity()) {
			return false
		}
		expected = append(expected, upstream.OutputIdentity())
	}
	slices.Sort(expected)
	expected = slices.Compact(expected)
	return slices.Equal(expected, descriptor.DependencyIdentities)
}

// PrepareContextPacket appends and fsyncs the first checkpoint before an external packet Put.
func (c *Coordinator) PrepareContextPacket(ctx context.Context, plan ReviewRunPlan, lease TaskLease, descriptor ContextPacketDescriptor, at time.Time) (PreparedContextPacket, error) {
	if err := c.validate(ctx, plan); err != nil {
		return PreparedContextPacket{}, err
	}
	if lease.Validate() != nil || !descriptor.valid(plan.Scope()) || descriptor.LeaseIdentity != lease.Identity() || descriptor.LeaseEventIdentity != lease.EventIdentity() || descriptor.ExpiresAtMilliseconds <= at.UnixMilli() || descriptor.CreatedAtMilliseconds > at.UnixMilli() {
		return PreparedContextPacket{}, ErrPreparedContextPacket
	}
	descriptor = clonePacketDescriptor(descriptor)
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return PreparedContextPacket{}, err
		}
		if state.Status() != ReviewRunActive {
			return PreparedContextPacket{}, ErrRunAlreadyTerminal
		}
		runtime, exists := state.Task(lease.TaskKey())
		if !exists || lease.PlanIdentity() != plan.Identity() || runtime.Definition().Kind() != TaskAssembleContext || lease.HandlerIdentity() != runtime.Definition().HandlerIdentity() || !runtimeMatchesLease(runtime, lease) {
			return PreparedContextPacket{}, ErrRunTransitionLeaseMismatch
		}
		if !exactPacketDependencies(state, runtime, descriptor) {
			return PreparedContextPacket{}, ErrPreparedContextPacket
		}
		if runtime.preparedEventIdentity != "" {
			if existing, ok := runtime.PreparedContextPacket(); ok && reflect.DeepEqual(existing.Descriptor(), descriptor) {
				return existing, nil
			}
			return PreparedContextPacket{}, ErrPreparedContextPacket
		}
		expectedLease := TaskLease{planIdentity: plan.Identity(), taskKey: runtime.Key(), taskIdentity: runtime.Definition().Identity(), handlerIdentity: runtime.Definition().HandlerIdentity(), workerIdentity: runtime.workerIdentity, tokenIdentity: runtime.leaseTokenIdentity, eventIdentity: runtime.lastEventIdentity, attempt: runtime.attempts, expiresAtMillis: runtime.leaseExpiresAtMillis}
		if descriptor.LeaseEventIdentity != runtime.lastEventIdentity || descriptor.LeaseIdentity != deriveTaskLeaseIdentity(expectedLease) {
			return PreparedContextPacket{}, ErrPreparedContextPacket
		}
		if !transitionTimeAllowed(state, at) || at.UnixMilli() > runtime.leaseExpiresAtMillis {
			return PreparedContextPacket{}, ErrRunTransitionLeaseMismatch
		}
		event := RunEvent{planIdentity: plan.Identity(), scope: plan.Scope(), sequence: state.Revision() + 1, previousIdentity: state.HeadIdentity(), kind: RunEventContextPacketPrepared, taskKey: runtime.Key(), taskIdentity: runtime.Definition().Identity(), attempt: runtime.Attempts(), leaseTokenIdentity: runtime.leaseTokenIdentity, outputIdentity: descriptor.ArtifactIdentity, occurredAtMillis: at.UnixMilli(), packetDescriptor: descriptor}
		event.identity = deriveRunEventIdentity(event)
		if _, err := EncodeRunEvent(event); err != nil {
			return PreparedContextPacket{}, err
		}
		err = c.journal.Append(ctx, state.HeadIdentity(), event)
		if err == nil {
			return PreparedContextPacket{event}, nil
		}
		if !errors.Is(err, ErrRunJournalHeadConflict) {
			return PreparedContextPacket{}, err
		}
	}
	return PreparedContextPacket{}, ErrCoordinatorContention
}

// TerminatePreparedContextPacket is trusted recovery's terminal, no-output CAS.
// Only an expired packet-only preparation can fail, and it cannot be retried.
func (c *Coordinator) TerminatePreparedContextPacket(ctx context.Context, plan ReviewRunPlan, prepared PreparedContextPacket, at time.Time) (ReviewRunState, error) {
	if err := c.validate(ctx, plan); err != nil {
		return ReviewRunState{}, err
	}
	if prepared.event.Validate() != nil || prepared.event.Kind() != RunEventContextPacketPrepared || prepared.event.PlanIdentity() != plan.Identity() {
		return ReviewRunState{}, ErrPreparedContextPacket
	}
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return ReviewRunState{}, err
		}
		if state.Status() != ReviewRunActive {
			return ReviewRunState{}, ErrRunAlreadyTerminal
		}
		runtime, exists := state.Task(prepared.event.TaskKey())
		if !exists || runtime.Definition().Identity() != prepared.event.TaskIdentity() {
			return ReviewRunState{}, ErrPreparedContextPacket
		}
		if runtime.Status() == TaskRuntimeFailed && runtime.preparedEventIdentity == prepared.Identity() && runtime.OutputIdentity() == "" && runtime.Failure() == RunFailurePolicy && runtime.FailureReason() == 0 {
			return state, nil
		}
		current, ok := runtime.PreparedContextPacket()
		if !ok || current.Identity() != prepared.Identity() || !transitionTimeAllowed(state, at) || at.UnixMilli() < runtime.leaseExpiresAtMillis {
			return ReviewRunState{}, ErrPreparedContextPacket
		}
		event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventTaskFailed, runtime.Definition(), runtime.Attempts(), runtime.leaseTokenIdentity, "", time.Time{}, "", RunFailurePolicy, time.Time{}, at)
		if err != nil {
			return ReviewRunState{}, err
		}
		err = c.journal.Append(ctx, state.HeadIdentity(), event)
		if err == nil {
			return c.load(ctx, plan)
		}
		if !errors.Is(err, ErrRunJournalHeadConflict) {
			return ReviewRunState{}, err
		}
	}
	return ReviewRunState{}, ErrCoordinatorContention
}

// RefusePreparedContextPacket settles a leased packet-only preparation as its
// lease holder's recorded route refusal: a terminal, no-output policy failure
// with a context route reason and, for route_context_insufficient, its counts.
// Unlike TerminatePreparedContextPacket it is allowed only within the lease.
func (c *Coordinator) RefusePreparedContextPacket(ctx context.Context, plan ReviewRunPlan, lease TaskLease, prepared PreparedContextPacket, reason TaskFailureReason, shortfall TaskFailureContextShortfall, at time.Time) (ReviewRunState, error) {
	if err := c.validate(ctx, plan); err != nil {
		return ReviewRunState{}, err
	}
	if lease.Validate() != nil || prepared.event.Validate() != nil || prepared.event.Kind() != RunEventContextPacketPrepared || prepared.event.PlanIdentity() != plan.Identity() || lease.PlanIdentity() != plan.Identity() || prepared.Descriptor().LeaseIdentity != lease.Identity() || !contextRefusalReason(reason) || !taskFailureReasonAllowed(TaskAssembleContext, reason, shortfall) {
		return ReviewRunState{}, ErrPreparedContextPacket
	}
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return ReviewRunState{}, err
		}
		if state.Status() != ReviewRunActive {
			return ReviewRunState{}, ErrRunAlreadyTerminal
		}
		runtime, exists := state.Task(prepared.event.TaskKey())
		if !exists || runtime.Definition().Identity() != prepared.event.TaskIdentity() || lease.TaskKey() != runtime.Key() {
			return ReviewRunState{}, ErrPreparedContextPacket
		}
		if runtime.Status() == TaskRuntimeFailed && runtime.preparedEventIdentity == prepared.Identity() && runtime.OutputIdentity() == "" && runtime.Failure() == RunFailurePolicy && runtime.FailureReason() == reason && runtime.shortfall == shortfall {
			return state, nil
		}
		current, ok := runtime.PreparedContextPacket()
		if !ok || current.Identity() != prepared.Identity() || !runtimeMatchesLease(runtime, lease) || !transitionTimeAllowed(state, at) || at.UnixMilli() > runtime.leaseExpiresAtMillis {
			return ReviewRunState{}, ErrPreparedContextPacket
		}
		event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventTaskFailed, runtime.Definition(), runtime.Attempts(), runtime.leaseTokenIdentity, "", time.Time{}, "", RunFailurePolicy, time.Time{}, at)
		if err == nil {
			event, err = event.withFailureReason(runtime.Definition(), reason, shortfall)
		}
		if err != nil {
			return ReviewRunState{}, err
		}
		err = c.journal.Append(ctx, state.HeadIdentity(), event)
		if err == nil {
			return c.load(ctx, plan)
		}
		if !errors.Is(err, ErrRunJournalHeadConflict) {
			return ReviewRunState{}, err
		}
	}
	return ReviewRunState{}, ErrCoordinatorContention
}
