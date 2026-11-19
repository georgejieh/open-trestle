package controlplane

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"time"
)

// ErrPreparedContextInput means the pinned input checkpoint cannot advance or settle.
var ErrPreparedContextInput = errors.New("invalid or unresolved prepared context input")

// ContextInputArtifactDescriptor binds an artifact envelope without retaining payload bytes.
type ContextInputArtifactDescriptor struct {
	ArtifactIdentity      string   `json:"artifact_identity"`
	PayloadDigest         string   `json:"payload_digest"`
	Classification        string   `json:"classification"`
	Protection            string   `json:"protection"`
	Provenance            []string `json:"provenance"`
	CreatedAtMilliseconds int64    `json:"created_at_milliseconds"`
	ExpiresAtMilliseconds int64    `json:"expires_at_milliseconds"`
}

func contextInputArtifactIdentity(scope interface{ Identity() string }, kind string, d ContextInputArtifactDescriptor) string {
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
	}{scope.Identity(), kind, "application/json", d.Classification, "host", d.Protection, d.Provenance, d.PayloadDigest, d.CreatedAtMilliseconds, d.ExpiresAtMilliseconds})
}
func (d ContextInputArtifactDescriptor) valid(scope interface{ Identity() string }, kind string) bool {
	return validControlPlaneDigest(d.ArtifactIdentity) && validControlPlaneDigest(d.PayloadDigest) &&
		(d.Classification == "public" || d.Classification == "internal" || d.Classification == "confidential" || d.Classification == "restricted") &&
		(d.Protection == "process_private" || d.Protection == "envelope_encrypted") && validPacketDigests(d.Provenance, 32) &&
		validRunMillis(d.CreatedAtMilliseconds) && validRunMillis(d.ExpiresAtMilliseconds) && d.ExpiresAtMilliseconds > d.CreatedAtMilliseconds &&
		d.ExpiresAtMilliseconds-d.CreatedAtMilliseconds <= int64((10*365*24*time.Hour)/time.Millisecond) &&
		contextInputArtifactIdentity(scope, kind, d) == d.ArtifactIdentity
}
func cloneContextInputArtifactDescriptor(d ContextInputArtifactDescriptor) ContextInputArtifactDescriptor {
	d.Provenance = append([]string(nil), d.Provenance...)
	return d
}

// ContextInputDescriptor pins the exact post-scan intent. Digests cannot recover absent bytes.
type ContextInputDescriptor struct {
	PacketPreparedEventIdentity string                         `json:"packet_prepared_event_identity"`
	PacketArtifactIdentity      string                         `json:"packet_artifact_identity"`
	LeaseIdentity               string                         `json:"lease_identity"`
	LeaseEventIdentity          string                         `json:"lease_event_identity"`
	Request                     ContextInputArtifactDescriptor `json:"request"`
	Receipt                     ContextInputArtifactDescriptor `json:"receipt"`
	Input                       ContextInputArtifactDescriptor `json:"input"`
	ReceiptIdentity             string                         `json:"receipt_identity"`
	ScannerHelperDigest         string                         `json:"scanner_helper_digest"`
	GenerationInputIdentity     string                         `json:"generation_input_identity"`
	AuthorizationIdentity       string                         `json:"authorization_identity"`
	SelectionReceiptIdentity    string                         `json:"selection_receipt_identity"`
	RoutingInputIdentity        string                         `json:"routing_input_identity"`
	SelectedRecordIdentity      string                         `json:"selected_record_identity"`

	PolicyIdentity      string `json:"policy_identity"`
	RoutePairIdentity   string `json:"route_pair_identity"`
	AuthorizerIdentity  string `json:"authorizer_identity"`
	SanitizerIdentity   string `json:"sanitizer_identity"`
	RegistryRevision    uint64 `json:"registry_revision"`
	PerformanceRevision uint64 `json:"performance_revision"`
}

func sortedContextInputParents(values ...string) []string { slices.Sort(values); return values }
func cloneContextInputDescriptor(d ContextInputDescriptor) ContextInputDescriptor {
	d.Request = cloneContextInputArtifactDescriptor(d.Request)
	d.Receipt = cloneContextInputArtifactDescriptor(d.Receipt)
	d.Input = cloneContextInputArtifactDescriptor(d.Input)
	return d
}
func (d ContextInputDescriptor) valid(scope interface{ Identity() string }) bool {
	for _, v := range []string{d.PacketPreparedEventIdentity, d.PacketArtifactIdentity, d.LeaseIdentity, d.LeaseEventIdentity, d.ReceiptIdentity, d.ScannerHelperDigest, d.GenerationInputIdentity, d.AuthorizationIdentity, d.SelectionReceiptIdentity, d.RoutingInputIdentity, d.SelectedRecordIdentity, d.PolicyIdentity, d.RoutePairIdentity, d.AuthorizerIdentity, d.SanitizerIdentity} {
		if !validControlPlaneDigest(v) {
			return false
		}
	}
	return d.RegistryRevision > 0 && d.PerformanceRevision > 0 && d.Request.valid(scope, "sanitized_model_request") && d.Receipt.valid(scope, "sanitized_egress_receipt") && d.Input.valid(scope, "task_input") &&
		slices.Equal(d.Request.Provenance, []string{d.PacketArtifactIdentity}) && slices.Equal(d.Receipt.Provenance, sortedContextInputParents(d.PacketArtifactIdentity, d.Request.ArtifactIdentity)) &&
		slices.Contains(d.Input.Provenance, d.PacketArtifactIdentity) && slices.Contains(d.Input.Provenance, d.Request.ArtifactIdentity) && slices.Contains(d.Input.Provenance, d.Receipt.ArtifactIdentity) && slices.Contains(d.Input.Provenance, d.AuthorizationIdentity) &&
		d.Request.Classification == d.Receipt.Classification && d.Request.Classification == d.Input.Classification && d.Request.Protection == d.Receipt.Protection && d.Request.Protection == d.Input.Protection &&
		d.Request.ExpiresAtMilliseconds == d.Receipt.ExpiresAtMilliseconds && d.Request.ExpiresAtMilliseconds == d.Input.ExpiresAtMilliseconds &&
		d.Request.CreatedAtMilliseconds == d.Receipt.CreatedAtMilliseconds && d.Input.CreatedAtMilliseconds >= d.Receipt.CreatedAtMilliseconds
}

func inputMatchesPacket(d ContextInputDescriptor, p ContextPacketDescriptor, preparedAtMilliseconds int64) bool {
	return d.Request.Classification == p.Classification && d.Request.Protection == p.Protection && d.Request.ExpiresAtMilliseconds == p.ExpiresAtMilliseconds &&
		d.Request.CreatedAtMilliseconds >= p.CreatedAtMilliseconds && d.Request.CreatedAtMilliseconds >= preparedAtMilliseconds
}

// PreparedContextInput is intent only. It grants no success or model dispatch authority.
type PreparedContextInput struct{ event RunEvent }

func (p PreparedContextInput) Identity() string { return p.event.Identity() }
func (p PreparedContextInput) Descriptor() ContextInputDescriptor {
	return cloneContextInputDescriptor(p.event.inputDescriptor)
}

// PrepareContextInput atomically advances the exact live v4 packet checkpoint to v5.
func (c *Coordinator) PrepareContextInput(ctx context.Context, plan ReviewRunPlan, lease TaskLease, packet PreparedContextPacket, d ContextInputDescriptor, at time.Time) (PreparedContextInput, error) {
	if err := c.validate(ctx, plan); err != nil {
		return PreparedContextInput{}, err
	}
	if lease.Validate() != nil || packet.event.Validate() != nil || packet.event.Kind() != RunEventContextPacketPrepared || !d.valid(plan.Scope()) || d.PacketPreparedEventIdentity != packet.Identity() || d.PacketArtifactIdentity != packet.Descriptor().ArtifactIdentity || d.LeaseIdentity != lease.Identity() || d.LeaseEventIdentity != lease.EventIdentity() {
		return PreparedContextInput{}, ErrPreparedContextInput
	}
	d = cloneContextInputDescriptor(d)
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return PreparedContextInput{}, err
		}
		if state.Status() != ReviewRunActive {
			return PreparedContextInput{}, ErrRunAlreadyTerminal
		}
		runtime, found := state.Task(lease.TaskKey())
		if !found || runtime.Definition().Kind() != TaskAssembleContext || lease.PlanIdentity() != plan.Identity() || lease.HandlerIdentity() != runtime.Definition().HandlerIdentity() || !runtimeMatchesLease(runtime, lease) {
			return PreparedContextInput{}, ErrRunTransitionLeaseMismatch
		}
		if existing, ok := runtime.PreparedContextInput(); ok {
			if reflect.DeepEqual(existing.Descriptor(), d) {
				return existing, nil
			}
			return PreparedContextInput{}, ErrPreparedContextInput
		}
		current, ok := runtime.PreparedContextPacket()
		at, timely := transitionTime(state, at)
		if !ok || current.Identity() != packet.Identity() || current.event.Attempt() != lease.Attempt() || current.event.LeaseTokenIdentity() != lease.tokenIdentity || !exactPacketDependencies(state, runtime, current.Descriptor()) || !timely || at.UnixMilli() > runtime.leaseExpiresAtMillis || d.Request.CreatedAtMilliseconds > at.UnixMilli() || d.Receipt.CreatedAtMilliseconds > at.UnixMilli() || d.Input.CreatedAtMilliseconds > at.UnixMilli() || d.Input.ExpiresAtMilliseconds <= at.UnixMilli() || !inputMatchesPacket(d, current.Descriptor(), current.event.occurredAtMillis) {
			return PreparedContextInput{}, ErrPreparedContextInput
		}
		event := RunEvent{planIdentity: plan.Identity(), scope: plan.Scope(), sequence: state.Revision() + 1, previousIdentity: state.HeadIdentity(), kind: RunEventContextInputPrepared, taskKey: runtime.Key(), taskIdentity: runtime.Definition().Identity(), attempt: runtime.Attempts(), leaseTokenIdentity: runtime.leaseTokenIdentity, outputIdentity: d.Input.ArtifactIdentity, occurredAtMillis: at.UnixMilli(), inputDescriptor: d}
		event.identity = deriveRunEventIdentity(event)
		if _, err := EncodeRunEvent(event); err != nil {
			return PreparedContextInput{}, err
		}
		err = c.journal.Append(ctx, state.HeadIdentity(), event)
		if err == nil {
			return PreparedContextInput{event}, nil
		}
		if !errors.Is(err, ErrRunJournalHeadConflict) {
			return PreparedContextInput{}, err
		}
	}
	return PreparedContextInput{}, ErrCoordinatorContention
}

// TerminatePreparedContextInput is a trusted no-output fail-closed path after expiry.
// It does not claim the byte objects are missing; the caller must establish that separately.
func (c *Coordinator) TerminatePreparedContextInput(ctx context.Context, plan ReviewRunPlan, prepared PreparedContextInput, at time.Time) (ReviewRunState, error) {
	if err := c.validate(ctx, plan); err != nil {
		return ReviewRunState{}, err
	}
	if prepared.event.Validate() != nil || prepared.event.Kind() != RunEventContextInputPrepared || prepared.event.PlanIdentity() != plan.Identity() {
		return ReviewRunState{}, ErrPreparedContextInput
	}
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return ReviewRunState{}, err
		}
		if state.Status() != ReviewRunActive {
			return ReviewRunState{}, ErrRunAlreadyTerminal
		}
		runtime, found := state.Task(prepared.event.TaskKey())
		if !found || runtime.Definition().Identity() != prepared.event.TaskIdentity() {
			return ReviewRunState{}, ErrPreparedContextInput
		}
		if runtime.Status() == TaskRuntimeFailed && runtime.preparedEventIdentity == prepared.Identity() && runtime.OutputIdentity() == "" && runtime.Failure() == RunFailurePolicy {
			return state, nil
		}
		current, ok := runtime.PreparedContextInput()
		at, timely := transitionTime(state, at)
		if !ok || current.Identity() != prepared.Identity() || !timely || at.UnixMilli() < runtime.leaseExpiresAtMillis {
			return ReviewRunState{}, ErrPreparedContextInput
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
