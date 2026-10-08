package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

var ErrPreparedContextAbstention = errors.New("invalid or unresolved prepared context abstention")

const maxPreparedPayloadBytes = 8 << 20

// PreparedContextAbstention is a read-only, secret-free descriptor from replayed journal state.
// Its artifact bytes are copied at the boundary; callers must validate domain-specific payloads.
type PreparedContextAbstention struct{ event RunEvent }

func (p PreparedContextAbstention) Identity() string           { return p.event.Identity() }
func (p PreparedContextAbstention) PlanIdentity() string       { return p.event.PlanIdentity() }
func (p PreparedContextAbstention) TaskKey() string            { return p.event.TaskKey() }
func (p PreparedContextAbstention) TaskIdentity() string       { return p.event.TaskIdentity() }
func (p PreparedContextAbstention) LeaseTokenIdentity() string { return p.event.LeaseTokenIdentity() }
func (p PreparedContextAbstention) Attempt() uint8             { return p.event.Attempt() }
func (p PreparedContextAbstention) ArtifactIdentity() string   { return p.event.OutputIdentity() }
func (p PreparedContextAbstention) Failure() RunFailure        { return p.event.Failure() }
func (p PreparedContextAbstention) EncodedArtifact() []byte    { return p.event.PreparedArtifact() }

// This narrow envelope validator mirrors artifact's canonical envelope and identity contract.
// An import of artifact here would form a cycle because artifact/task_handler imports controlplane.
type preparedArtifactRecord struct {
	Contract              string   `json:"contract"`
	SchemaVersion         int      `json:"schema_version"`
	Identity              string   `json:"identity"`
	TenantID              string   `json:"tenant_id"`
	RepositoryID          string   `json:"repository_id"`
	ReviewRunID           string   `json:"review_run_id"`
	Kind                  string   `json:"kind"`
	MediaType             string   `json:"media_type"`
	Classification        string   `json:"classification"`
	Origin                string   `json:"origin"`
	Protection            string   `json:"protection"`
	Provenance            []string `json:"provenance"`
	PayloadDigest         string   `json:"payload_digest"`
	Payload               []byte   `json:"payload"`
	CreatedAtMilliseconds int64    `json:"created_at_milliseconds"`
	ExpiresAtMilliseconds int64    `json:"expires_at_milliseconds"`
}

func preparedArtifactIdentity(encoded []byte, scope audit.ReviewScope) (string, error) {
	if len(encoded) == 0 || len(encoded) > maxPreparedArtifactBytes {
		return "", ErrPreparedContextAbstention
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var r preparedArtifactRecord
	if decoder.Decode(&r) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return "", ErrPreparedContextAbstention
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, encoded) || r.Contract != "open-trestle/runtime-artifact" || r.SchemaVersion != 1 || r.Kind != "deterministic_evidence" || !validControlPlaneDigest(r.Identity) || len(r.Payload) == 0 || len(r.Payload) > maxPreparedPayloadBytes {
		return "", ErrPreparedContextAbstention
	}
	artifactScope, err := audit.NewReviewScope(r.TenantID, r.RepositoryID, r.ReviewRunID)
	if err != nil || artifactScope.Identity() != scope.Identity() {
		return "", ErrPreparedContextAbstention
	}
	media, params, err := mime.ParseMediaType(r.MediaType)
	if err != nil || len(params) != 0 || media != r.MediaType || !strings.Contains(media, "/") || len(media) > 128 || (r.Classification != "public" && r.Classification != "internal" && r.Classification != "confidential" && r.Classification != "restricted") || (r.Origin != "host" && r.Origin != "repository" && r.Origin != "deterministic_tool" && r.Origin != "model" && r.Origin != "independent_verifier" && r.Origin != "policy" && r.Origin != "memory") || (r.Protection != "process_private" && r.Protection != "envelope_encrypted") {
		return "", ErrPreparedContextAbstention
	}
	if len(r.Provenance) == 0 || len(r.Provenance) > 32 || r.CreatedAtMilliseconds <= 0 || r.ExpiresAtMilliseconds <= r.CreatedAtMilliseconds || r.ExpiresAtMilliseconds > maxRunEventUnixMilliseconds || r.ExpiresAtMilliseconds-r.CreatedAtMilliseconds > int64((10*365*24*time.Hour)/time.Millisecond) {
		return "", ErrPreparedContextAbstention
	}
	for i, digest := range r.Provenance {
		if !validControlPlaneDigest(digest) || i > 0 && r.Provenance[i-1] >= digest {
			return "", ErrPreparedContextAbstention
		}
	}
	payloadDigest := sha256.Sum256(r.Payload)
	if r.PayloadDigest != hex.EncodeToString(payloadDigest[:]) {
		return "", ErrPreparedContextAbstention
	}
	preimage := struct {
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
	}{scope.Identity(), r.Kind, r.MediaType, r.Classification, r.Origin, r.Protection, r.Provenance, r.PayloadDigest, r.CreatedAtMilliseconds, r.ExpiresAtMilliseconds}
	value, _ := json.Marshal(preimage)
	identity := sha256.Sum256(value)
	if hex.EncodeToString(identity[:]) != r.Identity {
		return "", ErrPreparedContextAbstention
	}
	return r.Identity, nil
}

func newPreparedRunEvent(plan ReviewRunPlan, state ReviewRunState, runtime TaskRuntimeState, encoded []byte, identity string, failure RunFailure, at time.Time) (RunEvent, error) {
	event := RunEvent{planIdentity: plan.Identity(), scope: plan.Scope(), sequence: state.Revision() + 1, previousIdentity: state.HeadIdentity(), kind: RunEventContextAbstentionPrepared, taskKey: runtime.Key(), taskIdentity: runtime.Definition().Identity(), attempt: runtime.Attempts(), leaseTokenIdentity: runtime.leaseTokenIdentity, outputIdentity: identity, failure: failure, occurredAtMillis: at.UnixMilli()}
	event.preparedArtifact = append([]byte(nil), encoded...)
	event.identity = deriveRunEventIdentity(event)
	if event.Validate() != nil {
		return RunEvent{}, ErrPreparedContextAbstention
	}
	if _, err := EncodeRunEvent(event); err != nil {
		return RunEvent{}, err
	}
	return event, nil
}

// PrepareContextAbstention journals the exact proposed artifact before any external Put.
func (c *Coordinator) PrepareContextAbstention(ctx context.Context, plan ReviewRunPlan, lease TaskLease, encodedArtifact []byte, failure RunFailure, at time.Time) (PreparedContextAbstention, error) {
	if err := c.validate(ctx, plan); err != nil {
		return PreparedContextAbstention{}, err
	}
	if err := lease.Validate(); err != nil {
		return PreparedContextAbstention{}, err
	}
	if failure != RunFailurePolicy && failure != RunFailureResourceLimit {
		return PreparedContextAbstention{}, ErrPreparedContextAbstention
	}
	identity, err := preparedArtifactIdentity(encodedArtifact, plan.Scope())
	if err != nil {
		return PreparedContextAbstention{}, err
	}
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return PreparedContextAbstention{}, err
		}
		runtime, exists := state.Task(lease.TaskKey())
		if !exists || lease.PlanIdentity() != plan.Identity() || lease.HandlerIdentity() != runtime.Definition().HandlerIdentity() || runtime.Definition().Kind() != TaskAssembleContext || !runtimeMatchesLease(runtime, lease) {
			return PreparedContextAbstention{}, ErrRunTransitionLeaseMismatch
		}
		if existing, ok := runtime.PreparedContextAbstention(); ok {
			if existing.ArtifactIdentity() == identity && existing.Failure() == failure && bytes.Equal(existing.EncodedArtifact(), encodedArtifact) {
				return existing, nil
			}
			return PreparedContextAbstention{}, ErrPreparedContextAbstention
		}
		if !transitionTimeAllowed(state, at) || at.UnixMilli() > runtime.leaseExpiresAtMillis {
			return PreparedContextAbstention{}, ErrRunTransitionLeaseMismatch
		}
		event, err := newPreparedRunEvent(plan, state, runtime, encodedArtifact, identity, failure, at)
		if err != nil {
			return PreparedContextAbstention{}, err
		}
		err = c.journal.Append(ctx, state.HeadIdentity(), event)
		if err == nil {
			return PreparedContextAbstention{event: event}, nil
		}
		if !errors.Is(err, ErrRunJournalHeadConflict) {
			return PreparedContextAbstention{}, err
		}
	}
	return PreparedContextAbstention{}, ErrCoordinatorContention
}

// SettlePreparedContextAbstention is trusted recovery's CAS after verifying the stored artifact.
func (c *Coordinator) SettlePreparedContextAbstention(ctx context.Context, plan ReviewRunPlan, prepared PreparedContextAbstention, at time.Time) (ReviewRunState, error) {
	if err := c.validate(ctx, plan); err != nil {
		return ReviewRunState{}, err
	}
	if prepared.event.Validate() != nil || prepared.event.Kind() != RunEventContextAbstentionPrepared || prepared.PlanIdentity() != plan.Identity() {
		return ReviewRunState{}, ErrPreparedContextAbstention
	}
	for range maxCoordinatorConflicts {
		state, err := c.load(ctx, plan)
		if err != nil {
			return ReviewRunState{}, err
		}
		runtime, ok := state.Task(prepared.TaskKey())
		if !ok || runtime.Definition().Identity() != prepared.TaskIdentity() {
			return ReviewRunState{}, ErrPreparedContextAbstention
		}
		if runtime.Status() == TaskRuntimeFailed && runtime.preparedEventIdentity == prepared.Identity() && runtime.OutputIdentity() == prepared.ArtifactIdentity() && runtime.Failure() == prepared.Failure() {
			return state, nil
		}
		current, ok := runtime.PreparedContextAbstention()
		if !ok || current.Identity() != prepared.Identity() || !transitionTimeAllowed(state, at) {
			return ReviewRunState{}, ErrPreparedContextAbstention
		}
		retry := time.Time{}
		if prepared.Failure().Retryable() && runtime.Attempts() < runtime.Definition().MaxAttempts() {
			retry = at.Add(time.Duration(runtime.Definition().RetryDelayMilliseconds()) * time.Millisecond)
		}
		event, err := NewRunEvent(plan, state.Revision()+1, state.HeadIdentity(), RunEventTaskFailed, runtime.Definition(), runtime.Attempts(), runtime.leaseTokenIdentity, "", time.Time{}, prepared.ArtifactIdentity(), prepared.Failure(), retry, at)
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
