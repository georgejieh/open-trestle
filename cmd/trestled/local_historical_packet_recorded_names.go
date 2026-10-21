package main

import (
	"errors"
	"slices"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	"github.com/georgejieh/open-trestle/internal/analysiscodec"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memorycodec"
	"github.com/georgejieh/open-trestle/internal/sourceinput"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

var errHistoricalRecordedV4Names = errors.New("recorded v4 names unavailable")

type historicalRecordedSourceBinding struct {
	RootIdentity, RepositoryIdentity, AdapterIdentity string
}

func (b historicalRecordedSourceBinding) valid() bool {
	return physicalPacketDigest(b.RootIdentity) && physicalPacketDigest(b.RepositoryIdentity) && physicalPacketDigest(b.AdapterIdentity)
}

type historicalRecordedV4Artifacts struct {
	BaseInput, HeadInput, BaseSnapshot, HeadSnapshot artifact.Artifact
	Change, Analysis, Memory, Packet                 artifact.Artifact
}

// recordedHistoricalV4Names derives names from recorded metadata, not ownership
// or source-file integrity. Source binding is required caller-supplied metadata.
// Current pipeline enrollment is checked separately.
// Canonical physical reads and their final witnesses remain the caller's job.
func recordedHistoricalV4Names(fact controlplane.HistoricalContextPacketFact, a historicalRecordedV4Artifacts, binding historicalRecordedSourceBinding) ([]string, error) {
	if fact.ExpiryTail() != controlplane.ContextPacketExpiryTailActiveExactV4 && fact.ExpiryTail() != controlplane.ContextPacketExpiryTailExpiredV4PolicyTerminated {
		return nil, errHistoricalRecordedV4Names
	}
	if _, ok := fact.LinkedInputEvent(); ok {
		return nil, errHistoricalRecordedV4Names
	}
	return recordedHistoricalAncestorNames(fact, a, binding)
}

// recordedHistoricalAncestorNames checks the common recorded source lineage.
// Callers must separately prove their exact journal suffix and scope name set.
func recordedHistoricalAncestorNames(fact controlplane.HistoricalContextPacketFact, a historicalRecordedV4Artifacts, binding historicalRecordedSourceBinding) ([]string, error) {
	plan, prepared := fact.Plan(), fact.PreparedEvent()
	if !binding.valid() || !recordedV4PlanShape(plan) || prepared.Validate() != nil || prepared.Kind() != controlplane.RunEventContextPacketPrepared || prepared.TaskKey() != "context" || prepared.Attempt() != 1 || prepared.PlanIdentity() != plan.Identity() || prepared.Scope() != plan.Scope() {
		return nil, errHistoricalRecordedV4Names
	}
	contextTask, _ := plan.Task("context")
	lease := fact.LeaseEvent()
	if prepared.TaskIdentity() != contextTask.Identity() || lease.Validate() != nil || (lease.Kind() != controlplane.RunEventTaskLeased && lease.Kind() != controlplane.RunEventTaskLeaseRenewed) || lease.Attempt() != 1 || lease.TaskIdentity() != prepared.TaskIdentity() || lease.LeaseTokenIdentity() != prepared.LeaseTokenIdentity() || lease.Identity() != prepared.PacketDescriptor().LeaseEventIdentity || prepared.PacketDescriptor().SourceRootIdentity != binding.RootIdentity {
		return nil, errHistoricalRecordedV4Names
	}
	ancestors := fact.TransitiveDependencySuccessEvents()
	keys := []string{"analysis", "change", "memory", "source-base", "source-head"}
	outputs := []artifact.Artifact{a.Analysis, a.Change, a.Memory, a.BaseSnapshot, a.HeadSnapshot}
	if len(ancestors) != len(keys) {
		return nil, errHistoricalRecordedV4Names
	}
	for i, key := range keys {
		task, _ := plan.Task(key)
		event := ancestors[i]
		if event.Validate() != nil || event.Kind() != controlplane.RunEventTaskSucceeded || event.TaskKey() != key || event.TaskIdentity() != task.Identity() || event.Attempt() != 1 || event.PlanIdentity() != plan.Identity() || event.Scope() != plan.Scope() || event.Sequence() >= prepared.Sequence() || event.OutputIdentity() != outputs[i].Identity() {
			return nil, errHistoricalRecordedV4Names
		}
	}
	direct := fact.UpstreamSuccessEvents()
	if len(direct) != 2 || direct[0].Identity() != ancestors[0].Identity() || direct[1].Identity() != ancestors[2].Identity() {
		return nil, errHistoricalRecordedV4Names
	}
	values := []artifact.Artifact{a.BaseInput, a.HeadInput, a.BaseSnapshot, a.HeadSnapshot, a.Change, a.Analysis, a.Memory, a.Packet}
	names := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value.Validate() != nil || value.Scope() != plan.Scope() || value.Protection() != artifact.ProtectionProcessPrivate || value.Classification() != a.Packet.Classification() || value.ExpiresAt().Before(a.Packet.ExpiresAt()) {
			return nil, errHistoricalRecordedV4Names
		}
		if _, collision := names[value.Identity()]; collision {
			return nil, errHistoricalRecordedV4Names
		}
		names[value.Identity()] = struct{}{}
	}
	expectation := physicalPacketExpectation{scope: plan.Scope(), descriptor: prepared.PacketDescriptor()}
	if !physicalExpectationValid(expectation) || !physicalPacketMatches(a.Packet, expectation) || prepared.OutputIdentity() != a.Packet.Identity() {
		return nil, errHistoricalRecordedV4Names
	}
	base, err := sourceoutput.ParseSnapshotArtifact(a.BaseSnapshot)
	if err != nil {
		return nil, errHistoricalRecordedV4Names
	}
	head, err := sourceoutput.ParseSnapshotArtifact(a.HeadSnapshot)
	if err != nil {
		return nil, errHistoricalRecordedV4Names
	}
	var previous sourceinput.Input
	for i, pair := range []struct {
		key           string
		input, output artifact.Artifact
		snapshot      sourceoutput.Snapshot
	}{
		{"source-base", a.BaseInput, a.BaseSnapshot, base}, {"source-head", a.HeadInput, a.HeadSnapshot, head},
	} {
		task, _ := plan.Task(pair.key)
		if pair.input.Identity() != task.InputIdentity() || pair.input.Kind() != artifact.KindTaskInput || pair.input.Origin() != artifact.OriginHost || pair.input.MediaType() != "application/json" || !slices.Equal(pair.input.Provenance(), []string{plan.RequestIdentity()}) {
			return nil, errHistoricalRecordedV4Names
		}
		input, parseErr := sourceinput.ParseInput(pair.input.Payload())
		if parseErr != nil || input.SchemaVersion() != 2 || input.SourceRootIdentity() != binding.RootIdentity || input.Repository().Identity() != binding.RepositoryIdentity || input.SourceAdapterIdentity() != binding.AdapterIdentity || input.Repository().Identity() != pair.snapshot.RepositoryIdentity() || input.Revision().Identity() != pair.snapshot.RevisionIdentity() || input.SourceAdapterIdentity() != pair.snapshot.SourceAdapterIdentity() || !slices.Equal(pair.output.Provenance(), recordedV4Sorted(pair.input.Identity(), pair.snapshot.AcquisitionExecutionIdentity())) {
			return nil, errHistoricalRecordedV4Names
		}
		acquisition, makeErr := evidence.NewRepositoryAcquisitionRequest(input.Repository(), input.Revision(), input.Adapter(), evidence.AcquisitionArtifactManifestAndContent, evidence.AcquisitionEffectReadOnly)
		if makeErr != nil || acquisition.Identity() != pair.snapshot.AcquisitionRequestIdentity() {
			return nil, errHistoricalRecordedV4Names
		}
		if i > 0 && (previous.Repository().Identity() != input.Repository().Identity() || previous.SourceAdapterIdentity() != input.SourceAdapterIdentity() || previous.Revision().Identity() == input.Revision().Identity()) {
			return nil, errHistoricalRecordedV4Names
		}
		previous = input
	}
	change, err := changecodec.ParseResultArtifact(a.Change, a.BaseSnapshot, a.HeadSnapshot)
	if err != nil {
		return nil, errHistoricalRecordedV4Names
	}
	analysis, err := analysiscodec.ParseResultArtifact(a.Analysis, a.Change, a.BaseSnapshot, a.HeadSnapshot)
	if err != nil {
		return nil, errHistoricalRecordedV4Names
	}
	memory, err := memorycodec.ParseResultArtifact(a.Memory, a.Change, a.BaseSnapshot, a.HeadSnapshot)
	if err != nil || memory.PolicyIdentity() != plan.PolicyIdentity() {
		return nil, errHistoricalRecordedV4Names
	}
	provenance := recordedV4Sorted(a.Analysis.Identity(), a.Memory.Identity(), a.Change.Identity(), a.HeadSnapshot.Identity(), analysis.Identity(), memory.Identity())
	if !slices.Equal(a.Packet.Provenance(), provenance) || change.BaseSnapshotIdentity() != base.Identity() || change.HeadSnapshotIdentity() != head.Identity() {
		return nil, errHistoricalRecordedV4Names
	}
	if err := recordedV4AddSourceNames(names, base.Files(), head.Files()); err != nil {
		return nil, err
	}
	result := make([]string, 0, len(names))
	for name := range names {
		result = append(result, name)
	}
	slices.Sort(result)
	return result, nil
}

func recordedV4PlanShape(plan controlplane.ReviewRunPlan) bool {
	if runtimecatalog.ValidatePreparedReviewPlanTaskInputs(plan) != nil || len(plan.Tasks()) != 9 {
		return false
	}
	recipe := []struct {
		key  string
		kind controlplane.TaskKind
		deps []string
	}{
		{"source-base", controlplane.TaskAcquireSource, nil}, {"source-head", controlplane.TaskAcquireSource, nil},
		{"change", controlplane.TaskBuildChange, []string{"source-base", "source-head"}},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}},
		{"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}},
		{"candidates", controlplane.TaskGenerateCandidates, []string{"context"}},
		{"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}},
		{"readiness", controlplane.TaskEvaluatePublication, []string{"analysis", "change", "verification"}},
	}
	for _, spec := range recipe {
		task, ok := plan.Task(spec.key)
		attempt, err := controlplane.DefaultTaskAttemptPolicy(spec.kind)
		if !ok || err != nil || task.Kind() != spec.kind || !task.Required() || !slices.Equal(task.Dependencies(), spec.deps) || task.MaxAttempts() != attempt.MaximumAttempts() || task.RetryDelayMilliseconds() != attempt.RetryDelayMilliseconds() || task.LeaseDurationMilliseconds() != attempt.LeaseDurationMilliseconds() {
			return false
		}
	}
	task, _ := plan.Task("context")
	return task.HandlerIdentity() == contexthandler.PacketAuthorityHandlerIdentity()
}

// validateEnrolledCatalog compares against the caller's CURRENT enrolled pipeline.
// It does not establish where that catalog came from.
func validateEnrolledCatalog(plan controlplane.ReviewRunPlan, catalog runtimecatalog.PipelineCatalog) error {
	if !recordedV4PlanShape(plan) || catalog.Validate() != nil || catalog.Mode() != controlplane.ReviewRunLocal || len(catalog.Bindings()) != 8 {
		return errHistoricalRecordedV4Names
	}
	bindings := make(map[controlplane.TaskKind]string, 8)
	for _, binding := range catalog.Bindings() {
		bindings[binding.Kind] = binding.HandlerIdentity
	}
	for _, task := range plan.Tasks() {
		if task.HandlerIdentity() != bindings[task.Kind()] {
			return errHistoricalRecordedV4Names
		}
	}
	return nil
}

func recordedV4Sorted(ids ...string) []string { slices.Sort(ids); return ids }

// Source-file leaves contribute asserted names only, never parsed contents.
func recordedV4AddSourceNames(names map[string]struct{}, groups ...[]sourceoutput.FileReference) error {
	refs := make(map[string]sourceoutput.FileReference)
	for _, group := range groups {
		for _, ref := range group {
			id := ref.ArtifactIdentity()
			if !physicalPacketDigest(id) {
				return errHistoricalRecordedV4Names
			}
			if prior, exists := refs[id]; exists {
				if prior.Path() != ref.Path() || prior.Digest() != ref.Digest() || prior.SizeBytes() != ref.SizeBytes() {
					return errHistoricalRecordedV4Names
				}
				continue
			}
			if _, collision := names[id]; collision {
				return errHistoricalRecordedV4Names
			}
			if len(names) >= physicalPacketEntryLimit-1 {
				return errHistoricalRecordedV4Names
			}
			refs[id] = ref
			names[id] = struct{}{}
		}
	}
	return nil
}
