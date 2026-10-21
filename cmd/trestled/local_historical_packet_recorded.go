package main

import (
	"context"
	"os"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

type physicalRecordedV4Derivation struct {
	fact    controlplane.HistoricalContextPacketFact
	binding historicalRecordedSourceBinding
}

// observeBorrowedHistoricalRecordedV4Names derives exact names from the same
// eight canonical envelopes whose raw bytes the shared observer postchecks.
// Success is provisional until outer owner/root postchecks and close succeed.
// This proves selected metadata and names, not source-file contents or authority.
func observeBorrowedHistoricalRecordedV4Names(ctx context.Context, borrowed *os.Root, fact controlplane.HistoricalContextPacketFact, binding historicalRecordedSourceBinding) error {
	return observeBorrowedHistoricalRecordedV4NamesWithClose(ctx, borrowed, fact, binding, (*os.File).Close)
}

func observeBorrowedHistoricalRecordedV4NamesWithClose(ctx context.Context, borrowed *os.Root, fact controlplane.HistoricalContextPacketFact, binding historicalRecordedSourceBinding, closeFile func(*os.File) error) error {
	recorded := &physicalRecordedV4Derivation{fact: fact, binding: binding}
	expected, err := recorded.expectations()
	if err != nil {
		return err
	}
	return observeBorrowedHistoricalFilesWithRecorded(ctx, borrowed, expected, nil, closeFile, nil, recorded)
}

func (r *physicalRecordedV4Derivation) expectations() ([]physicalPacketExpectation, error) {
	plan := r.fact.Plan()
	if plan.Validate() != nil {
		return nil, errPhysicalPacketObservationUncertain
	}
	base, baseOK := plan.Task("source-base")
	head, headOK := plan.Task("source-head")
	ancestors := r.fact.TransitiveDependencySuccessEvents()
	keys := []string{"analysis", "change", "memory", "source-base", "source-head"}
	if !baseOK || !headOK || len(ancestors) != len(keys) {
		return nil, errPhysicalPacketObservationUncertain
	}
	for i, key := range keys {
		if ancestors[i].TaskKey() != key || !physicalPacketDigest(ancestors[i].OutputIdentity()) {
			return nil, errPhysicalPacketObservationUncertain
		}
	}
	scope := plan.Scope()
	makeRecorded := func(id string, kind artifact.Kind, origin artifact.Origin) physicalPacketExpectation {
		return physicalPacketExpectation{scope: scope, role: physicalRoleRecorded, recordedIdentity: id, recordedKind: kind, recordedOrigin: origin}
	}
	expected := []physicalPacketExpectation{
		makeRecorded(base.InputIdentity(), artifact.KindTaskInput, artifact.OriginHost),
		makeRecorded(head.InputIdentity(), artifact.KindTaskInput, artifact.OriginHost),
		makeRecorded(ancestors[3].OutputIdentity(), artifact.KindSourceSnapshot, artifact.OriginRepository),
		makeRecorded(ancestors[4].OutputIdentity(), artifact.KindSourceSnapshot, artifact.OriginRepository),
		makeRecorded(ancestors[1].OutputIdentity(), artifact.KindChangeModel, artifact.OriginDeterministicTool),
		makeRecorded(ancestors[0].OutputIdentity(), artifact.KindDeterministicEvidence, artifact.OriginDeterministicTool),
		makeRecorded(ancestors[2].OutputIdentity(), artifact.KindRetrievalResult, artifact.OriginMemory),
		{scope: scope, descriptor: r.fact.PreparedEvent().PacketDescriptor()},
	}
	seen := make(map[string]bool, 8)
	for _, e := range expected {
		id := physicalExpectationIdentity(e)
		if !physicalExpectationValid(e) || seen[id] {
			return nil, errPhysicalPacketObservationUncertain
		}
		seen[id] = true
	}
	return expected, nil
}

func (r *physicalRecordedV4Derivation) restriction(expected []physicalPacketExpectation, parsed map[string]artifact.Artifact) (*physicalExactScopeNames, error) {
	if len(expected) != 8 || len(parsed) != 8 {
		return nil, errPhysicalPacketObservationUncertain
	}
	values := make([]artifact.Artifact, 8)
	for i, e := range expected {
		value, ok := parsed[e.scope.Identity()+"-"+physicalExpectationIdentity(e)+".artifact.json"]
		if !ok {
			return nil, errPhysicalPacketObservationUncertain
		}
		values[i] = value
	}
	a := historicalRecordedV4Artifacts{BaseInput: values[0], HeadInput: values[1], BaseSnapshot: values[2], HeadSnapshot: values[3], Change: values[4], Analysis: values[5], Memory: values[6], Packet: values[7]}
	ids, err := recordedHistoricalV4Names(r.fact, a, r.binding)
	if err != nil {
		return nil, err
	}
	restriction := &physicalExactScopeNames{prefix: r.fact.Plan().Scope().Identity() + "-", names: make(map[string]struct{}, len(ids))}
	for _, id := range ids {
		restriction.names[restriction.prefix+id+".artifact.json"] = struct{}{}
	}
	return restriction, nil
}
