package context

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestOldCodePacketCandidateGoldenWithIndexedMemory(t *testing.T) {
	authority, request, coordinator, store, _, closeFixture, journal := newPacketWriterFixtureVariant(t, false, false, false, false, false, true)
	defer closeFixture()
	ctx := context.Background()
	at := time.UnixMilli(230)
	scope := request.Plan().Scope()
	memoryOutput, ok := request.DependencyOutput("memory")
	if !ok || !memoryOutput.Available() {
		t.Fatal("actual memory task did not succeed")
	}
	memoryArtifact, err := store.Get(ctx, scope, memoryOutput.OutputIdentity(), at)
	if err != nil {
		t.Fatal(err)
	}
	var producer struct {
		Queries []struct {
			Items []struct {
				Path string `json:"path"`
				Text string `json:"text"`
			} `json:"items"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(memoryArtifact.Payload(), &producer); err != nil {
		t.Fatal(err)
	}
	producerItems := 0
	for _, query := range producer.Queries {
		for _, item := range query.Items {
			if item.Path != "a.go" || item.Text != "this path has a parser invariant" {
				t.Fatalf("unexpected actual memory item: %+v", item)
			}
			producerItems++
		}
	}
	if producerItems == 0 {
		t.Fatal("STOP: real memory producer has no queries[].items")
	}
	beforeEvents := packetCandidateEvents(t, journal, scope)
	_, state, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	packetPuts := 0
	candidate, err := BuildPacketCandidate(ctx, packetCandidateGetReader{source: blockedPacketStore{Store: store, putCount: &packetPuts}}, request, state, contextTestClock{at}, authority.ownerRoot, at, at)
	if err != nil {
		t.Fatal(err)
	}
	if err := candidate.Artifact().Validate(); err != nil {
		t.Fatal(err)
	}
	var packet struct {
		Sources []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		} `json:"sources"`
		Memory struct {
			Items []struct {
				Path string `json:"path"`
				Text string `json:"text"`
			} `json:"items"`
		} `json:"memory"`
		AdditionalMemory []struct {
			Items []struct {
				Path string `json:"path"`
				Text string `json:"text"`
			} `json:"items"`
		} `json:"additional_memory"`
	}
	if err := json.Unmarshal(candidate.Artifact().Payload(), &packet); err != nil {
		t.Fatal(err)
	}
	packetItems := append([]struct {
		Path string `json:"path"`
		Text string `json:"text"`
	}{}, packet.Memory.Items...)
	for _, retrieval := range packet.AdditionalMemory {
		packetItems = append(packetItems, retrieval.Items...)
	}
	if len(packetItems) == 0 {
		t.Fatal("STOP: candidate has no memory/retrieval entries")
	}
	if len(packetItems) != producerItems {
		t.Fatalf("packet items %d != actual producer %d", len(packetItems), producerItems)
	}
	for _, item := range packetItems {
		if item.Path != "a.go" || item.Text != "this path has a parser invariant" {
			t.Fatalf("body was redacted or changed: %+v", item)
		}
	}
	sourceBodies := map[string]string{"a.go": "func Changed() int{return 2}\n", "a_test.go": "func TestChanged(){_=Changed()}\n"}
	if len(packet.Sources) != len(sourceBodies) {
		t.Fatalf("unexpected selected sources: %+v", packet.Sources)
	}
	for _, source := range packet.Sources {
		if source.Content != sourceBodies[source.Path] || source.Content == "" {
			t.Fatalf("source body was redacted or changed: %+v", source)
		}
	}
	if bytes.Contains(candidate.Artifact().Payload(), []byte("<redacted>")) {
		t.Fatal("candidate payload has redaction placeholder")
	}
	afterEvents := packetCandidateEvents(t, journal, scope)
	if len(beforeEvents) != len(afterEvents) {
		t.Fatal("candidate appended to journal")
	}
	for i := range beforeEvents {
		if beforeEvents[i].Identity() != afterEvents[i].Identity() {
			t.Fatal("candidate changed journal")
		}
	}
	_, afterState, err := coordinator.Resume(ctx, scope)
	if err != nil || afterState.HeadIdentity() != state.HeadIdentity() {
		t.Fatalf("candidate changed state: %v", err)
	}
	runtime, ok := afterState.Task("context")
	if !ok {
		t.Fatal("missing context runtime")
	}
	if _, prepared := runtime.PreparedContextPacket(); prepared {
		t.Fatal("candidate prepared packet")
	}
	if packetPuts != 0 {
		t.Fatalf("candidate forwarded %d packet Put calls", packetPuts)
	}
	if _, err := store.Get(ctx, scope, candidate.Artifact().Identity(), at); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("candidate wrote packet artifact: %v", err)
	}
	encoded, err := artifact.Encode(candidate.Artifact())
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := json.MarshalIndent(candidate.Descriptor(), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	golden, err := os.ReadFile("testdata/old_packet_candidate_envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	expectedDescriptor, err := os.ReadFile("testdata/old_packet_candidate_descriptor.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixed controlplane.ContextPacketDescriptor
	if err := json.Unmarshal(expectedDescriptor, &fixed); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, golden) {
		t.Fatal("old-code full artifact.Encode envelope changed")
	}
	if !reflect.DeepEqual(candidate.Descriptor(), fixed) || !bytes.Equal(append(descriptor, '\n'), expectedDescriptor) {
		t.Fatalf("old-code full descriptor changed: got %+v want %+v", candidate.Descriptor(), fixed)
	}
}
