package context

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"strings"

	analysiscodec "github.com/georgejieh/open-trestle/internal/analysiscodec"
	memorycodec "github.com/georgejieh/open-trestle/internal/memorycodec"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
)

func TestOldCodePacketCandidateGoldenWithIndexedMemory(t *testing.T) {
	authority, request, coordinator, store, _, closeFixture, journal := newPacketWriterFixtureVariant(t, false, false, false, false, false, true, false)
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
	golden, err := os.ReadFile("testdata/v11_packet_candidate_envelope.json")
	if err != nil {
		t.Fatal(err)
	}
	expectedDescriptor, err := os.ReadFile("testdata/v11_packet_candidate_descriptor.json")
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

// Capture this fixture only from the real empty-index producer, never from
// expected identities copied out of a prior fixture.
func TestOldCodePacketCandidateGoldenWithZeroHitMemory(t *testing.T) {
	authority, request, coordinator, store, _, closeFixture, journal := newPacketWriterFixtureVariant(t, false, false, false, false, false, false, true)
	defer closeFixture()
	ctx := context.Background()
	at := time.UnixMilli(230)
	scope := request.Plan().Scope()
	memoryOutput, ok := request.DependencyOutput("memory")
	if !ok || !memoryOutput.Available() {
		t.Fatal("STOP: memory producer did not succeed")
	}
	memoryArtifact, err := store.Get(ctx, scope, memoryOutput.OutputIdentity(), at)
	if err != nil {
		t.Fatal(err)
	}
	var producer struct {
		Queries []struct {
			Items []json.RawMessage `json:"items"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(memoryArtifact.Payload(), &producer); err != nil {
		t.Fatal(err)
	}
	if len(producer.Queries) == 0 {
		t.Fatal("STOP: empty index did not emit a query")
	}
	for _, query := range producer.Queries {
		if len(query.Items) != 0 {
			t.Fatal("STOP: empty index produced a memory hit")
		}
	}
	beforeEvents := packetCandidateEvents(t, journal, scope)
	_, state, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	puts := 0
	candidate, err := BuildPacketCandidate(ctx, packetCandidateGetReader{source: blockedPacketStore{Store: store, putCount: &puts}}, request, state, contextTestClock{at}, authority.ownerRoot, at, at)
	if err != nil {
		t.Fatalf("STOP: zero-hit candidate rejected: %v", err)
	}
	value := candidate.Artifact()
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	if value.Kind() != artifact.KindContextPacket || value.MediaType() != "application/json" || value.Origin() != artifact.OriginHost || value.Classification() != artifact.ClassificationConfidential || value.Protection() != artifact.ProtectionProcessPrivate {
		t.Fatal("wrong candidate envelope")
	}
	var packet struct {
		SchemaVersion int `json:"schema_version"`
		Sources       []struct {
			Path    string `json:"path"`
			Content string `json:"content"`
		} `json:"sources"`
		Memory struct {
			Items []json.RawMessage `json:"items"`
		} `json:"memory"`
		AdditionalMemory []struct {
			Items []json.RawMessage `json:"items"`
		} `json:"additional_memory"`
	}
	if err := json.Unmarshal(value.Payload(), &packet); err != nil {
		t.Fatal(err)
	}
	if packet.SchemaVersion != 11 || len(packet.Memory.Items) != 0 || bytes.Contains(value.Payload(), []byte("<redacted>")) {
		t.Fatal("wrong v11 or memory/redaction branch")
	}
	for _, retrieval := range packet.AdditionalMemory {
		if len(retrieval.Items) != 0 {
			t.Fatal("additional memory hit")
		}
	}
	bodies := map[string]string{"a.go": "func Changed() int{return 2}\n", "a_test.go": "func TestChanged(){_=Changed()}\n"}
	if len(packet.Sources) != len(bodies) {
		t.Fatalf("selected source count: %d", len(packet.Sources))
	}
	for _, source := range packet.Sources {
		if source.Content == "" || source.Content != bodies[source.Path] {
			t.Fatalf("selected body changed: %+v", source)
		}
		delete(bodies, source.Path)
	}
	if len(bodies) != 0 {
		t.Fatalf("selected bodies absent: %v", bodies)
	}
	assembly, _, abstention, failure := (&Handler{store: store, packetOnly: true}).assemble(ctx, request, at)
	if failure != 0 || abstention != nil || assembly.InitialContextArtifact.Identity() != value.Identity() {
		t.Fatal("live assembly differs from candidate")
	}
	analysisResult, err := analysiscodec.ParseResultArtifact(assembly.AnalysisArtifact, assembly.ChangeArtifact, assembly.BaseSnapshotArtifact, assembly.HeadSnapshotArtifact)
	if err != nil {
		t.Fatal(err)
	}
	memoryResult, err := memorycodec.ParseResultArtifact(assembly.MemoryArtifact, assembly.ChangeArtifact, assembly.BaseSnapshotArtifact, assembly.HeadSnapshotArtifact)
	if err != nil {
		t.Fatal(err)
	}
	provenance := []string{assembly.AnalysisArtifact.Identity(), assembly.MemoryArtifact.Identity(), assembly.ChangeArtifact.Identity(), assembly.HeadSnapshotArtifact.Identity(), analysisResult.Identity(), memoryResult.Identity()}
	slices.Sort(provenance)
	dependencies := []string{}
	for _, key := range []string{"analysis", "memory"} {
		output, ok := request.DependencyOutput(key)
		if !ok || !output.Available() {
			t.Fatal("missing dependency")
		}
		dependencies = append(dependencies, output.OutputIdentity())
	}
	slices.Sort(dependencies)
	d := candidate.Descriptor()
	if !slices.Equal(value.Provenance(), provenance) || !slices.Equal(d.Provenance, provenance) || !slices.Equal(d.DependencyIdentities, dependencies) || d.ArtifactIdentity != value.Identity() || d.PayloadDigest != value.PayloadDigest() || d.LeaseIdentity != request.Lease().Identity() || d.LeaseEventIdentity != request.Lease().EventIdentity() || d.SourceRootIdentity != authority.ownerRoot || d.SnapshotIdentity != assembly.Snapshot.Identity() || d.SnapshotIdentity == assembly.HeadSnapshotArtifact.Identity() || d.Classification != "confidential" || d.Protection != "process_private" || d.CreatedAtMilliseconds != 230 || d.ExpiresAtMilliseconds != value.ExpiresAt().UnixMilli() {
		t.Fatalf("descriptor/provenance mismatch: %+v", d)
	}
	expires := assembly.AnalysisArtifact.ExpiresAt()
	for _, source := range []artifact.Artifact{assembly.MemoryArtifact, assembly.ChangeArtifact, assembly.BaseSnapshotArtifact, assembly.HeadSnapshotArtifact} {
		if source.ExpiresAt().Before(expires) {
			expires = source.ExpiresAt()
		}
	}
	head, err := sourcehandler.ParseSnapshotArtifact(assembly.HeadSnapshotArtifact)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range head.Files() {
		file, err := store.Get(ctx, scope, ref.ArtifactIdentity(), at)
		if err != nil {
			t.Fatal(err)
		}
		if file.ExpiresAt().Before(expires) {
			expires = file.ExpiresAt()
		}
	}
	if value.ExpiresAt() != expires || expires.UnixMilli() != 120000 || request.Lease().ExpiresAt().UnixMilli() != 30111 || !expires.After(request.Lease().ExpiresAt()) {
		t.Fatalf("observed expiry=%v lease=%v", expires, request.Lease().ExpiresAt())
	}
	afterEvents := packetCandidateEvents(t, journal, scope)
	if len(beforeEvents) != len(afterEvents) {
		t.Fatal("candidate appended journal event")
	}
	for i := range beforeEvents {
		if beforeEvents[i].Identity() != afterEvents[i].Identity() {
			t.Fatal("journal identities changed")
		}
	}
	_, afterState, err := coordinator.Resume(ctx, scope)
	if err != nil || afterState.HeadIdentity() != state.HeadIdentity() {
		t.Fatalf("journal head changed: %v", err)
	}
	runtime, ok := afterState.Task("context")
	if !ok {
		t.Fatal("missing context task")
	}
	if _, prepared := runtime.PreparedContextPacket(); prepared {
		t.Fatal("v4 intent prepared")
	}
	if puts != 0 {
		t.Fatalf("forwarded %d Put calls", puts)
	}
	if _, err := store.Get(ctx, scope, value.Identity(), at); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("persisted candidate: %v", err)
	}
	encoded, err := artifact.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	descriptor, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	for path, actual := range map[string][]byte{"testdata/v11_packet_candidate_zero_hit_envelope.json": encoded, "testdata/v11_packet_candidate_zero_hit_descriptor.json": append(descriptor, '\n')} {
		expected, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, expected) {
			t.Fatalf("old-code full %s changed", strings.TrimPrefix(path, "testdata/"))
		}
	}
}
