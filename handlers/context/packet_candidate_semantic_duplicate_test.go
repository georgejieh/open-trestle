package context

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	analysiscodec "github.com/georgejieh/open-trestle/internal/analysiscodec"
	changecodec "github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycodec "github.com/georgejieh/open-trestle/internal/memorycodec"
)

// Freeze an unchanged test line with two distinct real semantic references.
func TestOldCodePacketCandidateSemanticDuplicate(t *testing.T) {
	authority, request, coordinator, store, _, closeFixture, journal := newPacketWriterFixtureWithDuplicate(t, false, false, false, false, false, false, true, true)
	defer closeFixture()
	ctx := context.Background()
	scope := request.Plan().Scope()
	at := time.UnixMilli(230)
	_, state, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	output := func(key string) artifact.Artifact {
		t.Helper()
		runtime, ok := state.Task(key)
		if !ok || runtime.OutputIdentity() == "" {
			t.Fatalf("STOP: missing %s producer", key)
		}
		value, err := store.Get(ctx, scope, runtime.OutputIdentity(), at)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	base := output("source-base")
	head := output("source-head")
	change := output("change")
	analysis := output("analysis")
	memory := output("memory")
	changeResult, err := changecodec.ParseResultArtifact(change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if entries := changeResult.Entries(); len(entries) != 1 || entries[0].Path() != "a.go" {
		t.Fatalf("STOP: unexpected actual change entries: %+v", entries)
	}
	analysisResult, err := analysiscodec.ParseResultArtifact(analysis, change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	refs := analysisResult.SemanticImpact().References()
	if len(refs) != 2 || refs[0].Path() != "a_test.go" || refs[1].Path() != "a_test.go" || refs[0].Line() != 2 || refs[1].Line() != 2 || refs[0].Identity() == refs[1].Identity() || refs[0].Column() == refs[1].Column() {
		t.Fatalf("STOP: expected two distinct real same-line references, got %+v", refs)
	}
	memoryResult, err := memorycodec.ParseResultArtifact(memory, change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	if len(memoryResult.Queries()) == 0 {
		t.Fatal("STOP: no real memory query")
	}
	var memoryWire struct {
		Queries []struct {
			Items []json.RawMessage `json:"items"`
		} `json:"queries"`
	}
	if err := json.Unmarshal(memory.Payload(), &memoryWire); err != nil {
		t.Fatal(err)
	}
	if len(memoryWire.Queries) == 0 {
		t.Fatal("STOP: missing memory wire queries")
	}
	for _, query := range memoryWire.Queries {
		if len(query.Items) != 0 {
			t.Fatal("STOP: empty index yielded hits")
		}
	}
	// Verify both actual adapter-backed snapshots preserve the unchanged test line.
	var headTestContent []byte
	var headTestReference sourcehandler.FileReference
	for _, source := range []artifact.Artifact{base, head} {
		snapshot, err := sourcehandler.ParseSnapshotArtifact(source)
		if err != nil {
			t.Fatal(err)
		}
		for _, reference := range snapshot.Files() {
			if reference.Path() != "a_test.go" {
				continue
			}
			fileArtifact, err := store.Get(ctx, scope, reference.ArtifactIdentity(), at)
			if err != nil {
				t.Fatal(err)
			}
			file, err := sourcehandler.ParseFileArtifact(fileArtifact, snapshot, reference)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(file.Content(), []byte("package p\nfunc TestChanged(){_=Changed();_=Changed()}\n")) {
				t.Fatal("STOP: adapter test source changed")
			}
			if source.Identity() == head.Identity() {
				headTestContent, headTestReference = file.Content(), reference
			}
		}
	}
	if len(headTestContent) == 0 {
		t.Fatal("STOP: adapter head test source absent")
	}
	if items := analysisResult.Items(); len(items) != 1 || items[0].Path() != "a.go" {
		t.Fatalf("STOP: unexpected actual analysis items: %+v", items)
	}
	sourceRange, err := evidence.NewSourceRange("a_test.go", 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	repositoryFile, err := evidence.NewRepositoryFile(headTestReference.Path(), headTestContent)
	if err != nil {
		t.Fatal(err)
	}
	slice, ok := physicalLineSlice(headTestContent, 2, 2)
	if !ok {
		t.Fatal("STOP: missing reference line")
	}
	binding, err := evidence.BindSourceSlice(repositoryFile, headTestContent, sourceRange, slice)
	if err != nil {
		t.Fatal(err)
	}
	expectedSourceIDs := map[string]string{"a.go": analysisResult.Items()[0].EvidenceID(), "a_test.go": binding.Identity()}
	before := packetCandidateEvents(t, journal, scope)
	puts := 0
	candidate, err := BuildPacketCandidate(ctx, packetCandidateGetReader{source: blockedPacketStore{Store: store, putCount: &puts}}, request, state, contextTestClock{at}, authority.ownerRoot, at, at)
	if err != nil {
		t.Fatal(err)
	}
	value := candidate.Artifact()
	if err := value.Validate(); err != nil {
		t.Fatal(err)
	}
	if value.Kind() != artifact.KindContextPacket || value.Classification() != artifact.ClassificationConfidential || value.Protection() != artifact.ProtectionProcessPrivate {
		t.Fatal("wrong packet envelope")
	}
	var packet struct {
		SchemaVersion int `json:"schema_version"`
		Sources       []struct {
			SourceID  string `json:"source_id"`
			Stage     string `json:"stage"`
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
			EndLine   int    `json:"end_line"`
			Content   string `json:"content"`
		} `json:"sources"`
		Omissions []struct {
			Path      string `json:"path"`
			StartLine int    `json:"start_line"`
			EndLine   int    `json:"end_line"`
			Reason    string `json:"reason"`
			Count     int    `json:"count"`
		} `json:"source_omissions"`
		Coverage struct {
			Analyzed            int `json:"analyzed"`
			PreselectionOmitted int `json:"preselection_omitted"`
			Available           int `json:"available"`
			Selected            int `json:"selected"`
			Omitted             int `json:"omitted"`
		} `json:"source_coverage"`
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
	if packet.SchemaVersion != 8 || packet.Coverage.Analyzed != 3 || packet.Coverage.PreselectionOmitted != 1 || packet.Coverage.Available != 2 || packet.Coverage.Selected != 2 || packet.Coverage.Omitted != 1 || len(packet.Omissions) != 1 {
		t.Fatalf("STOP: coverage/omission changed: %+v", packet)
	}
	omission := packet.Omissions[0]
	if omission.Path != "a_test.go" || omission.StartLine != 2 || omission.EndLine != 2 || omission.Reason != "semantic_duplicate_source" || omission.Count != 1 {
		t.Fatalf("STOP: duplicate omission changed: %+v", omission)
	}
	if len(packet.Memory.Items) != 0 {
		t.Fatal("memory hits")
	}
	for _, retrieval := range packet.AdditionalMemory {
		if len(retrieval.Items) != 0 {
			t.Fatal("additional memory hits")
		}
	}
	expectedBodies := map[string]struct{ stage, body string }{"a.go": {"changed_hunk", "func Changed() int{return 2}\n"}, "a_test.go": {"direct_reference", "func TestChanged(){_=Changed();_=Changed()}\n"}}
	if len(packet.Sources) != 2 {
		t.Fatalf("source count: %d", len(packet.Sources))
	}
	for _, source := range packet.Sources {
		expected, ok := expectedBodies[source.Path]
		if !ok || source.Stage != expected.stage || source.Content != expected.body || source.SourceID != expectedSourceIDs[source.Path] || source.StartLine != 2 || source.EndLine != 2 {
			t.Fatalf("STOP: source changed: %+v", source)
		}
		delete(expectedBodies, source.Path)
	}
	if len(expectedBodies) != 0 || bytes.Contains(value.Payload(), []byte("<redacted>")) {
		t.Fatal("missing source or redacted payload")
	}
	provenance := []string{analysis.Identity(), memory.Identity(), change.Identity(), head.Identity(), analysisResult.Identity(), memoryResult.Identity()}
	slices.Sort(provenance)
	dependencies := []string{analysis.Identity(), memory.Identity()}
	slices.Sort(dependencies)
	for _, key := range []string{"analysis", "memory"} {
		dependency, ok := request.DependencyOutput(key)
		if !ok || !dependency.Available() || !slices.Contains(dependencies, dependency.OutputIdentity()) {
			t.Fatalf("STOP: missing actual %s dependency", key)
		}
	}
	descriptor := candidate.Descriptor()
	assembly, _, abstention, failure := (&Handler{store: store, packetOnly: true}).assemble(ctx, request, at)
	if failure != 0 || abstention != nil || assembly.InitialContextArtifact.Identity() != value.Identity() {
		t.Fatal("live assembly differs from candidate")
	}
	producerExpiry := analysis.ExpiresAt()
	for _, upstream := range []artifact.Artifact{memory, change, base, head} {
		if upstream.ExpiresAt().Before(producerExpiry) {
			producerExpiry = upstream.ExpiresAt()
		}
	}
	headSnapshot, err := sourcehandler.ParseSnapshotArtifact(head)
	if err != nil {
		t.Fatal(err)
	}
	for _, reference := range headSnapshot.Files() {
		file, err := store.Get(ctx, scope, reference.ArtifactIdentity(), at)
		if err != nil {
			t.Fatal(err)
		}
		if file.ExpiresAt().Before(producerExpiry) {
			producerExpiry = file.ExpiresAt()
		}
	}
	if !value.ExpiresAt().Equal(producerExpiry) {
		t.Fatalf("STOP: candidate expiry differs from producer minimum: %v != %v", value.ExpiresAt(), producerExpiry)
	}
	if !slices.Equal(value.Provenance(), provenance) || len(provenance) != 6 || !slices.Equal(descriptor.Provenance, provenance) || !slices.Equal(descriptor.DependencyIdentities, dependencies) || descriptor.SourceRootIdentity != authority.ownerRoot || descriptor.SnapshotIdentity != assembly.Snapshot.Identity() || descriptor.SnapshotIdentity == head.Identity() || descriptor.LeaseIdentity != request.Lease().Identity() || descriptor.LeaseEventIdentity != request.Lease().EventIdentity() || descriptor.ArtifactIdentity != value.Identity() || descriptor.PayloadDigest != value.PayloadDigest() || descriptor.Classification != "confidential" || descriptor.Protection != "process_private" || descriptor.CreatedAtMilliseconds != 230 || descriptor.ExpiresAtMilliseconds != 120000 || value.ExpiresAt().UnixMilli() != 120000 || request.Lease().ExpiresAt().UnixMilli() != 30111 || !value.ExpiresAt().After(request.Lease().ExpiresAt()) {
		t.Fatalf("STOP: producer identity/expiry changed: %+v", descriptor)
	}
	after := packetCandidateEvents(t, journal, scope)
	if len(before) != len(after) {
		t.Fatal("candidate appended journal event")
	}
	for i := range before {
		if before[i].Identity() != after[i].Identity() {
			t.Fatal("candidate changed journal stream")
		}
	}
	_, afterState, err := coordinator.Resume(ctx, scope)
	if err != nil || afterState.HeadIdentity() != state.HeadIdentity() {
		t.Fatalf("candidate changed journal head: %v", err)
	}
	runtime, ok := afterState.Task("context")
	if !ok {
		t.Fatal("missing context runtime")
	}
	if _, prepared := runtime.PreparedContextPacket(); prepared {
		t.Fatal("candidate prepared v4 packet")
	}
	if puts != 0 {
		t.Fatalf("forwarded backing-store Put calls: %d", puts)
	}
	if _, err := store.Get(ctx, scope, value.Identity(), at); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("candidate persisted: %v", err)
	}
	encoded, err := artifact.Encode(value)
	if err != nil {
		t.Fatal(err)
	}
	descriptorBytes, err := json.MarshalIndent(descriptor, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	goldenPaths := map[string][]byte{"testdata/v8_packet_candidate_semantic_duplicate_envelope.json": encoded, "testdata/v8_packet_candidate_semantic_duplicate_descriptor.json": append(descriptorBytes, '\n')}
	for path, actual := range goldenPaths {
		expected, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(actual, expected) {
			t.Fatalf("old-code static %s differs", path)
		}
	}
	var fixed controlplane.ContextPacketDescriptor
	expectedDescriptor, err := os.ReadFile("testdata/v8_packet_candidate_semantic_duplicate_descriptor.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(expectedDescriptor, &fixed); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fixed, descriptor) {
		t.Fatal("descriptor wire differs")
	}
}
