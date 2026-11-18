package context

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/analysiscodec"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memorycodec"
	"github.com/georgejieh/open-trestle/internal/sourceinput"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

func TestOldCodePacketCandidateRejectsMemoryExpiryBeforeLease(t *testing.T) {
	expiry := time.UnixMilli(30000)
	authority, request, coordinator, store, _, closeFixture, journal := newPacketWriterFixtureWithMemoryExpiry(t, false, false, false, false, false, true, false, expiry)
	defer closeFixture()
	ctx := context.Background()
	scope := request.Plan().Scope()
	at := time.UnixMilli(230)
	clock := contextTestClock{at}
	plan, state, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	if request.Validate() != nil || request.Task().Kind() != controlplane.TaskAssembleContext || request.Task().HandlerIdentity() != PacketAuthorityHandlerIdentity() || request.Task().MaxAttempts() != 1 || !equalStrings(request.Task().Dependencies(), []string{"analysis", "memory"}) || state.Validate() != nil || state.Status() != controlplane.ReviewRunActive || plan.Identity() != request.Plan().Identity() || state.Plan().Identity() != plan.Identity() || state.Plan().Scope().Identity() != scope.Identity() || !validDigest(authority.ownerRoot) || !at.Before(request.Lease().ExpiresAt()) || request.Lease().ExpiresAt().UnixMilli() != 30111 {
		t.Fatal("STOP: invalid active producer request/state/lease")
	}
	output := func(key string) artifact.Artifact {
		t.Helper()
		runtime, ok := state.Task(key)
		if !ok || runtime.Status() != controlplane.TaskRuntimeSucceeded || runtime.OutputIdentity() == "" {
			t.Fatalf("STOP: %s producer did not succeed", key)
		}
		value, err := store.Get(ctx, scope, runtime.OutputIdentity(), at)
		if err != nil || value.Identity() != runtime.OutputIdentity() || value.Validate() != nil {
			t.Fatalf("STOP: %s producer artifact mismatch: %v", key, err)
		}
		return value
	}
	base, head := output("source-base"), output("source-head")
	change, analysis, memory := output("change"), output("analysis"), output("memory")
	if !memory.ExpiresAt().Equal(expiry) || !expiry.After(at) || !expiry.Before(request.Lease().ExpiresAt()) {
		t.Fatal("STOP: memory output does not cross the live context lease")
	}
	for _, value := range []artifact.Artifact{base, head, change, analysis} {
		if !value.ExpiresAt().After(expiry) || value.ExpiresAt().UnixMilli() != 120000 {
			t.Fatal("STOP: memory is not the unique earliest producer expiry")
		}
	}
	// Git commits supply revision identities; acquisition uses the map-backed adapter.
	var baseRevision, headRevision string
	for _, source := range []struct {
		key   string
		value artifact.Artifact
		body  string
	}{{"source-base", base, "package p\nfunc Changed() int{return 1}\n"}, {"source-head", head, "package p\nfunc Changed() int{return 2}\n"}} {
		snapshot, err := sourceoutput.ParseSnapshotArtifact(source.value)
		if err != nil || len(snapshot.Files()) != 3 {
			t.Fatalf("STOP: invalid %s snapshot: %v", source.key, err)
		}
		task, ok := plan.Task(source.key)
		if !ok {
			t.Fatal("STOP: source input task absent")
		}
		inputArtifact, err := store.Get(ctx, scope, task.InputIdentity(), at)
		if err != nil || inputArtifact.Identity() != task.InputIdentity() || inputArtifact.ExpiresAt().UnixMilli() != 120000 || !inputArtifact.ExpiresAt().After(expiry) {
			t.Fatalf("STOP: invalid %s source input artifact: %v", source.key, err)
		}
		input, err := sourceinput.ParseInput(inputArtifact.Payload())
		if err != nil || input.SchemaVersion() != 2 || input.SourceRootIdentity() != authority.ownerRoot || input.Repository().Identity() != snapshot.RepositoryIdentity() || input.SourceAdapterIdentity() != snapshot.SourceAdapterIdentity() || input.Revision().Identity() != snapshot.RevisionIdentity() || input.Revision().Kind() != evidence.RevisionKindGitCommit || input.Revision().Algorithm() != evidence.RevisionAlgorithmSHA1 {
			t.Fatalf("STOP: invalid %s bound source chain: %v", source.key, err)
		}
		if source.key == "source-base" {
			baseRevision = input.Revision().Digest()
		} else {
			headRevision = input.Revision().Digest()
		}
		foundChangedPath := false
		for _, reference := range snapshot.Files() {
			fileArtifact, err := store.Get(ctx, scope, reference.ArtifactIdentity(), at)
			if err != nil || fileArtifact.ExpiresAt().UnixMilli() != 120000 || !fileArtifact.ExpiresAt().After(expiry) {
				t.Fatalf("STOP: source file does not outlive memory: %v", err)
			}
			file, err := sourceoutput.ParseFileArtifact(fileArtifact, snapshot, reference)
			if err != nil {
				t.Fatalf("STOP: source file parse: %v", err)
			}
			if reference.Path() == "a.go" {
				foundChangedPath = true
				if !bytes.Equal(file.Content(), []byte(source.body)) {
					t.Fatal("STOP: map-backed changed source differs")
				}
			}
		}
		if !foundChangedPath {
			t.Fatal("STOP: changed path absent from source snapshot")
		}
	}
	if baseRevision == "" || headRevision == "" || baseRevision == headRevision {
		t.Fatal("STOP: distinct Git revision identities absent")
	}
	changeResult, err := changecodec.ParseResultArtifact(change, base, head)
	if err != nil {
		t.Fatalf("STOP: change output parse: %v", err)
	}
	if entries := changeResult.Entries(); len(entries) != 1 || entries[0].Path() != "a.go" {
		t.Fatal("STOP: actual change is not a.go")
	}
	analysisResult, err := analysiscodec.ParseResultArtifact(analysis, change, base, head)
	if err != nil {
		t.Fatalf("STOP: analysis output parse: %v", err)
	}
	if items := analysisResult.Items(); len(items) != 1 || items[0].Path() != "a.go" {
		t.Fatal("STOP: actual analysis is not a.go")
	}
	memoryResult, err := memorycodec.ParseResultArtifact(memory, change, base, head)
	if err != nil {
		t.Fatalf("STOP: memory output parse: %v", err)
	}
	memoryScope, err := memoryResult.MemoryScope()
	if err != nil || memoryResult.AsOf().UnixMilli() != 220 || len(memoryResult.Queries()) != 1 {
		t.Fatalf("STOP: unexpected memory query scope/time/count: %v", err)
	}
	query := memoryResult.Queries()[0]
	retrieval, err := query.Retrieval(memoryScope, memoryResult.AsOf())
	if err != nil || query.Path() != "a.go" || query.Identity() == "" || retrieval.Identity() != query.RetrievalIdentity() || len(query.Items()) != 1 {
		t.Fatalf("STOP: actual indexed a.go retrieval absent: %v", err)
	}
	item := query.Items()[0]
	record, err := item.Record(memoryScope)
	if err != nil || record.Identity() != item.RecordIdentity() || record.Path() != "a.go" || record.ValidUntilUnixMilliseconds() != 30000 || record.ObservedAtUnixMilliseconds() != 10 || record.ValidFromUnixMilliseconds() != 10 || !record.FreshAt(at) {
		t.Fatalf("STOP: actual a.go memory record expiry differs: %v", err)
	}
	for _, key := range []string{"analysis", "memory"} {
		dependency, ok := request.DependencyOutput(key)
		runtime, _ := state.Task(key)
		if !ok || !dependency.Available() || dependency.OutputIdentity() != runtime.OutputIdentity() {
			t.Fatalf("STOP: actual %s request dependency mismatch", key)
		}
	}
	snapshotEffects := func() ([]controlplane.RunEvent, controlplane.ReviewRunState) {
		t.Helper()
		events := packetCandidateEvents(t, journal, scope)
		if len(events) >= 100 {
			t.Fatal("STOP: effect snapshot may be truncated")
		}
		_, current, err := coordinator.Resume(ctx, scope)
		if err != nil {
			t.Fatal(err)
		}
		runtime, ok := current.Task("context")
		if !ok || runtime.Status() != controlplane.TaskRuntimeLeased || runtime.OutputIdentity() != "" {
			t.Fatal("context lease/output changed")
		}
		if _, prepared := runtime.PreparedContextPacket(); prepared {
			t.Fatal("read-only call prepared context packet")
		}
		return events, current
	}
	puts := 0
	reader := packetCandidateGetReader{source: blockedPacketStore{Store: store, putCount: &puts}}
	beforeEvents, beforeState := snapshotEffects()
	if !reflect.DeepEqual(beforeState, state) {
		t.Fatal("STOP: producer state changed before rebuild")
	}
	assertEffects := func(window string, events []controlplane.RunEvent, prior controlplane.ReviewRunState, expectedID string) ([]controlplane.RunEvent, controlplane.ReviewRunState) {
		t.Helper()
		afterEvents, afterState := snapshotEffects()
		if !reflect.DeepEqual(events, afterEvents) || afterState.HeadIdentity() != prior.HeadIdentity() || !reflect.DeepEqual(prior, afterState) {
			t.Fatalf("%s changed decoded events or coordinator state/head", window)
		}
		if puts != 0 {
			t.Fatalf("%s forwarded backing-store Put calls: %d", window, puts)
		}
		if _, err := store.Get(ctx, scope, expectedID, at); !errors.Is(err, artifact.ErrArtifactNotFound) {
			t.Fatalf("%s persisted read-only rebuild packet: %v", window, err)
		}
		return afterEvents, afterState
	}
	built, err := (packetAssembler{store: readOnlyPacketStore{reader: reader}, clock: clock, ownerRoot: authority.ownerRoot}).rebuild(ctx, request, state, at, at)
	if err != nil {
		t.Fatalf("STOP: same-input read-only rebuild failed before candidate lease fence: %v", err)
	}
	value := built.value
	provenance := []string{analysis.Identity(), memory.Identity(), change.Identity(), head.Identity(), analysisResult.Identity(), memoryResult.Identity()}
	slices.Sort(provenance)
	if err := value.Validate(); err != nil {
		t.Fatalf("STOP: rebuilt packet validation failed: %v", err)
	}
	if value.Kind() != artifact.KindContextPacket {
		t.Fatalf("STOP: rebuilt packet kind=%s", value.Kind())
	}
	if value.Protection() != artifact.ProtectionProcessPrivate {
		t.Fatalf("STOP: rebuilt packet protection=%s", value.Protection())
	}
	if !value.CreatedAt().Equal(at) {
		t.Fatalf("STOP: rebuilt packet created-at=%v, expected=%v", value.CreatedAt(), at)
	}
	if !value.ExpiresAt().Equal(expiry) || !value.ExpiresAt().Before(request.Lease().ExpiresAt()) {
		t.Fatalf("STOP: rebuilt packet expiry=%v, expected=%v before lease=%v", value.ExpiresAt(), expiry, request.Lease().ExpiresAt())
	}
	if built.root != authority.ownerRoot {
		t.Fatalf("STOP: rebuilt source root=%s, expected=%s", built.root, authority.ownerRoot)
	}
	if !validDigest(built.snapshot) {
		t.Fatalf("STOP: invalid rebuilt snapshot identity=%s", built.snapshot)
	}
	if !slices.Equal(value.Provenance(), provenance) {
		t.Fatalf("STOP: rebuilt provenance=%v, expected=%v", value.Provenance(), provenance)
	}
	if !clock.Now().Before(request.Lease().ExpiresAt()) {
		t.Fatalf("STOP: rebuild clock=%v reached lease=%v", clock.Now(), request.Lease().ExpiresAt())
	}
	if err := ctx.Err(); err != nil {
		t.Fatalf("STOP: rebuild context canceled: %v", err)
	}
	t.Logf("created-at comparison: packet=%d input=%d Equal=%v structEqual=%v packetLocation=%s inputLocation=%s", value.CreatedAt().UnixMilli(), at.UnixMilli(), value.CreatedAt().Equal(at), value.CreatedAt() == at, value.CreatedAt().Location(), at.Location())
	afterRebuildEvents, afterRebuildState := assertEffects("read-only rebuild", beforeEvents, beforeState, value.Identity())
	candidate, err := BuildPacketCandidate(ctx, reader, request, state, clock, authority.ownerRoot, at, at)
	if !errors.Is(err, ErrPacketAuthority) {
		t.Fatalf("candidate accepted packet expiry 30000 before lease 30111: %v", err)
	}
	if candidate.Artifact().Identity() != "" || candidate.Descriptor().ArtifactIdentity != "" || !reflect.DeepEqual(candidate, PacketCandidate{}) {
		t.Fatal("rejected build returned a candidate")
	}
	assertEffects("rejected candidate", afterRebuildEvents, afterRebuildState, value.Identity())
	t.Logf("map-backed producer: base Git revision=%s head Git revision=%s memory output=%s record=%s valid-until=30000", baseRevision, headRevision, memory.Identity(), record.Identity())
	t.Logf("same-input rebuild succeeded: packet=%s expiry=30000 lease=30111; candidate=zero ErrPacketAuthority; decoded events=%d head=%s forwarded Put=%d packet absent", value.Identity(), len(beforeEvents), state.HeadIdentity(), puts)
}
