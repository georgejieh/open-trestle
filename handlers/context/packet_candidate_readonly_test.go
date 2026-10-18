package context

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/testsupport"
)

// This reader deliberately exposes no Put method to the candidate builder.
type packetCandidateGetReader struct {
	source artifact.Store
}

func (r packetCandidateGetReader) Get(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (artifact.Artifact, error) {
	return r.source.Get(ctx, scope, identity, at)
}

func packetCandidateEvents(t *testing.T, journal controlplane.RunJournal, scope audit.ReviewScope) []controlplane.RunEvent {
	t.Helper()
	events, err := journal.Read(context.Background(), scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Kind() == controlplane.RunEventContextPacketPrepared {
			t.Fatal("fixture already has a v4 prepared event")
		}
	}
	return events
}

func TestBuildPacketCandidateMatchesUnwiredPrepareWithoutWriting(t *testing.T) {
	authority, request, coordinator, store, _, closeFixture, journal := newPacketWriterFixture(t, false, false, false, false, false)
	defer closeFixture()
	ctx := context.Background()
	scope := request.Plan().Scope()
	at := time.UnixMilli(230)
	beforeEvents := packetCandidateEvents(t, journal, scope)
	_, state, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}

	candidate, err := BuildPacketCandidate(ctx, packetCandidateGetReader{source: store}, request, state, contextTestClock{at}, authority.ownerRoot, at, at)
	if err != nil {
		t.Fatal(err)
	}
	expected := candidate.Artifact()
	descriptor := candidate.Descriptor()
	packet, snapshot := candidate.Packet(), candidate.Snapshot()
	providerRequest, requestErr := packet.ProviderRequest()
	if requestErr != nil || packet.Identity() == "" || snapshot.Identity() != descriptor.SnapshotIdentity || packet.SnapshotIdentity() != snapshot.Identity() || packet.ReviewScopeIdentity() != scope.Identity() || !bytes.Equal(providerRequest.Payload(), expected.Payload()) {
		t.Fatalf("candidate omitted its source-bound typed packet: %v", requestErr)
	}
	if expected.Validate() != nil || descriptor.ArtifactIdentity != expected.Identity() || descriptor.PayloadDigest != expected.PayloadDigest() || descriptor.SourceRootIdentity != authority.ownerRoot || descriptor.SnapshotIdentity == "" {
		t.Fatal("candidate does not describe its full packet artifact")
	}
	afterEvents := packetCandidateEvents(t, journal, scope)
	if len(afterEvents) != len(beforeEvents) {
		t.Fatal("read-only builder appended a journal event")
	}
	for i := range beforeEvents {
		if beforeEvents[i].Identity() != afterEvents[i].Identity() {
			t.Fatal("read-only builder changed the journal history")
		}
	}
	_, afterState, err := coordinator.Resume(ctx, scope)
	if err != nil || afterState.HeadIdentity() != state.HeadIdentity() {
		t.Fatalf("read-only builder changed the current head: %v", err)
	}
	runtime, ok := afterState.Task("context")
	if !ok {
		t.Fatal("missing context task")
	}
	if _, prepared := runtime.PreparedContextPacket(); prepared {
		t.Fatal("read-only builder prepared a durable packet")
	}
	if _, err := store.Get(ctx, scope, expected.Identity(), at); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("read-only builder wrote packet bytes: %v", err)
	}

	prepared, err := authority.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(descriptor, prepared.Descriptor()) {
		t.Fatal("candidate descriptor differs from unwired Prepare")
	}
	stored, err := store.Get(ctx, scope, expected.Identity(), at)
	if err != nil || !samePacketArtifact(expected, stored) {
		t.Fatalf("candidate envelope differs from stored packet: %v", err)
	}
	encodedCandidate, err := artifact.Encode(expected)
	if err != nil {
		t.Fatal(err)
	}
	encodedStored, err := artifact.Encode(stored)
	if err != nil || !bytes.Equal(encodedCandidate, encodedStored) {
		t.Fatalf("full encoded packet envelopes differ: %v", err)
	}
	events, err := journal.Read(ctx, scope, 0, 100)
	if err != nil || len(events) != len(beforeEvents)+1 || events[len(events)-1].Identity() != prepared.Identity() || events[len(events)-1].Kind() != controlplane.RunEventContextPacketPrepared {
		t.Fatalf("unwired Prepare did not append exactly one v4 event: %v", err)
	}
}

type changingIdentitySanitizer struct {
	testsupport.CleanGenerationSanitizer
	identity string
}

func (s *changingIdentitySanitizer) Identity() string { return s.identity }
func (s *changingIdentitySanitizer) SanitizeGeneration(ctx context.Context, raw provider.Request, scope string) (review.SanitizedModelRequest, review.SanitizedEgressReceipt, error) {
	request, receipt, err := s.CleanGenerationSanitizer.SanitizeGeneration(ctx, raw, scope)
	s.identity = strings.Repeat("9", 64)
	return request, receipt, err
}

func TestBuildSanitizedPacketCandidateDoesNotGrantOrPersistInput(t *testing.T) {
	authority, request, coordinator, store, _, closeFixture, journal := newPacketWriterFixture(t, false, false, false, false, false)
	defer closeFixture()
	ctx, scope, at := context.Background(), request.Plan().Scope(), time.UnixMilli(230)
	_, state, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := BuildPacketCandidate(ctx, packetCandidateGetReader{source: store}, request, state, contextTestClock{at}, authority.ownerRoot, at, at)
	if err != nil {
		t.Fatal(err)
	}
	before := packetCandidateEvents(t, journal, scope)
	drifting := &changingIdentitySanitizer{identity: strings.Repeat("8", 64)}
	if value, err := BuildSanitizedPacketCandidate(ctx, candidate, drifting, at); err == nil || value.SanitizerIdentity() != "" {
		t.Fatal("sanitizer identity changed during scan but candidate was issued")
	}
	sanitizer := testsupport.NewCleanGenerationSanitizer()
	sanitized, err := BuildSanitizedPacketCandidate(ctx, candidate, sanitizer, at)
	if err != nil {
		t.Fatal(err)
	}
	if sanitized.SanitizerIdentity() != sanitizer.Identity() {
		t.Fatal("sanitized candidate lost exact sanitizer identity")
	}
	requestArtifact, receiptArtifact := sanitized.RequestArtifact(), sanitized.ReceiptArtifact()
	if requestArtifact.Kind() != artifact.KindSanitizedModelRequest || receiptArtifact.Kind() != artifact.KindSanitizedEgressReceipt ||
		review.ValidateSanitizedEgressArtifacts(candidate.Artifact(), requestArtifact, receiptArtifact, testsupport.NewCleanGenerationSanitizer().ExpectedBinaryDigests()) != nil {
		t.Fatal("sanitized packet lacks exact scanner and packet lineage")
	}
	modelRequest, err := sanitized.Request()
	if err != nil || modelRequest.Identity() == "" || modelRequest.Identity() != sanitized.Receipt().SanitizedRequestIdentity() || sanitized.Receipt().RawRequestIdentity() != sanitized.RawRequestIdentity() {
		t.Fatalf("sanitized request does not match receipt: %v", err)
	}
	for _, value := range []artifact.Artifact{requestArtifact, receiptArtifact} {
		if _, err := store.Get(ctx, scope, value.Identity(), at); !errors.Is(err, artifact.ErrArtifactNotFound) {
			t.Fatalf("sanitization wrote artifact: %v", err)
		}
	}
	if after := packetCandidateEvents(t, journal, scope); !reflect.DeepEqual(before, after) {
		t.Fatal("sanitization wrote journal")
	}
	broken := candidate
	broken.value = artifact.Artifact{}
	if _, err := BuildSanitizedPacketCandidate(ctx, broken, testsupport.NewCleanGenerationSanitizer(), at); err == nil {
		t.Fatal("malformed packet gained sanitized candidate")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := BuildSanitizedPacketCandidate(canceled, candidate, testsupport.NewCleanGenerationSanitizer(), at); err == nil {
		t.Fatal("canceled sanitization succeeded")
	}
}

func sortedInputParents(values ...string) []string {
	sort.Strings(values)
	return values
}

func TestBuildAuthorizedPacketInputRequiresSanitizedGrant(t *testing.T) {
	authority, request, coordinator, store, _, closeFixture, journal := newPacketWriterFixture(t, false, false, false, false, false)
	defer closeFixture()
	ctx, scope, at := context.Background(), request.Plan().Scope(), time.UnixMilli(230)
	_, state, err := coordinator.Resume(ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := BuildPacketCandidate(ctx, packetCandidateGetReader{source: store}, request, state, contextTestClock{at}, authority.ownerRoot, at, at)
	if err != nil {
		t.Fatal(err)
	}
	sanitized, err := BuildSanitizedPacketCandidate(ctx, packet, testsupport.NewCleanGenerationSanitizer(), at)
	if err != nil {
		t.Fatal(err)
	}
	before := packetCandidateEvents(t, journal, scope)
	modelRequest, err := sanitized.Request()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := routeAuthorization(scope, modelRequest, "local-fixture", "adapter", "local-fixture", "model", "1", strings.Repeat("c", 64), strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	analysis, _ := request.DependencyOutput("analysis")
	memory, _ := request.DependencyOutput("memory")
	input, err := BuildAuthorizedPacketInput(ctx, sanitized, grant, request, strings.Repeat("e", 64), at)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := modelhandler.ParseGenerationInput(input.Payload())
	if err != nil || !parsed.IsSanitized() || parsed.Authorization().Identity() != grant.Identity() || parsed.ContextArtifactIdentity() != packet.Artifact().Identity() || parsed.SanitizedRequestArtifactIdentity() != sanitized.RequestArtifact().Identity() || parsed.SanitizedEgressReceiptArtifactIdentity() != sanitized.ReceiptArtifact().Identity() {
		t.Fatalf("authorized input lineage: %v", err)
	}
	if input.Kind() != artifact.KindTaskInput || !reflect.DeepEqual(input.Provenance(), sortedInputParents(analysis.OutputIdentity(), memory.OutputIdentity(), request.Plan().PolicyIdentity(), strings.Repeat("e", 64), packet.Artifact().Identity(), grant.Identity(), sanitized.RequestArtifact().Identity(), sanitized.ReceiptArtifact().Identity())) {
		t.Fatal("task input provenance does not bind dependencies, policy, and grant")
	}
	wrongLease := sanitized
	wrongLease.packet.descriptor.LeaseIdentity = strings.Repeat("a", 64)
	if _, err := BuildAuthorizedPacketInput(ctx, wrongLease, grant, request, strings.Repeat("e", 64), at); err == nil {
		t.Fatal("packet from another lease produced task input")
	}
	wrongArtifact := sanitized
	wrongArtifact.packet.descriptor.ArtifactIdentity = strings.Repeat("a", 64)
	if _, err := BuildAuthorizedPacketInput(ctx, wrongArtifact, grant, request, strings.Repeat("e", 64), at); err == nil {
		t.Fatal("unbound packet descriptor produced task input")
	}
	wrongEvent := sanitized
	wrongEvent.packet.descriptor.LeaseEventIdentity = strings.Repeat("a", 64)
	if _, err := BuildAuthorizedPacketInput(ctx, wrongEvent, grant, request, strings.Repeat("e", 64), at); err == nil {
		t.Fatal("packet from another lease event produced task input")
	}
	wrongSnapshot := sanitized
	wrongSnapshot.packet.descriptor.SnapshotIdentity = strings.Repeat("a", 64)
	if _, err := BuildAuthorizedPacketInput(ctx, wrongSnapshot, grant, request, strings.Repeat("e", 64), at); err == nil {
		t.Fatal("packet from another snapshot produced task input")
	}
	wrongProvenance := sanitized
	wrongProvenance.packet.descriptor.Provenance = append([]string(nil), packet.Descriptor().Provenance...)
	wrongProvenance.packet.descriptor.Provenance[0] = strings.Repeat("a", 64)
	if _, err := BuildAuthorizedPacketInput(ctx, wrongProvenance, grant, request, strings.Repeat("e", 64), at); err == nil {
		t.Fatal("packet with altered provenance produced task input")
	}
	for _, test := range []struct {
		name   string
		change func(*controlplane.ContextPacketDescriptor)
	}{
		{"payload_digest", func(d *controlplane.ContextPacketDescriptor) { d.PayloadDigest = strings.Repeat("a", 64) }},
		{"classification", func(d *controlplane.ContextPacketDescriptor) { d.Classification = "restricted" }},
		{"protection", func(d *controlplane.ContextPacketDescriptor) { d.Protection = "envelope_encrypted" }},
		{"dependencies", func(d *controlplane.ContextPacketDescriptor) {
			d.DependencyIdentities = []string{strings.Repeat("a", 64)}
		}},
		{"created_at", func(d *controlplane.ContextPacketDescriptor) { d.CreatedAtMilliseconds++ }},
		{"expires_at", func(d *controlplane.ContextPacketDescriptor) { d.ExpiresAtMilliseconds++ }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed := sanitized
			changed.packet.descriptor = packet.Descriptor()
			test.change(&changed.packet.descriptor)
			if _, err := BuildAuthorizedPacketInput(ctx, changed, grant, request, strings.Repeat("e", 64), at); !errors.Is(err, ErrPacketAuthority) {
				t.Fatalf("altered packet descriptor produced task input: %v", err)
			}
		})
	}
	if _, err := BuildAuthorizedPacketInput(ctx, sanitized, grant, controlplane.TaskExecutionRequest{}, strings.Repeat("e", 64), at); err == nil {
		t.Fatal("unbound execution produced task input")
	}
	if _, err := BuildAuthorizedPacketInput(ctx, sanitized, gateway.RouteAttemptAuthorization{}, request, strings.Repeat("e", 64), at); err == nil {
		t.Fatal("zero grant produced task input")
	}
	wrong, _ := audit.NewReviewScope("tenant", "repository", "other")
	foreign, err := routeAuthorization(wrong, modelRequest, "local-fixture", "adapter", "local-fixture", "model", "1", strings.Repeat("c", 64), strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BuildAuthorizedPacketInput(ctx, sanitized, foreign, request, strings.Repeat("e", 64), at); err == nil {
		t.Fatal("foreign grant produced task input")
	}
	if _, err := store.Get(ctx, scope, input.Identity(), at); !errors.Is(err, artifact.ErrArtifactNotFound) {
		t.Fatalf("builder persisted input: %v", err)
	}
	if after := packetCandidateEvents(t, journal, scope); !reflect.DeepEqual(before, after) {
		t.Fatal("builder advanced journal")
	}
}

// blockedBaseGetReader records that a base snapshot file, not a selected head
// range, was actually reached by sourceChain after clean assembly.
type blockedBaseGetReader struct {
	packetCandidateGetReader
	blocked string
	gets    int
}

func (r *blockedBaseGetReader) Get(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (artifact.Artifact, error) {
	if identity == r.blocked {
		r.gets++
	}
	return r.packetCandidateGetReader.Get(ctx, scope, identity, at)
}

func TestBuildPacketCandidateRejectsUnselectedFileDamageBeforeAnyEffect(t *testing.T) {
	for _, test := range []struct {
		name              string
		changed, baseFile bool
	}{{"missing", false, false}, {"mismatched", true, false}, {"base_missing", false, true}, {"base_mismatched", true, true}} {
		t.Run(test.name, func(t *testing.T) {
			authority, request, coordinator, store, _, closeFixture, journal := newPacketWriterFixture(t, true, test.baseFile, false, false, false)
			defer closeFixture()
			damaged := authority.store.(blockedPacketStore)
			if test.changed {
				damaged.changed = true
			}
			puts := 0
			damaged.putCount = &puts
			ctx := context.Background()
			scope := request.Plan().Scope()
			at := time.UnixMilli(230)
			beforeEvents := packetCandidateEvents(t, journal, scope)
			_, state, err := coordinator.Resume(ctx, scope)
			if err != nil {
				t.Fatal(err)
			}
			assembly, _, abstention, failure := (&Handler{store: store, packetOnly: true}).assemble(ctx, request, at)
			if failure != 0 || abstention != nil {
				t.Fatal("fixture cannot assemble its undamaged selected packet")
			}
			for _, item := range assembly.Packet.EvidenceItems() {
				if item.SourceRange().Path() == "z_unselected.txt" {
					t.Fatal("damaged base body selected")
				}
			}
			expectedIdentity := assembly.InitialContextArtifact.Identity()
			reader := &blockedBaseGetReader{packetCandidateGetReader: packetCandidateGetReader{source: damaged}, blocked: damaged.blocked}
			candidate, err := BuildPacketCandidate(ctx, reader, request, state, contextTestClock{at}, authority.ownerRoot, at, at)
			if !errors.Is(err, ErrPacketAuthority) {
				t.Fatalf("unselected file %s accepted: %v", test.name, err)
			}
			if candidate.Artifact().Identity() != "" || candidate.Descriptor().ArtifactIdentity != "" {
				t.Fatal("rejection returned candidate")
			}
			if test.baseFile && reader.gets != 1 {
				t.Fatalf("STOP: blocked base ID Get count=%d; sourceChain not proven", reader.gets)
			}
			afterEvents := packetCandidateEvents(t, journal, scope)
			if len(afterEvents) != len(beforeEvents) {
				t.Fatal("rejected candidate appended journal event")
			}
			for i := range beforeEvents {
				if beforeEvents[i].Identity() != afterEvents[i].Identity() {
					t.Fatal("rejected candidate changed ordered journal identities")
				}
			}
			_, afterState, err := coordinator.Resume(ctx, scope)
			if err != nil || afterState.HeadIdentity() != state.HeadIdentity() {
				t.Fatalf("rejected candidate changed journal head: %v", err)
			}
			runtime, ok := afterState.Task("context")
			if !ok {
				t.Fatal("missing context task")
			}
			if _, prepared := runtime.PreparedContextPacket(); prepared {
				t.Fatal("rejected candidate prepared durable packet")
			}
			if puts != 0 {
				t.Fatalf("rejected candidate forwarded %d Put calls", puts)
			}
			if _, err := store.Get(ctx, scope, expectedIdentity, at); !errors.Is(err, artifact.ErrArtifactNotFound) {
				t.Fatalf("rejected candidate persisted packet: %v", err)
			}
		})
	}
}
