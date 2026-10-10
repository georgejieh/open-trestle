package context

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
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
