package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

// This is a forensic baseline. Raw reopened handles are not an enrolled owner
// and cannot authorize creation, recovery, or any downstream effect.
func TestLocalPacketHistoryForensicReopenAndStartupRefusal(t *testing.T) {
	for _, withMissingInput := range []bool{false, true} {
		name := "v4"
		if withMissingInput {
			name = "v5-missing-three-objects"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newLocalPacketOwnerFixture(t)
			plan, lease, scope := fixture.request.Plan(), fixture.request.Lease(), fixture.request.Plan().Scope()
			prepared, err := fixture.owner.PreparePacket(ctx, fixture.request)
			if err != nil {
				t.Fatalf("real Git-enrolled owner packet: %v", err)
			}
			original, err := fixture.store.Get(ctx, scope, prepared.Descriptor().ArtifactIdentity, fixture.clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			originalBytes, err := artifact.Encode(original)
			if err != nil {
				t.Fatal(err)
			}
			if original.Kind() != artifact.KindContextPacket || !bytes.Contains(original.Payload(), []byte("fmt.Println")) ||
				original.Identity() != prepared.Descriptor().ArtifactIdentity || original.PayloadDigest() != prepared.Descriptor().PayloadDigest ||
				prepared.Descriptor().SourceRootIdentity != fixture.rootDigest || prepared.Descriptor().LeaseIdentity != lease.Identity() {
				t.Fatal("owner v4 is not bound to exact Git packet bytes and lease")
			}
			var inputDescriptor controlplane.ContextInputDescriptor
			var inputCheckpoint controlplane.PreparedContextInput
			if withMissingInput {
				inputDescriptor = missingLocalContextInputDescriptor(t, fixture, prepared, original)
				inputCheckpoint, err = fixture.coordinator.PrepareContextInput(ctx, plan, lease, prepared, inputDescriptor, fixture.clock.Now().Add(time.Millisecond))
				if err != nil {
					t.Fatalf("structural missing-byte v5 intent: %v", err)
				}
			}
			beforeEvents := encodedLocalPacketHistory(t, fixture.journal, scope)
			if err := fixture.resources.Close(); err != nil {
				t.Fatalf("close original owner resources: %v", err)
			}

			// Constructors below only classify durable facts. Close them before
			// attempting the second Git-qualified start on the same leased roots.
			verifyLocalPacketReopen(t, fixture, prepared, originalBytes, beforeEvents, inputCheckpoint, inputDescriptor, withMissingInput)
			if withMissingInput {
				assertMissingLocalInputLeaves(t, fixture.statePath, scope, inputDescriptor)
			}
			beforeFiles := snapshotLocalPacketFiles(t, fixture.statePath)
			second := &daemon{}
			active, journal, owner, bootErr := startLocalSourceOwnerGate(ctx, second, fixture.statePath, fixture.setupPath, &fixture.setupPlan,
				"tenant-a", "repo-a", fixture.repository, fixture.gitRoot, fixture.objectStore, fixture.adapter, fixture.rootDigest, fixture.clock)
			if active != nil || journal != nil || owner != nil {
				t.Fatalf("second Git-qualified boot activated historical packet: store=%v journal=%v owner=%v err=%v", active, journal, owner, bootErr)
			}
			if err := second.Close(); err != nil {
				t.Fatalf("close refused boot resources: %v", err)
			}
			afterFiles := snapshotLocalPacketFiles(t, fixture.statePath)
			if withMissingInput {
				assertMissingLocalInputLeaves(t, fixture.statePath, scope, inputDescriptor)
			}
			if !reflect.DeepEqual(beforeFiles, afterFiles) {
				t.Fatal("refused second boot altered or removed stored files")
			}
			verifyLocalPacketReopen(t, fixture, prepared, originalBytes, beforeEvents, inputCheckpoint, inputDescriptor, withMissingInput)
			if withMissingInput {
				const marker = "historical prepared context input artifact missing at startup"
				if bootErr == nil || errors.Is(bootErr, errHistoricalInputIntentQuarantinedAtStartup) ||
					errors.Is(bootErr, controlplane.ErrPreparedContextPacketAtStartup) ||
					errors.Is(bootErr, errHistoricalPacketObservedAtStartup) ||
					errors.Is(bootErr, errHistoricalPacketMissingAtStartup) ||
					errors.Is(bootErr, errHistoricalPacketMismatchAtStartup) ||
					!errors.Is(bootErr, errHistoricalInputArtifactMissingAtStartup) ||
					!strings.Contains(bootErr.Error(), marker) {
					t.Fatalf("three absent descriptor-named v5 leaves require a distinct missing refusal: %v", bootErr)
				}
			} else if !errors.Is(bootErr, errHistoricalPacketObservedAtStartup) ||
				errors.Is(bootErr, controlplane.ErrPreparedContextPacketAtStartup) {
				t.Fatalf("intact v4 must retain typed observed refusal, not blanket v4 refusal: %v", bootErr)
			}
		})
	}
}

func assertMissingLocalInputLeaves(t *testing.T, statePath string, scope audit.ReviewScope, descriptor controlplane.ContextInputDescriptor) {
	t.Helper()
	for role, identity := range map[string]string{
		"request": descriptor.Request.ArtifactIdentity,
		"receipt": descriptor.Receipt.ArtifactIdentity,
		"input":   descriptor.Input.ArtifactIdentity,
	} {
		leaf := filepath.Join(statePath, "artifacts", scope.Identity()+"-"+identity+".artifact.json")
		if _, err := os.Lstat(leaf); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s descriptor-named artifact leaf %s is not absent: %v", role, leaf, err)
		}
	}
}

func missingLocalContextInputDescriptor(t *testing.T, fixture localPacketOwnerFixture, prepared controlplane.PreparedContextPacket, packet artifact.Artifact) controlplane.ContextInputDescriptor {
	t.Helper()
	scope, lease := fixture.request.Plan().Scope(), fixture.request.Lease()
	at := fixture.clock.Now().Add(time.Millisecond)
	authorization := strings.Repeat("8", 64)
	newAbsent := func(kind artifact.Kind, parents []string) artifact.Artifact {
		t.Helper()
		slices.Sort(parents)
		value, err := artifact.New(scope, kind, "application/json", packet.Classification(), artifact.OriginHost, packet.Protection(), parents,
			[]byte(`{"unpersisted":"descriptor fixture only"}`), at, packet.ExpiresAt())
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	request := newAbsent(artifact.KindSanitizedModelRequest, []string{packet.Identity()})
	receipt := newAbsent(artifact.KindSanitizedEgressReceipt, []string{packet.Identity(), request.Identity()})
	input := newAbsent(artifact.KindTaskInput, []string{packet.Identity(), request.Identity(), receipt.Identity(), authorization})
	fromAbsent := func(value artifact.Artifact) controlplane.ContextInputArtifactDescriptor {
		return controlplane.ContextInputArtifactDescriptor{ArtifactIdentity: value.Identity(), PayloadDigest: value.PayloadDigest(),
			Classification: value.Classification().String(), Protection: value.Protection().String(), Provenance: value.Provenance(),
			CreatedAtMilliseconds: value.CreatedAt().UnixMilli(), ExpiresAtMilliseconds: value.ExpiresAt().UnixMilli()}
	}
	return controlplane.ContextInputDescriptor{
		PacketPreparedEventIdentity: prepared.Identity(), PacketArtifactIdentity: packet.Identity(),
		LeaseIdentity: lease.Identity(), LeaseEventIdentity: lease.EventIdentity(),
		Request: fromAbsent(request), Receipt: fromAbsent(receipt), Input: fromAbsent(input),
		ReceiptIdentity: strings.Repeat("4", 64), ScannerHelperDigest: strings.Repeat("5", 64), GenerationInputIdentity: strings.Repeat("7", 64),
		AuthorizationIdentity: authorization, SelectionReceiptIdentity: strings.Repeat("9", 64),
		RoutingInputIdentity: strings.Repeat("a", 64), SelectedRecordIdentity: strings.Repeat("b", 64),
		PolicyIdentity: strings.Repeat("d", 64), RoutePairIdentity: strings.Repeat("e", 64),
		AuthorizerIdentity: strings.Repeat("f", 64), SanitizerIdentity: strings.Repeat("1", 64),
		RegistryRevision: 11, PerformanceRevision: 5,
	}
}

func encodedLocalPacketHistory(t *testing.T, journal *controlplane.FileRunJournal, scope audit.ReviewScope) [][]byte {
	t.Helper()
	events, err := journal.Read(context.Background(), scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([][]byte, len(events))
	for i, event := range events {
		encoded[i], err = controlplane.EncodeRunEvent(event)
		if err != nil {
			t.Fatal(err)
		}
	}
	return encoded
}

func verifyLocalPacketReopen(t *testing.T, fixture localPacketOwnerFixture, prepared controlplane.PreparedContextPacket,
	originalBytes []byte, originalEvents [][]byte, checkpoint controlplane.PreparedContextInput,
	descriptor controlplane.ContextInputDescriptor, withMissingInput bool) {
	t.Helper()
	ctx, scope := context.Background(), fixture.request.Plan().Scope()
	journal, err := controlplane.NewFileRunJournal(fixture.statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := journal.Close(); err != nil {
			t.Errorf("close raw journal: %v", err)
		}
	}()
	store, err := artifact.NewFileStore(filepath.Join(fixture.statePath, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := store.Close(); err != nil {
			t.Errorf("close raw store: %v", err)
		}
	}()
	reopened, err := store.Get(ctx, scope, prepared.Descriptor().ArtifactIdentity, fixture.clock.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := artifact.Encode(reopened)
	if err != nil || !bytes.Equal(encoded, originalBytes) {
		t.Fatalf("raw reopened packet envelope differs from owner Put: %v", err)
	}
	events := encodedLocalPacketHistory(t, journal, scope)
	if !reflect.DeepEqual(events, originalEvents) {
		t.Fatal("raw reopened journal history differs from original v4/v5 events")
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		t.Fatal(err)
	}
	plan, state, err := coordinator.Resume(ctx, scope)
	if err != nil || plan.Identity() != fixture.request.Plan().Identity() {
		t.Fatalf("raw journal replay: %v", err)
	}
	runtime, ok := state.Task("context")
	if !ok || runtime.Status() != controlplane.TaskRuntimeLeased {
		t.Fatal("raw replay lost context lease")
	}
	storedEvents, err := journal.Read(ctx, scope, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	foundV4 := false
	for _, event := range storedEvents {
		if event.Kind() == controlplane.RunEventContextPacketPrepared && event.Identity() == prepared.Identity() &&
			reflect.DeepEqual(event.PacketDescriptor(), prepared.Descriptor()) {
			foundV4 = true
		}
	}
	if !foundV4 {
		t.Fatal("raw replay lost exact historical v4 packet descriptor")
	}
	currentPacket, hasPacket := runtime.PreparedContextPacket()
	if hasPacket != !withMissingInput || hasPacket && currentPacket.Identity() != prepared.Identity() {
		t.Fatal("raw replay current v4 status mismatch")
	}
	currentInput, hasInput := runtime.PreparedContextInput()
	if hasInput != withMissingInput {
		t.Fatal("raw replay v5 presence mismatch")
	}
	if withMissingInput {
		if currentInput.Identity() != checkpoint.Identity() || !reflect.DeepEqual(currentInput.Descriptor(), descriptor) ||
			state.HeadIdentity() != checkpoint.Identity() {
			t.Fatal("raw replay lost v5 intent or head")
		}
		for _, identity := range []string{descriptor.Request.ArtifactIdentity, descriptor.Receipt.ArtifactIdentity, descriptor.Input.ArtifactIdentity} {
			if _, err := store.Get(ctx, scope, identity, fixture.clock.Now().Add(2*time.Millisecond)); !errors.Is(err, artifact.ErrArtifactNotFound) {
				t.Fatalf("unpersisted v5 artifact %s present or unreadable: %v", identity, err)
			}
		}
	} else if state.HeadIdentity() != prepared.Identity() {
		t.Fatal("raw replay lost v4 head")
	}
	// Raw constructors expose facts, not authenticated restart authority.
}

func snapshotLocalPacketFiles(t *testing.T, root string) map[string][]byte {
	t.Helper()
	files := make(map[string][]byte)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return errors.New("unexpected non-regular runtime entry: " + path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files[relative], err = os.ReadFile(path)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
