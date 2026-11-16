package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

// Both cases retain the real Git-enrolled v4 journal and differ only in the
// physical packet leaf. A descriptor alone cannot establish packet presence.
func TestLocalHistoricalPacketRefusalPhysicalNegative(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, string, []byte)
		want   error
		other  error
	}{
		{"missing", func(t *testing.T, leaf string, _ []byte) {
			t.Helper()
			if err := os.Remove(leaf); err != nil {
				t.Fatal(err)
			}
		}, errHistoricalPacketMissingAtStartup, errHistoricalPacketMismatchAtStartup},
		{"stable canonical-byte mismatch", func(t *testing.T, leaf string, encoded []byte) {
			t.Helper()
			changed := bytes.Clone(encoded)
			marker := []byte(`"payload":"`)
			start := bytes.Index(changed, marker)
			if start < 0 || start+len(marker) >= len(changed) {
				t.Fatal("encoded packet payload missing")
			}
			at := start + len(marker)
			replacement := byte('A')
			if changed[at] == replacement {
				replacement = 'B'
			}
			changed[at] = replacement
			if !json.Valid(changed) {
				t.Fatal("fixture mutation lost canonical JSON framing")
			}
			if _, err := artifact.Parse(changed); !errors.Is(err, artifact.ErrInvalidArtifactIdentity) {
				t.Fatalf("mutated packet must fail canonical artifact verification: %v", err)
			}
			before, err := os.Lstat(leaf)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(leaf, changed, 0600); err != nil {
				t.Fatal(err)
			}
			after, err := os.Lstat(leaf)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
				t.Fatalf("fixture mutation changed inode, mode or length: %v", err)
			}
		}, errHistoricalPacketMismatchAtStartup, errHistoricalPacketMissingAtStartup},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			fixture := newLocalPacketOwnerFixture(t)
			scope := fixture.request.Plan().Scope()
			prepared, err := fixture.owner.PreparePacket(ctx, fixture.request)
			if err != nil {
				t.Fatalf("first owner PreparePacket: %v", err)
			}
			packet, err := fixture.store.Get(ctx, scope, prepared.Descriptor().ArtifactIdentity, fixture.clock.Now())
			if err != nil {
				t.Fatalf("first physical Put/readback: %v", err)
			}
			encoded, err := artifact.Encode(packet)
			if err != nil {
				t.Fatal(err)
			}
			if packet.Identity() != prepared.Descriptor().ArtifactIdentity || packet.PayloadDigest() != prepared.Descriptor().PayloadDigest {
				t.Fatal("first packet differs from durable descriptor")
			}
			events := encodedLocalPacketHistory(t, fixture.journal, scope)
			if err := fixture.resources.Close(); err != nil {
				t.Fatalf("close first writer leases: %v", err)
			}
			verifyLocalPacketReopen(t, fixture, prepared, encoded, events, controlplane.PreparedContextInput{}, controlplane.ContextInputDescriptor{}, false)
			leaf := filepath.Join(fixture.statePath, "artifacts", scope.Identity()+"-"+prepared.Descriptor().ArtifactIdentity+".artifact.json")
			if raw, err := os.ReadFile(leaf); err != nil || !bytes.Equal(raw, encoded) {
				t.Fatalf("physical packet leaf differs from first Put: %v", err)
			}
			tc.mutate(t, leaf, encoded)
			before := snapshotLocalPacketFiles(t, fixture.statePath)
			second := &daemon{}
			t.Cleanup(func() {
				if err := second.Close(); err != nil {
					t.Errorf("close refused boot resources on cleanup: %v", err)
				}
			})
			active, journal, owner, bootErr := startLocalSourceOwnerGate(ctx, second, fixture.statePath, fixture.setupPath, &fixture.setupPlan,
				"tenant-a", "repo-a", fixture.repository, fixture.gitRoot, fixture.objectStore, fixture.adapter, fixture.rootDigest, fixture.clock)
			if active != nil || journal != nil || owner != nil || bootErr == nil {
				t.Errorf("physical %s must refuse with nil handles: store=%v journal=%v owner=%v err=%v", tc.name, active, journal, owner, bootErr)
			}
			if err := second.Close(); err != nil {
				t.Fatalf("close refused boot resources: %v", err)
			}
			if after := snapshotLocalPacketFiles(t, fixture.statePath); !reflect.DeepEqual(before, after) {
				t.Fatal("second boot changed runtime file names or bytes beyond explicit fixture mutation")
			}
			reopenedJournal, err := controlplane.NewFileRunJournal(fixture.statePath)
			if err != nil {
				t.Fatalf("reopen journal writer lease: %v", err)
			}
			if got := encodedLocalPacketHistory(t, reopenedJournal, scope); !reflect.DeepEqual(got, events) {
				t.Error("reopened journal events changed")
			}
			if err := reopenedJournal.Close(); err != nil {
				t.Fatalf("close reopened journal writer: %v", err)
			}
			reopenedPending, err := artifact.OpenPendingFileStore(filepath.Join(fixture.statePath, "artifacts"))
			if err != nil {
				t.Fatalf("reopen artifact writer lease without activation: %v", err)
			}
			if err := reopenedPending.Close(); err != nil {
				t.Fatalf("close reopened artifact writer: %v", err)
			}
			if after := snapshotLocalPacketFiles(t, fixture.statePath); !reflect.DeepEqual(before, after) {
				t.Fatal("writer lease reopen changed runtime file names or bytes")
			}
			if errors.Is(bootErr, controlplane.ErrPreparedContextPacketAtStartup) {
				t.Fatalf("physical %s requires typed refusal, got legacy blanket: %v", tc.name, bootErr)
			}
			if !errors.Is(bootErr, tc.want) || errors.Is(bootErr, tc.other) || errors.Is(bootErr, errHistoricalPacketObservedAtStartup) {
				t.Fatalf("physical %s requires only its distinct typed refusal: %v", tc.name, bootErr)
			}
		})
	}
}
