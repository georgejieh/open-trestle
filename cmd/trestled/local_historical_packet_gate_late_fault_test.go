package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

// Change one byte without replacing or truncating the already observed inode.
func mutateHistoricalGateByte(path string, original []byte, offset int) ([]byte, error) {
	if offset < 0 || offset >= len(original) {
		return nil, fmt.Errorf("mutation offset outside leaf")
	}
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	changed := bytes.Clone(original)
	changed[offset] ^= 1
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}
	count, writeErr := file.WriteAt(changed[offset:offset+1], int64(offset))
	closeErr := file.Close()
	after, statErr := os.Lstat(path)
	if writeErr != nil || count != 1 || closeErr != nil || statErr != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
		return nil, fmt.Errorf("in-place mutation failed: written=%d: %w", count, errors.Join(writeErr, closeErr, statErr))
	}
	return changed, nil
}

func TestLocalHistoricalPacketGateLateFaultPrecedence(t *testing.T) {
	for _, name := range []string{"physical reread", "journal final witness", "checked physical close", "cancel after enum"} {
		t.Run(name, func(t *testing.T) {
			fixture := newLocalPacketOwnerFixture(t)
			ctx := context.Background()
			scope := fixture.request.Plan().Scope()
			prepared, err := fixture.owner.PreparePacket(ctx, fixture.request)
			if err != nil {
				t.Fatal(err)
			}
			packet, err := fixture.store.Get(ctx, scope, prepared.Descriptor().ArtifactIdentity, fixture.clock.Now())
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := artifact.Encode(packet)
			if err != nil {
				t.Fatal(err)
			}
			if packet.Identity() != prepared.Descriptor().ArtifactIdentity || packet.PayloadDigest() != prepared.Descriptor().PayloadDigest {
				t.Fatal("physical Put/readback differs from descriptor")
			}
			events := encodedLocalPacketHistory(t, fixture.journal, scope)
			if err := fixture.resources.Close(); err != nil {
				t.Fatal(err)
			}
			verifyLocalPacketReopen(t, fixture, prepared, encoded, events, controlplane.PreparedContextInput{}, controlplane.ContextInputDescriptor{}, false)
			baseline := snapshotLocalPacketFiles(t, fixture.statePath)
			packetLeaf := filepath.Join("artifacts", scope.Identity()+"-"+prepared.Descriptor().ArtifactIdentity+".artifact.json")
			planLeaf := scope.Identity() + ".run-plan.json"
			if !bytes.Equal(baseline[packetLeaf], encoded) || len(baseline[planLeaf]) < 2 {
				t.Fatal("missing durable packet or plan witness")
			}
			expected := make(map[string][]byte, len(baseline))
			for key, value := range baseline {
				expected[key] = bytes.Clone(value)
			}
			mutationLeaf := ""
			probe := &historicalGateFaultProbe{}
			called, closeCount, countAtHook := 0, 0, 0
			expectedMarker := errPhysicalPacketObservationUncertain
			gateCtx := ctx
			if name == "cancel after enum" {
				var cancel context.CancelFunc
				gateCtx, cancel = context.WithCancel(ctx)
				defer cancel()
				expectedMarker = controlplane.ErrRunJournalContextDone
				probe.afterClassified = func(class historicalPacketStartupClass) error {
					called++
					if class != historicalPacketObserved {
						return fmt.Errorf("unexpected provisional class %d", class)
					}
					cancel()
					return nil
				}
			} else {
				probe.afterClassified = func(class historicalPacketStartupClass) error {
					called++
					countAtHook = closeCount
					if class != historicalPacketObserved {
						return fmt.Errorf("unexpected provisional class %d", class)
					}
					if name == "checked physical close" {
						return nil
					}
					mutationLeaf = packetLeaf
					marker := []byte(`"payload":"`)
					start := bytes.Index(expected[packetLeaf], marker)
					if start < 0 {
						return errors.New("payload marker absent")
					}
					offset := start + len(marker)
					if name == "journal final witness" {
						mutationLeaf = planLeaf
						offset = len(expected[planLeaf]) - 2
					}
					changed, changeErr := mutateHistoricalGateByte(filepath.Join(fixture.statePath, mutationLeaf), expected[mutationLeaf], offset)
					if changeErr == nil {
						expected[mutationLeaf] = changed
					}
					return changeErr
				}
			}
			if name == "journal final witness" {
				expectedMarker = controlplane.ErrInvalidStartupInventoryEntry
			}
			if name == "checked physical close" {
				injectedClose := errors.New("injected third physical close")
				probe.closePhysicalFile = func(file *os.File) error {
					closeCount++
					closeErr := file.Close()
					if closeCount == 3 {
						return errors.Join(closeErr, injectedClose)
					}
					return closeErr
				}
			}
			second := &daemon{}
			t.Cleanup(func() {
				if err := second.Close(); err != nil {
					t.Errorf("cleanup second gate: %v", err)
				}
			})
			active, journal, owner, gateErr := startLocalSourceOwnerGateWithProbe(gateCtx, second, fixture.statePath, fixture.setupPath, &fixture.setupPlan,
				"tenant-a", "repo-a", fixture.repository, fixture.gitRoot, fixture.objectStore, fixture.adapter, fixture.rootDigest, fixture.clock, probe)
			if called != 1 || active != nil || journal != nil || owner != nil || !errors.Is(gateErr, expectedMarker) ||
				errors.Is(gateErr, errHistoricalPacketObservedAtStartup) || errors.Is(gateErr, errHistoricalPacketMissingAtStartup) ||
				errors.Is(gateErr, errHistoricalPacketMismatchAtStartup) || errors.Is(gateErr, controlplane.ErrPreparedContextPacketAtStartup) {
				t.Errorf("late %s: callback=%d handles=%v/%v/%v err=%v", name, called, active, journal, owner, gateErr)
			}
			if name == "checked physical close" && (closeCount != 4 || countAtHook != 2) {
				t.Errorf("physical closes: at hook=%d final=%d", countAtHook, closeCount)
			}
			if err := second.Close(); err != nil {
				t.Fatalf("close refused gate: %v", err)
			}
			if after := snapshotLocalPacketFiles(t, fixture.statePath); !reflect.DeepEqual(after, expected) {
				t.Error("gate changed file names or bytes beyond injected byte")
			}
			if mutationLeaf != "" {
				offset := 0
				for i := range baseline[mutationLeaf] {
					if baseline[mutationLeaf][i] != expected[mutationLeaf][i] {
						offset = i
						break
					}
				}
				restored, restoreErr := mutateHistoricalGateByte(filepath.Join(fixture.statePath, mutationLeaf), expected[mutationLeaf], offset)
				if restoreErr != nil || !bytes.Equal(restored, baseline[mutationLeaf]) {
					t.Fatalf("in-place restoration: %v", restoreErr)
				}
			}
			if after := snapshotLocalPacketFiles(t, fixture.statePath); !reflect.DeepEqual(after, baseline) {
				t.Error("restored snapshot differs from pre-gate baseline")
			}
			verifyLocalPacketReopen(t, fixture, prepared, encoded, events, controlplane.PreparedContextInput{}, controlplane.ContextInputDescriptor{}, false)
			reopenedJournal, err := controlplane.NewFileRunJournal(fixture.statePath)
			if err != nil {
				t.Fatalf("journal writer lease: %v", err)
			}
			if got := encodedLocalPacketHistory(t, reopenedJournal, scope); !reflect.DeepEqual(got, events) {
				t.Error("journal event bytes changed")
			}
			if err := reopenedJournal.Close(); err != nil {
				t.Fatal(err)
			}
			reopenedPending, err := artifact.OpenPendingFileStore(filepath.Join(fixture.statePath, "artifacts"))
			if err != nil {
				t.Fatalf("pending writer lease: %v", err)
			}
			if err := reopenedPending.Close(); err != nil {
				t.Fatal(err)
			}
			if after := snapshotLocalPacketFiles(t, fixture.statePath); !reflect.DeepEqual(after, baseline) {
				t.Error("lease reopening changed file bytes")
			}
		})
	}
}
