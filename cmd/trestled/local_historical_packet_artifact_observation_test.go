//go:build linux

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

type physicalPacketTestFixture struct {
	root     string
	expected []physicalPacketExpectation
	names    []string
	original [][]byte
	entries  []string
}

func newPhysicalPacketTestFixture(t *testing.T) physicalPacketTestFixture {
	t.Helper()
	return newPhysicalPacketTestFixtureAt(t, t.TempDir())
}

func newPhysicalPacketTestFixtureAt(t *testing.T, base string) physicalPacketTestFixture {
	t.Helper()
	ctx := context.Background()
	root := filepath.Join(base, "artifacts")
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-physical-packet")
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	fixture := physicalPacketTestFixture{root: root}
	for index, payload := range [][]byte{[]byte(`{"packet":"first"}`), []byte(`{"packet":"second"}`)} {
		created := time.UnixMilli(int64(1000 + index))
		packet, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential,
			artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, payload,
			created, created.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := artifact.Encode(packet)
		if err != nil {
			t.Fatal(err)
		}
		inserted, err := store.Put(ctx, packet, created)
		if err != nil || !inserted {
			t.Fatalf("Put packet %d: inserted=%v err=%v", index, inserted, err)
		}
		descriptor := controlplane.ContextPacketDescriptor{
			ArtifactIdentity: packet.Identity(), LeaseIdentity: strings.Repeat("b", 64),
			LeaseEventIdentity: strings.Repeat("c", 64), PayloadDigest: packet.PayloadDigest(),
			Classification: packet.Classification().String(), Protection: packet.Protection().String(),
			Provenance: packet.Provenance(), SourceRootIdentity: strings.Repeat("d", 64),
			SnapshotIdentity: strings.Repeat("e", 64), DependencyIdentities: []string{strings.Repeat("a", 64)},
			CreatedAtMilliseconds: packet.CreatedAt().UnixMilli(), ExpiresAtMilliseconds: packet.ExpiresAt().UnixMilli(),
		}
		fixture.expected = append(fixture.expected, physicalPacketExpectation{scope: scope, descriptor: descriptor})
		fixture.names = append(fixture.names, scope.Identity()+"-"+packet.Identity()+".artifact.json")
		fixture.original = append(fixture.original, encoded)
	}
	if fixture.names[0] == fixture.names[1] {
		t.Fatal("fixture identities must differ")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close first writer: %v", err)
	}
	fixture.entries = physicalPacketTestEntries(t, root)
	return fixture
}

func physicalPacketTestEntries(t *testing.T, root string) []string {
	t.Helper()
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func (f physicalPacketTestFixture) observe(t *testing.T, expected []physicalPacketExpectation, after func([]physicalPacketObservation) error) error {
	t.Helper()
	pending, err := artifact.OpenPendingFileStore(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pending.Close(); err != nil {
			t.Errorf("close pending lease: %v", err)
		}
	}()
	return pending.WithOwnedRoot(func(borrowed *os.Root) error {
		return observeBorrowedHistoricalPacketFiles(context.Background(), borrowed, expected, after)
	})
}

func (f physicalPacketTestFixture) unchanged(t *testing.T) {
	t.Helper()
	if entries := physicalPacketTestEntries(t, f.root); !reflect.DeepEqual(entries, f.entries) {
		t.Fatalf("reader changed directory names: got %v, want %v", entries, f.entries)
	}
	for i, name := range f.names {
		actual, err := os.ReadFile(filepath.Join(f.root, name))
		if err != nil || !bytes.Equal(actual, f.original[i]) {
			t.Fatalf("reader changed packet %d bytes: %v", i, err)
		}
	}
}

// Overwrite one encoded payload byte through the existing inode. Size, mode and
// name remain unchanged, so an inode/mode/size-only second pass cannot detect it.
func (f physicalPacketTestFixture) overwriteSecondPayloadByte(t *testing.T) {
	t.Helper()
	path := filepath.Join(f.root, f.names[1])
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	offset := bytes.Index(f.original[1], []byte(`"payload":"`)) + len(`"payload":"`)
	if offset < len(`"payload":"`) || offset >= len(f.original[1]) {
		t.Fatal("missing encoded payload")
	}
	replacement := byte('A')
	if f.original[1][offset] == replacement {
		replacement = 'B'
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	n, writeErr := file.WriteAt([]byte{replacement}, int64(offset))
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || n != 1 || syncErr != nil || closeErr != nil {
		t.Fatalf("fixture overwrite: n=%d write=%v sync=%v close=%v", n, writeErr, syncErr, closeErr)
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
		t.Fatalf("fixture changed metadata: %v", err)
	}
	t.Cleanup(func() {
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Errorf("restore packet fixture: %v", err)
			return
		}
		n, writeErr := file.WriteAt(f.original[1][offset:offset+1], int64(offset))
		syncErr := file.Sync()
		closeErr := file.Close()
		if writeErr != nil || n != 1 || syncErr != nil || closeErr != nil {
			t.Errorf("restore packet fixture: n=%d write=%v sync=%v close=%v", n, writeErr, syncErr, closeErr)
		}
	})
}

func physicalPacketTestKinds(t *testing.T, got []physicalPacketObservation, expected []physicalPacketExpectation, kinds ...physicalPacketObservationKind) {
	t.Helper()
	if len(got) != len(expected) || len(got) != len(kinds) {
		t.Fatalf("observation count: got %d, want %d", len(got), len(expected))
	}
	for i, observation := range got {
		if observation.expectation.scope.Identity() != expected[i].scope.Identity() ||
			observation.expectation.descriptor.ArtifactIdentity != expected[i].descriptor.ArtifactIdentity || observation.kind != kinds[i] {
			t.Errorf("observation %d is not its ordered expected kind: got %+v, want kind %v", i, observation, kinds[i])
		}
	}
}

func TestPhysicalPacketObservationTwoCanonicalPacketsRemainUnchanged(t *testing.T) {
	fixture := newPhysicalPacketTestFixture(t)
	callbacks := 0
	err := fixture.observe(t, fixture.expected, func(got []physicalPacketObservation) error {
		callbacks++
		physicalPacketTestKinds(t, got, fixture.expected, physicalPacketIntact, physicalPacketIntact)
		return nil
	})
	if err != nil || callbacks != 1 {
		t.Fatalf("two-packet late witness: callback=%d err=%v", callbacks, err)
	}
	fixture.unchanged(t)
}

func TestPhysicalPacketObservationSecondInPlaceOverwriteIsUncertain(t *testing.T) {
	fixture := newPhysicalPacketTestFixture(t)
	calls := 0
	err := fixture.observe(t, fixture.expected, func(got []physicalPacketObservation) error {
		calls++
		physicalPacketTestKinds(t, got, fixture.expected, physicalPacketIntact, physicalPacketIntact)
		fixture.overwriteSecondPayloadByte(t)
		return nil
	})
	if calls != 1 || !errors.Is(err, errPhysicalPacketObservationUncertain) {
		t.Fatalf("second leaf changed with stable metadata: callback=%d err=%v", calls, err)
	}
	if got := physicalPacketTestEntries(t, fixture.root); !reflect.DeepEqual(got, fixture.entries) {
		t.Fatal("fixture changed names")
	}
	if data, err := os.ReadFile(filepath.Join(fixture.root, fixture.names[0])); err != nil || !bytes.Equal(data, fixture.original[0]) {
		t.Fatalf("first leaf changed: %v", err)
	}
}

func TestPhysicalPacketObservationStableMalformedSecondIsMismatch(t *testing.T) {
	fixture := newPhysicalPacketTestFixture(t)
	fixture.overwriteSecondPayloadByte(t)
	calls := 0
	err := fixture.observe(t, fixture.expected, func(got []physicalPacketObservation) error {
		calls++
		physicalPacketTestKinds(t, got, fixture.expected, physicalPacketIntact, physicalPacketMismatch)
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("stable malformed bytes: callback=%d err=%v", calls, err)
	}
}

func TestPhysicalPacketObservationCallbackErrorDoesNotSkipLateByteWitness(t *testing.T) {
	fixture := newPhysicalPacketTestFixture(t)
	callbackErr := errors.New("fixture callback failed")
	calls := 0
	err := fixture.observe(t, fixture.expected, func(got []physicalPacketObservation) error {
		calls++
		physicalPacketTestKinds(t, got, fixture.expected, physicalPacketIntact, physicalPacketIntact)
		fixture.overwriteSecondPayloadByte(t)
		return callbackErr
	})
	if calls != 1 || !errors.Is(err, callbackErr) || !errors.Is(err, errPhysicalPacketObservationUncertain) {
		t.Fatalf("callback and final witness errors must both survive: callback=%d err=%v", calls, err)
	}
}

func TestPhysicalPacketObservationCallbackErrorWithoutDrift(t *testing.T) {
	fixture := newPhysicalPacketTestFixture(t)
	callbackErr := errors.New("fixture callback failed without drift")
	calls := 0
	err := fixture.observe(t, fixture.expected, func(got []physicalPacketObservation) error {
		calls++
		physicalPacketTestKinds(t, got, fixture.expected, physicalPacketIntact, physicalPacketIntact)
		return callbackErr
	})
	if calls != 1 || !errors.Is(err, callbackErr) || errors.Is(err, errPhysicalPacketObservationUncertain) {
		t.Fatalf("callback error without drift must not invent instability: callback=%d err=%v", calls, err)
	}
	fixture.unchanged(t)
}

func TestPhysicalPacketObservationMissingAndEnumeratedThenRemovedDiffer(t *testing.T) {
	t.Run("stable absent", func(t *testing.T) {
		fixture := newPhysicalPacketTestFixture(t)
		if err := os.Remove(filepath.Join(fixture.root, fixture.names[1])); err != nil {
			t.Fatal(err)
		}
		calls := 0
		err := fixture.observe(t, fixture.expected, func(got []physicalPacketObservation) error {
			calls++
			physicalPacketTestKinds(t, got, fixture.expected, physicalPacketIntact, physicalPacketMissing)
			return nil
		})
		if err != nil || calls != 1 {
			t.Fatalf("stable missing: callback=%d err=%v", calls, err)
		}
	})
	t.Run("removed after enumeration", func(t *testing.T) {
		fixture := newPhysicalPacketTestFixture(t)
		calls := 0
		err := fixture.observe(t, fixture.expected, func(got []physicalPacketObservation) error {
			calls++
			physicalPacketTestKinds(t, got, fixture.expected, physicalPacketIntact, physicalPacketIntact)
			return os.Remove(filepath.Join(fixture.root, fixture.names[1]))
		})
		if calls != 1 || !errors.Is(err, errPhysicalPacketObservationUncertain) {
			t.Fatalf("enumerated-then-removed is not stable missing: callback=%d err=%v", calls, err)
		}
	})
}

func TestPhysicalPacketObservationRejectsUnrelatedReceipt(t *testing.T) {
	fixture := newPhysicalPacketTestFixture(t)
	unrelated := strings.Repeat("f", 64) + "-" + strings.Repeat("e", 64) + ".artifact-deleted.json"
	if err := os.WriteFile(filepath.Join(fixture.root, unrelated), []byte(`{"receipt":"unrelated"}`), 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := fixture.observe(t, fixture.expected, func([]physicalPacketObservation) error { called = true; return nil })
	if err == nil {
		t.Fatal("unrelated deletion receipt was accepted")
	}
	if called {
		t.Fatal("receipt was provisionally classified")
	}
}

func TestPhysicalPacketObservationRejectsUntrustedDirectEntries(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, physicalPacketTestFixture)
	}{
		{"unknown", func(t *testing.T, f physicalPacketTestFixture) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(f.root, "partial.tmp"), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"long name", func(t *testing.T, f physicalPacketTestFixture) {
			t.Helper()
			if err := os.WriteFile(filepath.Join(f.root, strings.Repeat("a", 161)), []byte("x"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
		{"symlink", func(t *testing.T, f physicalPacketTestFixture) {
			t.Helper()
			if err := os.Remove(filepath.Join(f.root, f.names[1])); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(f.names[0], filepath.Join(f.root, f.names[1])); err != nil {
				t.Fatal(err)
			}
		}},
		{"hardlink", func(t *testing.T, f physicalPacketTestFixture) {
			t.Helper()
			if err := os.Link(filepath.Join(f.root, f.names[0]), filepath.Join(t.TempDir(), "other-link")); err != nil {
				t.Fatal(err)
			}
		}},
		{"oversized", func(t *testing.T, f physicalPacketTestFixture) {
			t.Helper()
			if err := os.Truncate(filepath.Join(f.root, f.names[0]), physicalPacketFileLimit+1); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newPhysicalPacketTestFixture(t)
			tt.mutate(t, f)
			called := false
			err := f.observe(t, f.expected, func([]physicalPacketObservation) error { called = true; return nil })
			if !errors.Is(err, errPhysicalPacketObservationUncertain) || called {
				t.Fatalf("untrusted entry was provisionally classified: callback=%v err=%v", called, err)
			}
		})
	}
}
func TestPhysicalLinkedRequestStableAbsenceAndLateAppearance(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	packet := f.expected[0]
	created := time.UnixMilli(1002)
	request, err := artifact.New(packet.scope, artifact.KindSanitizedModelRequest, "application/json", artifact.ClassificationConfidential,
		artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{packet.descriptor.ArtifactIdentity},
		[]byte(`{"unpersisted":"descriptor fixture only"}`), created, created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	d := controlplane.ContextInputArtifactDescriptor{ArtifactIdentity: request.Identity(), PayloadDigest: request.PayloadDigest(),
		Classification: request.Classification().String(), Protection: request.Protection().String(), Provenance: request.Provenance(),
		CreatedAtMilliseconds: request.CreatedAt().UnixMilli(), ExpiresAtMilliseconds: request.ExpiresAt().UnixMilli()}
	linked := physicalPacketExpectation{scope: packet.scope, role: physicalRoleRequest, input: d}
	name := packet.scope.Identity() + "-" + request.Identity() + ".artifact.json"
	pending, err := artifact.OpenPendingFileStore(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pending.Close(); err != nil {
			t.Errorf("close pending: %v", err)
		}
	}()
	observe := func(after func([]physicalPacketObservation) error) error {
		return pending.WithOwnedRoot(func(borrowed *os.Root) error {
			return observeBorrowedHistoricalFilesWithClose(context.Background(), borrowed,
				[]physicalPacketExpectation{packet, linked}, after, (*os.File).Close)
		})
	}
	check := func(got []physicalPacketObservation) {
		t.Helper()
		if len(got) != 2 || got[0].kind != physicalPacketIntact || got[1].kind != physicalPacketMissing ||
			!reflect.DeepEqual(got[1].expectation, linked) {
			t.Fatalf("linked request not observed at its exact absent name: %+v", got)
		}
	}
	if err := observe(func(got []physicalPacketObservation) error { check(got); return nil }); err != nil {
		t.Fatalf("stable linked absence: %v", err)
	}
	f.unchanged(t)
	if err := observe(func(got []physicalPacketObservation) error {
		check(got)
		return os.WriteFile(filepath.Join(f.root, name), []byte("late"), 0600)
	}); !errors.Is(err, errPhysicalPacketObservationUncertain) {
		t.Fatalf("late descriptor-named appearance must defeat provisional absence: %v", err)
	}
}

func TestPhysicalCombinedExpectationsBoundAndRolePreimage(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	pending, err := artifact.OpenPendingFileStore(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pending.Close(); err != nil {
			t.Errorf("close pending: %v", err)
		}
	}()
	observe := func(expected []physicalPacketExpectation, after func([]physicalPacketObservation) error) error {
		return pending.WithOwnedRoot(func(root *os.Root) error {
			return observeBorrowedHistoricalFilesWithClose(context.Background(), root, expected, after, (*os.File).Close)
		})
	}
	large := make([]physicalPacketExpectation, physicalCombinedExpectationLimit)
	for i := range large {
		large[i] = f.expected[0]
	}
	called := false
	if err := observe(large, func(got []physicalPacketObservation) error {
		called = true
		if len(got) != len(large) || got[len(got)-1].kind != physicalPacketIntact {
			t.Fatal("combined bound lost expectation")
		}
		return nil
	}); err != nil || !called {
		t.Fatalf("4096 expectations: callback=%v err=%v", called, err)
	}
	called = false
	large = append(large, f.expected[0])
	if err := observe(large, func([]physicalPacketObservation) error { called = true; return nil }); !errors.Is(err, errPhysicalPacketObservationUncertain) || called {
		t.Fatalf("4097 expectations must fail before scan: callback=%v err=%v", called, err)
	}
	wrongRole := f.expected[0]
	wrongRole.role = physicalRoleRequest
	wrongRole.input = controlplane.ContextInputArtifactDescriptor{ArtifactIdentity: wrongRole.descriptor.ArtifactIdentity,
		PayloadDigest: wrongRole.descriptor.PayloadDigest, Classification: wrongRole.descriptor.Classification,
		Protection: wrongRole.descriptor.Protection, Provenance: wrongRole.descriptor.Provenance,
		CreatedAtMilliseconds: wrongRole.descriptor.CreatedAtMilliseconds, ExpiresAtMilliseconds: wrongRole.descriptor.ExpiresAtMilliseconds}
	wrongRole.descriptor = controlplane.ContextPacketDescriptor{}
	if err := observe([]physicalPacketExpectation{wrongRole}, func([]physicalPacketObservation) error { called = true; return nil }); !errors.Is(err, errPhysicalPacketObservationUncertain) || called {
		t.Fatalf("packet identity cannot serve as request identity: callback=%v err=%v", called, err)
	}
	f.unchanged(t)
}

func TestPhysicalCombinedDistinctMissingRoleExpectationsBound(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	packet := f.expected[0]
	created := time.UnixMilli(1002)
	large := make([]physicalPacketExpectation, 0, physicalCombinedExpectationLimit+1)
	names := make(map[string]bool, physicalCombinedExpectationLimit+1)
	for i := 0; i <= physicalCombinedExpectationLimit; i++ {
		request, err := artifact.New(packet.scope, artifact.KindSanitizedModelRequest, "application/json", artifact.ClassificationConfidential,
			artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{packet.descriptor.ArtifactIdentity},
			[]byte(fmt.Sprintf(`{"unpersisted":%d}`, i)), created, created.Add(time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		name := packet.scope.Identity() + "-" + request.Identity() + ".artifact.json"
		if names[name] {
			t.Fatalf("request %d has duplicate expected name", i)
		}
		names[name] = true
		large = append(large, physicalPacketExpectation{scope: packet.scope, role: physicalRoleRequest,
			input: controlplane.ContextInputArtifactDescriptor{ArtifactIdentity: request.Identity(), PayloadDigest: request.PayloadDigest(),
				Classification: request.Classification().String(), Protection: request.Protection().String(), Provenance: request.Provenance(),
				CreatedAtMilliseconds: request.CreatedAt().UnixMilli(), ExpiresAtMilliseconds: request.ExpiresAt().UnixMilli()}})
	}
	pending, err := artifact.OpenPendingFileStore(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pending.Close(); err != nil {
			t.Errorf("close pending lease: %v", err)
		}
	}()
	observe := func(expected []physicalPacketExpectation, after func([]physicalPacketObservation) error) error {
		return pending.WithOwnedRoot(func(root *os.Root) error {
			return observeBorrowedHistoricalFilesWithClose(context.Background(), root, expected, after, (*os.File).Close)
		})
	}
	calls := 0
	if err := observe(large[:physicalCombinedExpectationLimit], func(got []physicalPacketObservation) error {
		calls++
		if len(got) != physicalCombinedExpectationLimit {
			t.Fatalf("distinct role observation count: %d", len(got))
		}
		for i, observation := range got {
			if observation.kind != physicalPacketMissing || !reflect.DeepEqual(observation.expectation, large[i]) {
				t.Fatalf("distinct request %d is not its exact missing observation: %+v", i, observation)
			}
		}
		return nil
	}); err != nil || calls != 1 {
		t.Fatalf("4096 distinct missing role expectations: callbacks=%d err=%v", calls, err)
	}
	calls = 0
	if err := observe(large, func([]physicalPacketObservation) error { calls++; return nil }); !errors.Is(err, errPhysicalPacketObservationUncertain) || calls != 0 {
		t.Fatalf("4097 distinct role expectations must refuse before callback: callbacks=%d err=%v", calls, err)
	}
	f.unchanged(t)
}

func TestPhysicalPacketObservationExpectationLimitBeforeScan(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	expected := make([]physicalPacketExpectation, physicalPacketExpectationLimit+1)
	for i := range expected {
		expected[i] = f.expected[0]
	}
	called := false
	err := f.observe(t, expected, func([]physicalPacketObservation) error { called = true; return nil })
	if !errors.Is(err, errPhysicalPacketObservationUncertain) || called {
		t.Fatalf("expectation cap: callback=%v err=%v", called, err)
	}
}
func TestPhysicalPacketObservationStableCrossWiredCanonicalPacketIsMismatch(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, f.names[0]), f.original[1], 0600); err != nil {
		t.Fatal(err)
	}
	called := false
	err := f.observe(t, f.expected, func(got []physicalPacketObservation) error {
		called = true
		physicalPacketTestKinds(t, got, f.expected, physicalPacketMismatch, physicalPacketIntact)
		return nil
	})
	if err != nil || !called {
		t.Fatalf("cross-wired canonical packet: callback=%v err=%v", called, err)
	}
}

type physicalPacketForgedInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (f physicalPacketForgedInfo) Sys() any { return &f.stat }

func TestPhysicalPacketObservationExactTrustedUIDContinuity(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires distinct root and process UIDs without chown")
	}
	f := newPhysicalPacketTestFixture(t)
	leaf, err := os.Lstat(filepath.Join(f.root, f.names[0]))
	if err != nil {
		t.Fatal(err)
	}
	lock, err := os.Lstat(filepath.Join(f.root, ".artifact-writer.lock"))
	if err != nil {
		t.Fatal(err)
	}
	directory, err := os.Lstat(f.root)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name     string
		original os.FileInfo
		same     func(os.FileInfo, os.FileInfo) bool
	}{
		{"leaf", leaf, physicalPacketSame},
		{"lock", lock, physicalPacketLockSame},
		{"root", directory, physicalPacketRootSame},
	} {
		t.Run(tt.name, func(t *testing.T) {
			original, ok := tt.original.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatal("Linux stat fixture missing")
			}
			copied := *original
			copied.Uid = 0
			forged := physicalPacketForgedInfo{FileInfo: tt.original, stat: copied}
			if !tt.same(tt.original, tt.original) {
				t.Fatal("original metadata refused")
			}
			if !tt.same(forged, forged) {
				t.Fatal("individually trusted root metadata refused")
			}
			if tt.same(tt.original, forged) || tt.same(forged, tt.original) {
				t.Fatal("trusted UID changed despite equal inode/mode/size/link")
			}
		})
	}
}

func TestPhysicalPacketObservationDirectEntryBoundary(t *testing.T) {
	base, err := os.MkdirTemp("", "open-trestle-stage4-packet-cap-")
	if err != nil {
		t.Skipf("test scratch unavailable: %v", err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(base); err != nil {
			t.Errorf("remove cap scratch: %v", err)
		}
	})
	f := newPhysicalPacketTestFixtureAt(t, base)
	create := func(i int) {
		t.Helper()
		name := strings.Repeat("f", 64) + "-" + fmt.Sprintf("%064x", i+1) + ".artifact.json"
		if err := os.WriteFile(filepath.Join(f.root, name), []byte{'x'}, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < physicalPacketEntryLimit-3; i++ {
		create(i)
	}
	if count := len(physicalPacketTestEntries(t, f.root)); count != physicalPacketEntryLimit {
		t.Fatalf("boundary entries: %d", count)
	}
	calls := 0
	if err := f.observe(t, f.expected, func(got []physicalPacketObservation) error {
		calls++
		physicalPacketTestKinds(t, got, f.expected, physicalPacketIntact, physicalPacketIntact)
		return nil
	}); err != nil || calls != 1 {
		t.Fatalf("entry limit must be accepted: callback=%d err=%v", calls, err)
	}
	create(physicalPacketEntryLimit - 3)
	if count := len(physicalPacketTestEntries(t, f.root)); count != physicalPacketEntryLimit+1 {
		t.Fatalf("over limit entries: %d", count)
	}
	calls = 0
	err = f.observe(t, f.expected, func([]physicalPacketObservation) error { calls++; return nil })
	if !errors.Is(err, errPhysicalPacketObservationUncertain) || calls != 0 {
		t.Fatalf("20,002 entries: callback=%d err=%v", calls, err)
	}
}

func TestPhysicalPacketObservationAggregateBudgetBeforeRead(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	scope := f.expected[0].scope
	created := time.UnixMilli(3000)
	third, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential,
		artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, []byte(`{"packet":"third"}`), created, created.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := artifact.Encode(third)
	if err != nil {
		t.Fatal(err)
	}
	name := scope.Identity() + "-" + third.Identity() + ".artifact.json"
	if err := os.WriteFile(filepath.Join(f.root, name), raw, 0600); err != nil {
		t.Fatal(err)
	}
	descriptor := f.expected[0].descriptor
	descriptor.ArtifactIdentity = third.Identity()
	descriptor.PayloadDigest = third.PayloadDigest()
	descriptor.CreatedAtMilliseconds = third.CreatedAt().UnixMilli()
	descriptor.ExpiresAtMilliseconds = third.ExpiresAt().UnixMilli()
	f.expected = append(f.expected, physicalPacketExpectation{scope: scope, descriptor: descriptor})
	f.names = append(f.names, name)
	for _, leaf := range f.names {
		if err := os.Truncate(filepath.Join(f.root, leaf), physicalPacketFileLimit); err != nil {
			t.Fatal(err)
		}
	}
	calls := 0
	err = f.observe(t, f.expected, func([]physicalPacketObservation) error { calls++; return nil })
	if !errors.Is(err, errPhysicalPacketObservationUncertain) || calls != 0 {
		t.Fatalf("three 22MiB leaves must preflight 64MiB cap: callback=%d err=%v", calls, err)
	}
}

func (f physicalPacketTestFixture) observeWithClose(t *testing.T, after func([]physicalPacketObservation) error, closeFile func(*os.File) error) error {
	t.Helper()
	pending, err := artifact.OpenPendingFileStore(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pending.Close(); err != nil {
			t.Errorf("close pending lease: %v", err)
		}
	}()
	return pending.WithOwnedRoot(func(borrowed *os.Root) error {
		return observeBorrowedHistoricalPacketFilesWithClose(context.Background(), borrowed, f.expected, after, closeFile)
	})
}
func TestPhysicalPacketObservationCheckedLateCloseJoinsCallbackError(t *testing.T) {
	for _, target := range []int{5, 6} {
		t.Run(fmt.Sprintf("close_%d", target), func(t *testing.T) {
			f := newPhysicalPacketTestFixture(t)
			injected := errors.New("fixture checked close failed")
			callback := errors.New("fixture callback failed")
			closeCount := 0
			callbacks := 0
			err := f.observeWithClose(t, func(got []physicalPacketObservation) error {
				callbacks++
				physicalPacketTestKinds(t, got, f.expected, physicalPacketIntact, physicalPacketIntact)
				return callback
			}, func(file *os.File) error {
				closeCount++
				closeErr := file.Close()
				if closeCount == target {
					return errors.Join(closeErr, injected)
				}
				return closeErr
			})
			if callbacks != 1 || closeCount != 6 || !errors.Is(err, callback) || !errors.Is(err, errPhysicalPacketObservationUncertain) {
				t.Fatalf("checked late close must preserve callback and structural uncertainty: callbacks=%d closes=%d err=%v", callbacks, closeCount, err)
			}
			f.unchanged(t)
		})
	}
}
func TestPhysicalPacketObservationRootPostcheckJoinsCallbackError(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	callback := errors.New("fixture callback failed")
	t.Cleanup(func() {
		if err := os.Chmod(f.root, 0700); err != nil {
			t.Errorf("restore root fixture mode: %v", err)
		}
	})
	calls := 0
	err := f.observe(t, f.expected, func(got []physicalPacketObservation) error {
		calls++
		physicalPacketTestKinds(t, got, f.expected, physicalPacketIntact, physicalPacketIntact)
		if err := os.Chmod(f.root, 0755); err != nil {
			t.Fatal(err)
		}
		return callback
	})
	if calls != 1 || !errors.Is(err, callback) || !errors.Is(err, errPhysicalPacketObservationUncertain) {
		t.Fatalf("root postcheck must preserve callback and structural uncertainty: callbacks=%d err=%v", calls, err)
	}
}
