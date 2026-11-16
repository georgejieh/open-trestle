package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/setup"
)

func setupBytesFixture(t *testing.T, receipt, staging, lockPayload, independentStaging bool) (string, string, *localSourceOwnerSnapshot, *artifact.PendingFileStore, *controlplane.FileRunJournal) {
	t.Helper()
	state, path, plan := snapshotFixture(t)
	writeSnapshotSetup(t, path, plan)
	if receipt {
		plan, _ = writeSnapshotReceipt(t, path, plan)
		if staging {
			names, err := os.ReadDir(path + ".receipts")
			if err != nil || len(names) != 1 {
				t.Fatalf("receipt fixture: %v", err)
			}
			name := filepath.Join(path+".receipts", names[0].Name())
			if independentStaging {
				raw, err := os.ReadFile(name)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name+".next", raw, 0600); err != nil {
					t.Fatal(err)
				}
			} else if err := os.Link(name, name+".next"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if lockPayload {
		if err := os.WriteFile(path+".lock", []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	snap, err := inspectLocalSourceOwnerSnapshot(context.Background(), state, path, &plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := snap.Close(); err != nil {
			t.Error(err)
		}
	})
	pending, err := artifact.OpenPendingFileStore(filepath.Join(state, "artifacts"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := pending.Close(); err != nil {
			t.Error(err)
		}
	})
	journal, err := controlplane.NewFileRunJournal(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := journal.Close(); err != nil {
			t.Error(err)
		}
	})
	return state, path, snap, pending, journal
}

func compareSetupBytesInLease(t *testing.T, snap *localSourceOwnerSnapshot, pending *artifact.PendingFileStore, journal *controlplane.FileRunJournal, ctx context.Context) error {
	t.Helper()
	return journal.WithOwnedRoot(context.Background(), func(state *os.Root) error {
		return pending.WithOwnedRoot(func(artifacts *os.Root) error {
			return recheckLocalSourceOwnerSetupBytes(ctx, snap, state, artifacts)
		})
	})
}

func TestLocalSourceOwnerSetupBytesFixedOriginalLeaves(t *testing.T) {
	for _, tc := range []struct {
		name             string
		receipt, staging bool
		count            int
	}{
		{"empty-ledger", false, false, 2}, {"committed", true, false, 3}, {"linked-staging", true, true, 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			state, path, snap, pending, journal := setupBytesFixture(t, tc.receipt, tc.staging, false, false)
			before := snapshotTree(t, filepath.Dir(state))
			if len(snap.SetupBytes) != tc.count {
				t.Fatalf("digest count=%d want=%d", len(snap.SetupBytes), tc.count)
			}
			for key, digest := range snap.SetupBytes {
				info, ok := snap.Entries[key]
				if !ok || info.Mode() != 0600 || info.Size() > 1<<20 {
					t.Fatalf("unexpected key or metadata %q", key)
				}
				raw, err := os.ReadFile(filepath.Join(state, filepath.FromSlash(key)))
				if err != nil {
					t.Fatal(err)
				}
				if digest != sha256.Sum256(raw) {
					t.Fatalf("incorrect digest %q", key)
				}
			}
			expectedKeys := map[string]bool{"setup/plan.json": true, "setup/plan.json.lock": true}
			receipts, err := os.ReadDir(path + ".receipts")
			if err != nil {
				t.Fatal(err)
			}
			for _, receipt := range receipts {
				expectedKeys["setup/plan.json.receipts/"+receipt.Name()] = true
			}
			if len(expectedKeys) != tc.count || len(expectedKeys) != len(snap.SetupBytes) {
				t.Fatalf("wrong fixed digest key set: expected=%v actual=%v", expectedKeys, snap.SetupBytes)
			}
			for key := range snap.SetupBytes {
				if !expectedKeys[key] {
					t.Fatalf("unexpected digest key %q", key)
				}
			}
			if err := compareSetupBytesInLease(t, snap, pending, journal, context.Background()); err != nil {
				t.Fatal(err)
			}
			inspected, err := setup.InspectStateFile(context.Background(), path)
			if err != nil || inspected.RootIdentity() == "" {
				t.Fatalf("independent inspection: %v", err)
			}
			assertSnapshotTreeUnchanged(t, before, snapshotTree(t, filepath.Dir(state)))
		})
	}
}

func TestLocalSourceOwnerSetupBytesRejectsSameInodeSameSizeMutation(t *testing.T) {
	for _, kind := range []string{"plan", "lock", "committed-receipt", "staged-receipt"} {
		t.Run(kind, func(t *testing.T) {
			receipt := strings.Contains(kind, "receipt")
			state, path, snap, pending, journal := setupBytesFixture(t, receipt, kind == "staged-receipt", kind == "lock", kind == "staged-receipt")
			target := path
			if kind == "lock" {
				target = path + ".lock"
			}
			if receipt {
				names, err := os.ReadDir(path + ".receipts")
				if err != nil {
					t.Fatal(err)
				}
				found := false
				for _, name := range names {
					isNext := strings.HasSuffix(name.Name(), ".next")
					if isNext == (kind == "staged-receipt") {
						target = filepath.Join(path+".receipts", name.Name())
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("missing %s receipt target", kind)
				}
			}
			before, err := os.Lstat(target)
			if err != nil {
				t.Fatal(err)
			}
			file, err := os.OpenFile(target, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, writeErr := file.WriteAt([]byte("X"), 0)
			if err := file.Close(); err != nil || writeErr != nil {
				t.Fatalf("mutation: write=%v close=%v", writeErr, err)
			}
			after, err := os.Lstat(target)
			if err != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.Mode() != after.Mode() {
				t.Fatalf("mutation changed metadata: %v", err)
			}
			// The existing metadata oracle accepts this change. The byte oracle must not.
			if err := recheckLocalSourceOwnerPostConstructorViaLease(snap, pending, journal); err != nil {
				t.Fatalf("metadata oracle: %v", err)
			}
			key, err := filepath.Rel(state, target)
			if err != nil {
				t.Fatal(err)
			}
			key = filepath.ToSlash(key)
			changed, err := os.ReadFile(target)
			if err != nil || sha256.Sum256(changed) == snap.SetupBytes[key] {
				t.Fatalf("%s digest unchanged: %v", kind, err)
			}
			entered := false
			var helperErr error
			outerErr := journal.WithOwnedRoot(context.Background(), func(stateRoot *os.Root) error {
				return pending.WithOwnedRoot(func(artifactRoot *os.Root) error {
					entered = true
					helperErr = recheckLocalSourceOwnerSetupBytes(context.Background(), snap, stateRoot, artifactRoot)
					return helperErr
				})
			})
			if !entered || helperErr == nil || outerErr == nil {
				t.Fatalf("%s byte helper not proven to reject in %s: entered=%t helper=%v outer=%v", kind, state, entered, helperErr, outerErr)
			}
		})
	}
}

func recheckLocalSourceOwnerPostConstructorViaLease(snap *localSourceOwnerSnapshot, pending *artifact.PendingFileStore, journal *controlplane.FileRunJournal) error {
	return journal.WithOwnedRoot(context.Background(), func(state *os.Root) error {
		return pending.WithOwnedRoot(func(artifacts *os.Root) error { return recheckLocalSourceOwnerPostConstructor(snap, state, artifacts) })
	})
}

func TestLocalSourceOwnerSetupBytesRejectsContextAndDigestSetChanges(t *testing.T) {
	state, _, snap, pending, journal := setupBytesFixture(t, false, false, false, false)
	before := snapshotTree(t, filepath.Dir(state))
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := compareSetupBytesInLease(t, snap, pending, journal, canceled); err == nil {
		t.Fatal("canceled compare accepted")
	}
	if err := compareSetupBytesInLease(t, snap, pending, journal, nil); err == nil {
		t.Fatal("nil context accepted")
	}
	assertSnapshotTreeUnchanged(t, before, snapshotTree(t, filepath.Dir(state)))
	delete(snap.SetupBytes, "setup/plan.json.lock")
	if err := compareSetupBytesInLease(t, snap, pending, journal, context.Background()); err == nil {
		t.Fatal("missing digest accepted")
	}
	assertSnapshotTreeUnchanged(t, before, snapshotTree(t, filepath.Dir(state)))
}

func TestLocalSourceOwnerSetupBytesRejectsChangedOriginalShape(t *testing.T) {
	for _, change := range []string{"plan-replacement", "lock-symlink", "lock-size", "receipt-directory-replacement", "setup-directory-replacement", "unexpected-receipt", "unexpected-setup", "setup-symlink", "receipts-symlink", "plan-mode"} {
		t.Run(change, func(t *testing.T) {
			receipt := change == "receipt-directory-replacement" || change == "unexpected-receipt"
			state, path, snap, pending, journal := setupBytesFixture(t, receipt, false, false, false)
			savedDir := filepath.Dir(state)
			switch change {
			case "plan-replacement":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(path, filepath.Join(savedDir, "saved-plan")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "lock-symlink":
				if err := os.Rename(path+".lock", filepath.Join(savedDir, "saved-lock")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(savedDir, "saved-lock"), path+".lock"); err != nil {
					t.Fatal(err)
				}
			case "lock-size":
				if err := os.WriteFile(path+".lock", []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			case "receipt-directory-replacement":
				if err := os.Rename(path+".receipts", filepath.Join(savedDir, "saved-receipts")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(path+".receipts", 0700); err != nil {
					t.Fatal(err)
				}
			case "setup-directory-replacement":
				if err := os.Rename(filepath.Dir(path), filepath.Join(savedDir, "saved-setup")); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
			case "unexpected-receipt":
				if err := os.WriteFile(filepath.Join(path+".receipts", "00000000000000000099-"+strings.Repeat("a", 64)+".receipt.json"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "unexpected-setup":
				if err := os.WriteFile(filepath.Join(filepath.Dir(path), "extra"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "setup-symlink":
				if err := os.Rename(filepath.Dir(path), filepath.Join(savedDir, "saved-setup")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(savedDir, "saved-setup"), filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
			case "receipts-symlink":
				if err := os.Rename(path+".receipts", filepath.Join(savedDir, "saved-receipts")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.Join(savedDir, "saved-receipts"), path+".receipts"); err != nil {
					t.Fatal(err)
				}
			case "plan-mode":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			}
			if err := compareSetupBytesInLease(t, snap, pending, journal, context.Background()); err == nil {
				t.Fatalf("accepted %s", change)
			}
		})
	}
}

func TestLocalSourceOwnerSnapshotRehashesAfterSemanticInspection(t *testing.T) {
	state, path, plan := snapshotFixture(t)
	writeSnapshotSetup(t, path, plan)
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	original := sha256.Sum256(raw)
	inspected := false
	_, err = inspectLocalSourceOwnerSnapshotWithInspector(context.Background(), state, path, &plan, func(ctx context.Context, name string) (setup.Plan, error) {
		valid, err := setup.InspectStateFile(ctx, name)
		if err != nil {
			return valid, err
		}
		inspected = true
		f, err := os.OpenFile(name, os.O_WRONLY, 0)
		if err != nil {
			return valid, err
		}
		_, writeErr := f.WriteAt([]byte("X"), 0)
		if closeErr := f.Close(); writeErr != nil || closeErr != nil {
			t.Fatalf("mutate: write=%v close=%v", writeErr, closeErr)
		}
		return valid, nil
	})
	if !inspected {
		t.Fatal("semantic inspector not entered")
	}
	if err == nil {
		t.Fatal("accepted a same-inode, same-size post-inspection mutation")
	}
	after, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() || before.Size() != after.Size() {
		t.Fatalf("mutation changed metadata: %v", err)
	}
	changed, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(changed) == original {
		t.Fatalf("mutation did not change bytes: %v", err)
	}
}

func TestLocalSourceOwnerSetupLeafByteLimitAndClosedRoots(t *testing.T) {
	dir := t.TempDir()
	name := "leaf"
	content := []byte(strings.Repeat("a", 1<<20))
	if err := os.WriteFile(filepath.Join(dir, name), content, 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := root.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	got, err := hashOriginalSetupLeaf(context.Background(), root, name, saved)
	if err != nil || got != sha256.Sum256(content) {
		t.Fatalf("1 MiB leaf: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(content, 'x'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := hashOriginalSetupLeaf(context.Background(), root, name, saved); err == nil {
		t.Fatal("size+1 leaf accepted against original metadata")
	}
	tooLarge, err := root.Lstat(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hashOriginalSetupLeaf(context.Background(), root, name, tooLarge); err == nil {
		t.Fatal("1 MiB+1 leaf accepted")
	}
	if _, err := hashOriginalSetupLeaf(context.Background(), nil, name, saved); err == nil {
		t.Fatal("nil root accepted")
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := hashOriginalSetupLeaf(context.Background(), root, name, saved); err == nil {
		t.Fatal("closed root accepted")
	}
}

func TestLocalSourceOwnerSetupBytesRejectsNilAndClosedBorrowedRoots(t *testing.T) {
	_, _, snap, pending, journal := setupBytesFixture(t, false, false, false, false)
	if err := recheckLocalSourceOwnerSetupBytes(context.Background(), snap, nil, nil); err == nil {
		t.Fatal("nil roots accepted")
	}
	closed, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := journal.WithOwnedRoot(context.Background(), func(state *os.Root) error {
		return pending.WithOwnedRoot(func(artifacts *os.Root) error {
			if err := recheckLocalSourceOwnerSetupBytes(context.Background(), snap, closed, artifacts); err == nil {
				t.Fatal("closed state root accepted")
			}
			if err := recheckLocalSourceOwnerSetupBytes(context.Background(), snap, state, closed); err == nil {
				t.Fatal("closed artifact root accepted")
			}
			return nil
		})
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLocalSourceOwnerSnapshotRejectsReceiptAndStagingShapeLimits(t *testing.T) {
	for _, shape := range []string{"258-receipts", "multiple-staging", "invalid-staging-name", "plan-next", "corrupt-committed"} {
		t.Run(shape, func(t *testing.T) {
			state, path, plan := snapshotFixture(t)
			writeSnapshotSetup(t, path, plan)
			dir := path + ".receipts"
			if shape == "multiple-staging" || shape == "corrupt-committed" {
				plan, _ = writeSnapshotReceipt(t, path, plan)
			}
			switch shape {
			case "258-receipts":
				for n := 0; n < 258; n++ {
					name := fmt.Sprintf("%020d-%s.receipt.json", n, strings.Repeat("a", 64))
					if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "multiple-staging":
				names, err := os.ReadDir(dir)
				if err != nil || len(names) != 1 {
					t.Fatalf("receipt: %v", err)
				}
				for n := 0; n < 2; n++ {
					name := fmt.Sprintf("%020d-%s.receipt.json.next", n, strings.Repeat("b", 64))
					if err := os.Link(filepath.Join(dir, names[0].Name()), filepath.Join(dir, name)); err != nil {
						t.Fatal(err)
					}
				}
			case "invalid-staging-name":
				if err := os.WriteFile(filepath.Join(dir, "invalid.receipt.json.next"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "plan-next":
				if err := os.WriteFile(path+".next", nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "corrupt-committed":
				names, err := os.ReadDir(dir)
				if err != nil || len(names) != 1 {
					t.Fatalf("receipt: %v", err)
				}
				file, err := os.OpenFile(filepath.Join(dir, names[0].Name()), os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, writeErr := file.WriteAt([]byte("X"), 0)
				if closeErr := file.Close(); writeErr != nil || closeErr != nil {
					t.Fatalf("corrupt: %v %v", writeErr, closeErr)
				}
			}
			before := snapshotTree(t, filepath.Dir(state))
			snap, err := inspectLocalSourceOwnerSnapshot(context.Background(), state, path, &plan)
			if snap != nil {
				_ = snap.Close()
			}
			if err == nil {
				t.Fatalf("accepted %s", shape)
			}
			assertSnapshotTreeUnchanged(t, before, snapshotTree(t, filepath.Dir(state)))
		})
	}
}

type setupFaultReader struct {
	io.Reader
	closeError error
}

func (r setupFaultReader) Close() error { return r.closeError }

func TestLocalSourceOwnerSetupLeafRejectsReadAndCloseFaults(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "leaf"), []byte("abcd"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	saved, err := root.Lstat("leaf")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, bytes string
		closeErr    error
	}{
		{"short-read", "ab", nil},
		{"extra-eof-byte", "abcde", nil},
		{"close-error", "abcd", errors.New("injected close failure")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entered := false
			_, err := hashOriginalSetupLeafWithReader(context.Background(), root, "leaf", saved, func(_ *os.File) io.ReadCloser {
				entered = true
				return setupFaultReader{Reader: bytes.NewReader([]byte(tc.bytes)), closeError: tc.closeErr}
			})
			if !entered || err == nil {
				t.Fatalf("fault accepted: entered=%t err=%v", entered, err)
			}
			if tc.closeErr != nil && !strings.Contains(err.Error(), "close setup reader") {
				t.Fatalf("close fault not observed: %v", err)
			}
		})
	}
}
