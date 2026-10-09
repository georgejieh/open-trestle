package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

// The helper borrows both roots only inside their constructor-held lease scopes.
func postConstructorFixture(t *testing.T, shape string) (string, string, *localSourceOwnerSnapshot, *artifact.PendingFileStore, *controlplane.FileRunJournal) {
	t.Helper()
	state, planPath, plan := snapshotFixture(t)
	if shape == "empty" {
		if err := os.Mkdir(state, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if shape == "setup-only" || shape == "setup-full" {
		writeSnapshotSetup(t, planPath, plan)
		if shape == "setup-full" {
			plan, _ = writeSnapshotReceipt(t, planPath, plan)
		}
	}
	snap, err := inspectLocalSourceOwnerSnapshot(context.Background(), state, planPath, &plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := snap.Close(); err != nil {
			t.Error(err)
		}
	})
	if shape != "missing" && recheckOwnerEntries(snap) != nil {
		t.Fatal("invalid original snapshot")
	}
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
	return state, planPath, snap, pending, journal
}

func checkPostConstructor(t *testing.T, snap *localSourceOwnerSnapshot, pending *artifact.PendingFileStore, journal *controlplane.FileRunJournal) error {
	t.Helper()
	return journal.WithOwnedRoot(context.Background(), func(state *os.Root) error {
		return pending.WithOwnedRoot(func(artifacts *os.Root) error {
			return recheckLocalSourceOwnerPostConstructor(snap, state, artifacts)
		})
	})
}

func TestLocalSourceOwnerPostConstructorAcceptsOnlyExactConstructorDelta(t *testing.T) {
	for _, shape := range []string{"missing", "empty", "setup-only", "setup-full"} {
		t.Run(shape, func(t *testing.T) {
			_, _, snap, pending, journal := postConstructorFixture(t, shape)
			if shape != "missing" && recheckOwnerEntries(snap) == nil {
				t.Fatal("old exact-entry recheck unexpectedly accepted constructor additions")
			}
			if err := checkPostConstructor(t, snap, pending, journal); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLocalSourceOwnerPostConstructorRefusesMutation(t *testing.T) {
	for _, change := range []string{"state-inode", "artifact-inode", "unknown", "root-overbound", "owner-final", "owner-temp", "setup-child", "setup-inode", "setup-plan-size", "setup-receipt-size", "state-mode", "artifact-mode", "state-lock-mode", "artifact-lock-mode", "state-lock-symlink", "artifact-lock-symlink", "state-lock-hardlink", "artifact-lock-hardlink", "artifact-extra", "artifact-overbound"} {
		t.Run(change, func(t *testing.T) {
			shape := "empty"
			if change == "setup-child" || change == "setup-inode" || change == "setup-plan-size" {
				shape = "setup-only"
			}
			if change == "setup-receipt-size" {
				shape = "setup-full"
			}
			state, planPath, snap, pending, journal := postConstructorFixture(t, shape)
			artifactPath := filepath.Join(state, "artifacts")
			switch change {
			case "state-inode":
				saved := state + "-saved"
				if err := os.Rename(state, saved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(state, 0700); err != nil {
					t.Fatal(err)
				}
				// The borrowed callback itself can reject this before entering our helper.
			case "artifact-inode":
				saved := artifactPath + "-saved"
				if err := os.Rename(artifactPath, saved); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(artifactPath, 0700); err != nil {
					t.Fatal(err)
				}
			case "unknown", "root-overbound", "owner-final", "owner-temp":
				name := map[string]string{"unknown": "unexpected", "owner-final": ".local-source-owner.json", "owner-temp": ".local-source-owner.json.next", "root-overbound": "unexpected"}[change]
				if change == "root-overbound" {
					for i := 0; i < 5; i++ {
						if err := os.WriteFile(filepath.Join(state, fmt.Sprintf("extra-%d", i)), nil, 0600); err != nil {
							t.Fatal(err)
						}
					}
				} else if err := os.WriteFile(filepath.Join(state, name), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "setup-child":
				if err := os.WriteFile(filepath.Join(state, "setup", "unexpected"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "setup-inode":
				original, err := os.ReadFile(planPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(planPath, filepath.Join(filepath.Dir(state), "saved-plan")); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(planPath, original, 0600); err != nil {
					t.Fatal(err)
				}
			case "state-lock-mode":
				if err := os.Chmod(filepath.Join(state, ".run-writer.lock"), 0644); err != nil {
					t.Fatal(err)
				}
			case "artifact-lock-mode":
				if err := os.Chmod(filepath.Join(artifactPath, ".artifact-writer.lock"), 0644); err != nil {
					t.Fatal(err)
				}
			case "state-lock-symlink", "artifact-lock-symlink":
				dir, name := state, ".run-writer.lock"
				if change == "artifact-lock-symlink" {
					dir, name = artifactPath, ".artifact-writer.lock"
				}
				saved := filepath.Join(filepath.Dir(state), change+".saved")
				if err := os.Rename(filepath.Join(dir, name), saved); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(saved, filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			case "state-lock-hardlink", "artifact-lock-hardlink":
				dir, name := state, ".run-writer.lock"
				if change == "artifact-lock-hardlink" {
					dir, name = artifactPath, ".artifact-writer.lock"
				}
				if err := os.Link(filepath.Join(dir, name), filepath.Join(filepath.Dir(state), change+".linked")); err != nil {
					t.Fatal(err)
				}
			case "artifact-extra", "artifact-overbound":
				count := 1
				if change == "artifact-overbound" {
					count = 5
				}
				for i := 0; i < count; i++ {
					if err := os.WriteFile(filepath.Join(artifactPath, fmt.Sprintf("payload-%d", i)), nil, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			if change == "state-inode" || change == "artifact-inode" {
				entered := false
				err := journal.WithOwnedRoot(context.Background(), func(stateRoot *os.Root) error {
					return pending.WithOwnedRoot(func(artifactRoot *os.Root) error {
						entered = true
						return recheckLocalSourceOwnerPostConstructor(snap, stateRoot, artifactRoot)
					})
				})
				if err == nil || entered {
					t.Fatalf("constructor-root swap crossed borrowed callback: error=%v entered=%v", err, entered)
				}
			} else {
				entered := false
				var helperErr error
				err := journal.WithOwnedRoot(context.Background(), func(stateRoot *os.Root) error {
					return pending.WithOwnedRoot(func(artifactRoot *os.Root) error {
						entered = true
						var mutationErr error
						switch change {
						case "state-mode":
							mutationErr = os.Chmod(state, 0755)
						case "artifact-mode":
							mutationErr = os.Chmod(artifactPath, 0755)
						case "setup-plan-size":
							mutationErr = appendPostConstructorByte(planPath)
						case "setup-receipt-size":
							receipts := filepath.Join(state, "setup", "plan.json.receipts")
							entries, readErr := os.ReadDir(receipts)
							if readErr != nil {
								return readErr
							}
							if len(entries) != 1 {
								return fmt.Errorf("want one receipt, found %d", len(entries))
							}
							mutationErr = appendPostConstructorByte(filepath.Join(receipts, entries[0].Name()))
						}
						if mutationErr != nil {
							return mutationErr
						}
						helperErr = recheckLocalSourceOwnerPostConstructor(snap, stateRoot, artifactRoot)
						return helperErr
					})
				})
				if !entered || helperErr == nil || err == nil {
					t.Fatalf("mutation must reach and be refused by helper: entered=%v helper=%v lease=%v", entered, helperErr, err)
				}
			}
		})
	}
}

func appendPostConstructorByte(path string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return err
	}
	_, writeErr := file.Write([]byte("x"))
	return errors.Join(writeErr, file.Close())
}
