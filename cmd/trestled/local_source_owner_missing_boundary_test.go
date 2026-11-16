package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

func missingBoundaryFixture(t *testing.T, nested bool) (string, *localMissingStateBoundary) {
	t.Helper()
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(parent, "state")
	if nested {
		state = filepath.Join(parent, "new", "deep", "state")
	}
	boundary, err := captureLocalMissingStateBoundary(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := boundary.Close(); err != nil {
			t.Error(err)
		}
	})
	return state, boundary
}

func missingBoundaryConstruct(t *testing.T, state string, boundary *localMissingStateBoundary) (*artifact.PendingFileStore, *controlplane.FileRunJournal) {
	t.Helper()
	if err := boundary.RecheckMissing(context.Background()); err != nil {
		t.Fatal(err)
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
	return pending, journal
}

func missingBoundaryUnderLeases(pending *artifact.PendingFileStore, journal *controlplane.FileRunJournal, boundary *localMissingStateBoundary) error {
	return journal.WithOwnedRoot(context.Background(), func(state *os.Root) error {
		return pending.WithOwnedRoot(func(artifacts *os.Root) error {
			if err := boundary.RecheckConstructed(context.Background(), state); err != nil {
				return err
			}
			return recheckLocalSourceOwnerPostConstructor(&localSourceOwnerSnapshot{Kind: localSourceOwnerMissing}, state, artifacts)
		})
	})
}

func TestLocalMissingStateBoundaryConstructed(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(map[bool]string{false: "direct", true: "nested"}[nested], func(t *testing.T) {
			state, boundary := missingBoundaryFixture(t, nested)
			if boundary.ParentRoot == nil || boundary.ParentInfo == nil || boundary.ParentPin == nil || len(boundary.Suffix) == 0 {
				t.Fatal("original parent not retained")
			}
			pending, journal := missingBoundaryConstruct(t, state, boundary)
			if err := missingBoundaryUnderLeases(pending, journal, boundary); err != nil {
				t.Fatal(err)
			}
			if err := boundary.Close(); err != nil {
				t.Fatal(err)
			}
			if boundary.ParentRoot != nil || boundary.Close() != nil {
				t.Fatal("close not idempotent")
			}
		})
	}
}

func TestLocalMissingStateBoundaryRefusesInsertedFirstChild(t *testing.T) {
	state, boundary := missingBoundaryFixture(t, true)
	if err := os.Mkdir(filepath.Join(filepath.Dir(filepath.Dir(state)), "deep"), 0700); err == nil {
		t.Fatal("fixture unexpectedly had deep parent")
	}
	if err := os.Mkdir(filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(state))), "new"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := boundary.RecheckMissing(context.Background()); err == nil {
		t.Fatal("accepted inserted private first child")
	}
}

func TestLocalMissingStateBoundaryRefusesConstructedMutation(t *testing.T) {
	for _, change := range []string{"sibling", "symlink", "public", "final-replaced", "parent-replaced-preserve-state"} {
		t.Run(change, func(t *testing.T) {
			var movedParent string
			t.Cleanup(func() {
				if movedParent != "" {
					_ = os.RemoveAll(movedParent)
				}
			})
			state, boundary := missingBoundaryFixture(t, true)
			pending, journal := missingBoundaryConstruct(t, state, boundary)
			first := filepath.Join(boundary.ParentPath, "new")
			called := false
			err := journal.WithOwnedRoot(context.Background(), func(stateRoot *os.Root) error {
				return pending.WithOwnedRoot(func(_ *os.Root) error {
					called = true
					switch change {
					case "sibling":
						if err := os.Mkdir(filepath.Join(first, "extra"), 0700); err != nil {
							t.Fatal(err)
						}
					case "symlink":
						if err := os.Rename(filepath.Join(first, "deep"), filepath.Join(first, "saved")); err != nil {
							t.Fatal(err)
						}
						if err := os.Symlink("saved", filepath.Join(first, "deep")); err != nil {
							t.Fatal(err)
						}
					case "public":
						if err := os.Chmod(first, 0755); err != nil {
							t.Fatal(err)
						}
					case "final-replaced":
						if err := os.Rename(state, state+"-saved"); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(state, 0700); err != nil {
							t.Fatal(err)
						}
					case "parent-replaced-preserve-state":
						saved := boundary.ParentPath + "-saved"
						movedParent = saved
						if err := os.Rename(boundary.ParentPath, saved); err != nil {
							t.Fatal(err)
						}
						if err := os.Mkdir(boundary.ParentPath, 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.MkdirAll(filepath.Dir(state), 0700); err != nil {
							t.Fatal(err)
						}
						if err := os.Rename(filepath.Join(saved, "new", "deep", "state"), state); err != nil {
							t.Fatal(err)
						}
					}
					if err := boundary.RecheckConstructed(context.Background(), stateRoot); err == nil {
						t.Error("accepted mutation", change)
					}
					return nil
				})
			})
			if !called {
				t.Fatal("leases did not enter callback", err)
			}
		})
	}
}

func TestLocalMissingStateBoundaryRefusesInvalidInput(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		path string
	}{
		{"nil", nil, filepath.Join(parent, "state")}, {"canceled", canceled, filepath.Join(parent, "state")},
		{"empty", context.Background(), ""}, {"root", context.Background(), string(filepath.Separator)},
		{"overdeep", context.Background(), filepath.Join(parent, strings.Repeat("x/", 65), "state")},
		{"overlong", context.Background(), filepath.Join(parent, strings.Repeat("x", 129))},
		{"existing-file", context.Background(), filepath.Join(parent, "file", "state")},
		{"public-parent", context.Background(), filepath.Join(parent, "public", "state")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "existing-file" {
				if err := os.WriteFile(filepath.Join(parent, "file"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.name == "public-parent" {
				if err := os.Mkdir(filepath.Join(parent, "public"), 0755); err != nil {
					t.Fatal(err)
				}
			}
			boundary, err := captureLocalMissingStateBoundary(tc.ctx, tc.path)
			if err == nil {
				_ = boundary.Close()
				t.Fatal("accepted invalid input")
			}
		})
	}
}

func TestLocalMissingStateBoundaryCancelAndClose(t *testing.T) {
	state, boundary := missingBoundaryFixture(t, false)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := boundary.RecheckMissing(canceled); err == nil {
		t.Fatal("accepted canceled before constructors")
	}
	pending, journal := missingBoundaryConstruct(t, state, boundary)
	err := journal.WithOwnedRoot(context.Background(), func(root *os.Root) error {
		return pending.WithOwnedRoot(func(_ *os.Root) error { return boundary.RecheckConstructed(canceled, root) })
	})
	if err == nil {
		t.Fatal("accepted canceled callback")
	}
	if err := boundary.Close(); err != nil {
		t.Fatal(err)
	}
	if err := boundary.RecheckMissing(context.Background()); err == nil {
		t.Fatal("accepted closed parent")
	}
	if err := boundary.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
		t.Fatal(err)
	}
}

func TestLocalMissingStateBoundaryRefusesOriginalParentReplacement(t *testing.T) {
	var movedParent string
	t.Cleanup(func() {
		if movedParent != "" {
			_ = os.RemoveAll(movedParent)
		}
	})
	state, boundary := missingBoundaryFixture(t, false)
	saved := boundary.ParentPath + "-saved"
	movedParent = saved
	if err := os.Rename(boundary.ParentPath, saved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(boundary.ParentPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := boundary.RecheckMissing(context.Background()); err == nil {
		t.Fatal("accepted substituted original parent")
	}
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("test requires absent state", err)
	}
}

func TestLocalMissingStateBoundaryRefusesOriginalSymlink(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(parent, "real"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(parent, "link")); err != nil {
		t.Fatal(err)
	}
	if b, err := captureLocalMissingStateBoundary(context.Background(), filepath.Join(parent, "link", "state")); err == nil {
		_ = b.Close()
		t.Fatal("accepted linked existing intermediate")
	}
}

func TestLocalMissingStateBoundaryJoinsCloseError(t *testing.T) {
	_, boundary := missingBoundaryFixture(t, false)
	closeFailure := errors.New("injected parent close failure")
	calls := 0
	boundary.closeParent = func(root *os.Root) error { calls++; return errors.Join(root.Close(), closeFailure) }
	callbackFailure := errors.New("injected callback failure")
	combined := errors.Join(callbackFailure, boundary.Close())
	if !errors.Is(combined, closeFailure) || !errors.Is(combined, callbackFailure) {
		t.Fatal("lost primary or close error", combined)
	}
	if err := boundary.Close(); err != nil || calls != 1 {
		t.Fatal("close was not idempotent", calls, err)
	}
}

func TestLocalMissingStateBoundaryRefusesLinkedFirstChild(t *testing.T) {
	state, boundary := missingBoundaryFixture(t, true)
	if err := os.Mkdir(filepath.Join(boundary.ParentPath, "target"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("target", filepath.Join(boundary.ParentPath, "new")); err != nil {
		t.Fatal(err)
	}
	if err := boundary.RecheckMissing(context.Background()); err == nil {
		t.Fatal("accepted linked first missing child")
	}
	if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("nested state unexpectedly exists", err)
	}
}

func TestLocalMissingStateBoundaryRefusesAncestorSwapAfterOpeningParent(t *testing.T) {
	base := t.TempDir()
	ancestor := filepath.Join(base, "ancestor")
	deepest := filepath.Join(ancestor, "deepest")
	if err := os.MkdirAll(deepest, 0700); err != nil {
		t.Fatal(err)
	}
	original, err := os.Lstat(deepest)
	if err != nil {
		t.Fatal(err)
	}
	saved := ancestor + "-saved"
	t.Cleanup(func() { _ = os.RemoveAll(saved) })
	calls := 0
	state := filepath.Join(deepest, "state")
	boundary, err := captureLocalMissingStateBoundaryWithOpenedParent(context.Background(), state, func(opened string) {
		if opened != deepest {
			return
		}
		calls++
		if err := os.Rename(ancestor, saved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(ancestor, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(filepath.Join(saved, "deepest"), deepest); err != nil {
			t.Fatal(err)
		}
	})
	if boundary != nil {
		_ = boundary.Close()
	}
	if calls != 1 {
		t.Fatalf("expected one deepest-parent opener callback, got %d", calls)
	}
	current, statErr := os.Lstat(deepest)
	if statErr != nil || !os.SameFile(original, current) {
		t.Fatalf("test requires original deepest parent inode: %v", statErr)
	}
	if _, statErr := os.Lstat(state); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("test requires first child still missing: %v", statErr)
	}
	if err == nil {
		t.Fatal("accepted retained parent after original ancestor was replaced")
	}
}
