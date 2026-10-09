package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recordedFixture(t *testing.T) (string, string) {
	t.Helper()
	state := filepath.Join(t.TempDir(), "state")
	artifacts := filepath.Join(state, "artifacts")
	for _, dir := range []string{state, artifacts, filepath.Join(state, "audit"), filepath.Join(state, "diagnostics"), filepath.Join(state, "webhook-inbox"), filepath.Join(state, "setup")} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, data := range map[string][]byte{
		filepath.Join(state, localSourceOwnerLeaf):                                                             []byte("not valid owner content"),
		filepath.Join(state, ".run-writer.lock"):                                                               {},
		filepath.Join(artifacts, ".artifact-writer.lock"):                                                      {},
		filepath.Join(state, strings.Repeat("a", 64)+".run-plan.json"):                                         []byte("invalid plan"),
		filepath.Join(state, strings.Repeat("a", 64)+".run.jsonl"):                                             []byte("invalid stream"),
		filepath.Join(artifacts, strings.Repeat("b", 64)+"-"+strings.Repeat("c", 64)+".artifact.json"):         []byte("invalid artifact"),
		filepath.Join(artifacts, strings.Repeat("b", 64)+"-"+strings.Repeat("c", 64)+".artifact-deleted.json"): []byte("invalid receipt"),
	} {
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return state, artifacts
}

const recordedExtraArtifactName = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.artifact.json"

func mustRecordedMutation(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func mustRecordedSymlink(t *testing.T, target, path string) {
	t.Helper()
	mustRecordedMutation(t, os.Symlink(target, path))
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("mutation did not install symlink %s: %v", path, err)
	}
}

func TestLocalSourceOwnerRecordedSnapshotExactShape(t *testing.T) {
	state, artifacts := recordedFixture(t)
	assertSnapshotNoWrite(t, filepath.Dir(state), func() {
		snap, err := inspectLocalSourceOwnerRecordedSnapshot(context.Background(), state)
		if err != nil {
			t.Fatal(err)
		}
		if snap.StateRoot == nil || snap.ArtifactRoot == nil || snap.OwnerInfo == nil || len(snap.StateEntries) != 9 || len(snap.ArtifactEntries) != 3 {
			t.Fatalf("incomplete candidate: %+v", snap)
		}
		stateRoot, err := os.OpenRoot(state)
		if err != nil {
			t.Fatal(err)
		}
		defer stateRoot.Close()
		artifactRoot, err := os.OpenRoot(artifacts)
		if err != nil {
			t.Fatal(err)
		}
		defer artifactRoot.Close()
		if err := recheckLocalSourceOwnerRecordedSnapshot(context.Background(), snap, stateRoot, artifactRoot); err != nil {
			t.Fatal(err)
		}
		if _, err := readLocalSourceOwnerRecord(snap.StateRoot, snap.StatePath); !errors.Is(err, ErrLocalSourceOwnerMalformed) {
			t.Fatalf("later strict reader accepted dummy owner bytes: %v", err)
		}
		if err := snap.Close(); err != nil {
			t.Fatal(err)
		}
		if snap.StateRoot != nil || snap.ArtifactRoot != nil {
			t.Fatal("retained roots after close")
		}
		if err := snap.Close(); err != nil {
			t.Fatal(err)
		}
		if err := recheckLocalSourceOwnerRecordedSnapshot(context.Background(), snap, stateRoot, artifactRoot); err == nil {
			t.Fatal("closed candidate passed")
		}
	})
	if _, err := decodeLocalSourceOwnerRecord([]byte("not valid owner content")); err == nil {
		t.Fatal("dummy owner unexpectedly authenticated")
	}
}

func TestLocalSourceOwnerRecordedSnapshotRefusesUnsafeShapes(t *testing.T) {
	cases := map[string]func(*testing.T, string, string){
		"owner absent": func(t *testing.T, s, a string) { os.Remove(filepath.Join(s, localSourceOwnerLeaf)) },
		"owner empty":  func(t *testing.T, s, a string) { os.WriteFile(filepath.Join(s, localSourceOwnerLeaf), nil, 0600) },
		"owner oversize": func(t *testing.T, s, a string) {
			os.WriteFile(filepath.Join(s, localSourceOwnerLeaf), bytes.Repeat([]byte("x"), maxLocalSourceOwnerRecordBytes+1), 0600)
		},
		"owner public": func(t *testing.T, s, a string) { os.Chmod(filepath.Join(s, localSourceOwnerLeaf), 0644) },
		"owner hardlink": func(t *testing.T, s, a string) {
			os.Link(filepath.Join(s, localSourceOwnerLeaf), filepath.Join(t.TempDir(), "alias"))
		},
		"owner symlink": func(t *testing.T, s, a string) {
			p := filepath.Join(s, localSourceOwnerLeaf)
			outside := filepath.Join(filepath.Dir(s), "owner-saved")
			mustRecordedMutation(t, os.Rename(p, outside))
			mustRecordedSymlink(t, outside, p)
		},
		"owner temp": func(t *testing.T, s, a string) {
			os.WriteFile(filepath.Join(s, localSourceOwnerLeaf+".next"), []byte("x"), 0600)
		},
		"missing artifacts": func(t *testing.T, s, a string) { os.Rename(a, a+".saved") },
		"artifact symlink": func(t *testing.T, s, a string) {
			outside := filepath.Join(filepath.Dir(s), "artifacts-saved")
			mustRecordedMutation(t, os.Rename(a, outside))
			mustRecordedSymlink(t, outside, a)
		},
		"artifact public": func(t *testing.T, s, a string) { os.Chmod(a, 0755) },
		"state public":    func(t *testing.T, s, a string) { os.Chmod(s, 0755) },
		"public ancestor": func(t *testing.T, s, a string) {
			parent := filepath.Dir(s)
			if err := os.Chmod(parent, 0777); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(parent, 0700) })
		},
		"ancestor symlink": func(t *testing.T, s, a string) {},
		"state unknown":    func(t *testing.T, s, a string) { os.WriteFile(filepath.Join(s, "unknown.json"), []byte("x"), 0600) },
		"plan wrong digest": func(t *testing.T, s, a string) {
			os.WriteFile(filepath.Join(s, strings.Repeat("A", 64)+".run-plan.json"), []byte("x"), 0600)
		},
		"runtime symlink": func(t *testing.T, s, a string) {
			target := filepath.Join(filepath.Dir(s), "runtime-target")
			mustRecordedMutation(t, os.WriteFile(target, []byte("valid shape plan"), 0600))
			mustRecordedSymlink(t, target, filepath.Join(s, strings.Repeat("d", 64)+".run-plan.json"))
		},
		"runtime public": func(t *testing.T, s, a string) {
			os.Chmod(filepath.Join(s, strings.Repeat("a", 64)+".run-plan.json"), 0644)
		},
		"state lock absent": func(t *testing.T, s, a string) { os.Remove(filepath.Join(s, ".run-writer.lock")) },
		"state lock hardlink": func(t *testing.T, s, a string) {
			os.Link(filepath.Join(s, ".run-writer.lock"), filepath.Join(t.TempDir(), "alias"))
		},
		"artifact lock absent": func(t *testing.T, s, a string) { os.Remove(filepath.Join(a, ".artifact-writer.lock")) },
		"artifact unknown":     func(t *testing.T, s, a string) { os.WriteFile(filepath.Join(a, "unknown.next"), []byte("x"), 0600) },
		"artifact bad name": func(t *testing.T, s, a string) {
			os.WriteFile(filepath.Join(a, strings.Repeat("B", 64)+"-"+strings.Repeat("c", 64)+".artifact.json"), []byte("x"), 0600)
		},
		"artifact file public": func(t *testing.T, s, a string) {
			os.Chmod(filepath.Join(a, strings.Repeat("b", 64)+"-"+strings.Repeat("c", 64)+".artifact.json"), 0644)
		},
		"artifact child symlink": func(t *testing.T, s, a string) {
			target := filepath.Join(filepath.Dir(s), "artifact-target")
			mustRecordedMutation(t, os.WriteFile(target, []byte("valid shape artifact"), 0600))
			mustRecordedSymlink(t, target, filepath.Join(a, recordedExtraArtifactName))
		},
		"artifact child directory": func(t *testing.T, s, a string) {
			mustRecordedMutation(t, os.Mkdir(filepath.Join(a, recordedExtraArtifactName), 0700))
		},
		"nil context":      func(t *testing.T, s, a string) {},
		"canceled context": func(t *testing.T, s, a string) {},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			state, artifacts := recordedFixture(t)
			fixtureParent := filepath.Dir(state)
			change(t, state, artifacts)
			if name == "ancestor symlink" {
				alias := filepath.Join(t.TempDir(), "alias")
				if err := os.Symlink(filepath.Dir(state), alias); err != nil {
					t.Fatal(err)
				}
				state = filepath.Join(alias, "state")
			}
			ctx := context.Background()
			if name == "nil context" {
				ctx = nil
			}
			if name == "canceled context" {
				c, cancel := context.WithCancel(ctx)
				cancel()
				ctx = c
			}
			// Include targets saved beside state, even when state is reached by an alias.
			assertSnapshotNoWrite(t, fixtureParent, func() {
				snap, err := inspectLocalSourceOwnerRecordedSnapshot(ctx, state)
				if snap != nil {
					snap.Close()
				}
				if err == nil {
					t.Fatal("unsafe shape accepted")
				}
				if name == "owner absent" && !errors.Is(err, ErrLocalSourceOwnerMissing) {
					t.Fatalf("missing classification: %v", err)
				}
			})
		})
	}
}

func TestLocalSourceOwnerRecordedSnapshotBounds(t *testing.T) {
	for _, kind := range []string{"state", "artifact"} {
		t.Run(kind, func(t *testing.T) {
			state, artifacts := recordedFixture(t)
			count := 1015
			dir := state
			if kind == "artifact" {
				count = 19998
				dir = artifacts
			}
			nameAt := func(i int) string {
				if kind == "artifact" {
					return fmt.Sprintf("%064x-%064x.artifact.json", i, i)
				}
				return fmt.Sprintf("%064x.run-plan.json", i)
			}
			for i := 0; i < count; i++ {
				mustRecordedMutation(t, os.WriteFile(filepath.Join(dir, nameAt(i)), []byte("x"), 0600))
			}
			snap, err := inspectLocalSourceOwnerRecordedSnapshot(context.Background(), state)
			if err != nil {
				t.Fatalf("exact limit refused: %v", err)
			}
			mustRecordedMutation(t, snap.Close())
			mustRecordedMutation(t, os.WriteFile(filepath.Join(dir, nameAt(count)), []byte("x"), 0600))
			snap, err = inspectLocalSourceOwnerRecordedSnapshot(context.Background(), state)
			if snap != nil {
				snap.Close()
			}
			if err == nil {
				t.Fatal("overbound accepted")
			}
		})
	}
}

// Clone only the small fixed fixture. Replacements must otherwise pass shape checks.
func cloneRecordedTree(t *testing.T, from, to string) {
	t.Helper()
	mustRecordedMutation(t, os.Mkdir(to, 0700))
	entries, err := os.ReadDir(from)
	mustRecordedMutation(t, err)
	for _, entry := range entries {
		src, dst := filepath.Join(from, entry.Name()), filepath.Join(to, entry.Name())
		if entry.IsDir() {
			cloneRecordedTree(t, src, dst)
			continue
		}
		data, err := os.ReadFile(src)
		mustRecordedMutation(t, err)
		mustRecordedMutation(t, os.WriteFile(dst, data, 0600))
	}
}

func TestLocalSourceOwnerRecordedSnapshotRecheckChanges(t *testing.T) {
	changes := map[string]func(*testing.T, string, string){
		"owner replaced": func(t *testing.T, s, a string) {
			p := filepath.Join(s, localSourceOwnerLeaf)
			original, err := os.Lstat(p)
			mustRecordedMutation(t, err)
			mustRecordedMutation(t, os.Rename(p, filepath.Join(filepath.Dir(s), "owner-original")))
			mustRecordedMutation(t, os.WriteFile(p, []byte("not valid owner content"), 0600))
			replacement, err := os.Lstat(p)
			mustRecordedMutation(t, err)
			if os.SameFile(original, replacement) {
				t.Fatal("owner replacement reused original inode")
			}
		},
		"owner hardlinked": func(t *testing.T, s, a string) {
			os.Link(filepath.Join(s, localSourceOwnerLeaf), filepath.Join(t.TempDir(), "alias"))
		},
		"owner chmod":   func(t *testing.T, s, a string) { os.Chmod(filepath.Join(s, localSourceOwnerLeaf), 0644) },
		"entry removed": func(t *testing.T, s, a string) { os.Remove(filepath.Join(s, strings.Repeat("a", 64)+".run.jsonl")) },
		"entry resized": func(t *testing.T, s, a string) {
			os.WriteFile(filepath.Join(s, strings.Repeat("a", 64)+".run-plan.json"), []byte("larger invalid plan"), 0600)
		},
		"entry added": func(t *testing.T, s, a string) {
			mustRecordedMutation(t, os.WriteFile(filepath.Join(s, strings.Repeat("d", 64)+".run-plan.json"), []byte("x"), 0600))
		},
		"artifact child chmod": func(t *testing.T, s, a string) { os.Chmod(a, 0755) },
		"artifact entry replaced": func(t *testing.T, s, a string) {
			p := filepath.Join(a, strings.Repeat("b", 64)+"-"+strings.Repeat("c", 64)+".artifact.json")
			original, err := os.Lstat(p)
			mustRecordedMutation(t, err)
			mustRecordedMutation(t, os.Rename(p, filepath.Join(filepath.Dir(s), "artifact-original")))
			mustRecordedMutation(t, os.WriteFile(p, []byte("invalid artifact"), 0600))
			replacement, err := os.Lstat(p)
			mustRecordedMutation(t, err)
			if os.SameFile(original, replacement) {
				t.Fatal("artifact replacement reused original inode")
			}
		},
		"artifact entry added": func(t *testing.T, s, a string) {
			mustRecordedMutation(t, os.WriteFile(filepath.Join(a, recordedExtraArtifactName), []byte("x"), 0600))
		},
		"state replaced": func(t *testing.T, s, a string) {
			outside := filepath.Join(t.TempDir(), "state-saved")
			mustRecordedMutation(t, os.Rename(s, outside))
			cloneRecordedTree(t, outside, s)
		},
		"artifact replaced": func(t *testing.T, s, a string) {
			outside := filepath.Join(t.TempDir(), "artifacts-saved")
			mustRecordedMutation(t, os.Rename(a, outside))
			cloneRecordedTree(t, outside, a)
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			state, artifact := recordedFixture(t)
			snap, err := inspectLocalSourceOwnerRecordedSnapshot(context.Background(), state)
			if err != nil {
				t.Fatal(err)
			}
			defer snap.Close()
			if err := recheckLocalSourceOwnerRecordedSnapshot(context.Background(), snap, snap.StateRoot, snap.ArtifactRoot); err != nil {
				t.Fatalf("baseline refused: %v", err)
			}
			change(t, state, artifact)
			if name == "state replaced" || name == "artifact replaced" || name == "entry added" || name == "artifact entry added" {
				fresh, err := inspectLocalSourceOwnerRecordedSnapshot(context.Background(), state)
				if err != nil {
					t.Fatalf("changed tree is not valid independently: %v", err)
				}
				mustRecordedMutation(t, fresh.Close())
			}
			stateRoot, err := os.OpenRoot(state)
			if err != nil {
				t.Fatal(err)
			}
			defer stateRoot.Close()
			artifactRoot, err := os.OpenRoot(filepath.Join(state, "artifacts"))
			if err != nil {
				t.Fatal(err)
			}
			defer artifactRoot.Close()
			if err := recheckLocalSourceOwnerRecordedSnapshot(context.Background(), snap, stateRoot, artifactRoot); err == nil {
				t.Fatal("changed snapshot accepted")
			}
		})
	}
}

// Isolate the saved entry-map comparison from directory-size changes. These test-only
// metadata updates model a filesystem whose directory size stays stable across an add;
// they do not make the original saved entry set or retained pins authoritative anew.
func TestLocalSourceOwnerRecordedSnapshotRecheckAddedEntrySet(t *testing.T) {
	for _, kind := range []string{"state", "artifact"} {
		t.Run(kind, func(t *testing.T) {
			state, artifacts := recordedFixture(t)
			snap, err := inspectLocalSourceOwnerRecordedSnapshot(context.Background(), state)
			if err != nil {
				t.Fatal(err)
			}
			defer snap.Close()
			if err := recheckLocalSourceOwnerRecordedSnapshot(context.Background(), snap, snap.StateRoot, snap.ArtifactRoot); err != nil {
				t.Fatalf("baseline refused: %v", err)
			}

			if kind == "state" {
				mustRecordedMutation(t, os.WriteFile(filepath.Join(state, strings.Repeat("d", 64)+".run-plan.json"), []byte("x"), 0600))
			} else {
				mustRecordedMutation(t, os.WriteFile(filepath.Join(artifacts, recordedExtraArtifactName), []byte("x"), 0600))
			}
			fresh, err := inspectLocalSourceOwnerRecordedSnapshot(context.Background(), state)
			if err != nil {
				t.Fatalf("changed tree is not valid independently: %v", err)
			}
			mustRecordedMutation(t, fresh.Close())

			if kind == "state" {
				current, err := os.Lstat(state)
				mustRecordedMutation(t, err)
				if !os.SameFile(snap.StateInfo, current) {
					t.Fatal("state root inode changed")
				}
				snap.StateInfo = current
			} else {
				current, err := os.Lstat(artifacts)
				mustRecordedMutation(t, err)
				if !os.SameFile(snap.ArtifactInfo, current) {
					t.Fatal("artifact root inode changed")
				}
				snap.ArtifactInfo = current
				snap.StateEntries["artifacts"] = current
			}
			if err := recheckLocalSourceOwnerRecordedSnapshot(context.Background(), snap, snap.StateRoot, snap.ArtifactRoot); err == nil {
				t.Fatal("added entry accepted after directory metadata isolation")
			}
		})
	}
}

// The callback is scoped to this call, after localExistingRoot returned the opened inode.
// Reparenting the same state tree must not let a later fresh pin bless its new parent.
func TestLocalSourceOwnerRecordedSnapshotOriginalAncestor(t *testing.T) {
	for _, rootToSwap := range []string{"state", "artifact"} {
		t.Run(rootToSwap, func(t *testing.T) {
			state, _ := recordedFixture(t)
			parent := filepath.Dir(state)
			backup := filepath.Join(t.TempDir(), "original-parent")
			calls := 0
			open := func(path string) (*os.Root, error) {
				opened, err := localExistingRoot(path)
				if err != nil || opened == nil {
					return opened, err
				}
				calls++
				if calls == 1 && rootToSwap == "state" || calls == 2 && rootToSwap == "artifact" {
					mustRecordedMutation(t, os.Rename(parent, backup))
					mustRecordedMutation(t, os.Mkdir(parent, 0700))
					mustRecordedMutation(t, os.Rename(filepath.Join(backup, "state"), state))
				}
				return opened, nil
			}
			snap, err := inspectLocalSourceOwnerRecordedSnapshotWithOpen(context.Background(), state, open)
			if snap != nil {
				snap.Close()
			}
			if err == nil {
				t.Fatal("original parent substitution accepted")
			}
		})
	}
}

type recordedCancelAfterChecks struct {
	context.Context
	remaining int
}

func (c *recordedCancelAfterChecks) Err() error {
	c.remaining--
	if c.remaining <= 0 {
		return context.Canceled
	}
	return nil
}

func TestLocalSourceOwnerRecordedSnapshotRecheckCancellation(t *testing.T) {
	state, _ := recordedFixture(t)
	snap, err := inspectLocalSourceOwnerRecordedSnapshot(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	if err := recheckLocalSourceOwnerRecordedSnapshot(nil, snap, snap.StateRoot, snap.ArtifactRoot); err == nil {
		t.Fatal("nil recheck context accepted")
	}
	if err := recheckLocalSourceOwnerRecordedSnapshot(&recordedCancelAfterChecks{Context: context.Background(), remaining: 4}, snap, snap.StateRoot, snap.ArtifactRoot); err == nil {
		t.Fatal("mid-recheck cancellation accepted")
	}
}

func TestLocalSourceOwnerRecordedSnapshotFirstUseUnchanged(t *testing.T) {
	for _, shape := range []string{"missing", "empty", "setup-only", "recordless-lock", "recordless-artifacts"} {
		t.Run(shape, func(t *testing.T) {
			state, path, plan := snapshotFixture(t)
			switch shape {
			case "empty", "recordless-lock", "recordless-artifacts":
				if err := os.Mkdir(state, 0700); err != nil {
					t.Fatal(err)
				}
			case "setup-only":
				writeSnapshotSetup(t, path, plan)
			}
			switch shape {
			case "recordless-lock":
				if err := os.WriteFile(filepath.Join(state, ".run-writer.lock"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "recordless-artifacts":
				if err := os.Mkdir(filepath.Join(state, "artifacts"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			want := localSourceOwnerMissing
			if shape == "empty" {
				want = localSourceOwnerEmpty
			}
			if shape == "setup-only" {
				want = localSourceOwnerSetupOnly
			}
			first, err := inspectLocalSourceOwnerSnapshot(context.Background(), state, path, &plan)
			if shape == "recordless-lock" || shape == "recordless-artifacts" {
				if err == nil {
					if first != nil {
						first.Close()
					}
					t.Fatal("recordless runtime reached first use")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				defer first.Close()
				if first.Kind != want {
					t.Fatalf("kind %v want %v", first.Kind, want)
				}
			}
			recorded, err := inspectLocalSourceOwnerRecordedSnapshot(context.Background(), state)
			if recorded != nil {
				recorded.Close()
				t.Fatal("recordless candidate")
			}
			if !errors.Is(err, ErrLocalSourceOwnerMissing) && (shape == "missing" || shape == "empty" || shape == "setup-only" || shape == "recordless-lock" || shape == "recordless-artifacts") {
				t.Fatalf("missing recorded owner: %v", err)
			}
		})
	}
}

func TestLocalSourceOwnerRecordedSnapshotBorrowedArtifactMismatch(t *testing.T) {
	state, _ := recordedFixture(t)
	otherState, otherArtifact := recordedFixture(t)
	_ = otherState
	snap, err := inspectLocalSourceOwnerRecordedSnapshot(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	stateRoot, err := os.OpenRoot(state)
	if err != nil {
		t.Fatal(err)
	}
	defer stateRoot.Close()
	otherRoot, err := os.OpenRoot(otherArtifact)
	if err != nil {
		t.Fatal(err)
	}
	defer otherRoot.Close()
	if err := recheckLocalSourceOwnerRecordedSnapshot(context.Background(), snap, stateRoot, otherRoot); err == nil {
		t.Fatal("borrowed artifact mismatch accepted")
	}
	if err := recheckLocalSourceOwnerRecordedSnapshot(context.Background(), snap, nil, otherRoot); err == nil {
		t.Fatal("nil borrowed state accepted")
	}
}

func TestLocalSourceOwnerRecordedSnapshotCloseExternallyClosedRoots(t *testing.T) {
	state, _ := recordedFixture(t)
	snap, err := inspectLocalSourceOwnerRecordedSnapshot(context.Background(), state)
	if err != nil {
		t.Fatal(err)
	}
	if err := snap.StateRoot.Close(); err != nil {
		t.Fatal(err)
	}
	if err := snap.ArtifactRoot.Close(); err != nil {
		t.Fatal(err)
	}
	if err := snap.Close(); err != nil {
		t.Fatalf("closing already closed roots: %v", err)
	}
	if snap.StateRoot != nil || snap.ArtifactRoot != nil {
		t.Fatal("closed roots retained")
	}
}
