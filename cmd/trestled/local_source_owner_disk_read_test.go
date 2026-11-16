package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// Decode-only fixture: its fictional record identity does not bind the live opened root.
func ownerReadFixture(t *testing.T) (string, *os.Root, []byte) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	raw, err := encodeLocalSourceOwnerRecord(localOwnerFixture())
	if err != nil {
		t.Fatal(err)
	}
	return path, root, raw
}

func TestLocalSourceOwnerDiskReadMissingAndCanonical(t *testing.T) {
	path, root, raw := ownerReadFixture(t)
	if _, err := readLocalSourceOwnerRecord(root, path); !errors.Is(err, ErrLocalSourceOwnerMissing) {
		t.Fatalf("missing: %v", err)
	}
	if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), raw, 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readLocalSourceOwnerRecord(root, path)
	if err != nil || got != localOwnerFixture() {
		t.Fatalf("valid: %+v, %v", got, err)
	}
	changed := got
	changed.Git.Inode++
	if err := matchLocalSourceOwnerRecord(got, changed); !errors.Is(err, ErrLocalSourceOwnerMismatch) {
		t.Fatalf("only comparator classifies owner change: %v", err)
	}
}

func TestLocalSourceOwnerDiskReadUnsafeAndCorrupt(t *testing.T) {
	cases := map[string]struct {
		makeLeaf func(string, []byte) error
		want     error
	}{
		"zero": {func(p string, _ []byte) error { return os.WriteFile(p, nil, 0600) }, ErrLocalSourceOwnerMalformed},
		"oversize": {func(p string, _ []byte) error {
			return os.WriteFile(p, bytes.Repeat([]byte("x"), maxLocalSourceOwnerRecordBytes+1), 0600)
		}, ErrLocalSourceOwnerMalformed},
		"public": {func(p string, b []byte) error {
			if err := os.WriteFile(p, b, 0600); err != nil {
				return err
			}
			return os.Chmod(p, 0644)
		}, ErrLocalSourceOwnerMalformed},
		"directory": {func(p string, _ []byte) error { return os.Mkdir(p, 0700) }, ErrLocalSourceOwnerMalformed},
		"symlink": {func(p string, b []byte) error {
			if err := os.WriteFile(filepath.Join(filepath.Dir(p), "target"), b, 0600); err != nil {
				return err
			}
			return os.Symlink("target", p)
		}, ErrLocalSourceOwnerMalformed},
		"truncated": {func(p string, b []byte) error { return os.WriteFile(p, b[:len(b)-1], 0600) }, ErrLocalSourceOwnerMalformed},
		"checksum": {func(p string, b []byte) error {
			return os.WriteFile(p, bytes.Replace(b, []byte(`"tenant_id":"team"`), []byte(`"tenant_id":"else"`), 1), 0600)
		}, ErrLocalSourceOwnerChecksum},
		"future": {func(p string, _ []byte) error {
			payload := localSourceOwnerPayload{Contract: localSourceOwnerRecordContract, Version: 2, localSourceOwnerRecord: localOwnerFixture()}
			b, e := json.Marshal(payload)
			if e != nil {
				return e
			}
			out, e := json.Marshal(localSourceOwnerEnvelope{localSourceOwnerPayload: payload, ChecksumSHA256: localSourceOwnerChecksum(b)})
			return os.WriteFile(p, append(out, '\n'), 0600)
		}, ErrLocalSourceOwnerVersion},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			path, root, raw := ownerReadFixture(t)
			if err := tc.makeLeaf(filepath.Join(path, localSourceOwnerLeaf), raw); err != nil {
				t.Fatal(err)
			}
			if _, err := readLocalSourceOwnerRecord(root, path); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestLocalSourceOwnerDiskReadChangedRoot(t *testing.T) {
	path, root, _ := ownerReadFixture(t)
	moved := path + "-moved"
	if err := os.Rename(path, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := readLocalSourceOwnerRecord(root, path); !errors.Is(err, errLocalSourceOwnerPersistence) || errors.Is(err, ErrLocalSourceOwnerMissing) {
		t.Fatalf("replaced root: %v", err)
	}
	if _, err := readLocalSourceOwnerRecord(nil, path); !errors.Is(err, errLocalSourceOwnerPersistence) {
		t.Fatalf("nil root: %v", err)
	}
}

func TestLocalSourceOwnerDiskReadRootAndLeafPolicy(t *testing.T) {
	t.Run("root-public", func(t *testing.T) {
		path, root, _ := ownerReadFixture(t)
		if err := os.Chmod(path, 0755); err != nil {
			t.Fatal(err)
		}
		if _, err := readLocalSourceOwnerRecord(root, path); !errors.Is(err, errLocalSourceOwnerPersistence) || errors.Is(err, ErrLocalSourceOwnerMissing) {
			t.Fatalf("public root: %v", err)
		}
	})
	t.Run("root-removed", func(t *testing.T) {
		path, root, _ := ownerReadFixture(t)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if _, err := readLocalSourceOwnerRecord(root, path); !errors.Is(err, errLocalSourceOwnerPersistence) || !errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrLocalSourceOwnerMissing) {
			t.Fatalf("absent root: %v", err)
		}
	})
	t.Run("missing-path", func(t *testing.T) {
		_, root, _ := ownerReadFixture(t)
		if _, err := readLocalSourceOwnerRecord(root, "/no/such/owner-state"); !errors.Is(err, errLocalSourceOwnerPersistence) || errors.Is(err, ErrLocalSourceOwnerMissing) {
			t.Fatalf("absent path: %v", err)
		}
	})
	t.Run("valid-record-does-not-bind-owner", func(t *testing.T) {
		path, root, raw := ownerReadFixture(t)
		if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), raw, 0600); err != nil {
			t.Fatal(err)
		}
		got, encoded, opened, err := readLocalSourceOwnerRecordDetails(root, path)
		if err != nil || got != localOwnerFixture() || !bytes.Equal(encoded, raw) {
			t.Fatalf("details: %v", err)
		}
		leaf, err := root.Lstat(localSourceOwnerLeaf)
		if err != nil || !os.SameFile(leaf, opened) {
			t.Fatalf("opened inode: %v", err)
		}
	})
}

func TestLocalSourceOwnerDiskReadDisappearingAndReadIO(t *testing.T) {
	for _, stage := range []string{"before-open", "before-after-lookup"} {
		t.Run(stage, func(t *testing.T) {
			path, root, raw := ownerReadFixture(t)
			leaf := filepath.Join(path, localSourceOwnerLeaf)
			if err := os.WriteFile(leaf, raw, 0600); err != nil {
				t.Fatal(err)
			}
			_, _, _, err := readLocalSourceOwnerRecordDetailsWithHook(root, path, func(current string, file *os.File) {
				if current == stage {
					if removeErr := os.Remove(leaf); removeErr != nil {
						t.Error(removeErr)
					}
				}
			})
			if !errors.Is(err, errLocalSourceOwnerPersistence) || !errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrLocalSourceOwnerMissing) {
				t.Fatalf("disappeared leaf: %v", err)
			}
		})
	}
	for _, stage := range []string{"before-close"} {
		t.Run(stage, func(t *testing.T) {
			path, root, raw := ownerReadFixture(t)
			if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), raw, 0600); err != nil {
				t.Fatal(err)
			}
			_, _, _, err := readLocalSourceOwnerRecordDetailsWithHook(root, path, func(current string, file *os.File) {
				if current == stage {
					if closeErr := file.Close(); closeErr != nil {
						t.Error(closeErr)
					}
				}
			})
			if !errors.Is(err, errLocalSourceOwnerPersistence) || !errors.Is(err, os.ErrClosed) || errors.Is(err, ErrLocalSourceOwnerMissing) {
				t.Fatalf("read or close I/O: %v", err)
			}
		})
	}
}

// A checked opened root must not accept a pathname whose parent later becomes linked.
func TestLocalSourceOwnerDiskReadLinkedAncestor(t *testing.T) {
	for _, existingLeaf := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "record"}[existingLeaf], func(t *testing.T) {
			base := t.TempDir()
			parent := filepath.Join(base, "parent")
			path := filepath.Join(parent, "state")
			if err := os.Mkdir(parent, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
			root, err := localExistingRoot(path)
			if err != nil || root == nil {
				t.Fatalf("checked root: %v", err)
			}
			defer root.Close()
			if existingLeaf {
				raw, err := encodeLocalSourceOwnerRecord(localOwnerFixture())
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Rename(parent, parent+"-original"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("parent-original", parent); err != nil {
				t.Fatal(err)
			}
			_, err = readLocalSourceOwnerRecord(root, path)
			if !errors.Is(err, errLocalSourceOwnerPersistence) || errors.Is(err, ErrLocalSourceOwnerMissing) {
				t.Fatalf("linked ancestor accepted (leaf present=%v): %v", existingLeaf, err)
			}
		})
	}
}

func TestLocalSourceOwnerDiskReadLinkedAncestorAfterInitialCheck(t *testing.T) {
	base := t.TempDir()
	parent := filepath.Join(base, "parent")
	path := filepath.Join(parent, "state")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := localExistingRoot(path)
	if err != nil || root == nil {
		t.Fatalf("checked root: %v", err)
	}
	defer root.Close()
	raw, err := encodeLocalSourceOwnerRecord(localOwnerFixture())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), raw, 0600); err != nil {
		t.Fatal(err)
	}
	_, _, _, err = readLocalSourceOwnerRecordDetailsWithHook(root, path, func(stage string, _ *os.File) {
		if stage != "before-after-lookup" {
			return
		}
		if e := os.Rename(parent, parent+"-original"); e != nil {
			t.Fatal(e)
		}
		if e := os.Symlink("parent-original", parent); e != nil {
			t.Fatal(e)
		}
	})
	if !errors.Is(err, errLocalSourceOwnerPersistence) || errors.Is(err, ErrLocalSourceOwnerMissing) {
		t.Fatalf("late linked ancestor: %v", err)
	}
}

func TestLocalSourceOwnerDiskReadStageTransitions(t *testing.T) {
	for _, stage := range []string{"before-open", "before-after-lookup"} {
		t.Run("unsafe-leaf-"+stage, func(t *testing.T) {
			path, root, raw := ownerReadFixture(t)
			leaf := filepath.Join(path, localSourceOwnerLeaf)
			if err := os.WriteFile(leaf, raw, 0600); err != nil {
				t.Fatal(err)
			}
			_, _, _, err := readLocalSourceOwnerRecordDetailsWithHook(root, path, func(current string, _ *os.File) {
				if current == stage {
					if e := os.Chmod(leaf, 0644); e != nil {
						t.Fatal(e)
					}
				}
				// For the opened-stat case, restore the name before the final
				// lookup so that only the opened-file guard can reject it.
				if stage == "before-open" && current == "before-after-lookup" {
					if e := os.Chmod(leaf, 0600); e != nil {
						t.Fatal(e)
					}
				}
			})
			if !errors.Is(err, ErrLocalSourceOwnerMalformed) || errors.Is(err, ErrLocalSourceOwnerMissing) {
				t.Fatalf("leaf became public at %s: %v", stage, err)
			}
		})
	}
	t.Run("root-replaced-after-initial-check", func(t *testing.T) {
		path, root, raw := ownerReadFixture(t)
		if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), raw, 0600); err != nil {
			t.Fatal(err)
		}
		_, _, _, err := readLocalSourceOwnerRecordDetailsWithHook(root, path, func(stage string, _ *os.File) {
			if stage != "before-open" {
				return
			}
			if e := os.Rename(path, path+"-original"); e != nil {
				t.Fatal(e)
			}
			if e := os.Mkdir(path, 0700); e != nil {
				t.Fatal(e)
			}
		})
		if !errors.Is(err, errLocalSourceOwnerPersistence) || errors.Is(err, ErrLocalSourceOwnerMissing) {
			t.Fatalf("late root replacement: %v", err)
		}
	})
}

func TestLocalSourceOwnerDiskReadFailureIndependentOfClose(t *testing.T) {
	path, root, raw := ownerReadFixture(t)
	if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), raw, 0600); err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected read-stage failure")
	sawOpenFile := false
	_, _, _, err := readLocalSourceOwnerRecordDetailsWithReadError(root, path, func(stage string, file *os.File) {
		if stage == "before-close" {
			if _, statErr := file.Stat(); statErr != nil {
				t.Fatalf("real file closed before close stage: %v", statErr)
			}
			sawOpenFile = true
		}
	}, func() error { return injected })
	if !sawOpenFile || !errors.Is(err, errLocalSourceOwnerPersistence) || !errors.Is(err, injected) || errors.Is(err, os.ErrClosed) {
		t.Fatalf("independent read failure: open=%v error=%v", sawOpenFile, err)
	}
}
