package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestLocalSourceOwnerDiskPublishFresh(t *testing.T) {
	path, stateRoot, expected := ownerReadFixture(t)
	record := localOwnerFixture()
	if err := publishLocalSourceOwnerRecord(stateRoot, path, record, nil); err != nil {
		t.Fatal(err)
	}
	final, raw, opened, err := readLocalSourceOwnerRecordDetails(stateRoot, path)
	if err != nil || final != record || !bytes.Equal(raw, expected) {
		t.Fatalf("read: %v", err)
	}
	info, err := stateRoot.Lstat(localSourceOwnerLeaf)
	if err != nil || !os.SameFile(info, opened) || info.Mode() != 0600 {
		t.Fatalf("final metadata: %v, %v", info, err)
	}
	entries, err := os.ReadDir(path)
	if err != nil || len(entries) != 1 || entries[0].Name() != localSourceOwnerLeaf {
		t.Fatalf("unexpected entries: %v, %v", entries, err)
	}
	if err := publishLocalSourceOwnerRecord(stateRoot, path, record, nil); !errors.Is(err, errLocalSourceOwnerConflict) {
		t.Fatalf("existing final not conflict: %v", err)
	}
	finalBytes, err := os.ReadFile(filepath.Join(path, localSourceOwnerLeaf))
	if err != nil || !bytes.Equal(finalBytes, expected) {
		t.Fatalf("overwrite: %v", err)
	}
}

func TestLocalSourceOwnerDiskPublishCollisionAtLink(t *testing.T) {
	path, stateRoot, _ := ownerReadFixture(t)
	alternate := localOwnerFixture()
	alternate.TenantID = "other"
	other, err := encodeLocalSourceOwnerRecord(alternate)
	if err != nil {
		t.Fatal(err)
	}
	var tempName string
	sawCleanupSync := false
	hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
		switch stage {
		case "link":
			tempName = temp
			if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), other, 0600); err != nil {
				t.Fatal(err)
			}
		case "cleanup-parent-sync":
			sawCleanupSync = true
		}
		return nil
	}}
	err = publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
	if !errors.Is(err, errLocalSourceOwnerConflict) || !errors.Is(err, os.ErrExist) || !sawCleanupSync {
		t.Fatalf("link collision: %v; sync=%v", err, sawCleanupSync)
	}
	got, err := os.ReadFile(filepath.Join(path, localSourceOwnerLeaf))
	if err != nil || !bytes.Equal(got, other) {
		t.Fatalf("final overwritten: %v", err)
	}
	if _, err := stateRoot.Lstat(tempName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temp not removed: %v", err)
	}
}

func TestLocalSourceOwnerDiskPublishPreLinkFailures(t *testing.T) {
	stages := []string{"write", "file-sync", "close", "temp-recheck", "link"}
	for _, failed := range stages {
		t.Run(failed, func(t *testing.T) {
			path, stateRoot, _ := ownerReadFixture(t)
			primary := errors.New("primary " + failed)
			stagesSeen := []string{}
			var tempName string
			hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
				stagesSeen = append(stagesSeen, stage)
				if stage == failed {
					tempName = temp
					if stage == "close" {
						if _, err := file.Stat(); err != nil {
							t.Fatalf("close hook did not observe open file: %v", err)
						}
					}
					return primary
				}
				return nil
			}}
			err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
			if !errors.Is(err, primary) || !errors.Is(err, errLocalSourceOwnerPersistence) {
				t.Fatalf("primary lost: %v", err)
			}
			if _, err := stateRoot.Lstat(localSourceOwnerLeaf); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected final: %v", err)
			}
			if _, err := stateRoot.Lstat(tempName); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("temp not cleaned: %v", err)
			}
			if !strings.Contains(strings.Join(stagesSeen, ","), "cleanup-parent-sync") {
				t.Fatalf("cleanup directory sync omitted: %v", stagesSeen)
			}
			if failed == "link" && strings.Join(stagesSeen[:4], ",") != "write,file-sync,close,temp-recheck" {
				t.Fatalf("file sync/link ordering: %v", stagesSeen)
			}
		})
	}
	t.Run("short-write", func(t *testing.T) {
		path, stateRoot, _ := ownerReadFixture(t)
		hook := &localSourceOwnerPublishHook{Write: func(file *os.File, raw []byte) (int, error) { return file.Write(raw[:1]) }}
		err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
		if !errors.Is(err, io.ErrShortWrite) || !errors.Is(err, errLocalSourceOwnerPersistence) {
			t.Fatalf("short write: %v", err)
		}
		entries, err := os.ReadDir(path)
		if err != nil || len(entries) != 0 {
			t.Fatalf("failed publish left entries: %v, %v", entries, err)
		}
	})
}

func TestLocalSourceOwnerDiskPublishJoinedCleanupErrors(t *testing.T) {
	for _, cleanupStage := range []string{"cleanup-remove", "cleanup-parent-sync"} {
		t.Run(cleanupStage, func(t *testing.T) {
			path, stateRoot, _ := ownerReadFixture(t)
			primary := errors.New("write failure")
			cleanup := errors.New("cleanup failure")
			hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
				if stage == "write" {
					return primary
				}
				if stage == cleanupStage {
					return cleanup
				}
				return nil
			}}
			err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
			if !errors.Is(err, primary) || !errors.Is(err, cleanup) || !errors.Is(err, errLocalSourceOwnerPersistence) {
				t.Fatalf("joined failure: %v", err)
			}
			if _, err := stateRoot.Lstat(localSourceOwnerLeaf); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("final created: %v", err)
			}
			entries, err := os.ReadDir(path)
			if err != nil || len(entries) != map[string]int{"cleanup-remove": 1, "cleanup-parent-sync": 0}[cleanupStage] {
				t.Fatalf("unexpected temp count: %v, %v", entries, err)
			}
		})
	}
}

func TestLocalSourceOwnerDiskPublishNoRemovalOfReplacedTemp(t *testing.T) {
	for _, stageToSwap := range []string{"temp-recheck", "cleanup-remove", "post-link-remove"} {
		t.Run(stageToSwap, func(t *testing.T) {
			path, stateRoot, raw := ownerReadFixture(t)
			var tempName string
			primary := errors.New("link failure")
			hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
				tempName = temp
				if stage == stageToSwap {
					if err := r.Remove(temp); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(path, temp), []byte("foreign inode"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				if stage == "link" && stageToSwap == "cleanup-remove" {
					return primary
				}
				return nil
			}}
			err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
			if !errors.Is(err, errLocalSourceOwnerPersistence) {
				t.Fatalf("changed temp admitted: %v", err)
			}
			if stageToSwap == "cleanup-remove" && !errors.Is(err, primary) {
				t.Fatalf("primary lost: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(path, tempName))
			if err != nil || string(got) != "foreign inode" {
				t.Fatalf("foreign temp removed: %q %v", got, err)
			}
			if stageToSwap == "post-link-remove" {
				got, err = os.ReadFile(filepath.Join(path, localSourceOwnerLeaf))
				if err != nil || !bytes.Equal(got, raw) {
					t.Fatalf("published final rolled back: %v", err)
				}
			} else if _, err = stateRoot.Lstat(localSourceOwnerLeaf); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unexpected final: %v", err)
			}
		})
	}
}

func TestLocalSourceOwnerDiskPublishPostLinkFailsClosed(t *testing.T) {
	for _, failed := range []string{"post-link-parent-sync", "strict-read", "post-link-remove", "final-parent-sync"} {
		t.Run(failed, func(t *testing.T) {
			path, stateRoot, raw := ownerReadFixture(t)
			primary := errors.New("post-link " + failed)
			var tempName string
			hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
				if stage == failed {
					tempName = temp
					return primary
				}
				return nil
			}}
			err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
			if !errors.Is(err, primary) || !errors.Is(err, errLocalSourceOwnerPersistence) {
				t.Fatalf("post-link error: %v", err)
			}
			final, err := os.ReadFile(filepath.Join(path, localSourceOwnerLeaf))
			if err != nil || !bytes.Equal(final, raw) {
				t.Fatalf("final rolled back: %v", err)
			}
			_, err = stateRoot.Lstat(tempName)
			if failed == "final-parent-sync" {
				if !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("temp retained after removal: %v", err)
				}
			} else if err != nil {
				t.Fatalf("temp not retained: %v", err)
			}
		})
	}
}

func TestLocalSourceOwnerDiskPublishUnsupportedAndInvalidRoot(t *testing.T) {
	for _, failed := range []string{"link", "post-link-parent-sync", "cleanup-parent-sync"} {
		t.Run(failed, func(t *testing.T) {
			path, stateRoot, _ := ownerReadFixture(t)
			hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
				if stage == "write" && failed == "cleanup-parent-sync" {
					return errors.New("force cleanup")
				}
				if stage == failed {
					return syscall.ENOTSUP
				}
				return nil
			}}
			err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
			if !errors.Is(err, errLocalSourceOwnerUnsupported) || !errors.Is(err, syscall.ENOTSUP) {
				t.Fatalf("unsupported: %v", err)
			}
		})
	}
	path, stateRoot, _ := ownerReadFixture(t)
	if err := publishLocalSourceOwnerRecord(nil, path, localOwnerFixture(), nil); !errors.Is(err, errLocalSourceOwnerPersistence) {
		t.Fatalf("nil root: %v", err)
	}
	if err := os.Chmod(path, 0755); err != nil {
		t.Fatal(err)
	}
	if err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), nil); !errors.Is(err, errLocalSourceOwnerPersistence) {
		t.Fatalf("nonprivate root: %v", err)
	}
}

func TestLocalSourceOwnerDiskPublishAmbiguousLinkFailure(t *testing.T) {
	path, stateRoot, raw := ownerReadFixture(t)
	primary := errors.New("link returned error after creating final")
	var captured os.FileInfo
	var tempName string
	syncCount := 0
	hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
		switch stage {
		case "link":
			tempName = temp
			info, err := r.Lstat(temp)
			if err != nil || info.Mode() != 0600 {
				t.Fatalf("temp mode: %v, %v", info, err)
			}
			captured = info
			if err := r.Link(temp, localSourceOwnerLeaf); err != nil {
				t.Fatal(err)
			}
			return primary
		case "cleanup-parent-sync":
			syncCount++
		}
		return nil
	}}
	err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
	if !errors.Is(err, primary) || !errors.Is(err, errLocalSourceOwnerPersistence) || syncCount != 1 {
		t.Fatalf("ambiguous link error: %v; sync=%d", err, syncCount)
	}
	final, err := stateRoot.Lstat(localSourceOwnerLeaf)
	if err != nil || !os.SameFile(final, captured) {
		t.Fatalf("final inode lost: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(path, localSourceOwnerLeaf))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("final bytes lost: %v", err)
	}
	if _, err := stateRoot.Lstat(tempName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("temporary name not cleaned: %v", err)
	}
}

func TestLocalSourceOwnerDiskPublishRejectsChangedFinalInode(t *testing.T) {
	path, stateRoot, raw := ownerReadFixture(t)
	var replacement os.FileInfo
	hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
		if stage == "strict-read" {
			if err := r.Remove(localSourceOwnerLeaf); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), raw, 0600); err != nil {
				t.Fatal(err)
			}
			var err error
			replacement, err = r.Lstat(localSourceOwnerLeaf)
			if err != nil {
				t.Fatal(err)
			}
		}
		return nil
	}}
	err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
	if !errors.Is(err, errLocalSourceOwnerPersistence) {
		t.Fatalf("same bytes different inode accepted: %v", err)
	}
	final, err := stateRoot.Lstat(localSourceOwnerLeaf)
	if err != nil || !os.SameFile(final, replacement) {
		t.Fatalf("final modified after failure: %v", err)
	}
}

func TestLocalSourceOwnerDiskPublishExistingDifferentFinal(t *testing.T) {
	path, stateRoot, _ := ownerReadFixture(t)
	other := localOwnerFixture()
	other.TenantID = "different"
	raw, err := encodeLocalSourceOwnerRecord(other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), raw, 0600); err != nil {
		t.Fatal(err)
	}
	original, err := stateRoot.Lstat(localSourceOwnerLeaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), nil); !errors.Is(err, errLocalSourceOwnerConflict) {
		t.Fatalf("existing different leaf: %v", err)
	}
	final, err := stateRoot.Lstat(localSourceOwnerLeaf)
	if err != nil || !os.SameFile(original, final) {
		t.Fatalf("existing inode replaced: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(path, localSourceOwnerLeaf))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("existing bytes replaced: %v", err)
	}
}

func TestLocalSourceOwnerDiskPublishLinkCollisionDoesNotRemoveSwappedTemp(t *testing.T) {
	path, stateRoot, _ := ownerReadFixture(t)
	other := localOwnerFixture()
	other.TenantID = "collision"
	raw, err := encodeLocalSourceOwnerRecord(other)
	if err != nil {
		t.Fatal(err)
	}
	var tempName string
	hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
		if stage != "link" {
			return nil
		}
		tempName = temp
		if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if err := r.Remove(temp); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, temp), []byte("unknown temp"), 0600); err != nil {
			t.Fatal(err)
		}
		return nil
	}}
	err = publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
	if !errors.Is(err, errLocalSourceOwnerConflict) || !errors.Is(err, os.ErrExist) || !errors.Is(err, errLocalSourceOwnerPersistence) {
		t.Fatalf("collision with temp change: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(path, tempName))
	if err != nil || string(got) != "unknown temp" {
		t.Fatalf("removed unknown temp: %q %v", got, err)
	}
	got, err = os.ReadFile(filepath.Join(path, localSourceOwnerLeaf))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("removed collision leaf: %v", err)
	}
}

func TestLocalSourceOwnerDiskPublishRejectsLateFinalReplacement(t *testing.T) {
	path, stateRoot, raw := ownerReadFixture(t)
	var replacement os.FileInfo
	var tempName string
	hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
		if stage != "post-link-remove" {
			return nil
		}
		tempName = temp
		if err := r.Remove(localSourceOwnerLeaf); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, localSourceOwnerLeaf), raw, 0600); err != nil {
			t.Fatal(err)
		}
		var err error
		replacement, err = r.Lstat(localSourceOwnerLeaf)
		if err != nil {
			t.Fatal(err)
		}
		original, err := r.Lstat(temp)
		if err != nil || os.SameFile(replacement, original) {
			t.Fatalf("replacement is not a separate inode: %v", err)
		}
		return nil
	}}
	err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
	if !errors.Is(err, errLocalSourceOwnerPersistence) {
		t.Fatalf("late identical-byte replacement admitted: %v", err)
	}
	final, err := stateRoot.Lstat(localSourceOwnerLeaf)
	if err != nil || !os.SameFile(final, replacement) {
		t.Fatalf("replacement final removed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(path, localSourceOwnerLeaf))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("replacement bytes lost: %v", err)
	}
	if _, err := stateRoot.Lstat(tempName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original temp still present: %v", err)
	}
}

func TestLocalSourceOwnerDiskPublishRejectsLateStatePathReplacement(t *testing.T) {
	path, stateRoot, raw := ownerReadFixture(t)
	moved := path + "-moved"
	var tempName string
	hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
		if stage != "final-parent-sync" {
			return nil
		}
		tempName = temp
		if err := os.Rename(path, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
		return nil
	}}
	err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
	if !errors.Is(err, errLocalSourceOwnerPersistence) {
		t.Fatalf("replacement state path admitted: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(moved, localSourceOwnerLeaf))
	if err != nil || !bytes.Equal(got, raw) {
		t.Fatalf("original final changed: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(path, localSourceOwnerLeaf)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("replacement path acquired a final: %v", err)
	}
	if _, err := stateRoot.Lstat(tempName); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("original temp still present: %v", err)
	}
}

func TestLocalSourceOwnerDiskPublishAmbiguousEINVALIsPersistence(t *testing.T) {
	for _, failed := range []string{"link", "post-link-parent-sync", "final-parent-sync", "cleanup-parent-sync"} {
		t.Run(failed, func(t *testing.T) {
			path, stateRoot, _ := ownerReadFixture(t)
			hook := &localSourceOwnerPublishHook{Stage: func(stage string, r *os.Root, temp string, file *os.File) error {
				if stage == "write" && failed == "cleanup-parent-sync" {
					return errors.New("force cleanup")
				}
				if stage == failed {
					return syscall.EINVAL
				}
				return nil
			}}
			err := publishLocalSourceOwnerRecord(stateRoot, path, localOwnerFixture(), hook)
			if !errors.Is(err, syscall.EINVAL) || !errors.Is(err, errLocalSourceOwnerPersistence) || errors.Is(err, errLocalSourceOwnerUnsupported) {
				t.Fatalf("ambiguous EINVAL taxonomy: %v", err)
			}
		})
	}
}
