package audit

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestObserveFileStreamBorrowsRootWithoutWriterOrMutation(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	ledger, err := NewFileLedger(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	scope, _ := NewReviewScope("tenant", "repo", "observed")
	first := auditEvent(t, scope, 1, "", EventRouteSelected, 'a')
	second := auditEvent(t, scope, 2, first.Identity(), EventRouteAttemptClaimed, 'b')
	if err := ledger.Append(context.Background(), "", first); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Append(context.Background(), first.Identity(), second); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, scope.Identity()+auditStreamFileSuffix)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	events, err := ObserveFileStream(context.Background(), root, scope)
	if err != nil || len(events) != 2 || events[0].Identity() != first.Identity() || events[1].Identity() != second.Identity() {
		t.Fatalf("borrowed observation failed: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("observation mutated stream")
	}
	if _, err := root.Stat("."); err != nil {
		t.Fatal("observation closed borrowed root")
	}
	other, _ := NewReviewScope("tenant", "repo", "absent")
	empty, err := ObserveFileStream(context.Background(), root, other)
	if err != nil || len(empty) != 0 {
		t.Fatalf("absent stream: %v", err)
	}
	if _, err := root.Stat(other.Identity() + auditStreamFileSuffix); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("observation created absent stream")
	}
	third := auditEvent(t, scope, 3, second.Identity(), EventRouteDispatchCompleted, 'c')
	if err := ledger.Append(context.Background(), second.Identity(), third); err != nil {
		t.Fatalf("observation disturbed writer: %v", err)
	}
	current, err := ObserveFileStream(context.Background(), root, scope)
	if err != nil || len(current) != 3 || current[2].Identity() != third.Identity() {
		t.Fatalf("observation cached old stream: %v", err)
	}
}

func TestObserveFileStreamRefusesUnsafeOrNoncanonicalFiles(t *testing.T) {
	scope, _ := NewReviewScope("tenant", "repo", "observed")
	first := auditEvent(t, scope, 1, "", EventRouteSelected, 'a')
	encoded, err := EncodeEvent(first)
	if err != nil {
		t.Fatal(err)
	}
	valid := append(append([]byte(nil), encoded...), '\n')
	other, _ := NewReviewScope("other", "repo", "observed")
	cross := auditEvent(t, other, 1, "", EventRouteSelected, 'a')
	crossBytes, err := EncodeEvent(cross)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string][]byte{
		"empty": {}, "missing newline": encoded, "blank record": append(append([]byte(nil), valid...), '\n'),
		"cross scope": append(crossBytes, '\n'), "duplicate event": append(append([]byte(nil), valid...), valid...),
		"noncanonical": append([]byte(" "), valid...),
	} {
		t.Run(name, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(directory, scope.Identity()+auditStreamFileSuffix), body, 0600); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if events, err := ObserveFileStream(context.Background(), root, scope); err == nil || events != nil {
				t.Fatal("unsafe stream admitted")
			}
		})
	}
	for _, kind := range []string{"symlink", "directory", "broad file", "broad root"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, scope.Identity()+auditStreamFileSuffix)
			switch kind {
			case "symlink":
				target := filepath.Join(directory, "target")
				if err := os.WriteFile(target, valid, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("target", path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				if err := os.WriteFile(path, valid, 0600); err != nil {
					t.Fatal(err)
				}
				if kind == "broad file" {
					if err := os.Chmod(path, 0644); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "broad root" {
					if err := os.Chmod(directory, 0755); err != nil {
						t.Fatal(err)
					}
				}
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if events, err := ObserveFileStream(context.Background(), root, scope); err == nil || events != nil {
				t.Fatal("unsafe path admitted")
			}
		})
	}
	if events, err := ObserveFileStream(context.Background(), nil, scope); err == nil || events != nil {
		t.Fatal("nil root admitted")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if events, err := ObserveFileStream(canceled, root, scope); !errors.Is(err, ErrAuditContextDone) || events != nil {
		t.Fatal("cancellation ignored")
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	if events, err := ObserveFileStream(context.Background(), root, scope); err == nil || events != nil {
		t.Fatal("closed root admitted")
	}
}

func TestObserveFileStreamRejectsChangedBytesAndUncertainClose(t *testing.T) {
	scope, _ := NewReviewScope("tenant", "repo", "observed")
	first := auditEvent(t, scope, 1, "", EventRouteSelected, 'a')
	other := auditEvent(t, scope, 1, "", EventRouteSelected, 'b')
	encoded, err := EncodeEvent(first)
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := EncodeEvent(other)
	if err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("injected observation failure")
	for _, kind := range []string{"same inode changed", "replacement", "disappeared", "appeared", "root mode", "callback", "close"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, scope.Identity()+auditStreamFileSuffix)
			if kind != "appeared" {
				if err := os.WriteFile(path, append(append([]byte(nil), encoded...), '\n'), 0600); err != nil {
					t.Fatal(err)
				}
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			afterRead := func() error {
				switch kind {
				case "same inode changed", "appeared":
					return os.WriteFile(path, append(append([]byte(nil), replacement...), '\n'), 0600)
				case "replacement", "disappeared":
					if err := os.Rename(path, path+".retained"); err != nil {
						return err
					}
					if kind == "replacement" {
						return os.WriteFile(path, append(append([]byte(nil), encoded...), '\n'), 0600)
					}
				case "root mode":
					return os.Chmod(directory, 0755)
				case "callback":
					return sentinel
				}
				return nil
			}
			closeFile := (*os.File).Close
			if kind == "close" {
				closeFile = func(file *os.File) error { return errors.Join(file.Close(), sentinel) }
			}
			events, err := observeFileStream(context.Background(), root, scope, afterRead, closeFile)
			if err == nil || events != nil {
				t.Fatal("uncertain observation admitted")
			}
			if (kind == "callback" || kind == "close") && !errors.Is(err, sentinel) {
				t.Fatal("injected failure lost")
			}
		})
	}
}

func TestObserveFileStreamKeepsExistingStreamBounds(t *testing.T) {
	scope, _ := NewReviewScope("tenant", "repo", "bounded")
	for _, kind := range []string{"bytes", "events"} {
		t.Run(kind, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(directory, scope.Identity()+auditStreamFileSuffix)
			file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "bytes" {
				if err := file.Truncate(maxAuditStreamBytes + 1); err != nil {
					t.Fatal(err)
				}
			} else {
				previous := ""
				for sequence := uint64(1); sequence <= maxAuditStreamEvents+1; sequence++ {
					event := auditEvent(t, scope, sequence, previous, EventRouteSelected, 'a')
					raw, err := EncodeEvent(event)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := file.Write(append(raw, '\n')); err != nil {
						t.Fatal(err)
					}
					previous = event.Identity()
				}
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(directory)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			if events, err := ObserveFileStream(context.Background(), root, scope); !errors.Is(err, ErrAuditStreamTooLarge) || events != nil {
				t.Fatalf("stream bound changed: %v", err)
			}
		})
	}
}
