//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

func TestPhysicalRecordedRoleClosedAndExclusive(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	pairs := []struct {
		kind   artifact.Kind
		origin artifact.Origin
	}{
		{artifact.KindTaskInput, artifact.OriginHost}, {artifact.KindSourceSnapshot, artifact.OriginRepository},
		{artifact.KindChangeModel, artifact.OriginDeterministicTool}, {artifact.KindDeterministicEvidence, artifact.OriginDeterministicTool}, {artifact.KindRetrievalResult, artifact.OriginMemory},
	}
	for _, pair := range pairs {
		e := physicalPacketExpectation{scope: f.expected[0].scope, role: physicalRoleRecorded, recordedIdentity: strings.Repeat("a", 64), recordedKind: pair.kind, recordedOrigin: pair.origin}
		if !physicalExpectationValid(e) || physicalExpectationIdentity(e) != e.recordedIdentity {
			t.Fatal("valid recorded role rejected")
		}
		value, err := artifact.New(e.scope, pair.kind, "application/json", artifact.ClassificationConfidential, pair.origin, artifact.ProtectionProcessPrivate, []string{strings.Repeat("b", 64)}, []byte(`{}`), time.UnixMilli(100), time.UnixMilli(200))
		if err != nil {
			t.Fatal(err)
		}
		e.recordedIdentity = value.Identity()
		if !physicalExpectationMatches(value, e) {
			t.Fatal("exact recorded envelope rejected")
		}
		e.recordedOrigin = artifact.OriginHost
		if pair.origin != artifact.OriginHost && physicalExpectationMatches(value, e) {
			t.Fatal("wrong origin accepted")
		}
	}
	base := physicalPacketExpectation{scope: f.expected[0].scope, role: physicalRoleRecorded, recordedIdentity: strings.Repeat("a", 64), recordedKind: artifact.KindTaskInput, recordedOrigin: artifact.OriginHost}
	bad := base
	bad.descriptor = f.expected[0].descriptor
	if physicalExpectationValid(bad) {
		t.Fatal("recorded role accepted packet descriptor")
	}
	bad = base
	bad.input.ArtifactIdentity = base.recordedIdentity
	if physicalExpectationValid(bad) {
		t.Fatal("recorded role accepted input descriptor")
	}
	bad = base
	bad.recordedKind = artifact.KindContextPacket
	if physicalExpectationValid(bad) {
		t.Fatal("unlisted pair accepted")
	}
	bad = base
	bad.role = 255
	if physicalExpectationValid(bad) || physicalExpectationIdentity(bad) != "" {
		t.Fatal("unknown role accepted")
	}
	for _, field := range []string{"identity", "kind", "origin"} {
		old := f.expected[0]
		switch field {
		case "identity":
			old.recordedIdentity = base.recordedIdentity
		case "kind":
			old.recordedKind = base.recordedKind
		case "origin":
			old.recordedOrigin = base.recordedOrigin
		}
		if physicalExpectationValid(old) {
			t.Fatal("old role accepted recorded fields")
		}
	}
}

func TestPhysicalRecordedCanonicalFailureStillRereads(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	// A recorded task-input selection of existing packet bytes must mismatch,
	// but preserve the same normal callback and byte-reread semantics.
	selected := physicalPacketExpectation{scope: f.expected[0].scope, role: physicalRoleRecorded, recordedIdentity: f.expected[0].descriptor.ArtifactIdentity, recordedKind: artifact.KindTaskInput, recordedOrigin: artifact.OriginHost}
	calls := 0
	err := f.observe(t, []physicalPacketExpectation{selected}, func(observed []physicalPacketObservation) error {
		calls++
		if len(observed) != 1 || observed[0].kind != physicalPacketMismatch {
			t.Fatal("wrong mismatch")
		}
		raw, err := os.ReadFile(filepath.Join(f.root, f.names[0]))
		if err != nil {
			t.Fatal(err)
		}
		raw[len(raw)-2] ^= 1
		if err = os.WriteFile(filepath.Join(f.root, f.names[0]), raw, 0600); err != nil {
			t.Fatal(err)
		}
		return nil
	})
	if err == nil || calls != 1 {
		t.Fatal("late drift accepted")
	}
}

type physicalRecordedFixture struct {
	names    recordedNamesFixture
	root     string
	selected []string
}

func newPhysicalRecordedFixture(t *testing.T) physicalRecordedFixture {
	t.Helper()
	f := newRecordedNamesFixture(t, nil, "", false)
	root := filepath.Join(t.TempDir(), "artifacts")
	store, err := artifact.NewFileStore(root)
	if err != nil {
		t.Fatal(err)
	}
	values := []artifact.Artifact{f.a.BaseInput, f.a.HeadInput, f.a.BaseSnapshot, f.a.HeadSnapshot, f.a.Change, f.a.Analysis, f.a.Memory, f.a.Packet}
	selected := make([]string, 0, 8)
	for _, value := range values {
		if _, err := store.Put(context.Background(), value, value.CreatedAt()); err != nil {
			t.Fatal(err)
		}
		selected = append(selected, value.Scope().Identity()+"-"+value.Identity()+".artifact.json")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	ids, err := recordedHistoricalV4Names(f.fact, f.a, f.binding)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range ids {
		path := filepath.Join(root, f.fact.Plan().Scope().Identity()+"-"+id+".artifact.json")
		if _, err := os.Stat(path); os.IsNotExist(err) {
			// Source-file names are intentionally names-only in this prerequisite.
			if err = os.WriteFile(path, []byte("not a source envelope"), 0600); err != nil {
				t.Fatal(err)
			}
		} else if err != nil {
			t.Fatal(err)
		}
	}
	return physicalRecordedFixture{f, root, selected}
}
func (f physicalRecordedFixture) observe(t *testing.T, closer func(*os.File) error, sourceRoot string) error {
	t.Helper()
	pending, err := artifact.OpenPendingFileStore(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := pending.Close(); err != nil {
			t.Error(err)
		}
	}()
	return pending.WithOwnedRoot(func(root *os.Root) error {
		binding := f.names.binding
		binding.RootIdentity = sourceRoot
		return observeBorrowedHistoricalRecordedV4NamesWithClose(context.Background(), root, f.names.fact, binding, closer)
	})
}
func TestPhysicalRecordedExactNames(t *testing.T) {
	f := newPhysicalRecordedFixture(t)
	if err := f.observe(t, (*os.File).Close, f.names.root); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"unknown", "missing"} {
		t.Run(name, func(t *testing.T) {
			f := newPhysicalRecordedFixture(t)
			path := filepath.Join(f.root, f.names.fact.Plan().Scope().Identity()+"-"+strings.Repeat("f", 64)+".artifact.json")
			if name == "unknown" {
				if err := os.WriteFile(path, []byte("unread unknown"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				ids, err := recordedHistoricalV4Names(f.names.fact, f.names.a, f.names.binding)
				if err != nil {
					t.Fatal(err)
				}
				selected := map[string]bool{}
				for _, n := range f.selected {
					selected[n] = true
				}
				for _, id := range ids {
					n := f.names.fact.Plan().Scope().Identity() + "-" + id + ".artifact.json"
					if !selected[n] {
						if err = os.Remove(filepath.Join(f.root, n)); err != nil {
							t.Fatal(err)
						}
						break
					}
				}
			}
			if err := f.observe(t, (*os.File).Close, f.names.root); err == nil {
				t.Fatal("extra/missing accepted")
			}
		})
	}
}
func TestPhysicalRecordedRefusalStillRereadsAllEight(t *testing.T) {
	for _, mode := range []string{"parser", "canonical", "unknown", "late drift", "close error"} {
		t.Run(mode, func(t *testing.T) {
			f := newPhysicalRecordedFixture(t)
			sourceRoot := f.names.root
			if mode == "parser" {
				sourceRoot = strings.Repeat("f", 64)
			}
			if mode == "canonical" {
				path := filepath.Join(f.root, f.selected[0])
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(path, append(raw, ' '), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "unknown" {
				if err := os.WriteFile(filepath.Join(f.root, f.names.fact.Plan().Scope().Identity()+"-"+strings.Repeat("f", 64)+".artifact.json"), []byte("extra"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			closes := 0
			closer := func(file *os.File) error {
				info, err := file.Stat()
				if err != nil {
					file.Close()
					return err
				}
				err = file.Close()
				if info.Mode().IsRegular() {
					closes++
					if closes == 8 && mode == "late drift" {
						path := filepath.Join(f.root, f.selected[2])
						raw, e := os.ReadFile(path)
						if e != nil {
							t.Fatal(e)
						}
						raw[len(raw)-2] ^= 1
						if e = os.WriteFile(path, raw, 0600); e != nil {
							t.Fatal(e)
						}
					}
					if closes == 9 && mode == "close error" {
						return errors.New("injected close")
					}
				}
				return err
			}
			if err := f.observe(t, closer, sourceRoot); err == nil {
				t.Fatal("fault accepted")
			}
			// Parser, canonical and name refusals must not skip any selected reread.
			if closes != 16 {
				t.Fatalf("selected closes=%d, want16", closes)
			}
		})
	}
}

func TestPhysicalRecordedBudgetBeforeAnyRead(t *testing.T) {
	f := newPhysicalRecordedFixture(t)
	for _, name := range f.selected[:3] {
		if err := os.Truncate(filepath.Join(f.root, name), physicalPacketFileLimit); err != nil {
			t.Fatal(err)
		}
	}
	reads := 0
	err := f.observe(t, func(file *os.File) error {
		info, e := file.Stat()
		if e == nil && info.Mode().IsRegular() {
			reads++
		}
		return file.Close()
	}, f.names.root)
	if err == nil || reads != 0 {
		t.Fatalf("budget refusal must precede reads: reads=%d err=%v", reads, err)
	}
}
func TestPhysicalRecordedLateNameAndRootChanges(t *testing.T) {
	for _, mode := range []string{"name", "root"} {
		t.Run(mode, func(t *testing.T) {
			f := newPhysicalRecordedFixture(t)
			t.Cleanup(func() { os.Chmod(f.root, 0700) })
			closes := 0
			err := f.observe(t, func(file *os.File) error {
				info, e := file.Stat()
				e = errors.Join(e, file.Close())
				if info != nil && info.Mode().IsRegular() {
					closes++
				}
				if closes == 8 {
					if mode == "name" {
						e = errors.Join(e, os.WriteFile(filepath.Join(f.root, f.names.fact.Plan().Scope().Identity()+"-"+strings.Repeat("f", 64)+".artifact.json"), []byte("late"), 0600))
					} else {
						e = errors.Join(e, os.Chmod(f.root, 0755))
					}
				}
				return e
			}, f.names.root)
			if err == nil {
				t.Fatal("late root/name accepted")
			}
		})
	}
}
func TestPhysicalRecordedCancellation(t *testing.T) {
	f := newPhysicalRecordedFixture(t)
	pending, err := artifact.OpenPendingFileStore(f.root)
	if err != nil {
		t.Fatal(err)
	}
	defer pending.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closes := 0
	err = pending.WithOwnedRoot(func(root *os.Root) error {
		return observeBorrowedHistoricalRecordedV4NamesWithClose(ctx, root, f.names.fact, f.names.binding, func(file *os.File) error {
			info, e := file.Stat()
			e = errors.Join(e, file.Close())
			if info != nil && info.Mode().IsRegular() {
				closes++
				if closes == 8 {
					cancel()
				}
			}
			return e
		})
	})
	if err == nil {
		t.Fatal("cancellation accepted")
	}
}

func TestPhysicalRecordedSelectedByteBudgetBoundary(t *testing.T) {
	for _, over := range []bool{false, true} {
		t.Run(fmt.Sprint(over), func(t *testing.T) {
			f := newPhysicalRecordedFixture(t)
			for i, name := range f.selected {
				size := int64(physicalPacketTotalLimit / 8)
				if over && i == 0 {
					size++
				}
				if err := os.Truncate(filepath.Join(f.root, name), size); err != nil {
					t.Fatal(err)
				}
			}
			reads := 0
			err := f.observe(t, func(file *os.File) error {
				info, e := file.Stat()
				if e == nil && info.Mode().IsRegular() {
					reads++
				}
				return file.Close()
			}, f.names.root)
			if err == nil {
				t.Fatal("malformed sparse fixture accepted")
			}
			want := 16
			if over {
				want = 0
			}
			if reads != want {
				t.Fatalf("reads=%d want=%d", reads, want)
			}
		})
	}
}
