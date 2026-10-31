//go:build linux

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

func exactScopeFixtureIDs(f physicalPacketTestFixture) []string {
	ids := make([]string, len(f.expected))
	for i, e := range f.expected {
		ids[i] = e.descriptor.ArtifactIdentity
	}
	return ids
}

func exactScopeObserve(t *testing.T, f physicalPacketTestFixture, ids []string, expected []physicalPacketExpectation, closer func(*os.File) error) error {
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
		return observeBorrowedHistoricalExactScopeNamesWithClose(context.Background(), root, f.expected[0].scope, ids, expected, closer)
	})
}

func TestPhysicalExactScopeNamesExactAndMetadataOnlyLimits(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	ids := exactScopeFixtureIDs(f)
	// Unselected allowlisted leaves and foreign leaves are metadata-only, not
	// canonical inventory. The caller must derive the asserted names elsewhere.
	extra := strings.Repeat("f", 64)
	foreign := strings.Repeat("e", 64) + "-" + strings.Repeat("d", 64) + ".artifact.json"
	for _, name := range []string{f.expected[0].scope.Identity() + "-" + extra + ".artifact.json", foreign} {
		if err := os.WriteFile(filepath.Join(f.root, name), []byte("x"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	ids = append(ids, extra)
	if err := exactScopeObserve(t, f, ids, f.expected, (*os.File).Close); err != nil {
		t.Fatal(err)
	}
	f.entries = physicalPacketTestEntries(t, f.root)
	f.unchanged(t)
}

func TestPhysicalExactScopeNamesUnknownOrMissingRefusesBeforePayload(t *testing.T) {
	for _, kind := range []artifact.Kind{artifact.KindSanitizedModelRequest, artifact.KindSanitizedEgressReceipt, artifact.KindTaskInput, 0} {
		t.Run(kind.String(), func(t *testing.T) {
			f := newPhysicalPacketTestFixture(t)
			id := strings.Repeat("f", 64)
			raw := []byte("malformed")
			if kind != 0 {
				created := time.UnixMilli(2000)
				value, err := artifact.New(f.expected[0].scope, kind, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{f.expected[0].descriptor.ArtifactIdentity}, []byte(`{"orphan":true}`), created, created.Add(time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				id = value.Identity()
				raw, err = artifact.Encode(value)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(f.root, f.expected[0].scope.Identity()+"-"+id+".artifact.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			reads := 0
			err := exactScopeObserve(t, f, exactScopeFixtureIDs(f), f.expected, func(file *os.File) error {
				info, err := file.Stat()
				if err == nil && !info.IsDir() {
					reads++
				}
				return file.Close()
			})
			if !errors.Is(err, errPhysicalPacketObservationUncertain) || reads != 0 {
				t.Fatal("unknown name read or accepted", reads, err)
			}
		})
	}
	f := newPhysicalPacketTestFixture(t)
	ids := append(exactScopeFixtureIDs(f), strings.Repeat("f", 64))
	reads := 0
	err := exactScopeObserve(t, f, ids, f.expected, func(file *os.File) error {
		info, err := file.Stat()
		if err == nil && !info.IsDir() {
			reads++
		}
		return file.Close()
	})
	if !errors.Is(err, errPhysicalPacketObservationUncertain) || reads != 0 {
		t.Fatal("missing asserted name", reads, err)
	}
}

func TestPhysicalExactScopeNamesRejectsInvalidAssertions(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	ids := exactScopeFixtureIDs(f)
	other, err := audit.NewReviewScope("other", "repo", "run")
	if err != nil {
		t.Fatal(err)
	}
	foreign := append([]physicalPacketExpectation(nil), f.expected...)
	foreign[0].scope = other
	unselected := append([]physicalPacketExpectation(nil), f.expected...)
	unselected[0].descriptor.ArtifactIdentity = strings.Repeat("f", 64)
	for _, tc := range []struct {
		name     string
		ids      []string
		expected []physicalPacketExpectation
	}{
		{"empty", nil, f.expected}, {"duplicate", []string{ids[0], ids[0]}, f.expected}, {"malformed", []string{"bad"}, f.expected},
		{"bound", make([]string, physicalPacketEntryLimit), f.expected}, {"empty-selected", ids, nil}, {"foreign-selected", ids, foreign}, {"unlisted-selected", ids, unselected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := exactScopeObserve(t, f, tc.ids, tc.expected, (*os.File).Close); !errors.Is(err, errPhysicalPacketObservationUncertain) {
				t.Fatal(err)
			}
		})
	}
	if err := observeBorrowedHistoricalExactScopeNames(context.Background(), nil, audit.ReviewScope{}, ids, f.expected); !errors.Is(err, errPhysicalPacketObservationUncertain) {
		t.Fatal(err)
	}
	if err := observeBorrowedHistoricalExactScopeNames(context.Background(), nil, f.expected[0].scope, ids, f.expected); !errors.Is(err, errPhysicalPacketObservationUncertain) {
		t.Fatal(err)
	}
}

func TestPhysicalExactScopeNamesSelectedMustBeIntact(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	if err := os.WriteFile(filepath.Join(f.root, f.names[0]), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := exactScopeObserve(t, f, exactScopeFixtureIDs(f), f.expected, (*os.File).Close); !errors.Is(err, errPhysicalPacketObservationUncertain) {
		t.Fatal(err)
	}
}

func TestPhysicalExactScopeNamesClonesCallerNames(t *testing.T) {
	f := newPhysicalPacketTestFixture(t)
	ids := exactScopeFixtureIDs(f)
	changed := false
	err := exactScopeObserve(t, f, ids, f.expected, func(file *os.File) error {
		info, err := file.Stat()
		closeErr := file.Close()
		if err == nil && info.IsDir() && !changed {
			ids[0] = strings.Repeat("f", 64)
			changed = true
		}
		return closeErr
	})
	if err != nil || !changed {
		t.Fatal(err)
	}
}

func TestPhysicalExactScopeNamesLateDriftAndCheckedClose(t *testing.T) {
	for _, mode := range []string{"byte", "same-scope-name", "foreign-name", "close", "directory-close", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			f := newPhysicalPacketTestFixture(t)
			changed := false
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			pending, err := artifact.OpenPendingFileStore(f.root)
			if err != nil {
				t.Fatal(err)
			}
			defer pending.Close()
			sentinel := errors.New("checked close")
			err = pending.WithOwnedRoot(func(root *os.Root) error {
				return observeBorrowedHistoricalExactScopeNamesWithClose(ctx, root, f.expected[0].scope, exactScopeFixtureIDs(f), f.expected, func(file *os.File) error {
					info, statErr := file.Stat()
					closeErr := file.Close()
					if statErr != nil {
						return errors.Join(closeErr, statErr)
					}
					if mode == "directory-close" && info.IsDir() {
						return errors.Join(closeErr, sentinel)
					}
					if !changed && !info.IsDir() {
						changed = true
						switch mode {
						case "byte":
							f.overwriteSecondPayloadByte(t)
						case "same-scope-name", "foreign-name":
							prefix := f.expected[0].scope.Identity()
							if mode == "foreign-name" {
								prefix = strings.Repeat("e", 64)
							}
							if err := os.WriteFile(filepath.Join(f.root, prefix+"-"+strings.Repeat("f", 64)+".artifact.json"), []byte("x"), 0600); err != nil {
								t.Fatal(err)
							}
						case "close":
							return errors.Join(closeErr, sentinel)
						case "cancel":
							cancel()
						}
					}
					return closeErr
				})
			})
			if !errors.Is(err, errPhysicalPacketObservationUncertain) {
				t.Fatal("late fault accepted", err)
			}
		})
	}
}
