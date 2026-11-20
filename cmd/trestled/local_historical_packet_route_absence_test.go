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

	"github.com/georgejieh/open-trestle/audit"
)

type historicalAuditTestReader struct {
	ledger *audit.FileLedger
	read   func(context.Context, audit.ReviewScope, uint64, uint16) ([]audit.Event, error)
	head   func(context.Context, audit.ReviewScope) (audit.Event, bool, error)
}

func (r historicalAuditTestReader) Head(ctx context.Context, scope audit.ReviewScope) (audit.Event, bool, error) {
	if r.head != nil {
		return r.head(ctx, scope)
	}
	return r.ledger.Head(ctx, scope)
}
func (r historicalAuditTestReader) Read(ctx context.Context, scope audit.ReviewScope, after uint64, limit uint16) ([]audit.Event, error) {
	if r.read != nil {
		return r.read(ctx, scope, after, limit)
	}
	return r.ledger.Read(ctx, scope, after, limit)
}
func historicalAuditFixture(t *testing.T, kinds []audit.EventKind) (*audit.FileLedger, audit.ReviewScope, string) {
	t.Helper()
	root := filepath.Join(t.TempDir(), "audit")
	ledger, err := audit.NewFileLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ledger.Close() })
	scope, err := audit.NewReviewScope("tenant", "repository", "run")
	if err != nil {
		t.Fatal(err)
	}
	previous := ""
	for i, kind := range kinds {
		event, err := audit.NewEvent(scope, uint64(i+1), previous, kind, fmt.Sprintf("%064x", i+1), nil, time.UnixMilli(int64(i+100)))
		if err != nil {
			t.Fatal(err)
		}
		if err = ledger.Append(context.Background(), previous, event); err != nil {
			t.Fatal(err)
		}
		previous = event.Identity()
	}
	return ledger, scope, root
}
func TestHistoricalPacketRouteAbsenceEmptyAndAllowedKind(t *testing.T) {
	t.Parallel()
	for _, count := range []int{0, 1, 64, 65, 128, 129} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			kinds := make([]audit.EventKind, count)
			for i := range kinds {
				kinds[i] = audit.EventReviewSnapshotBound
			}
			ledger, scope, root := historicalAuditFixture(t, kinds)
			path := filepath.Join(root, scope.Identity()+".audit.jsonl")
			before, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			result, err := observeHistoricalPacketRouteAbsence(context.Background(), ledger, scope)
			if err != nil || result.present != (count > 0) || result.sequence != uint64(count) {
				t.Fatalf("result=%+v err=%v", result, err)
			}
			head, present, err := ledger.Head(context.Background(), scope)
			if err != nil || present != result.present || present && head.Identity() != result.identity {
				t.Fatal("head mismatch")
			}
			after, err := os.ReadFile(path)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("observer wrote audit")
			}
		})
	}
}
func TestHistoricalPacketRouteAbsenceRejectsLaterKinds(t *testing.T) {
	t.Parallel()
	for kind := audit.EventRouteSelected; kind <= audit.EventInvestigationToolCompleted; kind++ {
		if kind == audit.EventReviewSnapshotBound || kind.Validate() != nil {
			continue
		}
		t.Run(kind.String(), func(t *testing.T) {
			ledger, scope, _ := historicalAuditFixture(t, []audit.EventKind{kind})
			result, err := observeHistoricalPacketRouteAbsence(context.Background(), ledger, scope)
			if err == nil || result != (localHistoricalPacketAuditHead{}) {
				t.Fatal("later event accepted")
			}
		})
	}
}
func TestHistoricalPacketRouteAbsenceRefusesUnstableReads(t *testing.T) {
	t.Parallel()
	kinds := make([]audit.EventKind, 65)
	for i := range kinds {
		kinds[i] = audit.EventReviewSnapshotBound
	}
	for _, name := range []string{"late corrupt", "truncated", "cross scope", "head changed", "canceled", "extra after head"} {
		t.Run(name, func(t *testing.T) {
			ledger, scope, _ := historicalAuditFixture(t, kinds)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := historicalAuditTestReader{ledger: ledger}
			reader.read = func(ctx context.Context, s audit.ReviewScope, after uint64, limit uint16) ([]audit.Event, error) {
				page, err := ledger.Read(ctx, s, after, limit)
				if err != nil {
					return nil, err
				}
				if after == 64 {
					switch name {
					case "late corrupt":
						return nil, audit.ErrCorruptAuditStream
					case "truncated":
						return nil, nil
					case "cross scope":
						foreign, _ := audit.NewReviewScope("tenant", "repository", "other")
						event, _ := audit.NewEvent(foreign, 65, page[0].PreviousIdentity(), audit.EventReviewSnapshotBound, strings.Repeat("a", 64), nil, time.UnixMilli(500))
						return []audit.Event{event}, nil
					case "head changed", "extra after head":
						head, _, e := ledger.Head(ctx, s)
						if e != nil {
							return nil, e
						}
						event, _ := audit.NewEvent(s, head.Sequence()+1, head.Identity(), audit.EventReviewSnapshotBound, strings.Repeat("a", 64), nil, time.UnixMilli(500))
						if e = ledger.Append(ctx, head.Identity(), event); e != nil {
							return nil, e
						}
					case "canceled":
						cancel()
					}
				}
				if name == "head changed" && after == 65 {
					return nil, nil
				}
				return page, nil
			}
			result, err := readHistoricalPacketRouteAbsence(ctx, reader, scope)
			if err == nil || result != (localHistoricalPacketAuditHead{}) {
				t.Fatal("unstable audit accepted")
			}
		})
	}
}
func TestHistoricalPacketRouteAbsenceInvalidInputsAndClosedLedger(t *testing.T) {
	t.Parallel()
	ledger, scope, _ := historicalAuditFixture(t, nil)
	for _, check := range []func() error{
		func() error { _, err := observeHistoricalPacketRouteAbsence(nil, ledger, scope); return err },
		func() error {
			_, err := observeHistoricalPacketRouteAbsence(context.Background(), nil, scope)
			return err
		},
		func() error {
			_, err := observeHistoricalPacketRouteAbsence(context.Background(), ledger, audit.ReviewScope{})
			return err
		},
	} {
		if err := check(); err == nil {
			t.Fatal("invalid input accepted")
		}
	}
	ledger.Close()
	if _, err := observeHistoricalPacketRouteAbsence(context.Background(), ledger, scope); !errors.Is(err, audit.ErrAuditLedgerClosed) {
		t.Fatalf("closed err=%v", err)
	}
}

// The predicate checks allowed kinds, not source closure. This arbitrary subject
// and missing six source parents pass without proving an acquired snapshot.
func TestHistoricalPacketRouteAbsenceArbitrarySnapshotBoundIsNotSourceValidation(t *testing.T) {
	t.Parallel()
	ledger, scope, _ := historicalAuditFixture(t, []audit.EventKind{audit.EventReviewSnapshotBound})
	if _, err := observeHistoricalPacketRouteAbsence(context.Background(), ledger, scope); err != nil {
		t.Fatal(err)
	}
}
func TestHistoricalPacketRouteAbsenceRouteBeforeSnapshotWithoutV5(t *testing.T) {
	t.Parallel()
	ledger, scope, _ := historicalAuditFixture(t, []audit.EventKind{audit.EventRouteSelected, audit.EventReviewSnapshotBound})
	if result, err := observeHistoricalPacketRouteAbsence(context.Background(), ledger, scope); err == nil || result != (localHistoricalPacketAuditHead{}) {
		t.Fatal("route-only historical scope accepted")
	}
}
func TestHistoricalPacketRouteAbsencePageChainAndFinalHeadChecks(t *testing.T) {
	t.Parallel()
	kinds := make([]audit.EventKind, 65)
	for i := range kinds {
		kinds[i] = audit.EventReviewSnapshotBound
	}
	for _, name := range []string{"wrong sequence", "wrong previous", "head read failure", "final head cancellation", "absent final head"} {
		t.Run(name, func(t *testing.T) {
			ledger, scope, _ := historicalAuditFixture(t, kinds)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			reader := historicalAuditTestReader{ledger: ledger}
			heads := 0
			reader.head = func(ctx context.Context, s audit.ReviewScope) (audit.Event, bool, error) {
				heads++
				if heads == 2 {
					switch name {
					case "head read failure":
						return audit.Event{}, false, audit.ErrAuditPersistence
					case "absent final head":
						return audit.Event{}, false, nil
					case "final head cancellation":
						cancel()
					}
				}
				return ledger.Head(ctx, s)
			}
			reader.read = func(ctx context.Context, s audit.ReviewScope, after uint64, limit uint16) ([]audit.Event, error) {
				page, err := ledger.Read(ctx, s, after, limit)
				if err == nil && after == 64 && len(page) == 1 && (name == "wrong sequence" || name == "wrong previous") {
					seq, prev := uint64(65), page[0].PreviousIdentity()
					if name == "wrong sequence" {
						seq = 66
					} else {
						prev = strings.Repeat("f", 64)
					}
					event, e := audit.NewEvent(s, seq, prev, audit.EventReviewSnapshotBound, strings.Repeat("a", 64), nil, time.UnixMilli(500))
					if e != nil {
						return nil, e
					}
					return []audit.Event{event}, nil
				}
				return page, err
			}
			if result, err := readHistoricalPacketRouteAbsence(ctx, reader, scope); err == nil || result != (localHistoricalPacketAuditHead{}) {
				t.Fatal("invalid chain/head accepted")
			}
		})
	}
}

func TestHistoricalPacketRouteAbsenceLateFileCorruption(t *testing.T) {
	t.Parallel()
	kinds := make([]audit.EventKind, 65)
	for i := range kinds {
		kinds[i] = audit.EventReviewSnapshotBound
	}
	ledger, scope, root := historicalAuditFixture(t, kinds)
	reader := historicalAuditTestReader{ledger: ledger}
	reader.read = func(ctx context.Context, s audit.ReviewScope, after uint64, limit uint16) ([]audit.Event, error) {
		page, err := ledger.Read(ctx, s, after, limit)
		if err == nil && after == 0 {
			path := filepath.Join(root, s.Identity()+".audit.jsonl")
			stream, e := os.ReadFile(path)
			if e != nil {
				return nil, e
			}
			lines := strings.Split(strings.TrimSuffix(string(stream), "\n"), "\n")
			lines[64] = "corrupt"
			if e = os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0600); e != nil {
				return nil, e
			}
		}
		return page, err
	}
	result, err := readHistoricalPacketRouteAbsence(context.Background(), reader, scope)
	if !errors.Is(err, audit.ErrCorruptAuditStream) || result != (localHistoricalPacketAuditHead{}) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
}
