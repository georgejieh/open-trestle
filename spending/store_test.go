package spending

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/filelock"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "state", "open-trestle", "usage"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestDefaultDirectoryFollowsXDGStateHome(t *testing.T) {
	env := map[string]string{"XDG_STATE_HOME": "/srv/state", "HOME": "/home/someone"}
	getenv := func(name string) string { return env[name] }
	if dir, err := DefaultDirectory(getenv); err != nil || dir != "/srv/state/open-trestle/usage" {
		t.Fatalf("XDG_STATE_HOME: %q %v", dir, err)
	}
	env["XDG_STATE_HOME"] = "relative/state"
	if dir, err := DefaultDirectory(getenv); err != nil || dir != "/home/someone/.local/state/open-trestle/usage" {
		t.Fatalf("a relative XDG_STATE_HOME is ignored, as the specification says: %q %v", dir, err)
	}
	delete(env, "XDG_STATE_HOME")
	if dir, err := DefaultDirectory(getenv); err != nil || dir != "/home/someone/.local/state/open-trestle/usage" {
		t.Fatalf("default: %q %v", dir, err)
	}
}

func TestStoreLimitsAreProtectedAndReplaced(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	scope := mustScope(t, "openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	if _, found, err := store.Limit(scope); err != nil || found {
		t.Fatalf("a missing folder must read as no limit: %v %v", found, err)
	}
	if limits, err := store.Limits(); err != nil || len(limits) != 0 {
		t.Fatalf("a missing folder must list no limits: %v %v", limits, err)
	}
	first, _ := NewLimit(scope, PeriodMonth, 10_000_000, DefaultAlertPercents, utc(t, "2026-11-13T10:00:00Z"))
	if err := store.SetLimit(ctx, first); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.Directory())
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("usage folder mode: %v %v", info, err)
	}
	second, _ := NewLimit(scope, PeriodWeek, 2_500_000, []int{90}, utc(t, "2026-11-14T10:00:00Z"))
	if err := store.SetLimit(ctx, second); err != nil {
		t.Fatal(err)
	}
	got, found, err := store.Limit(scope)
	if err != nil || !found || got.Period != PeriodWeek || got.AmountMicroUSD != 2_500_000 {
		t.Fatalf("the limit was not replaced: %+v %v %v", got, found, err)
	}
	other := mustScope(t, "ollama-cloud", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD")
	third, _ := NewLimit(other, PeriodYear, 100_000_000, DefaultAlertPercents, utc(t, "2026-11-14T10:00:00Z"))
	if err := store.SetLimit(ctx, third); err != nil {
		t.Fatal(err)
	}
	limits, err := store.Limits()
	if err != nil || len(limits) != 2 || limits[0].Scope != other || limits[1].Scope != scope {
		t.Fatalf("limits: %+v %v", limits, err)
	}
	entries, _ := os.ReadDir(store.Directory())
	for _, entry := range entries {
		info, _ := entry.Info()
		if strings.HasPrefix(entry.Name(), ".limit-") || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s is left behind or not 0600 (%v)", entry.Name(), info.Mode())
		}
	}
	if cleared, err := store.ClearLimit(ctx, scope); err != nil || !cleared {
		t.Fatalf("clear: %v %v", cleared, err)
	}
	if cleared, err := store.ClearLimit(ctx, scope); err != nil || cleared {
		t.Fatalf("clearing a missing limit: %v %v", cleared, err)
	}
	if _, found, _ := store.Limit(scope); found {
		t.Fatal("the cleared limit is still read")
	}
	// A limit file whose mode lets others read it is refused, not trusted.
	path := filepath.Join(store.Directory(), limitName(other))
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.Limit(other); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an unprotected limit file was read: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// A folder others can enter is refused.
	if err := os.Chmod(store.Directory(), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Limits(); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("a folder that is not 0700 was used: %v", err)
	}
	if err := store.Append(ctx, testEntry(t, "2026-11-13T10:00:00Z", 1, true, scope)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an entry was appended to a folder that is not 0700: %v", err)
	}
}

func TestStoreAppendSumsChargedEntriesByPeriod(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	openRouter := mustScope(t, "openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	other := mustScope(t, "ollama-cloud", "OPEN_TRESTLE_PROVIDER_OLLAMA_CLOUD")
	for _, entry := range []Entry{
		testEntry(t, "2026-10-31T23:59:59Z", 1_000_000, true, openRouter),        // the month before
		testEntry(t, "2026-11-01T00:00:00Z", 2_000_000, true, openRouter),        // first second of the month
		testEntry(t, "2026-11-09T00:00:00Z", 300_000, false, openRouter),         // reservation upper bound
		testEntry(t, "2026-11-13T10:00:00Z", 40_000, true, openRouter, other),    // both keys charged in full
		testEntry(t, "2026-11-13T11:00:00Z", 5_000, true, other),                 // another key only
		testEntry(t, "2026-12-01T00:00:00Z", 7_000_000, true, openRouter, other), // the next month
	} {
		if err := store.Append(ctx, entry); err != nil {
			t.Fatal(err)
		}
	}
	check := func(scope Scope, period Period, at string, micro uint64, entries, upper int) {
		t.Helper()
		start, end := period.Bounds(utc(t, at))
		spend, err := store.Spent(scope, start, end)
		if err != nil || spend.MicroUSD != micro || spend.Entries != entries || spend.UpperBound != upper {
			t.Fatalf("%s %s at %s: %+v %v, want %d over %d (%d upper bound)", scope.CredentialEnvironment, period, at, spend, err, micro, entries, upper)
		}
	}
	check(openRouter, PeriodMonth, "2026-11-20T00:00:00Z", 2_340_000, 3, 1)
	check(openRouter, PeriodWeek, "2026-11-13T00:00:00Z", 340_000, 2, 1)   // week of Monday 9 November
	check(openRouter, PeriodWeek, "2026-11-01T12:00:00Z", 3_000_000, 2, 0) // week of Monday 26 October spans two files
	check(openRouter, PeriodYear, "2026-06-01T00:00:00Z", 10_340_000, 5, 1)
	check(other, PeriodMonth, "2026-11-30T23:59:59Z", 45_000, 2, 0)
	check(other, PeriodMonth, "2027-01-01T00:00:00Z", 0, 0, 0)
	for _, name := range []string{"ledger-2026-10.jsonl", "ledger-2026-11.jsonl", "ledger-2026-12.jsonl", "ledger.lock"} {
		info, err := os.Lstat(filepath.Join(store.Directory(), name))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", name, info, err)
		}
	}
	data, _ := os.ReadFile(filepath.Join(store.Directory(), "ledger-2026-11.jsonl"))
	for _, forbidden := range []string{"sk-", "prompt", "source"} {
		if strings.Contains(string(data), forbidden) {
			t.Fatalf("the ledger holds %q", forbidden)
		}
	}
}

func TestStoreLedgerToleratesOnlyATornFinalLine(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	scope := mustScope(t, "openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	if err := store.Append(ctx, testEntry(t, "2026-11-13T10:00:00Z", 100, true, scope)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Directory(), "ledger-2026-11.jsonl")
	torn, _ := EncodeEntry(testEntry(t, "2026-11-13T10:00:01Z", 900, true, scope))
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.Write(torn[:len(torn)/2])
	_ = file.Close()
	start, end := PeriodMonth.Bounds(utc(t, "2026-11-13T00:00:00Z"))
	if spend, err := store.Spent(scope, start, end); err != nil || spend.MicroUSD != 100 {
		t.Fatalf("a torn final line must be ignored: %+v %v", spend, err)
	}
	// The next entry closes the torn line, so it starts on a line of its own;
	// the torn line is then a complete, invalid line.
	if err := store.Append(ctx, testEntry(t, "2026-11-13T10:00:02Z", 200, true, scope)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Spent(scope, start, end); !errors.Is(err, ErrLedgerUnreadable) {
		t.Fatalf("an invalid complete line must make the ledger unreadable, not be skipped: %v", err)
	}
	// A line that is not an entry, such as one hand-edited to lower the total,
	// is refused rather than ignored.
	other := testStore(t)
	if err := other.Append(ctx, testEntry(t, "2026-11-13T10:00:00Z", 100, true, scope)); err != nil {
		t.Fatal(err)
	}
	edited := filepath.Join(other.Directory(), "ledger-2026-11.jsonl")
	data, _ := os.ReadFile(edited)
	if err := os.WriteFile(edited, []byte(strings.Replace(string(data), `"cost_micro_usd":100`, `"cost_micro_usd": 1`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := other.Spent(scope, start, end); !errors.Is(err, ErrLedgerUnreadable) {
		t.Fatalf("a non-canonical line was read: %v", err)
	}
	// An entry filed under the wrong month is refused too.
	moved := testStore(t)
	if err := moved.Append(ctx, testEntry(t, "2026-10-13T10:00:00Z", 100, true, scope)); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(moved.Directory(), "ledger-2026-10.jsonl"), filepath.Join(moved.Directory(), "ledger-2026-11.jsonl")); err != nil {
		t.Fatal(err)
	}
	if _, err := moved.Spent(scope, start, end); !errors.Is(err, ErrLedgerUnreadable) {
		t.Fatalf("an entry in another month's file was read: %v", err)
	}
}

func TestStoreAppendIsSerializedByTheLedgerLock(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	scope := mustScope(t, "openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	// Create the folder, then hold the ledger lock as another writer would.
	if err := store.Append(ctx, testEntry(t, "2026-11-13T09:00:00Z", 1, true, scope)); err != nil {
		t.Fatal(err)
	}
	held, err := filelock.Acquire(filepath.Join(store.Directory(), ledgerLock))
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- store.Append(ctx, testEntry(t, "2026-11-13T09:00:01Z", 10, true, scope)) }()
	select {
	case err := <-done:
		t.Fatalf("an append did not wait for the held lock: %v", err)
	case <-time.After(150 * time.Millisecond):
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatalf("the waiting append failed after the lock was released: %v", err)
	}
	// Concurrent appends each land as one complete line.
	var group sync.WaitGroup
	errs := make(chan error, 24)
	for i := range 24 {
		group.Add(1)
		go func() {
			defer group.Done()
			entry := testEntry(t, fmt.Sprintf("2026-11-13T10:00:%02dZ", i), 1000, true, scope)
			entry.ReviewRunID = fmt.Sprintf("local-%02d", i)
			errs <- store.Append(ctx, entry)
		}()
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	start, end := PeriodMonth.Bounds(utc(t, "2026-11-13T00:00:00Z"))
	spend, err := store.Spent(scope, start, end)
	if err != nil || spend.Entries != 26 || spend.MicroUSD != 24_011 {
		t.Fatalf("concurrent appends: %+v %v", spend, err)
	}
	// A canceled append waiting on the lock gives up.
	held, err = filelock.Acquire(filepath.Join(store.Directory(), ledgerLock))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if err := store.Append(canceled, testEntry(t, "2026-11-13T11:00:00Z", 1, true, scope)); err == nil {
		t.Fatal("a canceled append succeeded while the lock was held")
	}
}

func TestStoreRefusesALedgerFileItCannotTrust(t *testing.T) {
	store := testStore(t)
	ctx := context.Background()
	scope := mustScope(t, "openrouter", "OPEN_TRESTLE_PROVIDER_OPENROUTER")
	if err := store.Append(ctx, testEntry(t, "2026-11-13T10:00:00Z", 1, true, scope)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(store.Directory(), "ledger-2026-11.jsonl")
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, testEntry(t, "2026-11-13T10:00:01Z", 1, true, scope)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an entry was appended to a file others can read: %v", err)
	}
	start, end := PeriodMonth.Bounds(utc(t, "2026-11-13T00:00:00Z"))
	if _, err := store.Spent(scope, start, end); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an unprotected ledger was read: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// A ledger file replaced by a symbolic link is refused.
	elsewhere := filepath.Join(t.TempDir(), "elsewhere.jsonl")
	if err := os.WriteFile(elsewhere, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(store.Directory(), "ledger-2026-12.jsonl")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}
	if err := store.Append(ctx, testEntry(t, "2026-12-13T10:00:00Z", 1, true, scope)); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("an entry was appended through a symbolic link: %v", err)
	}
}
