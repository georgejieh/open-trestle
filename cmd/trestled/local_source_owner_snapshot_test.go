package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/setup"
)

func snapshotFixture(t *testing.T) (string, string, setup.Plan) {
	t.Helper()
	base := t.TempDir()
	state := filepath.Join(base, "state")
	path := filepath.Join(state, "setup", "plan.json")
	plan, err := setup.NewPlan(setup.ProfileLocalSingleNode, "tenant-one", "repository-one", "operator", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return state, path, plan
}

func writeSnapshotSetup(t *testing.T, path string, plan setup.Plan) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	file, err := setup.OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Initialize(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

type snapshotChecker struct {
	key      setup.CheckKey
	identity string
	calls    int
}

func (c *snapshotChecker) Key() setup.CheckKey     { return c.key }
func (c *snapshotChecker) CheckerIdentity() string { return c.identity }
func (c *snapshotChecker) Check(context.Context, setup.Plan) setup.CheckResult {
	c.calls++
	return setup.NewPassedCheckResult(fmt.Sprintf("%064x", 1))
}

type snapshotClock struct{ at time.Time }

func (c snapshotClock) Now() time.Time { return c.at }

func writeSnapshotReceipt(t *testing.T, path string, plan setup.Plan) (setup.Plan, setup.CheckReceipt) {
	t.Helper()
	state, err := setup.OpenStateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	catalog, err := setup.BuiltInCheckerCatalog(plan.Profile())
	if err != nil {
		t.Fatal(err)
	}
	for _, requirement := range plan.Requirements() {
		if requirement.State() != setup.CheckPending {
			continue
		}
		key := requirement.Key()
		identity, found := catalog.Resolve(key)
		if !found {
			t.Fatal("pending checker absent from catalog")
		}
		checker := &snapshotChecker{key: key, identity: identity}
		runner, err := setup.NewRunner(state, []setup.Checker{checker}, snapshotClock{plan.CreatedAt().Add(time.Hour)})
		if err != nil {
			t.Fatal(err)
		}
		next, receipt, err := runner.RunExpected(context.Background(), key, plan.Identity())
		if err != nil || checker.calls != 1 {
			t.Fatalf("runner receipt=%v calls=%d", err, checker.calls)
		}
		if next.Revision() != 2 || len(next.Receipts()) != 1 || receipt.Identity() != next.Receipts()[0].Identity() {
			t.Fatal("runner did not commit one receipt")
		}
		inspected, err := setup.InspectStateFile(context.Background(), path)
		if err != nil || inspected.Identity() != next.Identity() || inspected.RootIdentity() != plan.RootIdentity() {
			t.Fatalf("inspection after runner: %v", err)
		}
		records, err := os.ReadDir(path + ".receipts")
		if err != nil || len(records) != 1 || !strings.HasSuffix(records[0].Name(), "-"+receipt.Identity()+".receipt.json") {
			t.Fatalf("physical ledger: %v %v", records, err)
		}
		return next, receipt
	}
	t.Fatal("no pending requirement")
	return setup.Plan{}, setup.CheckReceipt{}
}

type snapshotTreeEntry struct {
	mode os.FileMode
	info os.FileInfo
	data []byte
}

func snapshotTree(t *testing.T, base string) map[string]snapshotTreeEntry {
	t.Helper()
	result := make(map[string]snapshotTreeEntry)
	err := filepath.WalkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(base, path)
		if err != nil {
			return err
		}
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		item := snapshotTreeEntry{mode: info.Mode(), info: info}
		if info.Mode().IsRegular() {
			item.data, err = os.ReadFile(path)
			if err != nil {
				return err
			}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			link, e := os.Readlink(path)
			if e != nil {
				return e
			}
			item.data = []byte(link)
		}
		result[rel] = item
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
func assertSnapshotTreeUnchanged(t *testing.T, before, after map[string]snapshotTreeEntry) {
	t.Helper()
	names := func(tree map[string]snapshotTreeEntry) []string {
		out := make([]string, 0, len(tree))
		for name := range tree {
			out = append(out, name)
		}
		sort.Strings(out)
		return out
	}
	if !reflect.DeepEqual(names(before), names(after)) {
		t.Fatalf("tree names changed: %v -> %v", names(before), names(after))
	}
	for name, old := range before {
		now := after[name]
		if old.mode != now.mode || !os.SameFile(old.info, now.info) || !bytes.Equal(old.data, now.data) {
			t.Fatalf("tree changed at %q", name)
		}
	}
}
func assertSnapshotNoWrite(t *testing.T, base string, inspect func()) {
	t.Helper()
	before := snapshotTree(t, base)
	inspect()
	assertSnapshotTreeUnchanged(t, before, snapshotTree(t, base))
}

func TestLocalSourceOwnerSnapshotFirstUse(t *testing.T) {
	for _, shape := range []string{"missing", "nested-missing", "empty", "nested-empty", "setup-deterministic", "setup-full", "alias", "relative-alias"} {
		t.Run(shape, func(t *testing.T) {
			state, path, plan := snapshotFixture(t)
			base := filepath.Dir(state)
			want := localSourceOwnerMissing
			switch shape {
			case "nested-missing":
				state = filepath.Join(state, "missing", "child")
				path = filepath.Join(state, "setup", "plan.json")
			case "empty", "nested-empty":
				want = localSourceOwnerEmpty
				if shape == "nested-empty" {
					state = filepath.Join(state, "child")
					path = filepath.Join(state, "setup", "plan.json")
				}
				if err := os.MkdirAll(state, 0700); err != nil {
					t.Fatal(err)
				}
			case "setup-deterministic", "setup-full", "alias", "relative-alias":
				want = localSourceOwnerSetupOnly
				writeSnapshotSetup(t, path, plan)
				if shape == "setup-full" {
					plan, _ = writeSnapshotReceipt(t, path, plan)
				}
				if shape == "alias" {
					// Join would clean these segments before they reach the helper.
					state = base + "/./state/../state"
					path = filepath.Join(base, "state", "setup", "plan.json")
				}
				if shape == "relative-alias" {
					cwd, err := os.Getwd()
					if err != nil {
						t.Fatal(err)
					}
					state, err = filepath.Rel(cwd, state)
					if err != nil || filepath.IsAbs(state) {
						t.Fatalf("relative fixture: %v", err)
					}
				}
			}
			assertSnapshotNoWrite(t, base, func() {
				snap, err := inspectLocalSourceOwnerSnapshot(context.Background(), state, path, &plan)
				if err != nil {
					t.Fatal(err)
				}
				defer snap.Close()
				if snap.Kind != want {
					t.Fatalf("kind %v want %v", snap.Kind, want)
				}
				if (shape == "alias" || shape == "relative-alias") && snap.StatePath != filepath.Join(base, "state") {
					t.Fatalf("state alias not canonicalized: %q", snap.StatePath)
				}
				if want == localSourceOwnerSetupOnly {
					if err := recheckOwnerEntries(snap); err != nil {
						t.Fatalf("fresh recheck: %v", err)
					}
					inspected, err := setup.InspectStateFile(context.Background(), path)
					if err != nil || inspected.Revision() != plan.Revision() || len(inspected.Receipts()) != len(plan.Receipts()) || inspected.RootIdentity() != plan.RootIdentity() {
						t.Fatalf("setup classification: %v", err)
					}
				}
			})
			if _, err := os.Lstat(filepath.Join(state, "artifacts")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("artifact constructor reached: %v", err)
			}
		})
	}
}

func TestLocalSourceOwnerSnapshotRefusesUncertainState(t *testing.T) {
	for _, shape := range []string{"root-sibling", "root-overbound", "artifact-sibling", "setup-sibling", "setup-overbound", "corrupt-plan", "bad-mode", "public-state", "bad-lock", "bad-receipts", "linked-plan", "linked-receipt", "linked-parent", "large-plan", "many-receipts", "wrong-path", "wrong-plan", "staging", "missing-plan", "missing-lock", "missing-ledger", "linked-setup", "linked-ledger", "receipt-mode", "receipt-large", "receipt-directory", "linked-missing-ancestor", "invalid-expected", "nil-context", "canceled-context"} {
		t.Run(shape, func(t *testing.T) {
			state, path, plan := snapshotFixture(t)
			writeSnapshotSetup(t, path, plan)
			configured := path
			expected := plan
			switch shape {
			case "root-sibling":
				os.WriteFile(filepath.Join(state, ".local-source-owner.json.next"), []byte("x"), 0600)
			case "root-overbound":
				for _, name := range []string{"artifact-journal.lock", "audit.json", "webhook.json"} {
					if err := os.WriteFile(filepath.Join(state, name), []byte("x"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "artifact-sibling":
				if err := os.Mkdir(filepath.Join(state, "artifacts"), 0700); err != nil {
					t.Fatal(err)
				}
			case "setup-sibling":
				os.WriteFile(filepath.Join(state, "setup", "other"), []byte("x"), 0600)
			case "setup-overbound":
				for _, name := range []string{"x", "y", "z"} {
					if err := os.WriteFile(filepath.Join(state, "setup", name), []byte("x"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "corrupt-plan":
				if err := os.WriteFile(path, []byte("invalid"), 0600); err != nil {
					t.Fatal(err)
				}
			case "public-state":
				if err := os.Chmod(state, 0755); err != nil {
					t.Fatal(err)
				}
			case "bad-mode":
				os.Chmod(filepath.Join(state, "setup"), 0755)
			case "bad-lock":
				os.Chmod(path+".lock", 0644)
			case "bad-receipts":
				os.Chmod(path+".receipts", 0755)
			case "linked-plan":
				os.Remove(path)
				os.Symlink(path+".lock", path)
			case "linked-receipt":
				if err := os.Symlink(path, filepath.Join(path+".receipts", "00000000000000000002-"+strings.Repeat("a", 64)+".receipt.json")); err != nil {
					t.Fatal(err)
				}
			case "linked-parent":
				sibling := filepath.Join(filepath.Dir(state), "alias")
				os.Symlink(state, sibling)
				state = sibling
				configured = filepath.Join(state, "setup", "plan.json")
			case "large-plan":
				if err := os.WriteFile(path, make([]byte, (1<<20)+1), 0600); err != nil {
					t.Fatal(err)
				}
			case "many-receipts":
				for i := 0; i < 260; i++ {
					name := fmt.Sprintf("%020d-%064x.receipt.json", i+2, i+1)
					if err := os.WriteFile(filepath.Join(path+".receipts", name), []byte("x"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			case "wrong-path":
				configured = filepath.Join(state, "setup", "other.json")
			case "wrong-plan":
				expected, _ = setup.NewPlan(setup.ProfileLocalSingleNode, "tenant-other", "repository-one", "operator", time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
			case "staging":
				// Valid protected writer-recoverable staging is refused by bootstrap policy.
				if err := os.Link(path, path+".next"); err != nil {
					t.Fatal(err)
				}
				inspected, err := setup.InspectStateFile(context.Background(), path)
				if err != nil || inspected.Identity() != plan.Identity() {
					t.Fatalf("valid staging inspected: %v", err)
				}
			case "missing-plan":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "missing-lock":
				if err := os.Remove(path + ".lock"); err != nil {
					t.Fatal(err)
				}
			case "missing-ledger":
				if err := os.Remove(path + ".receipts"); err != nil {
					t.Fatal(err)
				}
			case "linked-setup":
				if err := os.Rename(filepath.Dir(path), filepath.Join(state, "saved")); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("saved", filepath.Dir(path)); err != nil {
					t.Fatal(err)
				}
			case "linked-ledger":
				if err := os.Rename(path+".receipts", path+".saved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink("plan.json.saved", path+".receipts"); err != nil {
					t.Fatal(err)
				}
			case "receipt-mode", "receipt-large", "receipt-directory":
				next, _ := writeSnapshotReceipt(t, path, plan)
				_ = next
				items, err := os.ReadDir(path + ".receipts")
				if err != nil || len(items) != 1 {
					t.Fatalf("receipt fixture: %v", err)
				}
				receiptPath := filepath.Join(path+".receipts", items[0].Name())
				if shape == "receipt-mode" {
					err = os.Chmod(receiptPath, 0644)
				}
				if shape == "receipt-large" {
					err = os.Truncate(receiptPath, (1<<20)+1)
				}
				if shape == "receipt-directory" {
					err = os.Remove(receiptPath)
					if err == nil {
						err = os.Mkdir(receiptPath, 0700)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
			case "linked-missing-ancestor":
				sibling := filepath.Join(filepath.Dir(state), "alias")
				if err := os.Symlink(state, sibling); err != nil {
					t.Fatal(err)
				}
				state = filepath.Join(sibling, "new", "child")
				configured = filepath.Join(state, "setup", "plan.json")
			case "invalid-expected":
				expected = setup.Plan{}
			}
			ctx := context.Background()
			if shape == "canceled-context" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			if shape == "nil-context" {
				ctx = nil
			}
			assertSnapshotNoWrite(t, filepath.Dir(filepath.Dir(path)), func() {
				snap, err := inspectLocalSourceOwnerSnapshot(ctx, state, configured, &expected)
				if snap != nil {
					snap.Close()
				}
				if err == nil {
					t.Fatalf("%s classified fresh", shape)
				}
			})
			if _, statErr := os.Lstat(filepath.Join(state, "artifacts")); shape != "artifact-sibling" && !errors.Is(statErr, os.ErrNotExist) {
				t.Fatalf("constructor reached: %v", statErr)
			} else if shape == "artifact-sibling" && statErr != nil {
				t.Fatalf("legacy artifact sibling was changed: %v", statErr)
			}
		})
	}
}

// These direct checks are deterministic mutations after observation, not a race test.
func TestLocalSourceOwnerSnapshotRecheckRootMode(t *testing.T) {
	state, path, plan := snapshotFixture(t)
	writeSnapshotSetup(t, path, plan)
	snap, err := inspectLocalSourceOwnerSnapshot(context.Background(), state, path, &plan)
	if err != nil {
		t.Fatal(err)
	}
	defer snap.Close()
	if err := os.Chmod(state, 0755); err != nil {
		t.Fatal(err)
	}
	if err := recheckOwnerEntries(snap); err == nil {
		t.Fatal("root mode changed without refusal")
	}
}

func TestLocalSourceOwnerSnapshotReceiptStaging(t *testing.T) {
	state, path, plan := snapshotFixture(t)
	writeSnapshotSetup(t, path, plan)
	next, _ := writeSnapshotReceipt(t, path, plan)
	entries, err := os.ReadDir(path + ".receipts")
	if err != nil || len(entries) != 1 {
		t.Fatal(err)
	}
	receipt := filepath.Join(path+".receipts", entries[0].Name())
	if err := os.Link(receipt, receipt+".next"); err != nil {
		t.Fatal(err)
	}
	inspected, err := setup.InspectStateFile(context.Background(), path)
	if err != nil || inspected.Identity() != next.Identity() {
		t.Fatalf("valid staged ledger inspection: %v", err)
	}
	assertSnapshotNoWrite(t, filepath.Dir(state), func() {
		snap, err := inspectLocalSourceOwnerSnapshot(context.Background(), state, path, &next)
		if err != nil {
			t.Fatal(err)
		}
		defer snap.Close()
		if snap.Kind != localSourceOwnerSetupOnly {
			t.Fatalf("kind=%v", snap.Kind)
		}
		if err := recheckOwnerEntries(snap); err != nil {
			t.Fatal(err)
		}
	})
}

func TestLocalSourceOwnerSnapshotRecheckMissing(t *testing.T) {
	state, path, plan := snapshotFixture(t)
	snap, err := inspectLocalSourceOwnerSnapshot(context.Background(), state, path, &plan)
	if err != nil || snap.Kind != localSourceOwnerMissing {
		t.Fatalf("missing snapshot: %v", err)
	}
	if err := recheckOwnerEntries(snap); err == nil {
		t.Fatal("missing root has no inode to recheck")
	}
}

func TestLocalSourceOwnerSnapshotRecheckChanges(t *testing.T) {
	for _, change := range []string{"empty", "missing", "nil-roots", "nil-receipts", "root-identity", "replacement", "removal", "insertion", "root-mode", "same-size-bytes"} {
		t.Run(change, func(t *testing.T) {
			state, path, plan := snapshotFixture(t)
			if change == "empty" {
				if err := os.Mkdir(state, 0700); err != nil {
					t.Fatal(err)
				}
			} else {
				writeSnapshotSetup(t, path, plan)
			}
			snap, err := inspectLocalSourceOwnerSnapshot(context.Background(), state, path, &plan)
			if err != nil {
				t.Fatal(err)
			}
			defer snap.Close()
			if change == "empty" {
				if err := recheckOwnerEntries(snap); err != nil {
					t.Fatal(err)
				}
				return
			}
			if change == "missing" {
				snap.Kind = localSourceOwnerMissing
			}
			if change == "nil-roots" {
				snap.SetupRoot.Close()
				snap.SetupRoot = nil
			}
			if change == "nil-receipts" {
				snap.ReceiptRoot.Close()
				snap.ReceiptRoot = nil
			}
			if change == "root-identity" {
				other := filepath.Join(filepath.Dir(state), "other")
				if err := os.Mkdir(other, 0700); err != nil {
					t.Fatal(err)
				}
				info, err := os.Lstat(other)
				if err != nil {
					t.Fatal(err)
				}
				snap.Entries["."] = info
			}
			if change == "replacement" {
				// Move the original outside the state root so the setup directory
				// still has exactly three members. Only inode replacement can fail.
				old := filepath.Join(filepath.Dir(state), "old-plan.json")
				if err := os.Rename(path, old); err != nil {
					t.Fatal(err)
				}
				data, err := os.ReadFile(old)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if change == "removal" {
				if err := os.Remove(path + ".lock"); err != nil {
					t.Fatal(err)
				}
			}
			if change == "insertion" {
				if err := os.WriteFile(filepath.Join(state, "unexpected"), []byte("x"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if change == "root-mode" {
				if err := os.Chmod(state, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if change == "same-size-bytes" {
				file, err := os.OpenFile(path, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = file.WriteAt([]byte("X"), 0)
				if e := file.Close(); err == nil {
					err = e
				}
				if err != nil {
					t.Fatal(err)
				}
				// Metadata-only recheck cannot detect this. Under-lock setup reread is required.
				if err := recheckOwnerEntries(snap); err != nil {
					t.Fatalf("same-size in-place mutation changed metadata: %v", err)
				}
				if _, err := setup.InspectStateFile(context.Background(), path); err == nil {
					t.Fatal("independent setup inspection accepted changed bytes")
				}
				return
			}
			if err := recheckOwnerEntries(snap); err == nil {
				t.Fatalf("%s was accepted", change)
			}
		})
	}
}

// Test the size guard directly: an oversized plan is also invalid to the
// public setup decoder, so a daemon-level refusal alone would be a weak oracle.
func TestLocalSourceOwnerSnapshotFileSizeGuard(t *testing.T) {
	base := t.TempDir()
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	const limit = 1 << 20
	for _, fixture := range []struct {
		name      string
		size      int
		wantError bool
	}{{"at-limit", limit, false}, {"over-limit", limit + 1, true}} {
		if err := os.WriteFile(filepath.Join(base, fixture.name), make([]byte, fixture.size), 0600); err != nil {
			t.Fatal(err)
		}
		err := ownerPrivateFile(root, fixture.name, limit, make(map[string]os.FileInfo), fixture.name)
		if (err != nil) != fixture.wantError {
			t.Fatalf("%s size guard: %v", fixture.name, err)
		}
	}
}
