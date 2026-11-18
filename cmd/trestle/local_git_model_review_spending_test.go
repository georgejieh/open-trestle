package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/spending"
)

// The reviews below use the offline remote fixture: an Ollama Cloud setup at
// $1 input and $2 output per million tokens, whose fake provider reports 120
// input and 80 output tokens per request, so a review settles at 2 x 280 =
// 560 micro-USD. Nothing here contacts a provider.

var spendingTestNow = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

const spendingTestVariable = "OPEN_TRESTLE_PROVIDER_REMOTE_TEST"

// spendingTestStore gives the test its own usage folder and a fixed clock.
func spendingTestStore(t *testing.T) *spending.Store {
	t.Helper()
	state := t.TempDir()
	t.Setenv("XDG_STATE_HOME", state)
	previous := spendingNow
	spendingNow = func() time.Time { return spendingTestNow }
	t.Cleanup(func() { spendingNow = previous })
	store, err := spending.NewStore(filepath.Join(state, "open-trestle", "usage"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func spendingTestScope(t *testing.T) spending.Scope {
	t.Helper()
	scope, err := spending.NewScope("ollama-cloud", spendingTestVariable)
	if err != nil {
		t.Fatal(err)
	}
	return scope
}

func spendingTestLimit(t *testing.T, store *spending.Store, amount uint64, alerts []int) {
	t.Helper()
	limit, err := spending.NewLimit(spendingTestScope(t), spending.PeriodMonth, amount, alerts, spendingTestNow.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetLimit(t.Context(), limit); err != nil {
		t.Fatal(err)
	}
}

// spendingReviewSetup saves a ready Ollama Cloud setup and returns its review
// command with the given format.
func spendingReviewSetup(t *testing.T, format string) ([]string, *remoteModelTransport) {
	t.Helper()
	remoteScannerInstalled(t)
	t.Setenv(spendingTestVariable, remoteTestKey)
	bootstrap, _ := remoteBootstrapArgs(t, "ollama-cloud")
	ready, _ := remoteBootstrapInvoke(t, bootstrap, 0)
	transport := &remoteModelTransport{t: t, target: "https://ollama.com/v1/chat/completions", models: map[string]string{"gemma4:31b": "", "qwen3.5:397b": ""}}
	remoteModelClient(t, transport)
	return replaceLocalGitChangeValue(ready.ReviewCommand[1:], "--format", format), transport
}

// spyCredentialLookups records every credential variable the review reads.
func spyCredentialLookups(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var names []string
	previous := localReviewCredentialLookup
	localReviewCredentialLookup = func(name string) string {
		mu.Lock()
		names = append(names, name)
		mu.Unlock()
		return previous(name)
	}
	t.Cleanup(func() { localReviewCredentialLookup = previous })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(names)
	}
}

func spendingMonthEntries(t *testing.T, store *spending.Store) []spending.Entry {
	t.Helper()
	start, end := spending.PeriodMonth.Bounds(spendingTestNow)
	entries, err := store.Entries(start, end)
	if err != nil {
		t.Fatal(err)
	}
	return entries
}

func spendingSeed(t *testing.T, store *spending.Store, cost uint64) {
	t.Helper()
	entry := spending.Entry{RecordedAt: spendingTestNow.Add(-24 * time.Hour), ReviewRunID: "local-earlier", RuntimePolicyIdentity: strings.Repeat("ab", 32), Scopes: []spending.Scope{spendingTestScope(t)}, Models: []string{"gemma4:31b"}, RequestsSent: 2, UsageKnown: true, CostMicroUSD: cost}
	if err := store.Append(t.Context(), entry); err != nil {
		t.Fatal(err)
	}
}

func TestModelReviewRecordsItsSettledSpendInTheUsageLedger(t *testing.T) {
	store := spendingTestStore(t)
	args, transport := spendingReviewSetup(t, "json")
	lookups := spyCredentialLookups(t)
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	var receipt map[string]any
	if code != 4 || json.Unmarshal(stdout.Bytes(), &receipt) != nil || receipt["status"] != "findings" || receipt["usage_known"] != true || receipt["actual_cost_micro_usd"] != float64(560) {
		t.Fatalf("review exit=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	if len(transport.requests) != 2 || !slices.Contains(lookups(), spendingTestVariable) {
		t.Fatalf("the review did not send its two requests with the key: %v %v", transport.requests, lookups())
	}
	entries := spendingMonthEntries(t, store)
	if len(entries) != 1 {
		t.Fatalf("entries=%d, want one", len(entries))
	}
	entry := entries[0]
	if entry.ReviewRunID != receipt["review_run_id"] || entry.RuntimePolicyIdentity != receipt["runtime_policy_identity"] || !slices.Equal(entry.Scopes, []spending.Scope{spendingTestScope(t)}) || !slices.Equal(entry.Models, []string{"gemma4:31b", "qwen3.5:397b"}) || entry.RequestsSent != 2 || !entry.UsageKnown || entry.CostMicroUSD != 560 || entry.CostKind() != spending.CostSettledUsage {
		t.Fatalf("entry=%+v", entry)
	}
	ledger, err := os.ReadFile(filepath.Join(store.Directory(), "ledger-2026-11.jsonl"))
	if err != nil || bytes.Contains(ledger, []byte(remoteTestKey)) || bytes.Contains(ledger, []byte("Zero-valued caller")) || bytes.Contains(ledger, []byte("Changed")) {
		t.Fatalf("the ledger holds a key, source or reply: %v %s", err, ledger)
	}
	// Without a limit nothing about spending is printed, and JSON stays one
	// document on standard output.
	if strings.Contains(stderr.String(), "Spending") {
		t.Fatalf("a review without a limit printed spending lines: %s", stderr.String())
	}
}

func TestModelReviewRefusesAtTheSpendingLimitBeforeAnyCredentialOrRequest(t *testing.T) {
	store := spendingTestStore(t)
	args, transport := spendingReviewSetup(t, "json")
	spendingTestLimit(t, store, 10_000, spending.DefaultAlertPercents)
	spendingSeed(t, store, 10_000)
	lookups := spyCredentialLookups(t)
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	var receipt map[string]any
	if code != 4 || json.Unmarshal(stdout.Bytes(), &receipt) != nil {
		t.Fatalf("review exit=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	for key, want := range map[string]any{"schema_version": float64(6), "status": "refused", "ci_disposition": "blocked", "run_status": "not_opened", "failure": "policy", "failure_detail": "spending_limit_reached"} {
		if receipt[key] != want {
			t.Fatalf("%s=%v, want %v: %s", key, receipt[key], want, stdout.String())
		}
	}
	if len(transport.requests) != 0 || len(lookups()) != 0 {
		t.Fatalf("a refused review sent %v or read credentials %v", transport.requests, lookups())
	}
	want := "Spending limit reached: $0.01 of your $0.01 monthly limit for OPEN_TRESTLE_PROVIDER_REMOTE_TEST (100%) is recorded this month, so this review was not started and nothing was sent. Run trestle usage to see it; raise or clear the limit with trestle usage set or trestle usage clear, or wait until the month ends.\n" + spending.Note + "\n"
	if withoutIndexNotice(stderr.String()) != want {
		t.Fatalf("stderr:\n%s\nwant:\n%s", stderr.String(), want)
	}
	if entries := spendingMonthEntries(t, store); len(entries) != 1 {
		t.Fatalf("a refused review was recorded: %d entries", len(entries))
	}
	// The text form names the detail and its hint.
	text := replaceLocalGitChangeValue(args, "--format", "text")
	stdout.Reset()
	stderr.Reset()
	if code := run(text, &stdout, &stderr); code != 4 || !strings.Contains(stdout.String(), "failure: policy: spending_limit_reached\nhint: the spend recorded for an API key this review uses has reached its spending limit") {
		t.Fatalf("text exit=%d out=%s", code, stdout.String())
	}
	if !strings.Contains(stderr.String(), "Spending: $0.01 of your $0.01 monthly limit for OPEN_TRESTLE_PROVIDER_REMOTE_TEST this month (100%), alerts at 80% and 100%.") {
		t.Fatalf("text output did not show the limit's state: %s", stderr.String())
	}
}

func TestModelReviewWarnsBeforeAndAlertsAfterCrossingAnAlertPercentage(t *testing.T) {
	store := spendingTestStore(t)
	args, transport := spendingReviewSetup(t, "text")
	// $0.01 a month, alerting at 5% (500 micro-USD) and 100%. The review's
	// worst case, two requests at the $1.00 per-request bound, could pass it.
	spendingTestLimit(t, store, 10_000, []int{5, 100})
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	if code != 4 || !strings.Contains(stdout.String(), "status: findings") || len(transport.requests) != 2 {
		t.Fatalf("review exit=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	want := strings.Join([]string{
		"Spending warning: this review may cost up to $2.00, which could take the $0.00 recorded this month past your $0.01 monthly limit for OPEN_TRESTLE_PROVIDER_REMOTE_TEST; it runs anyway.",
		spending.Note,
		"Spending alert: $0.01 of your $0.01 monthly limit for OPEN_TRESTLE_PROVIDER_REMOTE_TEST (5%)",
		spending.Note,
		"Spending: $0.01 of your $0.01 monthly limit for OPEN_TRESTLE_PROVIDER_REMOTE_TEST this month (5%), alerts at 5% and 100%.",
		spending.Note,
	}, "\n") + "\n"
	if withoutIndexNotice(stderr.String()) != want {
		t.Fatalf("stderr:\n%s\nwant:\n%s", stderr.String(), want)
	}
	// A second review starts (560 is under the limit) and crosses no new
	// percentage, so it prints the warning and the state but no alert.
	// Amounts are rounded up to the cent, so 1120 micro-USD reads $0.01.
	stdout.Reset()
	stderr.Reset()
	if code := run(args, &stdout, &stderr); code != 4 || strings.Contains(stderr.String(), "Spending alert") || !strings.Contains(stderr.String(), "Spending: $0.01 of your $0.01 monthly limit for OPEN_TRESTLE_PROVIDER_REMOTE_TEST this month (11%)") {
		t.Fatalf("second review exit=%d err=%s", code, stderr.String())
	}
	if entries := spendingMonthEntries(t, store); len(entries) != 2 {
		t.Fatalf("entries=%d, want two", len(entries))
	}
}

func TestModelReviewCountsUnknownUsageAtTheReservation(t *testing.T) {
	store := spendingTestStore(t)
	args, transport := spendingReviewSetup(t, "json")
	transport.verificationStatus = http.StatusInternalServerError
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	var receipt map[string]any
	if code != 1 || json.Unmarshal(stdout.Bytes(), &receipt) != nil || receipt["usage_known"] != false || len(transport.requests) != 2 {
		t.Fatalf("review exit=%d out=%s err=%s requests=%v", code, stdout.String(), stderr.String(), transport.requests)
	}
	entries := spendingMonthEntries(t, store)
	if len(entries) != 1 {
		t.Fatalf("entries=%d, want one", len(entries))
	}
	entry := entries[0]
	// The generation settled at 280; the verification reported nothing, so it
	// counts at its reservation, which the $1.00 per-request bound caps.
	if entry.UsageKnown || entry.CostKind() != spending.CostReservationUpperBound || entry.RequestsSent != 2 || entry.CostMicroUSD <= 280 || entry.CostMicroUSD > 280+1_000_000 {
		t.Fatalf("entry=%+v", entry)
	}
}

func TestModelReviewSetStopsAtTheSpendingLimit(t *testing.T) {
	store := spendingTestStore(t)
	args, transport := spendingReviewSetup(t, "json")
	spendingTestLimit(t, store, 10_000, spending.DefaultAlertPercents)
	spendingSeed(t, store, 12_000)
	profile := review.ContextSpecialistProfileIDs()[0]
	var stdout, stderr bytes.Buffer
	code := run(append(slices.Clone(args), "--specialists", profile), &stdout, &stderr)
	var set struct {
		Members []struct {
			Member, Status, FailureDetail, NotLaunchedReason string
			Launched                                         bool
		} `json:"members"`
	}
	decoder := json.NewDecoder(bytes.NewReader(stdout.Bytes()))
	if code != 4 || decoder.Decode(&set) != nil || len(set.Members) != 2 {
		t.Fatalf("set exit=%d out=%s err=%s", code, stdout.String(), stderr.String())
	}
	var raw struct {
		Members []map[string]any `json:"members"`
	}
	_ = json.Unmarshal(stdout.Bytes(), &raw)
	if raw.Members[0]["failure_detail"] != "spending_limit_reached" || raw.Members[0]["status"] != "refused" || raw.Members[1]["launched"] != false || len(transport.requests) != 0 {
		t.Fatalf("the set did not stop at the limit: %v requests=%v", raw.Members, transport.requests)
	}
	if !strings.Contains(stderr.String(), "Spending limit reached: $0.02 of your $0.01 monthly limit") {
		t.Fatalf("stderr: %s", stderr.String())
	}
}

func TestModelReviewOnThisMachineRecordsNothing(t *testing.T) {
	store := spendingTestStore(t)
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	localModelExecute(t, f, f.args, 4)
	if _, err := os.Lstat(store.Directory()); !os.IsNotExist(err) {
		t.Fatalf("a review on a local server touched the usage folder: %v", err)
	}
}

func TestModelReviewRunsWhenTheLedgerCannotBeRead(t *testing.T) {
	store := spendingTestStore(t)
	scope := spendingTestScope(t)
	// A ledger read failure, such as an unprotected folder, never blocks a
	// review; it is reported and the provider's limit stays the guarantee.
	args, transport := spendingReviewSetup(t, "json")
	spendingTestLimit(t, store, 10_000, spending.DefaultAlertPercents)
	if err := os.Chmod(store.Directory(), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(store.Directory(), 0o700) })
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 4 || len(transport.requests) != 2 {
		t.Fatalf("an unreadable ledger blocked the review: exit=%d err=%s", code, stderr.String())
	}
	for _, want := range []string{"Spending limit not checked for " + scope.CredentialEnvironment + ": ", "The review runs; your provider's own limit still applies.", "This review's spend (up to $0.01) was not recorded in the usage ledger: ", spending.Note} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr lacks %q:\n%s", want, stderr.String())
		}
	}
}
