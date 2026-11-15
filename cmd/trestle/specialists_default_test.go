package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/spending"
)

// savedReviewCommand reads the review command a setup saved.
func savedReviewCommand(t *testing.T, dir string) []string {
	t.Helper()
	var saved struct {
		ReviewCommand []string `json:"review_command"`
	}
	if err := json.Unmarshal([]byte(stringMustRead(t, filepath.Join(dir, "bootstrap.json"))), &saved); err != nil {
		t.Fatal(err)
	}
	return saved.ReviewCommand
}

func setReceiptOf(t *testing.T, stdout string) localModelSetReceipt {
	t.Helper()
	var receipt localModelSetReceipt
	if err := json.Unmarshal([]byte(stdout), &receipt); err != nil || receipt.Contract != "open-trestle/local-git-model-review-set" {
		t.Fatalf("not a review set: %v\n%s", err, stdout)
	}
	return receipt
}

// A new setup saves --specialists auto, and trestle review runs the general
// review and the specialists it selects from the change.
func TestInitSavesSpecialistsAutoAndReviewRunsThem(t *testing.T) {
	checkout := latestChangeCheckout(t)
	dir := latestChangeSetupWith(t, checkout)
	command := savedReviewCommand(t, dir)
	if index := slices.Index(command, "--specialists"); index < 0 || command[index+1] != "auto" {
		t.Fatalf("a new setup did not save --specialists auto: %v", command)
	}
	transport := latestFixtureTransport(t)
	code, stdout, stderr := runReviewCommand(t, checkout, "--format", "json")
	if code != 4 {
		t.Fatalf("trestle review exit=%d\nstderr:\n%s", code, stderr)
	}
	receipt := setReceiptOf(t, stdout)
	if receipt.Selection.Mode != "auto" || len(receipt.Members) < 2 || receipt.Members[0].Member != "general" || len(transport.requests) != 2*receipt.Summary.MembersRun {
		t.Fatalf("auto specialists did not run: mode=%s members=%d requests=%d", receipt.Selection.Mode, len(receipt.Members), len(transport.requests))
	}
	if !initHas(stderr, "Review finished:") {
		t.Fatalf("the review outcome line is missing:\n%s", stderr)
	}
}

// setup bootstrap init (the local form) saves --specialists auto in the
// review command when the flag is absent, and refuses another value.
func TestLocalBootstrapSavesSpecialistsAutoByDefault(t *testing.T) {
	args, _, _, _ := bootstrapFixture(t)
	index := slices.Index(args, "--specialists")
	invalid := slices.Clone(args)
	invalid[index+1] = "bug_hunter"
	var out, errOut bytes.Buffer
	if code := runSetupWithClock(append([]string{"bootstrap"}, invalid...), &out, &errOut, fixedSetupClock{setupTimeCLI()}); code != 2 {
		t.Fatalf("--specialists bug_hunter was accepted by setup: exit %d", code)
	}
	defaulted := slices.Delete(slices.Clone(args), index, index+2)
	result := bootstrapInvoke(t, defaulted, 3)
	if at := slices.Index(result.EphemeralReviewCommand, "--specialists"); at < 0 || result.EphemeralReviewCommand[at+1] != "auto" {
		t.Fatalf("the local bootstrap did not save --specialists auto: %v", result.EphemeralReviewCommand)
	}
}

// trestle init's first review, under the default, runs the specialist set and
// shows its walkthrough before the confirmed findings.
func TestInitFirstReviewRunsSpecialistsAndShowsTheWalkthrough(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	transport := &remoteModelTransport{t: t, target: "https://ollama.com/v1/chat/completions", models: map[string]string{"gemma4:31b": "", "qwen3.5:397b": ""}}
	remoteModelClient(t, transport)
	checkout := latestChangeCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	args := []string{"--no-input", "--run-review", "--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "--declare-remote-route"}
	setup := runInitScriptAsIs(t, checkout, args)
	output := setup.stdout + setup.stderr
	if setup.code != initExitDone || len(transport.requests) <= 2 || !initHas(output, "Specialists") || !initHas(output, "Review finished") {
		t.Fatalf("first review: exit=%d requests=%d\n%s", setup.code, len(transport.requests), output)
	}
	walkthrough, findings := strings.Index(output, "walkthrough:\n"), strings.Index(output, "confirmed findings (ranked):")
	if walkthrough < 0 || findings < walkthrough || !strings.Contains(output, "specialist review set: status=findings") {
		t.Fatalf("the first review did not show the set's walkthrough before its findings:\n%s", output)
	}
}

// --specialists none at setup saves the single general review, the shape
// every setup saved before specialists became the default; trestle review
// keeps running it.
func TestInitSpecialistsNoneSavesTheSingleReview(t *testing.T) {
	checkout := latestChangeCheckout(t)
	dir := latestChangeSetupWith(t, checkout, "--specialists", "none")
	if command := savedReviewCommand(t, dir); slices.Contains(command, "--specialists") {
		t.Fatalf("--specialists none still saved a specialist set: %v", command)
	}
	transport := latestFixtureTransport(t)
	code, stdout, _ := runReviewCommand(t, checkout)
	if code != 4 || len(transport.requests) != 2 || !strings.HasPrefix(stdout, "status: findings\n") {
		t.Fatalf("single review: exit=%d requests=%d\n%s", code, len(transport.requests), stdout)
	}
}

// trestle review --specialists none overrides a saved --specialists auto for
// one run, and --profile replaces the saved set with one specialist.
func TestReviewOverridesSavedSpecialists(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetupWith(t, checkout)
	transport := latestFixtureTransport(t)
	if code, stdout, stderr := runReviewCommand(t, checkout, "--specialists", "none"); code != 4 || len(transport.requests) != 2 || !strings.HasPrefix(stdout, "status: findings\n") {
		t.Fatalf("--specialists none: exit=%d requests=%d\n%s\n%s", code, len(transport.requests), stdout, stderr)
	}
	if code, stdout, stderr := runReviewCommand(t, checkout, "--profile", "bug_hunter"); code != 4 || len(transport.requests) != 4 || !strings.Contains(stdout, "specialist profile: bug_hunter\n") {
		t.Fatalf("--profile: exit=%d requests=%d\n%s\n%s", code, len(transport.requests), stdout, stderr)
	}
}

// concurrencyTransport measures how many specialist generation requests are
// in flight at once. Each waits briefly for a second one, so concurrent
// members overlap and sequential ones do not.
type concurrencyTransport struct {
	inner    *remoteModelTransport
	mu       sync.Mutex
	inFlight int
	most     int
	arrived  chan struct{}
}

func (c *concurrencyTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	request.Body = io.NopCloser(bytes.NewReader(body))
	if !bytes.Contains(body, []byte(`\"specialist\":{`)) {
		return c.inner.RoundTrip(request)
	}
	c.mu.Lock()
	c.inFlight++
	c.most = max(c.most, c.inFlight)
	c.mu.Unlock()
	select {
	case c.arrived <- struct{}{}:
	case <-c.arrived:
	case <-time.After(3 * time.Second):
	}
	defer func() {
		c.mu.Lock()
		c.inFlight--
		c.mu.Unlock()
	}()
	return c.inner.RoundTrip(request)
}

// On remote routes specialist members run concurrently, at most three at a
// time, and the set still lists them in selection order.
func TestRemoteSpecialistMembersRunConcurrently(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetupWith(t, checkout)
	inner := latestFixtureTransport(t)
	measured := &concurrencyTransport{inner: inner, arrived: make(chan struct{})}
	localReviewModelHTTPClient = &http.Client{Transport: measured, Timeout: time.Minute}
	code, stdout, stderr := runReviewCommand(t, checkout, "--specialists", "bug_hunter,backend", "--format", "json")
	if code != 4 {
		t.Fatalf("exit=%d\n%s", code, stderr)
	}
	receipt := setReceiptOf(t, stdout)
	var bounds struct {
		Bounds struct {
			Concurrency      int    `json:"specialist_concurrency"`
			SequentialReason string `json:"sequential_reason"`
		} `json:"bounds"`
		Limitations []string `json:"limitations"`
	}
	if err := json.Unmarshal([]byte(stdout), &bounds); err != nil {
		t.Fatal(err)
	}
	members := []string{}
	for _, member := range receipt.Members {
		members = append(members, member.Member)
	}
	if strings.Join(members, ",") != "general,bug_hunter,backend" || bounds.Bounds.Concurrency != 2 || bounds.Bounds.SequentialReason != "" || !slices.Contains(bounds.Limitations, "specialists_concurrent_bounded") {
		t.Fatalf("members=%v bounds=%+v limitations=%v", members, bounds.Bounds, bounds.Limitations)
	}
	if measured.most != 2 || receipt.Bounds.MaxModelWallTimeMillis != 2*receipt.Bounds.MemberTimeoutMillis {
		t.Fatalf("specialist generations in flight at once = %d, wall bound %d", measured.most, receipt.Bounds.MaxModelWallTimeMillis)
	}
}

// Members on a model on this machine run one by one, and say why.
func TestLocalSpecialistMembersRunSequentially(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{chatCompletions: true})
	_, stdout := runLocalModelSet(t, f, []string{"--specialists", "bug_hunter,backend"}, 4)
	if !strings.Contains(stdout, `"specialist_concurrency":1,"sequential_reason":"local_model_route"`) || !strings.Contains(stdout, `"sequential_members_no_parallelism"`) {
		t.Fatalf("local members did not run one by one with a reason:\n%s", stdout)
	}
}

// The spending warning counts every review a set may run, and a set whose
// concurrent wave could pass a limit runs its members one by one.
func TestSpendingWarningCountsEveryMember(t *testing.T) {
	store := spendingTestStore(t)
	args, transport := spendingReviewSetup(t, "json")
	args = append(args, "--specialists", "bug_hunter,backend")
	spendingTestLimit(t, store, 10_000, []int{50, 100})
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 4 || len(transport.requests) != 6 {
		t.Fatalf("set exit=%d requests=%d\n%s", code, len(transport.requests), stderr.String())
	}
	for _, want := range []string{
		"Spending warning: this review may cost up to $6.00, which could take the $0.00 recorded this month past your $0.01 monthly limit for OPEN_TRESTLE_PROVIDER_REMOTE_TEST; it runs anyway.\n",
		"That counts every review this command may run: the general review and up to 2 specialist reviews, each up to $2.00.\n",
		spending.Note,
	} {
		if !strings.Contains(stderr.String(), want) {
			t.Fatalf("stderr lacks %q:\n%s", want, stderr.String())
		}
	}
	if strings.Count(stderr.String(), "Spending warning:") != 1 {
		t.Fatalf("the set warned more than once:\n%s", stderr.String())
	}
	if !strings.Contains(stdout.String(), `"specialist_concurrency":1,"sequential_reason":"spending_limit_could_be_passed"`) {
		t.Fatalf("a set near its limit ran members concurrently:\n%s", stdout.String())
	}
}

// The first review's box never hides every finding: a review whose confirmed
// findings are all low severity lists them.
func TestInitFirstReviewListsLowSeverityFindings(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	transport := &remoteModelTransport{t: t, target: "https://ollama.com/v1/chat/completions", models: map[string]string{"gemma4:31b": "", "qwen3.5:397b": ""}, verificationSeverity: "low"}
	remoteModelClient(t, transport)
	checkout := latestChangeCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	args := []string{"--no-input", "--run-review", "--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "--declare-remote-route"}
	setup := runInitScriptAsIs(t, checkout, args)
	output := setup.stdout + setup.stderr
	if setup.code != initExitDone || !initHas(output, "Review finished: 1 confirmed finding") {
		t.Fatalf("first review: exit=%d\n%s", setup.code, output)
	}
	if !initHas(output, "│ confirmed findings (ranked): 1") || !initHas(output, "│ finding: information Zero-valued caller now panics") || initHas(output, "lower-severity finding not shown") {
		t.Fatalf("the first review box hid the only (low-severity) finding:\n%s", output)
	}
	// The review is advisory, and the closing line says so.
	if !initHas(strings.Join(strings.Fields(output), " "), "None of them blocks CI: each is low severity or on lines the change did not touch.") {
		t.Fatalf("the first review did not say the low-severity review is advisory:\n%s", output)
	}
}

// trestle review says when a finished review is advisory.
func TestLatestReviewSaysWhenTheReviewIsAdvisory(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetupWith(t, checkout)
	transport := latestFixtureTransport(t)
	transport.verificationSeverity = "low"
	code, stdout, stderr := runReviewCommand(t, checkout, "--format", "json")
	if code != 3 || setReceiptOf(t, stdout).CI != "inconclusive" {
		t.Fatalf("an advisory trestle review exit=%d\nstderr:\n%s", code, stderr)
	}
	if !initHas(strings.Join(strings.Fields(stderr), " "), "None of them blocks CI") {
		t.Fatalf("trestle review did not say the review is advisory:\n%s", stderr)
	}
}
