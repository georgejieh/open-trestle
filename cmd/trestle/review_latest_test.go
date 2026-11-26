package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/spending"
)

// Every repository below is a temporary Git checkout made with git itself;
// every model request goes to the offline remote fixture, and every key is
// the synthetic canary remoteTestKey.

// latestChangeCheckout is a real history: main holds the base files, and the
// checked-out branch review changes a.go on top of it, the change the remote
// fixture expects.
func latestChangeCheckout(t *testing.T) string {
	t.Helper()
	checkout := t.TempDir()
	checkoutGit(t, checkout, "init", "-q", "-b", "main")
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(checkout, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.go", "package p\nfunc Changed(x int) int { if x == 0 { return 0 }; return 10 / x }\n// "+localModelSecret+"\n")
	write("caller.go", "package p\nfunc Consume() int { return Changed(0) }\n")
	checkoutGit(t, checkout, "add", "a.go", "caller.go")
	checkoutGit(t, checkout, "commit", "-q", "-m", "base")
	checkoutGit(t, checkout, "update-ref", "refs/heads/base", "HEAD")
	checkoutGit(t, checkout, "checkout", "-q", "-b", "review")
	write("a.go", "package p\nfunc Changed(x int) int { return 10 / x }\n// "+localModelSecret+"\n")
	checkoutGit(t, checkout, "commit", "-q", "-am", "change")
	return checkout
}

// latestChangeSetup saves a ready Ollama Cloud setup for the checkout in the
// folder trestle init proposes, under a private HOME, and returns the folder.
// latestChangeSetup saves the setup for the single general review, which
// these tests cover; latestChangeSetupWith keeps trestle init's default
// (specialists on) unless extra flags choose.
func latestChangeSetup(t *testing.T, checkout string) string {
	t.Helper()
	return latestChangeSetupWith(t, checkout, "--specialists", "none")
}

// latestChangeSetupWith is latestChangeSetup with extra trestle init flags.
func latestChangeSetupWith(t *testing.T, checkout string, extra ...string) string {
	t.Helper()
	keyStoreForTest(t)
	clearSessionKeys(t)
	spendingTestStore(t)
	remoteScannerInstalled(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	args := []string{"--no-input", "--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "--declare-remote-route"}
	setup := runInitScriptAsIs(t, checkout, append(args, extra...))
	if setup.code != initExitDone {
		t.Fatalf("setup: exit=%d\n%s\n%s", setup.code, setup.stdout, setup.stderr)
	}
	resolved, err := filepath.EvalSymlinks(checkout)
	if err != nil {
		t.Fatal(err)
	}
	dir := defaultSetupDirectory(resolved)
	if !setupExists(dir) {
		t.Fatalf("no setup in the default folder %s", dir)
	}
	return dir
}

func latestFixtureTransport(t *testing.T) *remoteModelTransport {
	t.Helper()
	transport := &remoteModelTransport{t: t, target: "https://ollama.com/v1/chat/completions", models: map[string]string{"gemma4:31b": "", "qwen3.5:397b": ""}}
	remoteModelClient(t, transport)
	return transport
}

func runReviewCommand(t *testing.T, checkout string, args ...string) (int, string, string) {
	t.Helper()
	t.Chdir(checkout)
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"review"}, args...), &stdout, &stderr)
	if strings.Contains(stdout.String()+stderr.String(), remoteTestKey) {
		t.Fatal("trestle review printed the key")
	}
	return code, stdout.String(), stderr.String()
}

func gitObjects(t *testing.T, checkout string) []string {
	t.Helper()
	names := []string{}
	_ = filepath.WalkDir(filepath.Join(checkout, ".git", "objects"), func(path string, entry os.DirEntry, err error) error {
		if err == nil && !entry.IsDir() {
			names = append(names, path)
		}
		return nil
	})
	sort.Strings(names)
	return names
}

// After setup, a new commit on the branch is reviewed by `trestle review`
// alone: HEAD against its merge base with main, never the pair saved at
// setup time, with the setup's routes, policy, labels and egress.
func TestReviewWithoutAPathReviewsTheLatestChange(t *testing.T) {
	fixture, err := filepath.Abs(filepath.Join("testdata", "local-review", "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	checkout := latestChangeCheckout(t)
	dir := latestChangeSetup(t, checkout)
	manifest := stringMustRead(t, filepath.Join(dir, "bootstrap.json"))
	savedHead := checkoutGit(t, checkout, "rev-parse", "HEAD")
	base := checkoutGit(t, checkout, "rev-parse", "main")
	if err := os.WriteFile(filepath.Join(checkout, "b.go"), []byte("package p\nfunc Later() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, checkout, "add", "b.go")
	checkoutGit(t, checkout, "commit", "-q", "-m", "later")
	head := checkoutGit(t, checkout, "rev-parse", "HEAD")
	transport := latestFixtureTransport(t)
	code, stdout, stderr := runReviewCommand(t, checkout)
	if code != 4 || len(transport.requests) != 2 || !strings.HasPrefix(stdout, "status: findings\n") {
		t.Fatalf("trestle review: exit=%d requests=%v\nstdout:\n%s\nstderr:\n%s", code, transport.requests, stdout, stderr)
	}
	for _, want := range []string{"Open Trestle · review the latest change", "Base: " + initShort(base) + " (merge base with main)", "Head: HEAD (" + initShort(head) + ")", "Changes: 2 commits", "A review sends the selected source to Ollama Cloud (https://ollama.com/v1).", "Review finished: 1 confirmed finding."} {
		if !initHas(stderr, want) {
			t.Fatalf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if initHas(stderr, "uncommitted") {
		t.Fatal("a clean checkout was said to have uncommitted changes")
	}
	review, ok := readLastReview(dir)
	if !ok || review.Head != head || review.Base != base || review.Status != "findings" || review.Findings != 1 {
		t.Fatalf("last review %+v %v; want head %s (the setup saved %s)", review, ok, head, savedHead)
	}
	if stringMustRead(t, filepath.Join(dir, "bootstrap.json")) != manifest {
		t.Fatal("trestle review changed the saved setup")
	}
	// Flags pass through: one JSON document on stdout, lines on stderr.
	code, stdout, _ = runReviewCommand(t, checkout, "--format", "json", "--timeout", "9m")
	var result map[string]any
	if code != 4 || json.Unmarshal([]byte(stdout), &result) != nil || result["status"] != "findings" {
		t.Fatalf("--format json: exit=%d %s", code, stdout)
	}
	// The fixture form keeps working, unchanged, inside a configured repository.
	if code, stdout, stderr := runReviewCommand(t, checkout, fixture); code != 0 || !strings.HasPrefix(stdout, "status: verified\n") || stderr != "" {
		t.Fatalf("trestle review <fixture>: exit=%d %s %s", code, stdout, stderr)
	}
}

// Uncommitted work is named, not included, and nothing is written into the
// repository.
func TestReviewSaysUncommittedChangesAreNotIncludedAndWritesNothing(t *testing.T) {
	checkout := latestChangeCheckout(t)
	latestChangeSetup(t, checkout)
	if err := os.WriteFile(filepath.Join(checkout, "caller.go"), []byte("package p\nfunc Consume() int { return Changed(1) }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := gitObjects(t, checkout)
	status := checkoutGit(t, checkout, "status", "--porcelain")
	latestFixtureTransport(t)
	code, _, stderr := runReviewCommand(t, checkout)
	if code != 4 || !initHas(stderr, "Note: you have uncommitted changes, and they are not included: only committed work is reviewed. To include them, commit them first.") {
		t.Fatalf("exit=%d\n%s", code, stderr)
	}
	if after := gitObjects(t, checkout); !slices.Equal(before, after) {
		t.Fatal("trestle review wrote objects into the repository")
	}
	if checkoutGit(t, checkout, "status", "--porcelain") != status {
		t.Fatal("trestle review changed the working tree")
	}
}

func TestReviewExplainsWhatIsMissingBeforeSendingAnything(t *testing.T) {
	t.Run("no setup", func(t *testing.T) {
		checkout := latestChangeCheckout(t)
		t.Setenv("HOME", t.TempDir())
		code, stdout, stderr := runReviewCommand(t, checkout)
		if code != 3 || stdout != "" || !strings.Contains(stderr, "no Open Trestle setup yet") || !strings.Contains(stderr, "Nothing was sent.\n  -> trestle init\n") {
			t.Fatalf("exit=%d\n%s", code, stderr)
		}
	})
	t.Run("not a repository", func(t *testing.T) {
		code, _, stderr := runReviewCommand(t, t.TempDir())
		if code != 2 || !strings.Contains(stderr, "not inside a Git checkout") || !strings.Contains(stderr, "trestle review <path>") {
			t.Fatalf("exit=%d\n%s", code, stderr)
		}
	})
	t.Run("nothing to review", func(t *testing.T) {
		checkout := latestChangeCheckout(t)
		latestChangeSetup(t, checkout)
		transport := latestFixtureTransport(t)
		checkoutGit(t, checkout, "checkout", "-q", "main")
		code, stdout, stderr := runReviewCommand(t, checkout)
		if code != 3 || stdout != "" || len(transport.requests) != 0 || !initHas(stderr, "Nothing to review: HEAD") || !initHas(stderr, "is already the merge base with main") {
			t.Fatalf("exit=%d requests=%v\n%s", code, transport.requests, stderr)
		}
	})
	t.Run("no key", func(t *testing.T) {
		checkout := latestChangeCheckout(t)
		latestChangeSetup(t, checkout)
		transport := latestFixtureTransport(t)
		t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "")
		code, stdout, stderr := runReviewCommand(t, checkout)
		if code != 3 || stdout != "" || len(transport.requests) != 0 || !initHas(stderr, "No API key for OPEN_TRESTLE_PROVIDER_REMOTE_TEST") || !strings.Contains(stderr, "    trestle keys set OPEN_TRESTLE_PROVIDER_REMOTE_TEST\n") {
			t.Fatalf("exit=%d requests=%v\n%s", code, transport.requests, stderr)
		}
	})
	t.Run("bad flags", func(t *testing.T) {
		checkout := latestChangeCheckout(t)
		latestChangeSetup(t, checkout)
		for _, args := range [][]string{{"--format", "xml"}, {"--format", "json", "--format", "text"}, {"--profile", "nonexistent_profile"}, {"--timeout", "2h"}, {"extra", "args"}} {
			code, stdout, _ := runReviewCommand(t, checkout, args...)
			if code != 2 || stdout != "" {
				t.Fatalf("%v: exit=%d %s", args, code, stdout)
			}
		}
	})
}

// Re-running trestle init offers the latest change first and reviews it;
// the pair saved at setup time is never offered or run.
func TestInitRerunOffersAndReviewsTheLatestChange(t *testing.T) {
	checkout := latestChangeCheckout(t)
	dir := latestChangeSetup(t, checkout)
	if err := os.WriteFile(filepath.Join(checkout, "b.go"), []byte("package p\nfunc Later() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, checkout, "add", "b.go")
	checkoutGit(t, checkout, "commit", "-q", "-m", "later")
	head := checkoutGit(t, checkout, "rev-parse", "HEAD")
	transport := latestFixtureTransport(t)
	again := runInitScript(t, checkout, nil, "1")
	if again.code != initExitDone || len(transport.requests) != 2 {
		t.Fatalf("rerun: exit=%d requests=%v\n%s\n%s", again.code, transport.requests, again.stdout, again.stderr)
	}
	initAssertOutput(t, again, "1) Review the latest change (sends it to Ollama Cloud)", "2) Re-run the setup checks", "3) Change a setting", "4) Quit without changes", "Review the latest change", "Head: HEAD ("+initShort(head)+")", "Review finished")
	if review, ok := readLastReview(dir); !ok || review.Head != head {
		t.Fatalf("init reviewed %+v, want head %s", review, head)
	}
	next := stringMustRead(t, filepath.Join(dir, "NEXT-STEPS.txt"))
	if !strings.Contains(next, "    trestle review\n") || strings.Contains(next, "--head") {
		t.Fatalf("NEXT-STEPS.txt offers a pinned pair:\n%s", next)
	}
}

// The default base is the merge base with the default branch as this
// repository has it or as origin has it, whichever is newer.
func TestLatestChangeBaseUsesTheNewerOfTheLocalAndOriginDefaultBranch(t *testing.T) {
	ctx := t.Context()
	repo := t.TempDir()
	checkoutGit(t, repo, "init", "-q", "-b", "main")
	checkoutGit(t, repo, "commit", "-q", "--allow-empty", "-m", "old main")
	old := checkoutGit(t, repo, "rev-parse", "HEAD")
	checkoutGit(t, repo, "commit", "-q", "--allow-empty", "-m", "upstream work")
	upstream := checkoutGit(t, repo, "rev-parse", "HEAD")
	checkoutGit(t, repo, "update-ref", "refs/remotes/origin/main", upstream)
	checkoutGit(t, repo, "symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
	// The local main is behind origin; the feature was rebased onto origin.
	checkoutGit(t, repo, "update-ref", "refs/heads/main", old)
	checkoutGit(t, repo, "checkout", "-q", "-b", "feature", upstream)
	checkoutGit(t, repo, "commit", "-q", "--allow-empty", "-m", "my change")
	if base, label := initDefaultMergeBase(ctx, repo, "HEAD"); base != upstream || label != "merge base with main" {
		t.Fatalf("a stale local main pulled upstream commits into the review: %s %q (want %s, not %s)", base, label, upstream, old)
	}
	// Unpushed commits on main itself are reviewed against origin/main.
	checkoutGit(t, repo, "checkout", "-q", "main")
	checkoutGit(t, repo, "reset", "-q", "--hard", upstream)
	checkoutGit(t, repo, "commit", "-q", "--allow-empty", "-m", "unpushed")
	if base, _ := initDefaultMergeBase(ctx, repo, "HEAD"); base != upstream {
		t.Fatalf("unpushed work on main: base %s, want origin/main %s", base, upstream)
	}
	// Only a remote-tracking default branch: it is still found.
	checkoutGit(t, repo, "checkout", "-q", "feature")
	checkoutGit(t, repo, "branch", "-q", "-D", "main")
	if base, label := initDefaultMergeBase(ctx, repo, "HEAD"); base != upstream || label != "merge base with main" {
		t.Fatalf("origin/main alone: %s %q", base, label)
	}
}

// With --head and no --base, the default base is the merge base of the
// selected head with the default branch, whatever is checked out.
func TestDefaultBaseFollowsTheSelectedHead(t *testing.T) {
	ctx := t.Context()
	repo := t.TempDir()
	checkoutGit(t, repo, "init", "-q", "-b", "main")
	checkoutGit(t, repo, "commit", "-q", "--allow-empty", "-m", "fork point")
	fork := checkoutGit(t, repo, "rev-parse", "HEAD")
	checkoutGit(t, repo, "checkout", "-q", "-b", "feature")
	checkoutGit(t, repo, "commit", "-q", "--allow-empty", "-m", "feature work")
	checkoutGit(t, repo, "checkout", "-q", "main")
	checkoutGit(t, repo, "commit", "-q", "--allow-empty", "-m", "main moved")
	main := checkoutGit(t, repo, "rev-parse", "HEAD")
	base, label, head, _, code, problem := latestChange(ctx, latestReviewPrinter(ctx, io.Discard, repo), latestReviewOptions{head: "feature"})
	if code != 0 || base != fork || label != "merge base with main" || head != "refs/heads/feature" {
		t.Fatalf("review --head feature: base %s %q head %s (exit %d, %s), want base %s, not main %s", base, label, head, code, problem, fork, main)
	}
	// The wizard proposes the same base for --head.
	result := runInitScript(t, repo, []string{"--no-input", "--directory", filepath.Join(t.TempDir(), "setup"), "--head", "refs/heads/feature"})
	if !strings.Contains(result.stdout, "Base:       "+initShort(fork)+"  (merge base with main)") {
		t.Fatalf("init --head feature proposed another base than %s:\n%s\n%s", initShort(fork), result.stdout, result.stderr)
	}
	// On the default branch with unpushed commits, origin's copy is the base
	// when that branch is selected by name too.
	checkoutGit(t, repo, "update-ref", "refs/remotes/origin/main", fork)
	checkoutGit(t, repo, "checkout", "-q", "feature")
	if base, _ := initDefaultMergeBase(ctx, repo, "refs/heads/main"); base != fork {
		t.Fatalf("--head main from feature: base %s, want origin/main %s", base, fork)
	}
}

// A setup outlives the commits it was made with: after the setup-time head is
// rewritten and garbage-collected, re-running trestle init still checks the
// setup and reviews the latest change.
func TestInitRerunWorksAfterTheSetupTimeCommitsAreGone(t *testing.T) {
	checkout := latestChangeCheckout(t)
	dir := latestChangeSetup(t, checkout)
	pinned := checkoutGit(t, checkout, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(checkout, "b.go"), []byte("package p\nfunc Later() int { return 1 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, checkout, "add", "b.go")
	checkoutGit(t, checkout, "commit", "-q", "--amend", "-m", "change, amended")
	checkoutGit(t, checkout, "reflog", "expire", "--expire=now", "--all")
	checkoutGit(t, checkout, "gc", "-q", "--prune=now")
	if _, _, err := initGit(t.Context(), checkout, "cat-file", "-e", pinned); err == nil {
		t.Fatalf("the setup-time head %s is still stored", pinned)
	}
	checks := runInitScript(t, checkout, nil, "2")
	if checks.code != initExitDone || !initHas(checks.stdout, "Review the latest change any time with: trestle review") {
		t.Fatalf("checks after the pinned commits are gone: exit=%d\n%s\n%s", checks.code, checks.stdout, checks.stderr)
	}
	transport := latestFixtureTransport(t)
	reviewed := runInitScript(t, checkout, nil, "1")
	head := checkoutGit(t, checkout, "rev-parse", "HEAD")
	if reviewed.code != initExitDone || len(transport.requests) != 2 {
		t.Fatalf("review after the pinned commits are gone: exit=%d requests=%v\n%s\n%s", reviewed.code, transport.requests, reviewed.stdout, reviewed.stderr)
	}
	if review, ok := readLastReview(dir); !ok || review.Head != head {
		t.Fatalf("last review %+v, want head %s", review, head)
	}
}

// A setup saved with --directory under ~/.local/state/open-trestle is found by
// trestle review, the home screen and trestle init without the flag; a setup
// for another checkout in the same parent is never picked.
func TestReviewFindsASetupSavedUnderAnotherFolderName(t *testing.T) {
	checkout := latestChangeCheckout(t)
	dir := latestChangeSetup(t, checkout)
	resolved, err := filepath.EvalSymlinks(checkout)
	if err != nil {
		t.Fatal(err)
	}
	renamed := filepath.Join(filepath.Dir(dir), "my-custom-setup")
	if err := os.Rename(dir, renamed); err != nil {
		t.Fatal(err)
	}
	// The saved commands name the old folder; re-run setup into the custom folder instead.
	if err := os.RemoveAll(renamed); err != nil {
		t.Fatal(err)
	}
	args := []string{"--no-input", "--directory", renamed, "--provider", "ollama-cloud", "--generation-model", "gemma4:31b", "--verification-model", "qwen3.5:397b", "--context-tokens", "128000", "--output-tokens", "8192", "--input-micro-usd-per-million-tokens", "0", "--output-micro-usd-per-million-tokens", "0", "--max-cost-micro-usd", "0", "--credential-env", "OPEN_TRESTLE_PROVIDER_REMOTE_TEST", "--declare-remote-route"}
	if setup := runInitScript(t, checkout, args); setup.code != initExitDone {
		t.Fatalf("setup: exit=%d\n%s\n%s", setup.code, setup.stdout, setup.stderr)
	}
	if setupExists(defaultSetupDirectory(resolved)) {
		t.Fatal("the default folder should be empty for this test")
	}
	if got := discoverSetupDirectory(t.Context(), resolved); got != renamed {
		t.Fatalf("discovered %q, want %q", got, renamed)
	}
	// A setup for a different checkout in the same parent folder is ignored.
	other := latestChangeCheckout(t)
	otherDir := filepath.Join(filepath.Dir(renamed), "zz-other-repository")
	otherArgs := append([]string{}, args...)
	otherArgs[2] = otherDir
	if setup := runInitScript(t, other, otherArgs); setup.code != initExitDone {
		t.Fatalf("other setup: exit=%d\n%s\n%s", setup.code, setup.stdout, setup.stderr)
	}
	if got := discoverSetupDirectory(t.Context(), resolved); got != renamed {
		t.Fatalf("after another repository's setup, discovered %q, want %q", got, renamed)
	}
	if err := os.WriteFile(filepath.Join(checkout, "c.go"), []byte("package p\nfunc Again() int { return 2 }\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, checkout, "add", "c.go")
	checkoutGit(t, checkout, "commit", "-q", "-m", "again")
	transport := latestFixtureTransport(t)
	code, stdout, stderr := runReviewCommand(t, checkout)
	if code != 4 || len(transport.requests) != 2 || !strings.HasPrefix(stdout, "status: findings\n") || initHas(stderr, "no Open Trestle setup yet") {
		t.Fatalf("trestle review with a renamed setup folder: exit=%d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if _, ok := readLastReview(renamed); !ok {
		t.Fatal("the review was not recorded in the discovered setup folder")
	}
}

// stdinClosingTransport closes the review's standard input when the first
// model request arrives and holds that request until the review is canceled.
type stdinClosingTransport struct{ close func() error }

func (s stdinClosingTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	_ = s.close()
	<-request.Context().Done()
	return nil, request.Context().Err()
}

// With --stop-on-stdin-close, end of standard input cancels the review the
// way Ctrl-C does: the canceled result, the last review and the usage ledger
// entry are still written.
func TestReviewStopsWhenStandardInputCloses(t *testing.T) {
	checkout := latestChangeCheckout(t)
	dir := latestChangeSetup(t, checkout)
	input, closer := io.Pipe()
	previous := reviewChecksInput
	reviewChecksInput = input
	t.Cleanup(func() { reviewChecksInput = previous })
	localReviewModelHTTPClient = &http.Client{Transport: stdinClosingTransport{close: closer.Close}}
	localReviewModelHTTPClientIdentity = localModelDigest([]byte("stdin closing fixture transport"))
	t.Cleanup(func() { localReviewModelHTTPClient, localReviewModelHTTPClientIdentity = nil, "" })
	code, stdout, stderr := runReviewCommand(t, checkout, "--format", "json", "--stop-on-stdin-close")
	var result map[string]any
	if code != 3 || json.Unmarshal([]byte(stdout), &result) != nil || result["status"] != "canceled" {
		t.Fatalf("exit=%d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !initHas(stderr, "The review was stopped before it finished.") {
		t.Fatalf("stderr lacks the canceled line:\n%s", stderr)
	}
	if review, ok := readLastReview(dir); !ok || review.Status != "canceled" {
		t.Fatalf("last review %+v %v", review, ok)
	}
	store, err := spending.NewStore(filepath.Join(os.Getenv("XDG_STATE_HOME"), "open-trestle", "usage"))
	if err != nil {
		t.Fatal(err)
	}
	if entries := spendingMonthEntries(t, store); len(entries) != 1 || entries[0].RequestsSent == 0 {
		t.Fatalf("ledger entries %+v, want the canceled review", entries)
	}
}
