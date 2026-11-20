package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/checksandbox"
)

// checksChangeCheckout is latestChangeCheckout with a Go module and a test
// of the caller: the change makes Changed(0) divide by zero, so the test
// passes on base and fails on head.
func checksChangeCheckout(t *testing.T) string {
	t.Helper()
	checkout := t.TempDir()
	checkoutGit(t, checkout, "init", "-q", "-b", "main")
	write := func(name, content string) {
		if err := os.WriteFile(filepath.Join(checkout, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module p\n\ngo 1.22\n")
	write("a.go", "package p\nfunc Changed(x int) int { if x == 0 { return 0 }; return 10 / x }\n// "+localModelSecret+"\n")
	write("caller.go", "package p\nfunc Consume() int { return Changed(0) }\n")
	write("caller_test.go", "package p\n\nimport \"testing\"\n\nfunc TestConsume(t *testing.T) {\n\tif Consume() != 0 {\n\t\tt.Fatal(Consume())\n\t}\n}\n")
	checkoutGit(t, checkout, "add", ".")
	checkoutGit(t, checkout, "commit", "-q", "-m", "base")
	checkoutGit(t, checkout, "checkout", "-q", "-b", "review")
	write("a.go", "package p\nfunc Changed(x int) int { return 10 / x }\n// "+localModelSecret+"\n")
	checkoutGit(t, checkout, "commit", "-q", "-am", "change")
	return checkout
}

// A review with checks allowed runs the module's tests in the sandbox on
// base and head before the model calls, and the verifier receives the
// regression.
func TestReviewRunsAllowedRepositoryChecks(t *testing.T) {
	if err := checksandbox.Available(); err != nil {
		t.Skipf("the check sandbox is unavailable here: %v", err)
	}
	checkout := checksChangeCheckout(t)
	dir := latestChangeSetupWith(t, checkout, "--specialists", "none", "--checks")
	if allowed, decided := readChecksConsent(dir); !allowed || !decided {
		t.Fatalf("init --checks saved %v %v", allowed, decided)
	}
	transport := latestFixtureTransport(t)
	code, stdout, stderr := runReviewCommand(t, checkout)
	// Where the sandbox cannot run Go (no user namespaces, or a Windows NUL
	// device closed to AppContainers) the review reports that and the
	// regression cannot be shown.
	if initHas(stderr, "could not run (go test") && (initHas(stderr, "user namespaces") || initHas(stderr, "NUL device")) {
		t.Skipf("Go cannot run in the check sandbox here:\n%s", stderr)
	}
	if code != 4 || len(transport.payloads) != 2 {
		t.Fatalf("exit=%d requests=%v\nstdout:\n%s\nstderr:\n%s", code, transport.requests, stdout, stderr)
	}
	if !initHas(stderr, "ran 2 of 2 checks in the sandbox: 1 regression, 0 flaky dropped") {
		t.Fatalf("stderr lacks the summary:\n%s", stderr)
	}
	for index, payload := range transport.payloads {
		if !strings.Contains(payload, `"check_runs"`) || !strings.Contains(payload, "p.TestConsume") || !strings.Contains(payload, `"changed_and_dependents"`) && !strings.Contains(payload, `"changed_only"`) {
			t.Fatalf("request %d (%s) lacks the regression:\n%s", index, transport.requests[index], payload)
		}
	}
	if !initHas(stdout, "ran 2 of 2 checks in the sandbox") {
		t.Fatalf("the walkthrough lacks the what-ran line:\n%s", stdout)
	}
}

// Without an answer and without a terminal a review runs no checks, sends
// nothing about them, and says how to allow them.
func TestReviewWithoutConsentRunsNoChecks(t *testing.T) {
	checkout := checksChangeCheckout(t)
	dir := latestChangeSetup(t, checkout)
	if allowed, decided := readChecksConsent(dir); allowed || !decided {
		t.Fatalf("init --no-input without --checks saved %v %v, want off", allowed, decided)
	}
	if err := os.Remove(filepath.Join(dir, "checks.json")); err != nil {
		t.Fatal(err)
	}
	transport := latestFixtureTransport(t)
	code, stdout, stderr := runReviewCommand(t, checkout)
	if code != 4 || len(transport.payloads) != 2 {
		t.Fatalf("exit=%d\nstdout:\n%s\nstderr:\n%s", code, stdout, stderr)
	}
	if !initHas(stderr, "Repository checks did not run: they are off until you allow them") || initHas(stderr, "Running this repository's checks") {
		t.Fatalf("stderr:\n%s", stderr)
	}
	for _, payload := range transport.payloads {
		if strings.Contains(payload, `"check_runs"`) {
			t.Fatal("a request carried checks that never ran")
		}
	}
}
