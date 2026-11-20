package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checksTestDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "setup")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestChecksConsentRoundTrip(t *testing.T) {
	dir := checksTestDir(t)
	if _, decided := readChecksConsent(dir); decided {
		t.Fatal("a new setup has an answer")
	}
	for _, allowed := range []bool{true, false} {
		if err := writeChecksConsent(context.Background(), dir, allowed); err != nil {
			t.Fatal(err)
		}
		if got, decided := readChecksConsent(dir); !decided || got != allowed {
			t.Fatalf("read %v %v, want %v", got, decided, allowed)
		}
	}
}

func TestChecksConsentRefusesAnUnexpectedFile(t *testing.T) {
	dir := checksTestDir(t)
	for _, content := range []string{
		`{"contract":"open-trestle/repository-checks-consent","schema_version":2,"allowed":true,"recorded_at":"2026-11-18T00:00:00Z"}`,
		`{"contract":"open-trestle/repository-checks-consent","schema_version":1,"allowed":true,"recorded_at":"2026-11-18T00:00:00Z","extra":1}`,
		`{"contract":"other","schema_version":1,"allowed":true,"recorded_at":"2026-11-18T00:00:00Z"}`,
	} {
		if err := replaceProtectedFile(context.Background(), filepath.Join(dir, "checks.json"), []byte(content)); err != nil {
			t.Fatal(err)
		}
		if _, decided := readChecksConsent(dir); decided {
			t.Fatalf("accepted %s", content)
		}
	}
}

func TestReviewChecksDecision(t *testing.T) {
	var out bytes.Buffer
	w := latestReviewPrinter(context.Background(), &out, t.TempDir())
	dir := checksTestDir(t)
	nobody := strings.NewReader("")
	if reviewChecksAllowed(context.Background(), w, dir, latestReviewOptions{}, nobody) {
		t.Fatal("checks ran without an answer and without a terminal")
	}
	if !initHas(out.String(), "Repository checks did not run: they are off until you allow them") {
		t.Fatalf("no explanation: %q", out.String())
	}
	if !reviewChecksAllowed(context.Background(), w, dir, latestReviewOptions{checks: true}, nobody) {
		t.Fatal("--checks did not allow the checks")
	}
	if err := writeChecksConsent(context.Background(), dir, true); err != nil {
		t.Fatal(err)
	}
	if !reviewChecksAllowed(context.Background(), w, dir, latestReviewOptions{}, nobody) {
		t.Fatal("the stored answer did not allow the checks")
	}
	if reviewChecksAllowed(context.Background(), w, dir, latestReviewOptions{noChecks: true}, nobody) {
		t.Fatal("--no-checks did not skip the checks")
	}
}

func TestReviewRefusesChecksAndNoChecksTogether(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if _, code, done := parseLatestReviewFlags([]string{"--checks", "--no-checks"}, &stdout, &stderr); !done || code != 2 {
		t.Fatalf("code %d done %v: %s", code, done, stderr.String())
	}
}

func TestModelReviewAcceptsRepositoryChecksOnce(t *testing.T) {
	args := append(newLocalModelFixture(t, localModelFixtureOptions{}).args[2:], "--repository-checks")
	options, _, _, _, err := parseLocalModelReview(args)
	if err != nil || !options.repositoryChecks {
		t.Fatalf("options %+v, err %v", options.repositoryChecks, err)
	}
	if _, _, _, _, err := parseLocalModelReview(append(args, "--repository-checks")); err == nil {
		t.Fatal("the flag was accepted twice")
	}
	if _, _, _, _, err := parseLocalModelReview(append(args, "--investigation-policy", "/policy.json")); err == nil {
		t.Fatal("repository checks were accepted for an investigation session")
	}
}

func TestTerminalTextNeutralisesControls(t *testing.T) {
	if got := terminalText("npm test\x1b]52;c;aGk=\x07 \u202eok", 100); got != "npm test?]52;c;aGk=? ?ok" {
		t.Fatalf("got %q", got)
	}
	if got := terminalText("abcdef", 3); got != "abc..." {
		t.Fatalf("got %q", got)
	}
}

func TestReasonsShowTheHomeFolderAsTilde(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home folder")
	}
	if got := withoutHomeFolder("the sandbox could not be given read access to " + filepath.Join(home, "sdk", "go")); strings.Contains(got, home) {
		t.Fatalf("got %q", got)
	}
}

func TestDependentsWithoutAnIndexAreUnknown(t *testing.T) {
	var index *reviewIndexContext
	if paths, known := index.dependents(context.Background()); known || paths != nil {
		t.Fatalf("got %v %v without an index", paths, known)
	}
}
