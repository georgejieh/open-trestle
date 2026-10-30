package main

import (
	"bytes"
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func checkoutGit(t *testing.T, directory string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", directory}, args...)...)
	command.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + t.TempDir(), "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull, "GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL=fixture@example.test", "GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=fixture@example.test"}
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func newCheckoutFixture(t *testing.T, algorithm string) (string, string, string) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("Git is not installed")
	}
	directory := t.TempDir()
	checkoutGit(t, directory, "init", "--object-format="+algorithm)
	path := filepath.Join(directory, "main.go")
	if err := os.WriteFile(path, []byte("package main\nfunc main() {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, directory, "add", "main.go")
	checkoutGit(t, directory, "-c", "commit.gpgsign=false", "commit", "-m", "base")
	base := checkoutGit(t, directory, "rev-parse", "HEAD")
	if err := os.WriteFile(path, []byte("package main\nfunc main() { println(\"debug\") }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, directory, "add", "main.go")
	checkoutGit(t, directory, "-c", "commit.gpgsign=false", "commit", "-m", "head")
	return directory, base, checkoutGit(t, directory, "rev-parse", "HEAD")
}

func TestCheckoutOutputBoundsEveryWrite(t *testing.T) {
	var output checkoutOutput
	if n, err := io.Copy(&output, strings.NewReader(strings.Repeat("x", 8193))); err == nil || n > 8192 || output.buffer.Len() > 8192 || !output.exceeded {
		t.Fatalf("unbounded output: n=%d err=%v bytes=%d", n, err, output.buffer.Len())
	}
}

func TestCheckoutModelReviewRefusesMixedSourceForms(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	for _, extra := range [][]string{
		{"--checkout", t.TempDir(), "--base", "HEAD", "--head", "HEAD"},
		{"--base", "HEAD", "--head", "HEAD"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(append(append([]string(nil), f.args...), extra...), &stdout, &stderr); code != 2 || stdout.Len() != 0 {
			t.Fatalf("mixed source form code=%d stdout=%q", code, stdout.String())
		}
	}
	generation, _ := f.generation.snapshot()
	verification, _ := f.verification.snapshot()
	if generation != 0 || verification != 0 {
		t.Fatal("invalid source intent dispatched a model request")
	}
}

func TestResolveCheckoutUsesExplicitImmutableCommits(t *testing.T) {
	for _, algorithm := range []string{"sha1", "sha256"} {
		t.Run(algorithm, func(t *testing.T) {
			directory, base, head := newCheckoutFixture(t, algorithm)
			checkoutGit(t, directory, "branch", "base", base)
			checkoutGit(t, directory, "gc", "--prune=now")
			if err := os.WriteFile(filepath.Join(directory, "main.go"), []byte("dirty worktree"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("GIT_OBJECT_DIRECTORY", t.TempDir())
			t.Setenv("GIT_CONFIG_COUNT", "1")
			t.Setenv("GIT_CONFIG_KEY_0", "alias.rev-parse")
			t.Setenv("GIT_CONFIG_VALUE_0", "!exit 99")
			source, err := resolveLocalCheckout(context.Background(), directory, "refs/heads/base", "HEAD")
			if err != nil || source.algorithm != algorithm || source.base != base || source.head != head || source.objects != filepath.Join(directory, ".git", "objects") {
				t.Fatalf("source=%+v err=%v", source, err)
			}
			if algorithm == "sha256" {
				if _, err := resolveLocalCheckout(context.Background(), directory, base[:40], head); err == nil {
					t.Fatal("accepted abbreviated SHA-256 commit as full SHA-1")
				}
			}
		})
	}
}

func TestResolveCheckoutDoesNotRunConfiguredHelpers(t *testing.T) {
	directory, base, head := newCheckoutFixture(t, "sha1")
	marker := filepath.Join(t.TempDir(), "helper-ran")
	program := filepath.Join(t.TempDir(), "helper")
	if err := os.WriteFile(program, []byte("#!/bin/sh\ntouch "+marker+"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, directory, "config", "core.fsmonitor", program)
	checkoutGit(t, directory, "config", "credential.helper", program)
	checkoutGit(t, directory, "config", "diff.external", program)
	checkoutGit(t, directory, "config", "filter.hostile.clean", program)
	checkoutGit(t, directory, "config", "core.hooksPath", filepath.Dir(program))
	if _, err := resolveLocalCheckout(context.Background(), directory, base, head); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("checkout resolution ran a repository-configured helper")
	}
}

func TestResolveCheckoutLinkedWorktreeAndRefRefusals(t *testing.T) {
	directory, base, head := newCheckoutFixture(t, "sha1")
	worktree := filepath.Join(t.TempDir(), "linked")
	checkoutGit(t, directory, "worktree", "add", "--detach", worktree, head)
	source, err := resolveLocalCheckout(context.Background(), worktree, base, "HEAD")
	if err != nil || source.head != head || source.objects != filepath.Join(directory, ".git", "objects") {
		t.Fatalf("linked worktree source=%+v err=%v", source, err)
	}
	checkoutGit(t, directory, "update-ref", "refs/tags/refs/heads/missing", base)
	for _, refs := range [][2]string{{"HEAD", "HEAD"}, {"--help", "HEAD"}, {"HEAD~1", "HEAD"}, {base, "HEAD:main.go"}, {"refs/heads/missing", "HEAD"}} {
		if _, err := resolveLocalCheckout(context.Background(), directory, refs[0], refs[1]); err == nil {
			t.Errorf("accepted invalid selection %v", refs)
		}
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolveLocalCheckout(canceled, directory, base, head); err == nil {
		t.Fatal("accepted canceled preparation")
	}
}

func TestCheckoutModelReviewUsesExistingIndependentPipeline(t *testing.T) {
	f := newLocalModelFixture(t, localModelFixtureOptions{})
	directory := t.TempDir()
	checkoutGit(t, directory, "init")
	if err := os.CopyFS(filepath.Join(directory, ".git", "objects"), os.DirFS(f.objects)); err != nil {
		t.Fatal(err)
	}
	checkoutGit(t, directory, "update-ref", "refs/heads/base", f.base)
	checkoutGit(t, directory, "update-ref", "refs/heads/review", f.head)
	checkoutGit(t, directory, "gc", "--prune=now")
	args := []string{}
	for index := 0; index < len(f.args); index += 2 {
		switch f.args[index] {
		case "--objects-root", "--revision-algorithm", "--base-revision-digest", "--head-revision-digest":
			continue
		}
		args = append(args, f.args[index:index+2]...)
	}
	args = append(args, "--checkout", directory, "--base", "refs/heads/base", "--head", "refs/heads/review")
	result, _ := localModelExecute(t, f, args, 4)
	generation, _ := f.generation.snapshot()
	verification, _ := f.verification.snapshot()
	if result.Status != "findings" || result.RunStatus != "succeeded" || result.Independence != "distinct_provider" || generation != 1 || verification != 1 || len(result.Tasks) != 9 || len(result.Diagnostics.Findings) != 1 {
		t.Fatalf("checkout did not complete the independently verified pipeline: status=%s calls=%d/%d tasks=%d", result.Status, generation, verification, len(result.Tasks))
	}
}

func TestCheckoutModelReviewInvalidIntentDoesNotRunGit(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"local-git", "model-review", "--checkout", "SENSITIVE_PATH", "--base", "HEAD", "--head", "HEAD"}, &stdout, &stderr)
	if code != 2 || stdout.Len() != 0 || strings.Contains(stderr.String(), "SENSITIVE_PATH") {
		t.Fatalf("invalid intent code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}
