package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// initGit runs one read-only Git query with the same hardened environment as
// resolveLocalCheckout: no global/system config, hooks, pager, prompts, lazy
// fetches or replace objects. Output is bounded; a larger answer is truncated
// and reported, never streamed.
func initGit(ctx context.Context, directory string, args ...string) (string, bool, error) {
	git, err := exec.LookPath("git")
	if err != nil {
		return "", false, errors.New("git is not installed or not on PATH")
	}
	execution, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	prefix := []string{"--no-pager", "--no-lazy-fetch", "--no-replace-objects", "-c", "protocol.allow=never", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull, "-C", directory}
	command := exec.CommandContext(execution, git, append(prefix, args...)...)
	command.Env = []string{
		"PATH=" + filepath.Dir(git), "HOME=" + os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_LAZY_FETCH=1",
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_PAGER=cat", "LC_ALL=C",
	}
	command.Stderr = io.Discard
	command.WaitDelay = time.Second
	output := &initGitOutput{limit: 16384}
	command.Stdout = output
	if err := command.Run(); err != nil {
		return "", false, err
	}
	return strings.TrimRight(output.buffer.String(), "\n"), output.truncated, nil
}

type initGitOutput struct {
	buffer    bytes.Buffer
	limit     int
	truncated bool
}

func (w *initGitOutput) Write(p []byte) (int, error) {
	if room := w.limit - w.buffer.Len(); room < len(p) {
		w.truncated = true
		if room > 0 {
			w.buffer.Write(p[:room])
		}
		return len(p), nil
	}
	return w.buffer.Write(p)
}

func initGitRefExists(ctx context.Context, directory, ref string) bool {
	_, _, err := initGit(ctx, directory, "show-ref", "--verify", "--quiet", "--", ref)
	return err == nil
}

// initDefaultBase proposes the repository's default branch as a full local ref:
// origin/HEAD's branch when that branch also exists locally, else main, else master.
func initDefaultBase(ctx context.Context, directory string) string {
	if target, _, err := initGit(ctx, directory, "symbolic-ref", "-q", "refs/remotes/origin/HEAD"); err == nil {
		if branch, ok := strings.CutPrefix(target, "refs/remotes/origin/"); ok && branch != "" {
			if local := "refs/heads/" + branch; checkoutSelection.MatchString(local) && initGitRefExists(ctx, directory, local) {
				return local
			}
		}
	}
	for _, candidate := range []string{"refs/heads/main", "refs/heads/master"} {
		if initGitRefExists(ctx, directory, candidate) {
			return candidate
		}
	}
	return ""
}

// initDefaultMergeBase proposes the merge base of the default branch and HEAD,
// the commit a pull request is reviewed against, with a label naming it. It
// runs only the read-only `git merge-base`. Without a default branch it returns
// nothing; when Git finds no merge base it falls back to the branch itself.
func initDefaultMergeBase(ctx context.Context, directory string) (base, label string) {
	branch := initDefaultBase(ctx, directory)
	if branch == "" {
		return "", ""
	}
	if commit, _, err := initGit(ctx, directory, "merge-base", branch, "HEAD"); err == nil && checkoutSelection.MatchString(commit) && commit != "HEAD" {
		return commit, "merge base with " + strings.TrimPrefix(branch, "refs/heads/")
	}
	return branch, ""
}

// initNormalizeSelection turns a friendly answer (a branch name, tag or short
// commit) into the exact form the bootstrap accepts.
func initNormalizeSelection(ctx context.Context, directory, value string) (string, error) {
	if checkoutSelection.MatchString(value) {
		return value, nil
	}
	if !strings.HasPrefix(value, "-") && !strings.ContainsAny(value, " \t") {
		for _, prefix := range []string{"refs/heads/", "refs/tags/"} {
			if candidate := prefix + value; checkoutSelection.MatchString(candidate) && initGitRefExists(ctx, directory, candidate) {
				return candidate, nil
			}
		}
		if commit, _, err := initGit(ctx, directory, "rev-parse", "--verify", "--quiet", "--end-of-options", value+"^{commit}"); err == nil && checkoutSelection.MatchString(commit) {
			return commit, nil
		}
	}
	return "", errors.New("Git does not know that branch, tag or commit here. Type a branch name (main), a full ref (refs/heads/main), HEAD, or a commit ID.")
}

type initChangeSummary struct {
	commits      int
	shortstat    string
	uncommitted  bool
	currentLabel string
}

func initSummarizeChange(ctx context.Context, directory, base, head string) initChangeSummary {
	summary := initChangeSummary{commits: -1}
	if count, _, err := initGit(ctx, directory, "rev-list", "--count", base+".."+head, "--"); err == nil {
		if n, err := strconv.Atoi(count); err == nil {
			summary.commits = n
		}
	}
	if stat, _, err := initGit(ctx, directory, "diff", "--shortstat", "--no-ext-diff", "--no-textconv", base, head, "--"); err == nil {
		summary.shortstat = strings.TrimSpace(stat)
	}
	if status, truncated, err := initGit(ctx, directory, "status", "--porcelain", "--untracked-files=no"); err == nil {
		summary.uncommitted = status != "" || truncated
	}
	if branch, _, err := initGit(ctx, directory, "symbolic-ref", "-q", "--short", "HEAD"); err == nil {
		summary.currentLabel = branch
	}
	return summary
}
