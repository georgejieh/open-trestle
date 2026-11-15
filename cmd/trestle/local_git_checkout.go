package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type localCheckoutSource struct {
	objects, algorithm, base, head string
}

var checkoutSelection = regexp.MustCompile(`^(HEAD|[0-9a-f]{40}|[0-9a-f]{64}|refs/(heads|tags)/[A-Za-z0-9_][A-Za-z0-9_./-]*)$`)

// errCheckoutCommitUnavailable reports a selected base or head that could not be
// resolved to a commit in the checkout. It carries only operator-supplied
// selections and two repository-shape facts, never object content.
type errCheckoutCommitUnavailable struct {
	role, selection string
	shallow         bool
}

func (e errCheckoutCommitUnavailable) Error() string { return "checkout selection unavailable" }

// hint is the actionable operator guidance printed to stderr. No fetch is run.
func (e errCheckoutCommitUnavailable) hint() string {
	if e.shallow {
		return fmt.Sprintf("model-review: the %s revision %s is not in this shallow checkout. Fetch it with `git fetch --no-tags --depth=N origin %s` (N must reach back to the base), or check out with full history (GitHub Actions: actions/checkout with fetch-depth: 0). No fetch was attempted.", e.role, e.selection, e.selection)
	}
	return fmt.Sprintf("model-review: the %s revision %s could not be resolved to a commit in this checkout. Check the name, or fetch it with `git fetch --no-tags origin %s`. No fetch was attempted.", e.role, e.selection, e.selection)
}

const partialCheckoutHint = "model-review: the source could not be read completely. If this checkout is a partial clone (--filter), file contents for the base or head may be missing and are never fetched on demand; re-checkout without a filter (GitHub Actions: actions/checkout with fetch-depth: 0 and no filter)."

// checkoutGitRunner runs read-only, hook-free Git queries against a checkout.
type checkoutGitRunner func(args ...string) (string, error)

func newCheckoutGit(execution context.Context, directory string) (checkoutGitRunner, string, error) {
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return nil, "", err
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return nil, "", err
	}
	environment := []string{
		"PATH=" + filepath.Dir(git), "HOME=" + os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_LAZY_FETCH=1",
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_PAGER=cat", "LC_ALL=C",
	}
	return func(args ...string) (string, error) {
		prefix := []string{"--no-pager", "--no-lazy-fetch", "--no-replace-objects", "-c", "protocol.allow=never", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.DevNull, "-C", absolute}
		command := exec.CommandContext(execution, git, append(prefix, args...)...)
		command.Env = environment
		command.Stderr = io.Discard
		command.WaitDelay = time.Second
		var output checkoutOutput
		command.Stdout = &output
		if err := command.Run(); err != nil || output.exceeded {
			return "", errors.New("Git metadata unavailable")
		}
		value := strings.TrimSuffix(output.String(), "\n")
		if value == "" || strings.ContainsAny(value, "\r\n\x00") {
			return "", errors.New("invalid Git metadata")
		}
		return value, nil
	}, absolute, nil
}

// checkoutIsPartialClone reports a promisor remote, whose missing objects this
// command never fetches on demand.
func checkoutIsPartialClone(ctx context.Context, directory string) bool {
	execution, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	git, _, err := newCheckoutGit(execution, directory)
	if err != nil {
		return false
	}
	value, err := git("config", "--get-regexp", `^remote\..*\.promisor$`)
	return err == nil && strings.Contains(value, "true")
}

// resolveLocalCheckoutObjects is a checkout's objects folder and object
// format, without selecting any commit. A setup check uses it: the commits a
// setup was made with are only that moment's change, and every review picks
// its own.
func resolveLocalCheckoutObjects(ctx context.Context, directory string) (objects, algorithm string, err error) {
	if ctx == nil || ctx.Err() != nil || directory == "" || len(directory) > 4096 {
		return "", "", errors.New("checkout unavailable")
	}
	execution, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	run, _, err := newCheckoutGit(execution, directory)
	if err != nil {
		return "", "", errors.New("checkout unavailable")
	}
	return checkoutObjects(run)
}

func checkoutObjects(run checkoutGitRunner) (objects, algorithm string, err error) {
	algorithm, err = run("rev-parse", "--show-object-format")
	if err != nil || algorithm != "sha1" && algorithm != "sha256" {
		return "", "", errors.New("checkout unavailable")
	}
	objects, err = run("rev-parse", "--path-format=absolute", "--git-path", "objects")
	if err != nil || !filepath.IsAbs(objects) {
		return "", "", errors.New("checkout unavailable")
	}
	return filepath.Clean(objects), algorithm, nil
}

func resolveLocalCheckout(ctx context.Context, directory, base, head string) (localCheckoutSource, error) {
	fail := func() (localCheckoutSource, error) {
		return localCheckoutSource{}, errors.New("checkout selection unavailable")
	}
	if ctx == nil || ctx.Err() != nil || directory == "" || len(directory) > 4096 || !checkoutSelection.MatchString(base) || !checkoutSelection.MatchString(head) || len(base) > 4096 || len(head) > 4096 {
		return fail()
	}
	execution, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	run, _, err := newCheckoutGit(execution, directory)
	if err != nil {
		return fail()
	}
	objects, algorithm, err := checkoutObjects(run)
	if err != nil {
		return fail()
	}
	resolve := func(selection string) (string, error) {
		length := 40
		if algorithm == "sha256" {
			length = 64
		}
		if selection != "HEAD" && !strings.HasPrefix(selection, "refs/") && len(selection) != length {
			return "", errors.New("selected digest does not match object format")
		}
		if strings.HasPrefix(selection, "refs/") {
			exact, err := run("show-ref", "--verify", "--hash", "--", selection)
			if err != nil || len(exact) != length || strings.Trim(exact, "0123456789abcdef") != "" {
				return "", errors.New("exact ref unavailable")
			}
			selection = exact
		}
		value, err := run("rev-parse", "--verify", "--end-of-options", selection+"^{commit}")
		if err != nil || len(value) != length || strings.Trim(value, "0123456789abcdef") != "" {
			return "", errors.New("invalid selected commit")
		}
		return value, nil
	}
	unavailable := func(role, selection string) (localCheckoutSource, error) {
		shallow, _ := run("rev-parse", "--is-shallow-repository")
		return localCheckoutSource{}, errCheckoutCommitUnavailable{role: role, selection: selection, shallow: shallow == "true"}
	}
	baseID, err := resolve(base)
	if err != nil {
		return unavailable("base", base)
	}
	headID, err := resolve(head)
	if err != nil {
		return unavailable("head", head)
	}
	if baseID == headID || execution.Err() != nil {
		return fail()
	}
	return localCheckoutSource{objects: objects, algorithm: algorithm, base: baseID, head: headID}, nil
}

type checkoutOutput struct {
	buffer   bytes.Buffer
	exceeded bool
}

func (w *checkoutOutput) String() string { return w.buffer.String() }

func (w *checkoutOutput) Write(p []byte) (int, error) {
	if w.buffer.Len()+len(p) > 8192 {
		w.exceeded = true
		return 0, errors.New("Git metadata exceeds limit")
	}
	return w.buffer.Write(p)
}
