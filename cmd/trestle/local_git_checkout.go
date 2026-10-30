package main

import (
	"bytes"
	"context"
	"errors"
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

func resolveLocalCheckout(ctx context.Context, directory, base, head string) (localCheckoutSource, error) {
	fail := func() (localCheckoutSource, error) {
		return localCheckoutSource{}, errors.New("checkout selection unavailable")
	}
	if ctx == nil || ctx.Err() != nil || directory == "" || len(directory) > 4096 || !checkoutSelection.MatchString(base) || !checkoutSelection.MatchString(head) || len(base) > 4096 || len(head) > 4096 {
		return fail()
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return fail()
	}
	git, err := exec.LookPath("git")
	if err != nil {
		return fail()
	}
	execution, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	environment := []string{
		"PATH=" + filepath.Dir(git), "HOME=" + os.DevNull,
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=" + os.DevNull,
		"GIT_TERMINAL_PROMPT=0", "GIT_OPTIONAL_LOCKS=0", "GIT_NO_LAZY_FETCH=1",
		"GIT_NO_REPLACE_OBJECTS=1", "GIT_PAGER=cat", "LC_ALL=C",
	}
	run := func(args ...string) (string, error) {
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
	}
	algorithm, err := run("rev-parse", "--show-object-format")
	if err != nil || algorithm != "sha1" && algorithm != "sha256" {
		return fail()
	}
	objects, err := run("rev-parse", "--path-format=absolute", "--git-path", "objects")
	if err != nil || !filepath.IsAbs(objects) {
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
	baseID, err := resolve(base)
	if err != nil {
		return fail()
	}
	headID, err := resolve(head)
	if err != nil || baseID == headID || execution.Err() != nil {
		return fail()
	}
	return localCheckoutSource{objects: filepath.Clean(objects), algorithm: algorithm, base: baseID, head: headID}, nil
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
