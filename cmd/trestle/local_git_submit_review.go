package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/client"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

func runLocalGitSubmitReview(args []string, stdout, stderr io.Writer) int {
	return runLocalGitSubmitReviewWithOpener(args, stdout, stderr, openLocalGitRoot)
}
func runLocalGitSubmitReviewWithOpener(args []string, stdout, stderr io.Writer, opener localGitRootOpener) int {
	if len(args)%2 != 0 {
		fmt.Fprintln(stderr, "local-git submit-review: flag-value pairs are required")
		return 2
	}
	extra := map[string]string{}
	sourceArgs := make([]string, 0, len(args))
	for i := 0; i < len(args); i += 2 {
		name, value := args[i], args[i+1]
		switch name {
		case "--server", "--tenant", "--repository", "--run", "--review-policy-identity", "--inventory-identity", "--runtime-policy-identity", "--created-at-unix-milliseconds":
			if extra[name] != "" || value == "" || len(value) > 4096 {
				fmt.Fprintln(stderr, "local-git submit-review: invalid option")
				return 2
			}
			extra[name] = value
		case "--format":
			fmt.Fprintln(stderr, "local-git submit-review: output format is fixed to a run receipt")
			return 2
		default:
			sourceArgs = append(sourceArgs, name, value)
		}
	}
	for _, name := range []string{"--server", "--tenant", "--repository", "--run", "--review-policy-identity", "--inventory-identity", "--runtime-policy-identity"} {
		if extra[name] == "" {
			fmt.Fprintln(stderr, "local-git submit-review: missing option")
			return 2
		}
	}
	for _, name := range []string{"--review-policy-identity", "--inventory-identity", "--runtime-policy-identity"} {
		if controlplane.ValidateHandlerIdentity(extra[name]) != nil {
			fmt.Fprintln(stderr, "local-git submit-review: invalid policy identity")
			return 2
		}
	}
	options, repository, base, head, _, err := parseLocalGitReviewOptions(sourceArgs)
	if err != nil {
		fmt.Fprintln(stderr, "local-git submit-review: invalid source request")
		return 2
	}
	scope, err := audit.NewReviewScope(extra["--tenant"], extra["--repository"], extra["--run"])
	if err != nil {
		fmt.Fprintln(stderr, "local-git submit-review: invalid scope")
		return 2
	}
	handle, err := opener(options.objectsRoot)
	if err != nil || handle.root == nil || handle.close == nil {
		if handle.root != nil {
			_ = handle.root.Close()
		}
		fmt.Fprintln(stderr, "local-git submit-review: local source is unavailable")
		return 1
	}
	_, baseErr := buildLocalGitInspectResult(handle.root, repository, base)
	_, headErr := buildLocalGitInspectResult(handle.root, repository, head)
	closeErr := handle.close()
	if baseErr != nil || headErr != nil || closeErr != nil {
		fmt.Fprintln(stderr, "local-git submit-review: local source validation failed")
		return 1
	}
	createdAt := time.Now().UTC()
	if extra["--created-at-unix-milliseconds"] != "" {
		millis, parseErr := strconv.ParseInt(extra["--created-at-unix-milliseconds"], 10, 64)
		if parseErr != nil || millis <= 0 || millis > 253402300799999 || strconv.FormatInt(millis, 10) != extra["--created-at-unix-milliseconds"] {
			fmt.Fprintln(stderr, "local-git submit-review: invalid intent timestamp")
			return 2
		}
		createdAt = time.UnixMilli(millis).UTC()
	}
	intent, err := runtimecatalog.NewLocalFullReviewIntent(scope, repository, base, head, extra["--review-policy-identity"], extra["--inventory-identity"], extra["--runtime-policy-identity"], createdAt)
	if err != nil {
		fmt.Fprintln(stderr, "local-git submit-review: invalid review intent")
		return 2
	}
	apiClient, err := client.NewLocal(extra["--server"], os.Getenv("OPEN_TRESTLE_API_TOKEN"), nil)
	if err != nil {
		fmt.Fprintln(stderr, "local-git submit-review: invalid local daemon authority")
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), remoteCommandTimeout)
	defer cancel()
	receipt, err := apiClient.SubmitLocalFullReview(ctx, intent)
	if err != nil {
		fmt.Fprintln(stderr, "local-git submit-review: daemon admission failed")
		return 1
	}
	return writeRemoteReceipt(receipt, stdout, stderr)
}
