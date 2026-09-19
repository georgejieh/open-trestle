package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type localGitRetainedMemoryInputOptions struct {
	inventory  string
	policy     string
	feedback   string
	output     string
	tenant     string
	repository string
	format     string
	timeout    time.Duration
	validFor   time.Duration
}

type localGitRetainedMemoryInputReceipt struct {
	Contract                    string `json:"contract"`
	SchemaVersion               int    `json:"schema_version"`
	Status                      string `json:"status"`
	RetainedMemoryInputIdentity string `json:"retained_memory_input_identity"`
	ScopeIdentity               string `json:"scope_identity"`
	RepositoryIdentity          string `json:"repository_identity"`
	HeadRevisionIdentity        string `json:"head_revision_identity"`
	RuntimePolicyIdentity       string `json:"runtime_policy_identity"`
	RecordCount                 int    `json:"record_count"`
	PathCount                   int    `json:"path_count"`
	ExpiresAtUnixMilliseconds   int64  `json:"expires_at_unix_ms"`
}

func runLocalGitRetainedMemoryInput(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if stdout == nil || stderr == nil {
		return 1
	}
	options, repository, head, err := parseLocalGitRetainedMemoryInput(args)
	if err != nil {
		fmt.Fprintln(stderr, "local-git retained-memory-input: invalid usage")
		writeLocalGitRetainedMemoryInputUsage(stderr)
		return 2
	}
	if ctx == nil {
		fmt.Fprintln(stderr, "local-git retained-memory-input: internal failure")
		return 1
	}
	if err := ctx.Err(); err != nil {
		fmt.Fprintln(stderr, "local-git retained-memory-input: canceled")
		return 3
	}
	execution, cancel := context.WithTimeout(ctx, options.timeout)
	defer cancel()
	inventory, policy, err := runtimeconfig.LoadProtectedConfiguration(execution, options.inventory, options.policy)
	if err != nil || inventory.Validate() != nil || policy.ValidateAgainstInventory(inventory) != nil {
		if execution.Err() != nil {
			fmt.Fprintln(stderr, "local-git retained-memory-input: canceled")
			return 3
		}
		fmt.Fprintln(stderr, "local-git retained-memory-input: protected configuration refused")
		return 4
	}
	feedback, err := runtimeconfig.LoadProtectedRetainedMemoryFeedback(execution, options.feedback)
	if err != nil {
		if execution.Err() != nil {
			fmt.Fprintln(stderr, "local-git retained-memory-input: canceled")
			return 3
		}
		fmt.Fprintln(stderr, "local-git retained-memory-input: protected feedback refused")
		return 4
	}
	if execution.Err() != nil {
		fmt.Fprintln(stderr, "local-git retained-memory-input: canceled")
		return 3
	}
	observedAt := time.UnixMilli(time.Now().UTC().UnixMilli()).UTC()
	validUntil := observedAt.Add(options.validFor)
	scope, err := memory.NewScope(options.tenant, options.repository, "local-reviewer", memory.RefVisibilityExact, head.Identity(), []string{"."})
	if err != nil {
		fmt.Fprintln(stderr, "local-git retained-memory-input: protected scope refused")
		return 4
	}
	encoded, err := runtimeconfig.EncodeRetainedMemoryInput(execution, scope, repository, head, policy, feedback, observedAt, validUntil)
	if err != nil {
		if execution.Err() != nil {
			fmt.Fprintln(stderr, "local-git retained-memory-input: canceled")
			return 3
		}
		fmt.Fprintln(stderr, "local-git retained-memory-input: protected input refused")
		return 4
	}
	if err := fileauthority.WriteNewProtectedFile(execution, options.output, encoded, 65536); err != nil {
		switch {
		case errors.Is(err, fileauthority.ErrProtectedWriteRefused):
			fmt.Fprintln(stderr, "local-git retained-memory-input: protected output refused")
			return 4
		case errors.Is(err, fileauthority.ErrProtectedWriteIncomplete):
			fmt.Fprintln(stderr, "local-git retained-memory-input: output may remain incomplete")
			return 1
		case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
			fmt.Fprintln(stderr, "local-git retained-memory-input: canceled")
			return 3
		default:
			fmt.Fprintln(stderr, "local-git retained-memory-input: output may remain incomplete")
			return 1
		}
	}
	loaded, err := runtimeconfig.LoadProtectedRetainedMemoryInput(execution, options.output, scope, repository, policy, observedAt)
	if err != nil || execution.Err() != nil || !loaded.MatchesEncoding(encoded) {
		fmt.Fprintln(stderr, "local-git retained-memory-input: output may remain incomplete")
		return 1
	}
	receipt := localGitRetainedMemoryInputReceipt{
		Contract:                    "open-trestle/retained-memory-authoring-result",
		SchemaVersion:               1,
		Status:                      "authored",
		RetainedMemoryInputIdentity: loaded.Identity(),
		ScopeIdentity:               loaded.Scope().Identity(),
		RepositoryIdentity:          repository.Identity(),
		HeadRevisionIdentity:        head.Identity(),
		RuntimePolicyIdentity:       policy.Identity(),
		RecordCount:                 len(loaded.Records()),
		PathCount:                   len(feedback),
		ExpiresAtUnixMilliseconds:   validUntil.UnixMilli(),
	}
	if err := writeLocalGitRetainedMemoryInputReceipt(options.format, receipt, stdout); err != nil {
		fmt.Fprintln(stderr, "local-git retained-memory-input: output may remain incomplete")
		return 1
	}
	return 0
}

func parseLocalGitRetainedMemoryInput(args []string) (localGitRetainedMemoryInputOptions, evidence.RepositoryIdentity, evidence.RevisionIdentity, error) {
	var options localGitRetainedMemoryInputOptions
	fail := func() (localGitRetainedMemoryInputOptions, evidence.RepositoryIdentity, evidence.RevisionIdentity, error) {
		return options, evidence.RepositoryIdentity{}, evidence.RevisionIdentity{}, fmt.Errorf("invalid explicit retained memory authoring intent")
	}
	allowed := map[string]bool{
		"--repository-authority": true,
		"--repository-namespace": true,
		"--repository-name":      true,
		"--revision-algorithm":   true,
		"--head-revision-digest": true,
		"--tenant":               true,
		"--repository":           true,
		"--route-inventory":      true,
		"--runtime-policy":       true,
		"--egress":               true,
		"--timeout":              true,
		"--valid-for":            true,
		"--feedback-input":       true,
		"--output":               true,
		"--format":               true,
	}
	if len(args) != 28 && len(args) != 30 || len(args)%2 != 0 {
		return fail()
	}
	values := make(map[string]string, len(allowed))
	for i := 0; i < len(args); i += 2 {
		flag, value := args[i], args[i+1]
		if !allowed[flag] || value == "" || len(value) > 4096 || values[flag] != "" {
			return fail()
		}
		values[flag] = value
	}
	for flag := range allowed {
		if flag != "--format" && values[flag] == "" {
			return fail()
		}
	}
	if values["--egress"] != "local-only" {
		return fail()
	}
	format := values["--format"]
	if format == "" {
		format = "json"
	}
	if format != "json" && format != "text" {
		return fail()
	}
	timeout, err := parseWholeMillisecondDuration(values["--timeout"])
	if err != nil || timeout < time.Second || timeout > 15*time.Minute {
		return fail()
	}
	validFor, err := parseWholeMillisecondDuration(values["--valid-for"])
	if err != nil || validFor <= timeout || validFor > 168*time.Hour {
		return fail()
	}
	repository, err := evidence.NewRepositoryIdentity(values["--repository-authority"], strings.Split(values["--repository-namespace"], "/"), values["--repository-name"])
	if err != nil {
		return fail()
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithm(values["--revision-algorithm"]), values["--head-revision-digest"])
	if err != nil {
		return fail()
	}
	if _, err := memory.NewScope(values["--tenant"], values["--repository"], "local-reviewer", memory.RefVisibilityExact, head.Identity(), []string{"."}); err != nil {
		return fail()
	}
	options = localGitRetainedMemoryInputOptions{
		inventory:  values["--route-inventory"],
		policy:     values["--runtime-policy"],
		feedback:   values["--feedback-input"],
		output:     values["--output"],
		tenant:     values["--tenant"],
		repository: values["--repository"],
		format:     format,
		timeout:    timeout,
		validFor:   validFor,
	}
	return options, repository, head, nil
}

func parseWholeMillisecondDuration(value string) (time.Duration, error) {
	duration, err := time.ParseDuration(value)
	if err != nil || duration%time.Millisecond != 0 {
		return 0, fmt.Errorf("invalid duration")
	}
	return duration, nil
}

func writeLocalGitRetainedMemoryInputReceipt(format string, receipt localGitRetainedMemoryInputReceipt, stdout io.Writer) error {
	if format == "text" {
		text := fmt.Sprintf("status: %s\nretained_memory_input_identity: %s\nscope_identity: %s\nrepository_identity: %s\nhead_revision_identity: %s\nruntime_policy_identity: %s\nrecord_count: %d\npath_count: %d\nexpires_at_unix_ms: %d\n", receipt.Status, receipt.RetainedMemoryInputIdentity, receipt.ScopeIdentity, receipt.RepositoryIdentity, receipt.HeadRevisionIdentity, receipt.RuntimePolicyIdentity, receipt.RecordCount, receipt.PathCount, receipt.ExpiresAtUnixMilliseconds)
		written, err := io.WriteString(stdout, text)
		if err == nil && written != len(text) {
			return io.ErrShortWrite
		}
		return err
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	written, err := stdout.Write(encoded)
	if err != nil {
		return err
	}
	if written != len(encoded) {
		return io.ErrShortWrite
	}
	return nil
}

func writeLocalGitRetainedMemoryInputUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle local-git retained-memory-input --repository-authority AUTHORITY --repository-namespace SEGMENT[/SEGMENT...] --repository-name NAME --revision-algorithm sha1|sha256 --head-revision-digest HEX --tenant ID --repository ID --route-inventory PATH --runtime-policy PATH --egress local-only --timeout DURATION --valid-for DURATION --feedback-input PATH --output PATH [--format json|text]")
}
