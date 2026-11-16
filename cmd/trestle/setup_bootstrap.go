package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/localownerroot"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/routehint"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

type setupBootstrapManifest struct {
	Contract               string   `json:"contract"`
	Version                int      `json:"schema_version"`
	Inventory              string   `json:"inventory_identity"`
	Policy                 string   `json:"runtime_policy_identity"`
	Root                   string   `json:"setup_root_identity"`
	Objects                string   `json:"objects_root"`
	Algorithm              string   `json:"revision_algorithm"`
	Run                    string   `json:"run"`
	CreatedAt              int64    `json:"created_at_unix_milliseconds"`
	ReviewCommand          []string `json:"review_command"`
	EphemeralReviewCommand []string `json:"ephemeral_review_command"`
	StatusCommand          []string `json:"status_command"`
	LaunchCommand          []string `json:"launch_command"`
	// Scope is empty for the daemon setup. "direct-review" records a setup for
	// the foreground checkout review only; it carries no daemon commands.
	Scope string `json:"scope,omitempty"`
}

// The direct-review scope prepares only the foreground
// `local-git model-review --checkout` path. That path reads objects through a
// pinned root and authenticates every object by its digest, so it needs neither
// the daemon's private 0700 objects root nor loose objects. The daemon scope
// (the default) is unchanged.
const setupBootstrapDirectReviewScope = "direct-review"

type setupBootstrapReviewIntent struct {
	Root      string `json:"setup_root_identity"`
	Inventory string `json:"inventory_identity"`
	Policy    string `json:"runtime_policy_identity"`
	CreatedAt int64  `json:"created_at_unix_milliseconds"`
}

type setupBootstrapResult struct {
	Contract               string   `json:"contract"`
	Version                int      `json:"schema_version"`
	Status                 string   `json:"status"`
	Ready                  bool     `json:"ready"`
	Plan                   string   `json:"plan_identity,omitempty"`
	Pending                []string `json:"pending_checks"`
	ReviewCommand          []string `json:"review_command,omitempty"`
	EphemeralReviewCommand []string `json:"ephemeral_review_command,omitempty"`
	StatusCommand          []string `json:"status_command,omitempty"`
	LaunchCommand          []string `json:"launch_command,omitempty"`
	Limitations            []string `json:"limitations"`
	Scope                  string   `json:"scope,omitempty"`
	// Messages names, in fixed words, why this check's synthetic probe was
	// refused when a model server refused it; it is absent otherwise.
	Messages []string `json:"messages,omitempty"`
}

func runSetupBootstrap(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runSetupBootstrapWithContext(ctx, args, stdout, stderr, systemSetupClock{})
}

func runSetupBootstrapWithClock(args []string, stdout, stderr io.Writer, clock setupClock) int {
	return runSetupBootstrapWithContext(context.Background(), args, stdout, stderr, clock)
}

func runSetupBootstrapWithContext(ctx context.Context, args []string, stdout, stderr io.Writer, clock setupClock) int {
	if ctx == nil || ctx.Err() != nil {
		return writeSetupBootstrapRefusal(stdout)
	}
	if len(args) == 0 || clock == nil {
		writeSetupBootstrapUsage(stderr)
		return 2
	}
	if remoteSetupBootstrapRequested(args) {
		return runRemoteSetupBootstrap(ctx, args, stdout, stderr, clock)
	}
	seen := map[string]bool{}
	for _, argument := range args[1:] {
		if !strings.HasPrefix(argument, "-") {
			continue
		}
		name := strings.SplitN(argument, "=", 2)[0]
		name = strings.TrimLeft(name, "-")
		if seen[name] {
			writeSetupBootstrapUsage(stderr)
			return 2
		}
		seen[name] = true
	}
	flags := flag.NewFlagSet("trestle setup bootstrap "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "existing private bootstrap directory")
	values := map[string]*string{}
	for _, name := range []string{"tenant", "repository", "recovery-owner", "checkout", "base", "head", "repository-authority", "repository-namespace", "repository-name", "generation-endpoint", "generation-model", "generation-credential-environment", "verification-endpoint", "verification-model", "verification-credential-environment", "transport", "approved-by", "backup-directory"} {
		values[name] = flags.String(name, "", name)
	}
	specialists := flags.String("specialists", "", "auto (default) or none: whether the saved review runs specialist reviews")
	contextTokens := flags.Uint64("context-tokens", 0, "declared capacity of both models")
	outputTokens := flags.Uint64("output-tokens", 0, "declared output capacity of both models")
	reviewOutputTokens := flags.Uint64("max-output-tokens", 4096, "per-request review output allowance, from 4096 to --output-tokens")
	declare := flags.Bool("declare-local-capabilities", false, "declare local models, structured output, no logging, zero inference price and current availability")
	probe := flags.Bool("allow-local-probe", false, "permit two bounded synthetic local model requests, not repository source")
	scope := flags.String("scope", "", "daemon (default) or direct-review")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *directory == "" || *scope != "" && *scope != "daemon" && *scope != setupBootstrapDirectReviewScope || !validSetupSpecialists(*specialists) {
		writeSetupBootstrapUsage(stderr)
		return 2
	}
	allowed := map[string]bool{"directory": true}
	switch args[0] {
	case "init":
		for name := range values {
			allowed[name] = name != "approved-by" && name != "backup-directory"
		}
		allowed["context-tokens"], allowed["output-tokens"], allowed["declare-local-capabilities"], allowed["scope"] = true, true, true, true
		allowed["max-output-tokens"], allowed["specialists"] = true, true
	case "check":
		allowed["approved-by"], allowed["backup-directory"], allowed["allow-local-probe"], allowed["scope"] = true, true, true, true
	case "inspect", "prepare-review":
	default:
		writeSetupBootstrapUsage(stderr)
		return 2
	}
	invalid := false
	flags.Visit(func(f *flag.Flag) {
		if !allowed[f.Name] {
			invalid = true
		}
	})
	if invalid {
		writeSetupBootstrapUsage(stderr)
		return 2
	}
	directoryAbs, err := filepath.Abs(*directory)
	if err != nil {
		return writeSetupBootstrapRefusal(stdout)
	}
	info, err := os.Lstat(directoryAbs)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || fileauthority.CheckDirectory(directoryAbs) != nil {
		return writeSetupBootstrapRefusal(stdout)
	}
	for _, name := range []string{"plan.json", "plan.json.lock", "plan.json.receipts", "plan.json.next"} {
		if _, err := os.Lstat(filepath.Join(directoryAbs, name)); !os.IsNotExist(err) {
			return writeSetupBootstrapRefusal(stdout)
		}
	}
	if args[0] == "init" {
		for name, value := range values {
			if allowed[name] && (len(*value) > 4096 || !strings.HasSuffix(name, "-credential-environment") && *value == "") {
				writeSetupBootstrapUsage(stderr)
				return 2
			}
		}
		if !*declare || *contextTokens < 8192 || *outputTokens < 4096 || *outputTokens > *contextTokens || *reviewOutputTokens < 4096 || *reviewOutputTokens > *outputTokens || *values["generation-model"] == *values["verification-model"] || (*values["transport"] != "openai_responses" && *values["transport"] != "openai_chat_completions") {
			writeSetupBootstrapUsage(stderr)
			return 2
		}
		// A local Ollama daemon also relays Ollama Cloud models; those would send
		// source off this machine, so the local route refuses them by the
		// daemon's own model list (one bounded loopback GET), or by name.
		for _, role := range []string{"generation", "verification"} {
			if err := ollamaLocalModelError(ctx, *values[role+"-endpoint"], *values[role+"-model"]); err != nil {
				fmt.Fprintln(stderr, "trestle setup bootstrap: "+err.Error())
				return writeSetupBootstrapRefusal(stdout)
			}
		}
		// --specialists is optional (absent is auto), so it joins the values
		// only after the required ones were checked.
		values["specialists"] = specialists
		if err := initializeSetupBootstrap(ctx, directoryAbs, values, *contextTokens, *outputTokens, *reviewOutputTokens, *scope == setupBootstrapDirectReviewScope, clock); err != nil {
			return writeSetupBootstrapRefusal(stdout)
		}
	}
	manifest, plan, inventory, policy, err := loadSetupBootstrap(ctx, directoryAbs)
	if err != nil {
		return writeSetupBootstrapRefusal(stdout)
	}
	// A direct-review setup never qualifies its source for the daemon, so it
	// cannot be checked or prepared as one. A daemon setup may be checked in the
	// narrower direct-review scope; its daemon checks and commands are untouched.
	direct := manifest.Scope == setupBootstrapDirectReviewScope || *scope == setupBootstrapDirectReviewScope
	if manifest.Scope == setupBootstrapDirectReviewScope && (*scope == "daemon" || args[0] == "prepare-review") {
		return writeSetupBootstrapRefusal(stdout)
	}
	if direct && *values["backup-directory"] != "" {
		writeSetupBootstrapUsage(stderr)
		return 2
	}
	var probeMessages []string
	if args[0] == "check" {
		if *values["approved-by"] != plan.RecoveryOwner() {
			return writeSetupBootstrapRefusal(stdout)
		}
		probeMessages, err = checkSetupBootstrap(ctx, directoryAbs, *values["backup-directory"], *values["approved-by"], *probe, direct, plan, inventory, policy, clock)
		if err != nil {
			return writeSetupBootstrapRefusal(stdout)
		}
		manifest, plan, _, _, err = loadSetupBootstrap(ctx, directoryAbs)
		if err != nil {
			return writeSetupBootstrapRefusal(stdout)
		}
	}
	intentPath := filepath.Join(directoryAbs, "review-intent.json")
	if args[0] == "prepare-review" {
		if !plan.Ready() {
			return writeSetupBootstrapRefusal(stdout)
		}
		if _, err := os.Lstat(intentPath); os.IsNotExist(err) {
			intent := setupBootstrapReviewIntent{Root: manifest.Root, Inventory: manifest.Inventory, Policy: manifest.Policy, CreatedAt: clock.Now().UTC().UnixMilli()}
			encoded, _ := json.Marshal(intent)
			if fileauthority.WriteNewProtectedFile(ctx, intentPath, encoded, 65536) != nil {
				return writeSetupBootstrapRefusal(stdout)
			}
		}
	}
	manifest.ReviewCommand = nil
	if _, err := os.Lstat(intentPath); !os.IsNotExist(err) {
		content, err := readSetupBootstrapFile(intentPath)
		var intent setupBootstrapReviewIntent
		decoder := json.NewDecoder(bytes.NewReader(content))
		decoder.DisallowUnknownFields()
		if err != nil || decoder.Decode(&intent) != nil || decoder.Decode(&struct{}{}) != io.EOF || intent.Root != manifest.Root || intent.Inventory != manifest.Inventory || intent.Policy != manifest.Policy || intent.CreatedAt <= 0 {
			return writeSetupBootstrapRefusal(stdout)
		}
		manifest.CreatedAt = intent.CreatedAt
		manifest.ReviewCommand, _, _ = setupBootstrapCommands(directoryAbs, manifest, plan, policy, manifest.EphemeralReviewCommand[3:])
	}
	result := setupBootstrapResult{Contract: "open-trestle/local-first-bootstrap-result", Version: 1, Status: "pending", Ready: plan.Ready(), Plan: plan.Identity(), Pending: []string{}, ReviewCommand: manifest.ReviewCommand, EphemeralReviewCommand: manifest.EphemeralReviewCommand, StatusCommand: manifest.StatusCommand, LaunchCommand: manifest.LaunchCommand, Limitations: setupBootstrapLimitations(), Messages: probeMessages}
	if direct {
		// Readiness covers only the checks the foreground review relies on; the
		// daemon commands are omitted because this result does not qualify them.
		result.Scope, result.ReviewCommand, result.StatusCommand, result.LaunchCommand = setupBootstrapDirectReviewScope, nil, nil, nil
		result.Limitations = append(result.Limitations, "direct_review_scope_excludes_daemon_checks")
		result.Ready = true
	}
	for _, requirement := range plan.Requirements() {
		if direct && !setupDirectReviewRequirement(requirement, *probe && args[0] == "check") {
			continue
		}
		if direct && requirement.State() != setupcore.CheckPassed {
			result.Ready = false
		}
		if requirement.State() != setupcore.CheckPassed {
			result.Pending = append(result.Pending, string(requirement.Key()))
			if requirement.State() == setupcore.CheckBlocked {
				result.Status = "refused"
			}
		}
	}
	if result.Ready {
		result.Status = "ready"
	}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write bootstrap result failed")
		return 1
	}
	if result.Ready {
		return 0
	}
	if result.Status == "refused" {
		return 4
	}
	return 3
}

// setupDirectReviewRequirement reports whether the direct-review scope needs a
// plan requirement. The daemon's observer credentials and backup are excluded.
// The synthetic local inference probe counts once it was requested or attempted,
// so a failed probe is never hidden by a later check without the probe.
func setupDirectReviewRequirement(requirement setupcore.Requirement, probeRequested bool) bool {
	switch requirement.Key() {
	case setupcore.CheckObserverCredentialPostureValidated, setupcore.CheckBackupValidated:
		return false
	case setupcore.CheckLocalInferenceValidated:
		return probeRequested || requirement.State() != setupcore.CheckPending
	}
	return true
}

func setupBootstrapLimitations() []string {
	return []string{"operator_declared_model_capabilities_not_service_conformance", "ready_is_setup_checks_not_release_or_review_clearance", "foreground_review_is_ephemeral_no_resume", "durable_daemon_source_is_loose_objects_only", "no_publication", "no_model_download_or_credential_provisioning"}
}

func writeSetupBootstrapRefusal(stdout io.Writer) int {
	result := setupBootstrapResult{Contract: "open-trestle/local-first-bootstrap-result", Version: 1, Status: "refused", Pending: []string{}, Limitations: setupBootstrapLimitations()}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return 1
	}
	return 4
}

// validSetupSpecialists accepts the --specialists values setup takes: auto
// (the default when absent) or none.
func validSetupSpecialists(value string) bool {
	return value == "" || value == specialistModeAuto || value == specialistModeNone
}

// setupSpecialistsArgs is what a new setup saves in its review command: a
// specialist review set (--specialists auto, the default) unless the operator
// chose none, which saves the single general review. Setups saved before
// specialists were the default have neither and keep the single review.
func setupSpecialistsArgs(value string) []string {
	if value == specialistModeNone {
		return nil
	}
	return []string{"--specialists", specialistModeAuto}
}

func initializeSetupBootstrap(ctx context.Context, dir string, values map[string]*string, contextTokens, outputTokens, reviewOutputTokens uint64, direct bool, clock setupClock) error {
	value := func(name string) string { return *values[name] }
	specialists := ""
	if values["specialists"] != nil {
		specialists = *values["specialists"]
	}
	for _, name := range []string{"generation-endpoint", "verification-endpoint"} {
		locality, err := provider.ClassifyServiceEndpoint(value(name))
		if err != nil || locality != provider.ServiceEndpointLoopback {
			return errors.New("nonlocal endpoint")
		}
	}
	checkout, err := filepath.Abs(value("checkout"))
	if err != nil {
		return err
	}
	source, err := resolveLocalCheckout(ctx, checkout, value("base"), value("head"))
	if err != nil {
		return err
	}
	if direct {
		if err := setupCheckDirectReviewSource(ctx, source); err != nil {
			return err
		}
	} else if err := setupCheckDurableSource(source, value); err != nil {
		return err
	}
	// Validate scope and repository labels before writing any configuration.
	reviewArgs := []string{"--checkout", checkout, "--base", source.base, "--head", source.head, "--repository-authority", value("repository-authority"), "--repository-namespace", value("repository-namespace"), "--repository-name", value("repository-name"), "--tenant", value("tenant"), "--repository", value("repository"), "--route-inventory", filepath.Join(dir, "routes.json"), "--runtime-policy", filepath.Join(dir, "policy.json"), "--egress", "local-only", "--timeout", "5m", "--format", "text"}
	reviewArgs = append(reviewArgs, setupSpecialistsArgs(specialists)...)
	if _, _, _, _, err := parseLocalModelReview(reviewArgs); err != nil {
		return err
	}
	plan, err := setupcore.NewCurrentPlan(setupcore.ProfileLocalSingleNode, value("tenant"), value("repository"), value("recovery-owner"), clock.Now())
	if err != nil {
		return err
	}
	if err := ensureSetupBootstrapDirectories(ctx, dir); err != nil {
		return err
	}
	routes := []map[string]any{}
	connections := []map[string]string{}
	for _, role := range []string{"generation", "verification"} {
		declaration, _ := json.Marshal(map[string]any{"contract": "open-trestle/operator-local-bootstrap-declaration", "schema_version": 1, "declared_by": value("recovery-owner"), "role": role, "model": value(role + "-model"), "limitations": "operator declaration, not measured health or service conformance"})
		routes = append(routes, map[string]any{"zone": "local", "provider_id": "local-bootstrap", "adapter_id": "bootstrap-" + role, "connection_id": "bootstrap-" + role, "model_id": value(role + "-model"), "model_version": "", "max_context_tokens": contextTokens, "max_output_tokens": outputTokens, "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": 0, "output_micro_usd_per_million_tokens": 0, "quality": "tier_1", "registry_revision": 1, "registry_status": "approved", "evidence_manifest_base64": base64.StdEncoding.EncodeToString(declaration), "operational_revision": 1, "health": "healthy", "quota": "available", "performance_revision": 1, "latency_known": false, "p95_latency_milliseconds": 0, "latency_sample_count": 0})
		connection := map[string]string{"implementation": value("transport"), "adapter_id": "bootstrap-" + role, "endpoint": value(role + "-endpoint"), "credential_mode": "none"}
		if environment := value(role + "-credential-environment"); environment != "" {
			delete(connection, "credential_mode")
			connection["credential_environment"] = environment
		}
		connections = append(connections, connection)
	}
	inventoryBytes, _ := json.Marshal(map[string]any{"schema_version": 1, "routes": routes})
	inventory, err := runtimeconfig.DecodeRouteInventory(ctx, bytes.NewReader(inventoryBytes))
	if err != nil {
		return err
	}
	reviewPolicy := sha256.Sum256([]byte("open-trestle/local-first-bootstrap/review-policy/v1/local-only/distinct-model/no-publication"))
	templateBytes, _ := json.Marshal(map[string]any{"schema_version": 2, "inventory_identity": inventory.Identity(), "review_policy_identity": hex.EncodeToString(reviewPolicy[:]), "verification_route_record_identity": strings.Repeat("0", 64), "min_context_tokens": 1, "min_output_tokens": 1, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{"local"}, "content_logging_allowed": false, "estimated_input_tokens": 1, "max_output_tokens": reviewOutputTokens, "max_cost_micro_usd": 0, "pinned_route_record_identity": "", "preferred_route_record_identities": []string{}, "verification_independence": "distinct_model", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_model", "publication_block_on_inconclusive": true, "connections": connections})
	for name, content := range map[string][]byte{"routes.json": inventoryBytes, "policy-template.json": templateBytes} {
		if err := ensureSetupBootstrapFile(ctx, filepath.Join(dir, name), content); err != nil {
			return err
		}
	}
	bound, err := runtimeconfig.BindProtectedRuntimePolicy(ctx, filepath.Join(dir, "routes.json"), filepath.Join(dir, "policy-template.json"), "bootstrap-generation", "bootstrap-verification")
	if err != nil {
		return err
	}
	if err := ensureSetupBootstrapFile(ctx, filepath.Join(dir, "policy.json"), bound); err != nil {
		return err
	}
	_, policy, err := runtimeconfig.LoadProtectedConfiguration(ctx, filepath.Join(dir, "routes.json"), filepath.Join(dir, "policy.json"))
	if err != nil {
		return err
	}
	state := filepath.Join(dir, "runs", "setup", "plan.json")
	if _, err := os.Lstat(state); os.IsNotExist(err) {
		store, err := setupcore.OpenStateFile(state)
		if err != nil {
			return err
		}
		err = store.Initialize(ctx, plan)
		closeErr := store.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	}
	plan, err = setupcore.InspectStateFile(ctx, state)
	if err != nil || plan.TenantID() != value("tenant") || plan.RepositoryID() != value("repository") || plan.RecoveryOwner() != value("recovery-owner") || plan.Profile() != setupcore.ProfileLocalSingleNode {
		return errors.New("setup scope mismatch")
	}
	manifest := setupBootstrapManifest{Contract: "open-trestle/local-first-bootstrap", Version: 1, Inventory: inventory.Identity(), Policy: policy.Identity(), Root: plan.RootIdentity(), Objects: source.objects, Algorithm: source.algorithm, Run: "first-review", CreatedAt: plan.CreatedAt().UnixMilli(), EphemeralReviewCommand: append([]string{"trestle", "local-git", "model-review"}, reviewArgs...)}
	if direct {
		manifest.Scope = setupBootstrapDirectReviewScope
	} else {
		manifest.ReviewCommand, manifest.LaunchCommand, manifest.StatusCommand = setupBootstrapCommands(dir, manifest, plan, policy, reviewArgs)
	}

	encoded, _ := json.Marshal(manifest)
	return ensureSetupBootstrapFile(ctx, filepath.Join(dir, "bootstrap.json"), encoded)
}

// setupCheckDurableSource keeps the daemon's source rules: the objects folder is
// an owner-only 0700 root it can pin for its whole lifetime, and both commits
// are complete loose objects.
func setupCheckDurableSource(source localCheckoutSource, value func(string) string) error {
	root, err := localownerroot.ExistingRoot(source.objects, localownerroot.ErrUnsafePath)
	if err != nil {
		return err
	}
	if root == nil {
		return errors.New("durable source unavailable")
	}
	if _, err := localownerroot.ObserveDirectory(source.objects, root, localownerroot.ErrUnsafePath); err != nil {
		_ = root.Close()
		return err
	}
	repository, err := evidence.NewRepositoryIdentity(value("repository-authority"), strings.Split(value("repository-namespace"), "/"), value("repository-name"))
	if err != nil {
		_ = root.Close()
		return err
	}
	base, baseErr := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithm(source.algorithm), source.base)
	head, headErr := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithm(source.algorithm), source.head)
	_, inspectBaseErr := buildLocalGitInspectResult(root, repository, base)
	_, inspectHeadErr := buildLocalGitInspectResult(root, repository, head)
	closeErr := root.Close()
	if baseErr != nil || headErr != nil || inspectBaseErr != nil || inspectHeadErr != nil || closeErr != nil {
		return errors.New("durable source requires complete loose objects")
	}
	return nil
}

// setupCheckDirectReviewSource confirms that the foreground checkout review can
// read both selected commits with the reader it uses: a pinned objects root, the
// packed-layout rules (no alternates, multi-pack-index or promisor packs) and
// the loose-and-pack-index-v1 store, which verifies each object's digest. It
// reads two commit objects and nothing else.
func setupCheckDirectReviewSource(ctx context.Context, source localCheckoutSource) error {
	root, err := os.OpenRoot(source.objects)
	if err != nil {
		return errors.New("the Git objects folder cannot be opened")
	}
	defer root.Close()
	if err := scm.ValidateLocalGitPackedLayout(root); err != nil {
		return err
	}
	// The labels only scope the reader; they do not affect what is read.
	repository, err := evidence.NewRepositoryIdentity("local", []string{"open-trestle"}, "source-check")
	if err != nil {
		return err
	}
	algorithm := evidence.RevisionAlgorithm(source.algorithm)
	store, err := scm.NewLocalGitObjectStoreWithOptions(scm.LocalGitObjectStoreOptions{ObjectsRoot: root, Repository: repository, Profile: scm.LocalGitObjectStoreProfileLooseAndPackIndexV1, ObjectAlgorithm: algorithm})
	if err != nil {
		return err
	}
	var readErr error
	for _, commit := range []string{source.base, source.head} {
		revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, commit)
		if err == nil {
			_, err = store.ReadCommit(ctx, revision)
		}
		if err != nil && readErr == nil {
			readErr = fmt.Errorf("commit %s cannot be read: %w", commit[:min(len(commit), 12)], err)
		}
	}
	closing, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return errors.Join(readErr, store.Close(closing))
}

func ensureSetupBootstrapDirectories(ctx context.Context, dir string) error {
	for _, path := range []string{filepath.Join(dir, "runs"), filepath.Join(dir, "runs", "setup")} {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		parent, err := fileauthority.PinDirectory(filepath.Dir(path))
		if err != nil {
			return err
		}
		created := false
		if err := os.Mkdir(path, 0700); err != nil {
			if !os.IsExist(err) {
				return err
			}
		} else {
			created = true
		}
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || fileauthority.CheckDirectory(path) != nil || parent.Recheck() != nil {
			return errors.New("unsafe bootstrap setup directory")
		}
		if created {
			file, err := os.Open(filepath.Dir(path))
			if err != nil {
				return err
			}
			err = file.Sync()
			closeErr := file.Close()
			if err != nil || closeErr != nil {
				return errors.Join(err, closeErr)
			}
		}
	}
	return nil
}

func ensureSetupBootstrapFile(ctx context.Context, path string, content []byte) error {
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return fileauthority.WriteNewProtectedFile(ctx, path, content, 65536)
	}
	existing, err := readSetupBootstrapFile(path)
	if err != nil || !bytes.Equal(existing, content) {
		return errors.New("existing bootstrap output differs")
	}
	return nil
}

func readSetupBootstrapFile(path string) ([]byte, error) {
	file, err := fileauthority.OpenReadOnly(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || info.Mode().Perm() != 0600 {
		return nil, errors.New("unsafe bootstrap file")
	}
	content, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(content) > 65536 {
		return nil, errors.New("invalid bootstrap file")
	}
	return content, nil
}

func loadSetupBootstrap(ctx context.Context, dir string) (setupBootstrapManifest, setupcore.Plan, runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy, error) {
	var manifest setupBootstrapManifest
	fail := func() (setupBootstrapManifest, setupcore.Plan, runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy, error) {
		return manifest, setupcore.Plan{}, runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, errors.New("bootstrap configuration refused")
	}
	for _, path := range []string{filepath.Join(dir, "runs"), filepath.Join(dir, "runs", "setup")} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || fileauthority.CheckDirectory(path) != nil {
			return fail()
		}
	}
	for _, name := range []string{"routes.json", "policy-template.json", "policy.json"} {
		if _, err := readSetupBootstrapFile(filepath.Join(dir, name)); err != nil {
			return fail()
		}
	}
	content, err := readSetupBootstrapFile(filepath.Join(dir, "bootstrap.json"))
	if err != nil {
		return fail()
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(&struct{}{}) != io.EOF || manifest.Contract != "open-trestle/local-first-bootstrap" || manifest.Version != 1 {
		return fail()
	}
	plan, err := setupcore.InspectStateFile(ctx, filepath.Join(dir, "runs", "setup", "plan.json"))
	if err != nil || plan.Profile() != setupcore.ProfileLocalSingleNode || plan.RootIdentity() != manifest.Root {
		return fail()
	}
	inventory, policy, err := runtimeconfig.LoadProtectedConfiguration(ctx, filepath.Join(dir, "routes.json"), filepath.Join(dir, "policy.json"))
	if err != nil || inventory.Identity() != manifest.Inventory || policy.Identity() != manifest.Policy {
		return fail()
	}
	if len(manifest.EphemeralReviewCommand) < 3 || strings.Join(manifest.EphemeralReviewCommand[:3], " ") != "trestle local-git model-review" {
		return fail()
	}
	options, _, _, _, err := parseLocalModelReview(manifest.EphemeralReviewCommand[3:])
	if err != nil || options.tenant != plan.TenantID() || options.repository != plan.RepositoryID() || options.inventory != filepath.Join(dir, "routes.json") || options.policy != filepath.Join(dir, "policy.json") || options.egress != "local-only" {
		return fail()
	}
	if _, err := runtimecatalog.ResolveLocalGenerationRoutePair(policy, inventory); err != nil {
		return fail()
	}
	expectedReview, expectedLaunch, expectedStatus := setupBootstrapCommands(dir, manifest, plan, policy, manifest.EphemeralReviewCommand[3:])
	switch manifest.Scope {
	case "":
	case setupBootstrapDirectReviewScope:
		expectedReview, expectedLaunch, expectedStatus = nil, nil, nil
	default:
		return fail()
	}
	if !slices.Equal(manifest.LaunchCommand, expectedLaunch) || !slices.Equal(manifest.ReviewCommand, expectedReview) || !slices.Equal(manifest.StatusCommand, expectedStatus) || !filepath.IsAbs(manifest.Objects) || (manifest.Algorithm != "sha1" && manifest.Algorithm != "sha256") || manifest.Run != "first-review" || manifest.CreatedAt != plan.CreatedAt().UnixMilli() {
		return fail()
	}
	if !filepath.IsAbs(options.checkout) || strings.HasPrefix(options.baseSelection, "refs/") || options.baseSelection == "HEAD" || strings.HasPrefix(options.headSelection, "refs/") || options.headSelection == "HEAD" {
		return fail()
	}
	// A direct-review setup keeps working after its setup-time commits are
	// rewritten or collected: every review picks its own commits, so only the
	// checkout's objects folder and format must still match. The daemon's
	// submit command binds those commits, so a daemon setup still needs them.
	if manifest.Scope == setupBootstrapDirectReviewScope {
		objects, algorithm, err := resolveLocalCheckoutObjects(ctx, options.checkout)
		if err != nil || objects != manifest.Objects || algorithm != manifest.Algorithm {
			return fail()
		}
		return manifest, plan, inventory, policy, nil
	}
	resolved, err := resolveLocalCheckout(ctx, options.checkout, options.baseSelection, options.headSelection)
	if err != nil || resolved.objects != manifest.Objects || resolved.algorithm != manifest.Algorithm {
		return fail()
	}
	return manifest, plan, inventory, policy, nil
}

// setupProbeRefusal names a model server's refusal of the synthetic local
// probe in the fixed words a review prints for the same refusal, or returns
// nil. No probe, a probe that passed or failed otherwise, names none.
func setupProbeRefusal(inference *setupcore.LocalInferenceChecker) []string {
	failure, sent := inference.ProbeFailure()
	if !sent {
		return nil
	}
	detail, hint, ok := routehint.ProviderRefusal(failure)
	if !ok {
		return nil
	}
	return []string{string(setupcore.CheckLocalInferenceValidated) + ": " + detail + ": " + hint}
}

// checkSetupBootstrap runs the setup checks that have not passed, in order,
// and returns the fixed reason a refused local probe gives, if any.
func checkSetupBootstrap(ctx context.Context, dir, backupDir, owner string, allowProbe, direct bool, plan setupcore.Plan, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy, clock setupClock) ([]string, error) {
	store, err := setupcore.OpenStateFile(filepath.Join(dir, "runs", "setup", "plan.json"))
	if err != nil {
		return nil, err
	}
	defer store.Close()
	approval, err := setupcore.NewRuntimePolicyApproval(plan, inventory.Identity(), policy.Identity(), policy.ReviewPolicyIdentity(), owner)
	if err != nil {
		return nil, err
	}
	policyChecker, err := setupcore.NewRuntimePolicyFileChecker(filepath.Join(dir, "routes.json"), filepath.Join(dir, "policy.json"), approval)
	if err != nil {
		return nil, err
	}
	storage, err := setupcore.NewStateStorageChecker(filepath.Join(dir, "runs", "setup"))
	if err != nil {
		return nil, err
	}
	administrator, err := setupcore.NewLocalAdministratorChecker(plan, owner)
	if err != nil {
		return nil, err
	}
	observer, err := setupcore.NewObserverCredentialPostureChecker(os.Getenv)
	if err != nil {
		return nil, err
	}
	dryRun, err := setupcore.NewDryRunChecker(policyChecker)
	if err != nil {
		return nil, err
	}
	checkers := []setupcore.Checker{storage, administrator, observer, policyChecker, dryRun}
	if direct {
		// The foreground review never reads the daemon's API/observer tokens.
		checkers = []setupcore.Checker{storage, administrator, policyChecker, dryRun}
	}
	var inference *setupcore.LocalInferenceChecker
	if allowProbe {
		factory, err := newSetupLocalInferenceFactory(providerCredentialLookup)
		if err != nil {
			return nil, err
		}
		inference, err = setupcore.NewLocalInferenceChecker(policyChecker, factory)
		if err != nil {
			return nil, err
		}
		checkers = append(checkers, inference)
	}
	for _, checker := range checkers {
		current, err := store.Current(ctx)
		if err != nil {
			return nil, err
		}
		passed := false
		for _, r := range current.Requirements() {
			if r.Key() == checker.Key() && r.State() == setupcore.CheckPassed {
				passed = true
			}
		}
		if passed {
			continue
		}
		runner, err := setupcore.NewRunner(store, []setupcore.Checker{checker}, clock)
		if err != nil {
			return nil, err
		}
		_, receipt, err := runner.Run(ctx, checker.Key())
		if err != nil {
			return nil, err
		}
		if receipt.State() != setupcore.CheckPassed {
			return setupProbeRefusal(inference), nil
		}
	}
	current, err := store.Current(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range current.Requirements() {
		if r.Key() == setupcore.CheckBackupValidated && r.State() == setupcore.CheckPassed {
			return nil, nil
		}
	}
	if backupDir == "" {
		return nil, nil
	}
	backupDir, err = filepath.Abs(backupDir)
	if err != nil {
		return nil, err
	}
	// Backup creation inspects the live state independently, so release its writer first.
	if err := store.Close(); err != nil {
		return nil, err
	}
	snapshot := filepath.Join(backupDir, current.Identity()+".json")
	if _, err := os.Lstat(snapshot); os.IsNotExist(err) {
		if _, err := setupcore.CreateBackupSnapshot(ctx, filepath.Join(dir, "runs", "setup", "plan.json"), snapshot, current.Identity()); err != nil {
			return nil, err
		}
	}
	backup, err := setupcore.NewBackupSnapshotChecker(filepath.Join(dir, "runs", "setup", "plan.json"), snapshot, current)
	if err != nil {
		return nil, err
	}
	reopened, err := setupcore.OpenStateFile(filepath.Join(dir, "runs", "setup", "plan.json"))
	if err != nil {
		return nil, err
	}
	defer reopened.Close()
	runner, err := setupcore.NewRunner(reopened, []setupcore.Checker{backup}, clock)
	if err != nil {
		return nil, err
	}
	_, _, err = runner.Run(ctx, backup.Key())
	return nil, err
}

func writeSetupBootstrapUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle setup bootstrap init --directory PATH --tenant ID --repository ID --recovery-owner NAME --checkout PATH --base FULL_REF_OR_COMMIT --head FULL_REF_OR_COMMIT --repository-authority LABEL --repository-namespace NAME --repository-name NAME --generation-endpoint URL --generation-model ID --verification-endpoint URL --verification-model ID --transport openai_responses|openai_chat_completions --context-tokens N --output-tokens N [--max-output-tokens N] --declare-local-capabilities [--scope direct-review]")
	fmt.Fprintln(w, "       trestle setup bootstrap check --directory PATH --approved-by NAME [--scope direct-review] [--allow-local-probe] [--backup-directory PATH]")
	fmt.Fprintln(w, "       trestle setup bootstrap inspect --directory PATH")
	fmt.Fprintln(w, "       trestle setup bootstrap prepare-review --directory PATH")
	fmt.Fprintln(w, "remote models: trestle setup bootstrap init --provider openrouter-zdr|opencode-go|ollama-cloud ... (see docs/remote-model-review.md)")
}

func setupBootstrapCommands(dir string, manifest setupBootstrapManifest, plan setupcore.Plan, policy runtimeconfig.RuntimePolicy, sourceArgs []string) ([]string, []string, []string) {
	values := map[string]string{}
	for i := 0; i < len(sourceArgs); i += 2 {
		values[sourceArgs[i]] = sourceArgs[i+1]
	}
	source := []string{"--objects-root", manifest.Objects, "--repository-authority", values["--repository-authority"], "--repository-namespace", values["--repository-namespace"], "--repository-name", values["--repository-name"], "--revision-algorithm", manifest.Algorithm, "--base-revision-digest", values["--base"], "--head-revision-digest", values["--head"]}
	submit := append([]string{"trestle", "local-git", "submit-review"}, source...)
	submit = append(submit, "--server", "http://127.0.0.1:8741", "--tenant", plan.TenantID(), "--repository", plan.RepositoryID(), "--run", manifest.Run, "--review-policy-identity", policy.ReviewPolicyIdentity(), "--inventory-identity", manifest.Inventory, "--runtime-policy-identity", manifest.Policy, "--created-at-unix-milliseconds", strconv.FormatInt(manifest.CreatedAt, 10))
	launch := []string{"trestled", "--listen", "127.0.0.1:8741", "--state-dir", filepath.Join(dir, "runs"), "--setup-state", filepath.Join(dir, "runs", "setup", "plan.json"), "--expected-setup-root-identity", manifest.Root, "--tenant", plan.TenantID(), "--repository", plan.RepositoryID(), "--local-git-objects-root", manifest.Objects, "--local-git-repository-authority", values["--repository-authority"], "--local-git-repository-namespace", values["--repository-namespace"], "--local-git-repository-name", values["--repository-name"], "--local-full-review", "--local-model-workers", "--runtime-route-inventory", filepath.Join(dir, "routes.json"), "--runtime-policy", filepath.Join(dir, "policy.json")}
	status := []string{"trestle", "runs", "status", "--server", "http://127.0.0.1:8741", "--tenant", plan.TenantID(), "--repository", plan.RepositoryID(), "--run", manifest.Run, "--format", "json"}
	return submit, launch, status
}
