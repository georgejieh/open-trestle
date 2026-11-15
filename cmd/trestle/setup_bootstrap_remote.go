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
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/secretscan"
	"github.com/georgejieh/open-trestle/localreview"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

// The remote bootstrap writes protected configuration for the direct
// `local-git model-review --egress policy-approved` path. It has no setup plan,
// daemon or publication. Account facts and consent are explicit operator
// declarations. For OpenRouter, model and endpoint facts the operator does not
// give as flags are read from OpenRouter's public API and recorded as reported
// by it; nothing else is observed.

const (
	remoteBootstrapContract       = "open-trestle/remote-model-review-bootstrap"
	remoteBootstrapResultContract = "open-trestle/remote-model-review-bootstrap-result"
	remoteReviewMaxOutputTokens   = 4096
)

// Tests replace the installed-scanner probe; production checks the real install.
var setupBootstrapScannerPrerequisite = func() error { return secretscan.NewClient().InstalledPrerequisite() }

type remoteBootstrapProvider struct {
	zone          provider.ProviderZone
	providerID    string
	endpoint      string
	profile       string
	schemaVersion int
	// witness reports whether the profile carries a time-bounded privacy
	// witness (review window, broker and account evidence).
	witness bool
}

var remoteBootstrapProviders = map[string]remoteBootstrapProvider{
	// Every request requires zero data retention (provider.zdr), limited to the
	// detected or named provider slugs.
	"openrouter-zdr": {provider.ProviderZoneBrokeredRemote, "openrouter", "https://openrouter.ai/api/v1", runtimeconfig.OpenRouterZDRChatV2Profile, 8, false},
	// The same API without that requirement: a generic private_remote route,
	// like Ollama Cloud. Account or key settings may still enforce ZDR.
	"openrouter":   {provider.ProviderZonePrivateRemote, "openrouter", "https://openrouter.ai/api/v1", "", 2, false},
	"opencode-go":  {provider.ProviderZoneBrokeredRemote, "opencode-go", "https://opencode.ai/inference/go/openai/v1", runtimeconfig.OpenCodeGoChatProfile, 4, true},
	"ollama-cloud": {provider.ProviderZonePrivateRemote, "ollama-cloud", "https://ollama.com/v1", "", 2, false},
	// A local Ollama daemon signed in to Ollama Cloud: loopback endpoint, no
	// key, but source leaves the machine, so the zone is private_remote.
	ollamaSigninProvider: {provider.ProviderZonePrivateRemote, runtimeconfig.OllamaSigninProviderID, ollamaSigninDefaultBaseURL, runtimeconfig.OllamaSigninChatProfile, 7, false},
}

type remoteBootstrapManifest struct {
	Contract               string   `json:"contract"`
	Version                int      `json:"schema_version"`
	Provider               string   `json:"provider"`
	Inventory              string   `json:"inventory_identity"`
	Policy                 string   `json:"runtime_policy_identity"`
	CredentialEnvironments []string `json:"credential_environments"`
	ReviewCommand          []string `json:"review_command"`
}

type remoteBootstrapResult struct {
	Contract      string   `json:"contract"`
	Version       int      `json:"schema_version"`
	Status        string   `json:"status"`
	Ready         bool     `json:"ready"`
	Provider      string   `json:"provider,omitempty"`
	Inventory     string   `json:"inventory_identity,omitempty"`
	Policy        string   `json:"runtime_policy_identity,omitempty"`
	Pending       []string `json:"pending_checks"`
	Refused       []string `json:"refused_checks"`
	Messages      []string `json:"messages"`
	ReviewCommand []string `json:"review_command,omitempty"`
	Limitations   []string `json:"limitations"`
	// DataRetention is set for OpenRouter only: required_per_request when every
	// request sets provider.zdr, not_required_by_open_trestle otherwise. It
	// states what Open Trestle requires, never what a provider retains.
	DataRetention string `json:"data_retention,omitempty"`
}

var remoteBootstrapStringFlags = []string{"provider", "tenant", "repository", "checkout", "base", "head", "repository-authority", "repository-namespace", "repository-name", "generation-model", "verification-model", "generation-credential-environment", "verification-credential-environment", "endpoint", "declared-by", "valid-from", "valid-until", "reviewed-at", "evidence-retrieved-at", "generation-provider-slug", "verification-provider-slug", "generation-upstream-evidence", "verification-upstream-evidence", "generation-slug-evidence", "verification-slug-evidence", "generation-model-evidence", "verification-model-evidence", "broker-evidence", "account-evidence"}
var remoteBootstrapUintFlags = []string{"context-tokens", "output-tokens", "max-output-tokens", "input-micro-usd-per-million-tokens", "output-micro-usd-per-million-tokens", "max-cost-micro-usd"}
var remoteBootstrapBoolFlags = []string{"declare-remote-route", "declare-openrouter-zdr-account", "declare-opencode-go-account", "declare-ollama-cloud-signin"}

// Flags that only one provider family may use. Every other flag is common.
var remoteBootstrapProviderOnlyFlags = map[string][]string{
	"openrouter-zdr":     {"generation-provider-slug", "verification-provider-slug"},
	"opencode-go":        {"generation-model-evidence", "verification-model-evidence", "declare-opencode-go-account"},
	"ollama-cloud":       {"endpoint"},
	ollamaSigninProvider: {"endpoint", "declare-ollama-cloud-signin"},
}
var remoteBootstrapWitnessFlags = []string{"valid-from", "valid-until", "reviewed-at", "evidence-retrieved-at", "broker-evidence", "account-evidence"}

// Flags the reviewed OpenRouter witness needed. Setup now records OpenRouter's
// API responses itself, so no provider accepts them.
var remoteBootstrapRetiredFlags = []string{"generation-upstream-evidence", "verification-upstream-evidence", "generation-slug-evidence", "verification-slug-evidence", "declare-openrouter-zdr-account"}

// OpenRouter facts setup reads from the API unless given as these flags.
var remoteBootstrapOpenRouterDetected = []string{"context-tokens", "output-tokens", "input-micro-usd-per-million-tokens", "output-micro-usd-per-million-tokens"}

func remoteSetupBootstrapRequested(args []string) bool {
	if len(args) == 0 {
		return false
	}
	if args[0] == "init" {
		for _, argument := range args[1:] {
			name := strings.TrimLeft(strings.SplitN(argument, "=", 2)[0], "-")
			if strings.HasPrefix(argument, "-") && name == "provider" {
				return true
			}
		}
		return false
	}
	if args[0] != "check" && args[0] != "inspect" && args[0] != "prepare-review" {
		return false
	}
	directory := ""
	for i := 1; i < len(args); i++ {
		name, value, hasValue := strings.Cut(strings.TrimLeft(args[i], "-"), "=")
		if !strings.HasPrefix(args[i], "-") || name != "directory" {
			continue
		}
		if !hasValue && i+1 < len(args) {
			value = args[i+1]
		}
		directory = value
	}
	if directory == "" {
		return false
	}
	absolute, err := filepath.Abs(directory)
	if err != nil {
		return false
	}
	content, err := readSetupBootstrapFile(filepath.Join(absolute, "bootstrap.json"))
	if err != nil {
		return false
	}
	var header struct {
		Contract string `json:"contract"`
	}
	return json.Unmarshal(content, &header) == nil && header.Contract == remoteBootstrapContract
}

func remoteBootstrapLimitations(providerName string, policy runtimeconfig.RuntimePolicy) []string {
	if providerName == ollamaSigninProvider {
		return []string{"operator_declared_provider_account_and_model_facts_not_verified", "loopback_ollama_model_list_read_no_model_call_during_setup", "ollama_cloud_signin_not_verified_by_setup", "ready_is_local_prerequisites_not_review_clearance", "foreground_review_is_ephemeral_no_resume", "no_publication", "no_credential_provisioning"}
	}
	if remoteOpenRouterObserved(providerName, policy) {
		limitations := []string{"openrouter_api_reported_model_facts_not_verified", "operator_declared_consent_and_account_settings_not_verified", "openrouter_public_api_read_no_model_call_during_setup"}
		if remoteDataRetention(policy) == "not_required_by_open_trestle" {
			limitations = append(limitations, "zero_data_retention_not_required_by_open_trestle")
		}
		return append(limitations, "ready_is_local_prerequisites_not_review_clearance", "foreground_review_is_ephemeral_no_resume", "no_publication", "no_credential_provisioning")
	}
	return []string{"operator_declared_provider_account_and_model_facts_not_verified", "no_network_or_model_call_during_setup", "ready_is_local_prerequisites_not_review_clearance", "foreground_review_is_ephemeral_no_resume", "no_publication", "no_credential_provisioning"}
}

// remoteOpenRouterObserved reports an OpenRouter setup whose facts came from
// OpenRouter's API: the provider name of an init, or the profile and endpoint
// of a saved policy. A reviewed (v1 profile) setup is not one.
func remoteOpenRouterObserved(providerName string, policy runtimeconfig.RuntimePolicy) bool {
	connections := policy.Connections()
	if len(connections) == 0 {
		return providerName == "openrouter" || providerName == "openrouter-zdr"
	}
	for _, connection := range connections {
		if connection.RequestProfile() == runtimeconfig.OpenRouterZDRChatV2Profile || connection.RequestProfile() == "" && connection.Endpoint() == "https://openrouter.ai/api/v1" {
			return true
		}
	}
	return false
}

// remoteDataRetention names what an OpenRouter policy requires of every
// request, or "" for a policy with no OpenRouter connection.
func remoteDataRetention(policy runtimeconfig.RuntimePolicy) string {
	value := ""
	for _, connection := range policy.Connections() {
		if connection.Endpoint() != "https://openrouter.ai/api/v1" {
			continue
		}
		if !connection.RequiresZeroDataRetention() {
			return "not_required_by_open_trestle"
		}
		value = "required_per_request"
	}
	return value
}

// remoteReviewTimeout is the --timeout of the review command: ten minutes,
// or room for two model requests that each run to the deadline the default
// HTTP client gives their output allowance plus two minutes for the rest of
// the review, within the command's fifteen-minute bound.
func remoteReviewTimeout(allowance uint64) string {
	request := openai.DefaultClientRequestTimeout(uint32(min(allowance, 1<<31)))
	timeout := max(10*time.Minute, min(15*time.Minute, 2*request+2*time.Minute))
	return strconv.FormatInt(int64((timeout+time.Minute-1)/time.Minute), 10) + "m"
}

func writeRemoteBootstrapRefusal(stdout, stderr io.Writer, reason string) int {
	return writeRemoteBootstrapRefusalFor(stdout, stderr, reason, "")
}

func writeRemoteBootstrapRefusalFor(stdout, stderr io.Writer, reason, providerName string) int {
	fmt.Fprintln(stderr, "trestle setup bootstrap: "+reason)
	result := remoteBootstrapResult{Contract: remoteBootstrapResultContract, Version: 1, Status: "refused", Pending: []string{}, Refused: []string{"configuration_validated"}, Messages: []string{reason}, Limitations: remoteBootstrapLimitations(providerName, runtimeconfig.RuntimePolicy{})}
	if json.NewEncoder(stdout).Encode(result) != nil {
		return 1
	}
	return 4
}

func writeRemoteSetupBootstrapUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle setup bootstrap init --provider openrouter-zdr|openrouter|opencode-go|ollama-cloud|ollama-signin --directory PATH --tenant ID --repository ID --checkout PATH --base FULL_REF_OR_COMMIT --head FULL_REF_OR_COMMIT --repository-authority LABEL --repository-namespace NAME --repository-name NAME --generation-model ID --verification-model ID [--generation-credential-environment OPEN_TRESTLE_PROVIDER_NAME [--verification-credential-environment OPEN_TRESTLE_PROVIDER_NAME]] --declared-by NAME --context-tokens N --output-tokens N [--max-output-tokens N] --input-micro-usd-per-million-tokens N --output-micro-usd-per-million-tokens N --max-cost-micro-usd N --declare-remote-route [provider declarations, see docs/remote-model-review.md]")
	fmt.Fprintln(w, "       trestle setup bootstrap check --directory PATH")
	fmt.Fprintln(w, "       trestle setup bootstrap inspect --directory PATH")
}

func runRemoteSetupBootstrap(ctx context.Context, args []string, stdout, stderr io.Writer, clock setupClock) int {
	seen := map[string]bool{}
	for _, argument := range args[1:] {
		if !strings.HasPrefix(argument, "-") {
			continue
		}
		name := strings.TrimLeft(strings.SplitN(argument, "=", 2)[0], "-")
		if seen[name] {
			writeRemoteSetupBootstrapUsage(stderr)
			return 2
		}
		seen[name] = true
	}
	flags := flag.NewFlagSet("trestle setup bootstrap "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	directory := flags.String("directory", "", "existing private bootstrap directory")
	values := map[string]*string{}
	for _, name := range remoteBootstrapStringFlags {
		values[name] = flags.String(name, "", name)
	}
	numbers := map[string]*uint64{}
	for _, name := range remoteBootstrapUintFlags {
		numbers[name] = flags.Uint64(name, 0, name)
	}
	declarations := map[string]*bool{}
	for _, name := range remoteBootstrapBoolFlags {
		declarations[name] = flags.Bool(name, false, name)
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *directory == "" {
		writeRemoteSetupBootstrapUsage(stderr)
		return 2
	}
	set := map[string]bool{}
	flags.Visit(func(f *flag.Flag) { set[f.Name] = true })
	switch args[0] {
	case "init":
	case "check", "inspect":
		if len(set) != 1 {
			writeRemoteSetupBootstrapUsage(stderr)
			return 2
		}
	case "prepare-review":
		return writeRemoteBootstrapRefusal(stdout, stderr, "a remote bootstrap has no prepare-review step; run check, then the review_command it prints")
	default:
		writeRemoteSetupBootstrapUsage(stderr)
		return 2
	}
	directoryAbs, err := filepath.Abs(*directory)
	if err != nil {
		return writeRemoteBootstrapRefusal(stdout, stderr, "invalid --directory")
	}
	info, err := os.Lstat(directoryAbs)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || fileauthority.CheckDirectory(directoryAbs) != nil {
		return writeRemoteBootstrapRefusal(stdout, stderr, "--directory must be an existing private (0700) directory owned by this account")
	}
	if args[0] == "init" {
		if err := initializeRemoteSetupBootstrap(ctx, directoryAbs, values, numbers, declarations, set, clock); err != nil {
			return writeRemoteBootstrapRefusalFor(stdout, stderr, err.Error(), *values["provider"])
		}
	}
	manifest, inventory, policy, err := loadRemoteSetupBootstrap(ctx, directoryAbs)
	if err != nil {
		return writeRemoteBootstrapRefusal(stdout, stderr, err.Error())
	}
	result := checkRemoteSetupBootstrap(ctx, manifest, inventory, policy, clock.Now().UTC())
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write bootstrap result failed")
		return 1
	}
	switch result.Status {
	case "ready":
		return 0
	case "refused":
		return 4
	default:
		return 3
	}
}

func checkRemoteSetupBootstrap(ctx context.Context, manifest remoteBootstrapManifest, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy, now time.Time) remoteBootstrapResult {
	result := remoteBootstrapResult{Contract: remoteBootstrapResultContract, Version: 1, Provider: manifest.Provider, Inventory: manifest.Inventory, Policy: manifest.Policy, Pending: []string{}, Refused: []string{}, Messages: []string{}, ReviewCommand: manifest.ReviewCommand, Limitations: remoteBootstrapLimitations(manifest.Provider, policy), DataRetention: remoteDataRetention(policy)}
	pending := func(key, message string) {
		result.Pending = append(result.Pending, key)
		result.Messages = append(result.Messages, message)
	}
	refused := func(key, message string) {
		result.Refused = append(result.Refused, key)
		result.Messages = append(result.Messages, message)
	}
	current := true
	for _, connection := range policy.Connections() {
		var from, until time.Time
		switch connection.RequestProfile() {
		case runtimeconfig.OpenRouterZDRChatProfile:
			authority := connection.BrokeredAuthority()
			from, until = authority.ValidFrom(), authority.ValidUntil()
		case runtimeconfig.OpenCodeGoChatProfile:
			authority := connection.OpenCodeGoAuthority()
			from, until = authority.ValidFrom(), authority.ValidUntil()
		default:
			continue
		}
		if now.Before(from) {
			current = false
			pending("privacy_declaration_current", "the declared privacy review window starts at "+from.Format(time.RFC3339)+"; remote review is refused until then")
			break
		}
		if !now.Before(until) {
			current = false
			refused("privacy_declaration_current", "the declared privacy review window ended at "+until.Format(time.RFC3339)+"; review the provider and account again and initialize a new directory")
			break
		}
	}
	if current {
		resolver, err := runtimecatalog.NewEnvironmentOpenAICredentialResolver(providerCredentialLookup)
		if err == nil {
			// Construction resolves only credential references and performs no request.
			_, err = runtimecatalog.NewOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory, policy, resolver)
		}
		if err != nil {
			refused("dispatch_catalog_validated", "the protected inventory and policy do not construct the policy-approved dispatcher catalog")
		}
	}
	if manifest.Provider == ollamaSigninProvider {
		checkOllamaSigninBootstrap(ctx, inventory, policy, pending, refused)
	}
	for _, name := range manifest.CredentialEnvironments {
		if state := providerKeyStatus(name); !state.available() {
			message := "export " + name + " with the provider key in the shell that runs review_command, or save it once with `trestle keys set " + name + "`; setup bootstrap never stores or prints its value"
			if state.problem != nil {
				message += " (" + state.where() + ")"
			}
			pending("credential_environment_present", message)
		}
	}
	switch err := setupBootstrapScannerPrerequisite(); {
	case err == nil:
	case errors.Is(err, secretscan.ErrScannerNotInstalled):
		pending("sanitized_egress_scanner", "the secret scanner is not installed: run `sudo ./open-trestle-linux-amd64.pyz install` from a packaged candidate (or use the container image); remote egress is refused without it")
	default:
		refused("sanitized_egress_scanner", "this trestle binary cannot sanitize remote egress ("+err.Error()+"); use the packaged binary from `python3 tools/package_secret_scanner.py --output .container`")
	}
	result.Status = "pending"
	if len(result.Refused) != 0 {
		result.Status = "refused"
	} else if len(result.Pending) == 0 {
		result.Status, result.Ready = "ready", true
	}
	return result
}

func loadRemoteSetupBootstrap(ctx context.Context, dir string) (remoteBootstrapManifest, runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy, error) {
	var manifest remoteBootstrapManifest
	fail := func(reason string) (remoteBootstrapManifest, runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy, error) {
		return remoteBootstrapManifest{}, runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, errors.New(reason)
	}
	content, err := readSetupBootstrapFile(filepath.Join(dir, "bootstrap.json"))
	if err != nil {
		return fail("bootstrap.json is missing or not a protected 0600 file")
	}
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(&struct{}{}) != io.EOF || manifest.Contract != remoteBootstrapContract || manifest.Version != 1 {
		return fail("bootstrap.json is not a remote bootstrap manifest")
	}
	family, ok := remoteBootstrapProviders[manifest.Provider]
	if !ok {
		return fail("bootstrap.json names an unknown provider")
	}
	routes, policyPath := filepath.Join(dir, "routes.json"), filepath.Join(dir, "policy.json")
	inventory, policy, err := runtimeconfig.LoadProtectedConfiguration(ctx, routes, policyPath)
	if err != nil || inventory.Identity() != manifest.Inventory || policy.Identity() != manifest.Policy {
		return fail("routes.json or policy.json is unprotected, invalid or no longer matches bootstrap.json")
	}
	for _, candidate := range inventory.Candidates() {
		if candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().Zone() != family.zone {
			return fail("routes.json carries a route outside the provider zone")
		}
	}
	if len(manifest.ReviewCommand) < 4 || strings.Join(manifest.ReviewCommand[:3], " ") != "trestle local-git model-review" {
		return fail("bootstrap.json review command is invalid")
	}
	options, _, _, _, err := parseLocalModelReview(manifest.ReviewCommand[3:])
	if err != nil || options.inventory != routes || options.policy != policyPath || options.egress != localreview.EgressPolicyApproved || !filepath.IsAbs(options.checkout) {
		return fail("bootstrap.json review command does not use this directory's protected configuration")
	}
	if _, err := resolveLocalCheckout(ctx, options.checkout, options.baseSelection, options.headSelection); err != nil {
		return fail("the checkout or its selected commits are no longer available")
	}
	expected := remoteCredentialEnvironments(policy)
	if !slices.Equal(expected, manifest.CredentialEnvironments) {
		return fail("bootstrap.json credential references differ from policy.json")
	}
	return manifest, inventory, policy, nil
}

func remoteCredentialEnvironments(policy runtimeconfig.RuntimePolicy) []string {
	names := []string{}
	for _, connection := range policy.Connections() {
		if name := connection.CredentialEnvironment(); name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	return names
}

type remoteEvidence struct {
	URL           string `json:"url"`
	RetrievedAt   string `json:"retrieved_at"`
	ContentSHA256 string `json:"content_sha256"`
}

type remoteWitnessRoute struct {
	Zone              string `json:"zone"`
	ProviderID        string `json:"provider_id"`
	AdapterID         string `json:"adapter_id"`
	ConnectionID      string `json:"connection_id"`
	ModelID           string `json:"model_id"`
	ModelVersion      string `json:"model_version"`
	EffectiveSelector string `json:"effective_selector"`
}

// Field order is identity-bearing: it must match the runtimeconfig account preimages.
type openCodeGoAccountDeclaration struct {
	AuthorityLabel              string         `json:"authority_label"`
	CredentialReferenceIdentity string         `json:"credential_reference_identity"`
	Subscription                string         `json:"subscription"`
	WorkspaceMembership         string         `json:"workspace_membership"`
	PrivacyTraining             string         `json:"privacy_training"`
	ExtraUsage                  string         `json:"extra_usage"`
	ReviewEvidence              remoteEvidence `json:"review_evidence"`
}

func remoteDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}

func remoteAccountIdentity(contract string, version int, account any) string {
	encoded, _ := json.Marshal(struct {
		Contract string `json:"contract"`
		Version  int    `json:"version"`
		Account  any    `json:"account"`
	}{contract, version, account})
	return remoteDigest(encoded)
}

func remoteCanonicalTime(flagName, value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, fmt.Errorf("--%s must be a canonical UTC RFC3339 time such as 2026-11-07T00:00:00Z", flagName)
	}
	return parsed, nil
}

func remoteParseEvidence(flagName, value, retrievedAt string) (remoteEvidence, error) {
	location, digest, found := value, "", false
	if i := strings.LastIndex(value, ","); i >= 0 {
		location, digest, found = value[:i], value[i+1:], true
	}
	parsed, err := url.Parse(location)
	if !found || err != nil || len(location) > 2048 || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || strings.Contains(location, "#") {
		return remoteEvidence{}, fmt.Errorf("--%s must be HTTPS_URL,SHA256 where the URL has a host and no credentials, query or fragment", flagName)
	}
	if len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" || digest == strings.Repeat("0", 64) {
		return remoteEvidence{}, fmt.Errorf("--%s must end with the nonzero lowercase SHA-256 of the evidence you reviewed (for example from sha256sum)", flagName)
	}
	return remoteEvidence{URL: location, RetrievedAt: retrievedAt, ContentSHA256: digest}, nil
}

func remoteValidSlug(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || strings.Trim(part, "abcdefghijklmnopqrstuvwxyz0123456789-_.") != "" {
			return false
		}
	}
	return true
}

func remoteCredentialEnvironmentError(flagName, value string) error {
	valid := len(value) >= 23 && len(value) <= 128 && strings.HasPrefix(value, "OPEN_TRESTLE_PROVIDER_") && strings.Trim(value, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == ""
	if valid {
		return nil
	}
	return fmt.Errorf("--%s takes the NAME of an environment variable matching OPEN_TRESTLE_PROVIDER_[A-Z0-9_]+, never a key value; export the key under that name instead", flagName)
}

func initializeRemoteSetupBootstrap(ctx context.Context, dir string, values map[string]*string, numbers map[string]*uint64, declarations map[string]*bool, set map[string]bool, clock setupClock) error {
	value := func(name string) string { return *values[name] }
	name := value("provider")
	family, ok := remoteBootstrapProviders[name]
	if !ok {
		return errors.New("--provider must be openrouter-zdr, openrouter, opencode-go, ollama-cloud or ollama-signin")
	}
	openRouter := family.providerID == "openrouter"
	allowed := map[string]bool{"directory": true}
	for _, flagName := range append(append(append([]string{}, remoteBootstrapStringFlags...), remoteBootstrapUintFlags...), remoteBootstrapBoolFlags...) {
		allowed[flagName] = true
	}
	for _, only := range remoteBootstrapProviderOnlyFlags {
		for _, flagName := range only {
			allowed[flagName] = false
		}
	}
	for _, flagName := range remoteBootstrapProviderOnlyFlags[name] {
		allowed[flagName] = true
	}
	for _, flagName := range remoteBootstrapWitnessFlags {
		allowed[flagName] = family.witness
	}
	for _, flagName := range remoteBootstrapRetiredFlags {
		allowed[flagName] = false
	}
	if name == ollamaSigninProvider {
		// The daemon uses its own `ollama signin` account; no key is sent.
		allowed["generation-credential-environment"], allowed["verification-credential-environment"] = false, false
	}
	for flagName := range set {
		if !allowed[flagName] {
			if openRouter && (slices.Contains(remoteBootstrapRetiredFlags, flagName) || slices.Contains(remoteBootstrapWitnessFlags, flagName)) {
				return fmt.Errorf("--%s is no longer used: OpenRouter setup records OpenRouter's API responses itself and needs no evidence, timestamps or review window (docs/openrouter-zdr-profile.md)", flagName)
			}
			if name == "openrouter" && strings.HasSuffix(flagName, "-provider-slug") {
				return fmt.Errorf("--%s applies only with zero data retention (--provider openrouter-zdr)", flagName)
			}
			if name == ollamaSigninProvider && strings.HasSuffix(flagName, "-credential-environment") {
				return fmt.Errorf("--%s does not apply to --provider %s: it sends no key; your local Ollama uses its own `ollama signin` account", flagName, name)
			}
			return fmt.Errorf("--%s does not apply to --provider %s", flagName, name)
		}
	}
	required := []string{"tenant", "repository", "checkout", "base", "head", "repository-authority", "repository-namespace", "repository-name", "generation-model", "verification-model", "declared-by", "max-cost-micro-usd"}
	if !openRouter {
		required = append(required, remoteBootstrapOpenRouterDetected...)
	}
	if name != ollamaSigninProvider {
		required = append(required, "generation-credential-environment")
	}
	switch name {
	case "opencode-go":
		required = append(required, "generation-model-evidence", "verification-model-evidence")
	}
	if family.witness {
		required = append(required, remoteBootstrapWitnessFlags...)
	}
	for _, flagName := range required {
		if !set[flagName] || values[flagName] != nil && value(flagName) == "" {
			return fmt.Errorf("missing required --%s for --provider %s", flagName, name)
		}
	}
	for flagName, v := range values {
		if len(*v) > 4096 {
			return fmt.Errorf("--%s is too long", flagName)
		}
	}
	if openRouter && !*declarations["declare-remote-route"] {
		return errors.New("refusing to send source to OpenRouter without consent: pass --declare-remote-route to consent that each review sends the selected source, after secret scanning, to OpenRouter for both models, and to state that prompt logging is off for the key")
	}
	if !*declarations["declare-remote-route"] {
		return errors.New("refusing to invent route facts: pass --declare-remote-route to declare, as the operator, both models' context/output capacity, structured JSON output, disabled content logging, the stated prices and current availability")
	}
	if name == "opencode-go" && !*declarations["declare-opencode-go-account"] {
		return errors.New("refusing to claim OpenCode Go privacy: pass --declare-opencode-go-account only after reviewing that the key belongs to a single-member Go workspace with privacy training and extra usage disabled, and that both models document zero-day retention without training")
	}
	if name == ollamaSigninProvider && !*declarations["declare-ollama-cloud-signin"] {
		return errors.New("refusing to send source to Ollama Cloud without consent: pass --declare-ollama-cloud-signin only after confirming that the local Ollama daemon is signed in (`ollama signin`) to an Ollama account you control, and that each review sends the selected repository source, after secret scanning, from that daemon to Ollama Cloud (https://ollama.com) under that account; the models do not run on this machine")
	}
	if value("generation-model") == value("verification-model") {
		return errors.New("--generation-model and --verification-model must differ; the verifier must be an independent model")
	}
	environments := map[string]string{"generation": value("generation-credential-environment"), "verification": value("verification-credential-environment")}
	if environments["verification"] == "" {
		environments["verification"] = environments["generation"]
	}
	for _, role := range []string{"generation", "verification"} {
		if name == ollamaSigninProvider {
			break
		}
		if err := remoteCredentialEnvironmentError(role+"-credential-environment", environments[role]); err != nil {
			return err
		}
	}
	declaredBy := value("declared-by")
	if len(declaredBy) > 64 || strings.TrimSpace(declaredBy) != declaredBy || strings.ContainsFunc(declaredBy, unicode.IsControl) {
		return errors.New("--declared-by must be a short printable operator name")
	}
	var detected openRouterPlan
	if openRouter {
		models := map[string]string{"generation": value("generation-model"), "verification": value("verification-model")}
		slugs := map[string]string{"generation": value("generation-provider-slug"), "verification": value("verification-provider-slug")}
		var err error
		if detected, err = planOpenRouter(observeOpenRouter(ctx, clock), family.profile != "", models, slugs, set, numbers); err != nil {
			return err
		}
	}
	endpoint := family.endpoint
	if set["endpoint"] && name == ollamaSigninProvider {
		endpoint = value("endpoint")
		if !runtimeconfig.ValidOllamaSigninEndpoint(endpoint) {
			return errors.New("--endpoint for --provider ollama-signin must be exactly http://127.0.0.1:PORT/v1, the local Ollama daemon's address")
		}
	} else if set["endpoint"] {
		endpoint = value("endpoint")
		locality, err := provider.ClassifyServiceEndpoint(endpoint)
		if err != nil || locality != provider.ServiceEndpointRemote || !strings.HasPrefix(endpoint, "https://") {
			return errors.New("--endpoint must be a remote HTTPS base URL; a loopback or private endpoint belongs to the local bootstrap (omit --provider), or to --provider ollama-signin for a local Ollama signed in to Ollama Cloud")
		}
	}
	contextTokens, outputTokens := *numbers["context-tokens"], *numbers["output-tokens"]
	if contextTokens < 8192 || contextTokens > 1<<31 || outputTokens < remoteReviewMaxOutputTokens || outputTokens > contextTokens {
		return errors.New("--context-tokens must be at least 8192 and --output-tokens at least 4096 and no more than the context")
	}
	// --max-output-tokens is the per-request review output allowance written to
	// the runtime policy. It defaults to 4096, or for OpenRouter to the
	// allowance planOpenRouter chose for the pinned endpoints, and may be
	// raised up to the declared --output-tokens capacity, for example for
	// reasoning models that spend part of the allowance before answering. The
	// cost reservation below uses the same allowance.
	reviewOutputTokens := uint64(remoteReviewMaxOutputTokens)
	if openRouter {
		reviewOutputTokens = detected.allowance
	}
	if set["max-output-tokens"] {
		reviewOutputTokens = *numbers["max-output-tokens"]
		if reviewOutputTokens < remoteReviewMaxOutputTokens || reviewOutputTokens > outputTokens {
			return fmt.Errorf("--max-output-tokens must be from %d to the declared --output-tokens (%d)", remoteReviewMaxOutputTokens, outputTokens)
		}
	}
	inputPrice, outputPrice, maxCost := *numbers["input-micro-usd-per-million-tokens"], *numbers["output-micro-usd-per-million-tokens"], *numbers["max-cost-micro-usd"]
	if outputReservation := (reviewOutputTokens*outputPrice + 999_999) / 1_000_000; outputPrice > 1<<40 || inputPrice > 1<<40 || maxCost < outputReservation || inputPrice+outputPrice > 0 && maxCost == 0 {
		return fmt.Errorf("--max-cost-micro-usd %d cannot cover the %d-token output reservation at the declared output price", maxCost, reviewOutputTokens)
	}
	var reviewedAt, retrievedAt, validFrom, validUntil string
	var err error
	if family.witness {
		times := map[string]time.Time{}
		for _, flagName := range []string{"evidence-retrieved-at", "reviewed-at", "valid-from", "valid-until"} {
			parsed, err := remoteCanonicalTime(flagName, value(flagName))
			if err != nil {
				return err
			}
			times[flagName] = parsed
		}
		if times["evidence-retrieved-at"].After(times["reviewed-at"]) || times["reviewed-at"].After(times["valid-from"]) || !times["valid-until"].After(times["valid-from"]) {
			return errors.New("times must satisfy --evidence-retrieved-at <= --reviewed-at <= --valid-from < --valid-until")
		}
		if !clock.Now().Before(times["valid-until"]) {
			return errors.New("--valid-until is already in the past")
		}
		retrievedAt, reviewedAt, validFrom, validUntil = value("evidence-retrieved-at"), value("reviewed-at"), value("valid-from"), value("valid-until")
	}
	evidenceFor := func(flagName string) (remoteEvidence, error) {
		return remoteParseEvidence(flagName, value(flagName), retrievedAt)
	}
	var broker, account remoteEvidence
	if family.witness {
		if broker, err = evidenceFor("broker-evidence"); err != nil {
			return err
		}
		if account, err = evidenceFor("account-evidence"); err != nil {
			return err
		}
	}

	checkout, err := filepath.Abs(value("checkout"))
	if err != nil {
		return errors.New("invalid --checkout")
	}
	source, err := resolveLocalCheckout(ctx, checkout, value("base"), value("head"))
	if err != nil {
		return errors.New("--checkout, --base and --head must select two distinct commits in a local Git checkout (full refs/heads/... or refs/tags/... names, HEAD or full commit digests)")
	}
	if _, err := evidence.NewRepositoryIdentity(value("repository-authority"), strings.Split(value("repository-namespace"), "/"), value("repository-name")); err != nil {
		return errors.New("invalid --repository-authority, --repository-namespace or --repository-name")
	}
	// One bounded loopback GET: the daemon must relay both models to Ollama Cloud.
	observed := map[string]ollamaTag{}
	if name == ollamaSigninProvider {
		tags, err := checkOllamaSigninModels(ctx, endpoint, value("generation-model"), value("verification-model"))
		if err != nil {
			return err
		}
		observed["generation"], observed["verification"] = tags[0], tags[1]
	}
	reviewArgs := []string{"--checkout", checkout, "--base", source.base, "--head", source.head, "--repository-authority", value("repository-authority"), "--repository-namespace", value("repository-namespace"), "--repository-name", value("repository-name"), "--tenant", value("tenant"), "--repository", value("repository"), "--route-inventory", filepath.Join(dir, "routes.json"), "--runtime-policy", filepath.Join(dir, "policy.json"), "--egress", string(localreview.EgressPolicyApproved), "--timeout", remoteReviewTimeout(reviewOutputTokens), "--format", "text"}
	if _, _, _, _, err := parseLocalModelReview(reviewArgs); err != nil {
		return errors.New("invalid --tenant, --repository or repository labels for local-git model-review")
	}

	authorityLabel := "operator declaration by " + declaredBy + " via trestle setup bootstrap; not provider attestation"
	routes := []map[string]any{}
	connections := []map[string]any{}
	accounts := map[string]string{}
	for _, role := range []string{"generation", "verification"} {
		adapter := family.providerID + "-" + role
		connectionID := family.providerID + "/" + role
		model := value(role + "-model")
		// The same derivation the runtime policy connection records, so every
		// setup that names this key variable shares one credential reference.
		// Only the OpenRouter ZDR and OpenCode Go witnesses use it, and both
		// require a valid key variable (checked above).
		credentialIdentity, _ := runtimeconfig.CredentialReferenceIdentity(environments[role])
		route := remoteWitnessRoute{Zone: family.zone.String(), ProviderID: family.providerID, AdapterID: adapter, ConnectionID: connectionID, ModelID: model, ModelVersion: "", EffectiveSelector: model}
		declaration := map[string]any{"contract": "open-trestle/operator-remote-bootstrap-declaration", "schema_version": 1, "declared_by": declaredBy, "provider": name, "endpoint": endpoint, "role": role, "model": model, "limitations": "operator declaration, not measured health, provider privacy, account state or service conformance"}
		manifest := map[string]any{"open_trestle_bootstrap_declaration": declaration}
		switch name {
		case "openrouter-zdr":
			manifest["openrouter_privacy"] = detected.witness(role, route, credentialIdentity, value("tenant"), value("repository"))
		case "openrouter":
			manifest["openrouter_route"] = detected.routeObservation(role)
		case ollamaSigninProvider:
			tag := observed[role]
			manifest["ollama_daemon_observation"] = map[string]any{"source": "GET /api/tags on the loopback daemon during setup", "listed_name": tag.Name, "remote_model": tag.RemoteModel, "remote_host": tag.RemoteHost, "limitations": "an observation of the daemon's model list, not proof of sign-in, account state or Ollama Cloud retention"}
		case "opencode-go":
			modelEvidence, err := evidenceFor(role + "-model-evidence")
			if err != nil {
				return err
			}
			declared := openCodeGoAccountDeclaration{AuthorityLabel: authorityLabel, CredentialReferenceIdentity: credentialIdentity, Subscription: "go", WorkspaceMembership: "single_member", PrivacyTraining: "disabled", ExtraUsage: "disabled", ReviewEvidence: account}
			accounts[role] = remoteAccountIdentity("open-trestle/opencode-go-account-policy", 1, declared)
			manifest["opencode_go_privacy"] = map[string]any{
				"contract": "open-trestle/opencode-go-privacy-witness", "schema_version": 1, "route": route, "endpoint": family.endpoint, "request_profile": family.profile, "protocol": "openai_chat_completions", "credential_mode": "bearer",
				"model_privacy":  map[string]any{"training": "disabled", "retention_days": 0, "evidence": modelEvidence},
				"broker_privacy": map[string]any{"retention_contract": "model_specific_documented_zero_days", "evidence": broker},
				"account":        declared, "tenant_id": value("tenant"), "repository_id": value("repository"), "reviewed_at": reviewedAt, "valid_from": validFrom, "valid_until": validUntil,
				"byok": "excluded", "tools": "excluded", "plugins": "excluded", "streaming": "excluded",
				"client": map[string]any{"user_agent": "open-trestle/1", "session_derivation": "authorized_review_scope_sha256_v1"},
			}
		}
		encodedManifest, err := json.Marshal(manifest)
		if err != nil {
			return errors.New("cannot encode evidence manifest")
		}
		routes = append(routes, map[string]any{"zone": family.zone.String(), "provider_id": family.providerID, "adapter_id": adapter, "connection_id": connectionID, "model_id": model, "model_version": "", "max_context_tokens": contextTokens, "max_output_tokens": outputTokens, "features": []string{"structured_output"}, "content_logging": "disabled", "pricing_known": true, "input_micro_usd_per_million_tokens": inputPrice, "output_micro_usd_per_million_tokens": outputPrice, "quality": "tier_1", "registry_revision": 1, "registry_status": "approved", "evidence_manifest_base64": base64.StdEncoding.EncodeToString(encodedManifest), "operational_revision": 1, "health": "healthy", "quota": "available", "performance_revision": 1, "latency_known": false, "p95_latency_milliseconds": 0, "latency_sample_count": 0})
		if name == ollamaSigninProvider {
			connections = append(connections, map[string]any{"implementation": "openai_chat_completions", "adapter_id": adapter, "endpoint": endpoint, "credential_mode": "none", "request_profile": family.profile})
		} else {
			connections = append(connections, map[string]any{"implementation": "openai_chat_completions", "adapter_id": adapter, "endpoint": endpoint, "credential_environment": environments[role]})
		}
	}
	inventoryBytes, _ := json.Marshal(map[string]any{"schema_version": 1, "routes": routes})
	inventory, err := runtimeconfig.DecodeRouteInventory(ctx, bytes.NewReader(inventoryBytes))
	if err != nil {
		return errors.New("the declared routes do not form a valid inventory (check model IDs, slugs and evidence)")
	}
	records := map[string]provider.RouteRegistryRecord{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = record
	}
	for i, role := range []string{"generation", "verification"} {
		record := records[family.providerID+"-"+role]
		if family.profile == runtimeconfig.OpenRouterZDRChatV2Profile {
			connections[i]["request_profile"] = family.profile
			connections[i]["brokered_route_authority"] = map[string]any{"route_record_identity": record.Identity(), "evidence_manifest_digest": record.EvidenceManifestDigest(), "tenant_id": value("tenant"), "repository_id": value("repository"), "provider_slugs": detected.slugs[role]}
			continue
		}
		if !family.witness {
			continue
		}
		authority := map[string]any{"route_record_identity": record.Identity(), "evidence_manifest_digest": record.EvidenceManifestDigest(), "account_policy_identity": accounts[role], "tenant_id": value("tenant"), "repository_id": value("repository"), "valid_from": validFrom, "valid_until": validUntil}
		connections[i]["request_profile"] = family.profile
		connections[i]["opencode_go_authority"] = authority
	}
	generation, verification := records[family.providerID+"-generation"], records[family.providerID+"-verification"]
	reviewPolicy := sha256.Sum256([]byte("open-trestle/remote-model-review-bootstrap/review-policy/v1/" + name + "/distinct-model/no-publication"))
	policyBytes, _ := json.Marshal(map[string]any{"schema_version": family.schemaVersion, "inventory_identity": inventory.Identity(), "review_policy_identity": hex.EncodeToString(reviewPolicy[:]), "verification_route_record_identity": verification.Identity(), "min_context_tokens": 1, "min_output_tokens": 1, "required_features": []string{"structured_output"}, "classification": "confidential", "allowed_zones": []string{family.zone.String()}, "content_logging_allowed": false, "estimated_input_tokens": 1, "max_output_tokens": reviewOutputTokens, "max_cost_micro_usd": maxCost, "pinned_route_record_identity": generation.Identity(), "preferred_route_record_identities": []string{}, "verification_independence": "distinct_model", "publication_minimum_severity": "medium", "publication_max_inline_findings": 20, "publication_minimum_independence": "distinct_model", "publication_block_on_inconclusive": true, "connections": connections})
	policy, err := runtimeconfig.DecodeRuntimePolicy(ctx, bytes.NewReader(policyBytes), inventory)
	if err != nil || gateway.VerifyIndependentRouteRecords(policy.Independence(), generation, verification) != nil {
		return errors.New("the declared routes do not form a valid runtime policy")
	}
	manifest := remoteBootstrapManifest{Contract: remoteBootstrapContract, Version: 1, Provider: name, Inventory: inventory.Identity(), Policy: policy.Identity(), CredentialEnvironments: remoteCredentialEnvironments(policy), ReviewCommand: append([]string{"trestle", "local-git", "model-review"}, reviewArgs...)}
	manifestBytes, _ := json.Marshal(manifest)
	for _, file := range []struct {
		name    string
		content []byte
	}{{"routes.json", inventoryBytes}, {"policy.json", policyBytes}, {"bootstrap.json", manifestBytes}} {
		if err := ensureSetupBootstrapFile(ctx, filepath.Join(dir, file.name), file.content); err != nil {
			return errors.New(file.name + " already exists with different content; use a new directory for a different declaration")
		}
	}
	return nil
}
