package main

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// Every OpenRouter model, endpoint, price and response below is a synthetic
// offline fixture served by fakeOpenRouter; model requests go to
// remoteModelTransport. Nothing here contacts OpenRouter.

func initOpenRouterModels(extra ...fakeORModel) []fakeORModel {
	models := append([]fakeORModel{fakeORFinder, fakeORChecker, fakeORNoZDR}, extra...)
	for i := range 43 {
		models = append(models, fakeORModel{id: "filler/model-" + strconv.Itoa(i), context: 32000, output: 8192, prompt: "0.000001", completion: "0.000001"})
	}
	return models
}

type initSavedOpenRouter struct {
	policy    map[string]any
	manifests []map[string]any
	bootstrap map[string]any
	raw       string
}

func initReadOpenRouterSetup(t *testing.T, dir string) initSavedOpenRouter {
	t.Helper()
	var saved initSavedOpenRouter
	policy := stringMustRead(t, filepath.Join(dir, "policy.json"))
	routes := stringMustRead(t, filepath.Join(dir, "routes.json"))
	manifest := stringMustRead(t, filepath.Join(dir, "bootstrap.json"))
	saved.raw = policy + routes + manifest
	var inventory struct {
		Routes []struct {
			Manifest []byte `json:"evidence_manifest_base64"`
		} `json:"routes"`
	}
	if json.Unmarshal([]byte(policy), &saved.policy) != nil || json.Unmarshal([]byte(routes), &inventory) != nil || json.Unmarshal([]byte(manifest), &saved.bootstrap) != nil {
		t.Fatal("saved setup is not readable")
	}
	for _, route := range inventory.Routes {
		var decoded map[string]any
		if json.Unmarshal(route.Manifest, &decoded) != nil {
			t.Fatal("evidence manifest is not JSON")
		}
		saved.manifests = append(saved.manifests, decoded)
		saved.raw += string(route.Manifest)
	}
	return saved
}

func initAssertOutput(t *testing.T, result initRun, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(result.stdout, want) {
			t.Fatalf("output lacks %q:\n%s", want, result.stdout)
		}
	}
}

// initAssertNotLabelledZDR fails if a setup without zero data retention is
// described as requiring it anywhere it is saved or shown.
func initAssertNotLabelledZDR(t *testing.T, saved initSavedOpenRouter, shown string) {
	t.Helper()
	for _, forbidden := range []string{"required_per_request", "openrouter_zdr_chat", "openrouter_privacy"} {
		if strings.Contains(saved.raw, forbidden) {
			t.Fatalf("a setup without zero data retention saved %q", forbidden)
		}
	}
	for _, forbidden := range []string{"zero data retention required", "Zero data retention is required", "will require zero data retention"} {
		if strings.Contains(shown, forbidden) {
			t.Fatalf("a setup without zero data retention showed %q:\n%s", forbidden, shown)
		}
	}
}

func TestInitOpenRouterBothModelsWithZDRRequiresItByDefault(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	api := fakeOpenRouter(t, initOpenRouterModels()...)
	transport := &remoteModelTransport{t: t, target: "https://openrouter.ai/api/v1/chat/completions", models: map[string]string{"vendor/generator": `["fixture-cloud","fixture-cloud/us"]`, "other/verifier": `["fixture-host/fp8"]`}}
	remoteModelClient(t, transport)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1",              // OpenRouter
		"generator", "1", // finder from the filtered list
		"",                 // checker: no filter, type the ID
		"vendor/generator", // same model: must re-prompt
		"other/verifier",
		"",    // require zero data retention (the default)
		"",    // accept the proposed cost limit
		"",    // accept the proposed key variable name
		"yes", // consent
		"",    // keep names
		"y",   // run the review
	)
	if result.code != initExitDone {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertOutput(t, result, "46 models listed; 2 have zero-data-retention endpoints", "same model as the finder",
		"zero data retention on 2 endpoints (fixture-cloud, fixture-cloud/us)", "zero data retention on 1 endpoint (fixture-host/fp8)",
		"Limits: context 128000 and output 16000 tokens", "Prices: up to $3.3 input and $16.5 output", "[0.49]",
		"Zero data retention is required on every request", "Review finished: 1 confirmed finding",
		"A review sends the selected source to OpenRouter (https://openrouter.ai/api/v1), zero data retention required on every request")
	if strings.Contains(result.stdout, "openrouter_zero_data_retention_not_required") {
		t.Fatal("a ZDR review was labelled as not requiring zero data retention")
	}
	for _, asked := range []string{"provider slug for", "Evidence:", "How many days", "review window", "SHA-256 of the copy"} {
		if strings.Contains(result.stdout, asked) {
			t.Fatalf("the wizard still asked for %q:\n%s", asked, result.stdout)
		}
	}
	if !slices.Equal(api.requests, []string{"https://openrouter.ai/api/v1/endpoints/zdr", "https://openrouter.ai/api/v1/models"}) {
		t.Fatalf("OpenRouter's API was not read exactly once per list: %v", api.requests)
	}
	if !slices.Equal(transport.requests, []string{"candidate_generation:vendor/generator", "candidate_verification:other/verifier"}) {
		t.Fatalf("review did not use the two chosen models: %v", transport.requests)
	}
	for _, controls := range transport.providers {
		if string(controls["zdr"]) != "true" {
			t.Fatalf("a request did not require zero data retention: %v", controls)
		}
	}
	saved := initReadOpenRouterSetup(t, dir)
	if saved.policy["schema_version"] != float64(8) || saved.bootstrap["provider"] != "openrouter-zdr" || strings.Contains(saved.raw, remoteTestKey) {
		t.Fatalf("saved setup is not the ZDR route: %v %v", saved.policy["schema_version"], saved.bootstrap["provider"])
	}
	for _, manifest := range saved.manifests {
		witness := manifest["openrouter_privacy"].(map[string]any)
		observation := witness["observation"].(map[string]any)
		sources := observation["sources"].([]any)
		if witness["schema_version"] != float64(3) || witness["provider_slug_source"] != "openrouter_api" || !strings.HasPrefix(observation["authority_label"].(string), "as reported by OpenRouter's API at ") ||
			sources[0].(map[string]any)["content_sha256"] != initSHA256(api.zdr) || sources[1].(map[string]any)["content_sha256"] != initSHA256(api.models) {
			t.Fatalf("witness does not record the API observation: %v", witness)
		}
	}
}

func TestInitOpenRouterModelWithoutZDRWarnsAndSteersToOne(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	fakeOpenRouter(t, initOpenRouterModels()...)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1", "generator", "1", "plain", "1",
		"",  // choose a model with zero-data-retention endpoints instead
		"2", // other/verifier from the ZDR-only list
		"",  // require zero data retention
		"", "", "yes", "", "n",
	)
	if result.code != initExitDone {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertOutput(t, result, "plain/verifier has no zero-data-retention endpoint on OpenRouter", "key requires zero data retention, its requests will fail", "Checker model with zero data retention")
	saved := initReadOpenRouterSetup(t, dir)
	if saved.bootstrap["provider"] != "openrouter-zdr" || !strings.Contains(saved.raw, "other/verifier") || strings.Contains(saved.raw, "plain/verifier") {
		t.Fatalf("the steered model was not saved: %v", saved.bootstrap)
	}
}

func TestInitOpenRouterModelWithoutZDRContinuesOnlyWithConsent(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	fakeOpenRouter(t, initOpenRouterModels()...)
	transport := &remoteModelTransport{t: t, target: "https://openrouter.ai/api/v1/chat/completions", models: map[string]string{"vendor/generator": "", "plain/verifier": ""}}
	remoteModelClient(t, transport)
	checkout := remoteBootstrapCheckout(t)
	// Declining to continue writes nothing.
	declined := filepath.Join(t.TempDir(), "setup")
	stopped := runInitScript(t, checkout, []string{"--directory", declined, "--base", "refs/heads/base", "--head", "refs/heads/review"}, "1", "generator", "1", "plain", "1", "n", "")
	if stopped.code != initExitRefused || !strings.Contains(stopped.stderr, "nothing was written") {
		t.Fatalf("declining did not stop: exit=%d %s", stopped.code, stopped.stderr)
	}
	initAssertAbsent(t, declined)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1", "generator", "1", "plain", "1",
		"n", // keep the model without zero data retention
		"y", // continue without zero data retention
		"", "", "yes", "", "y",
	)
	if result.code != initExitDone {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertOutput(t, result, "may keep your prompts under its own terms", "https://openrouter.ai/docs/guides/features/zdr",
		"Limits: context 64000 and output 8192 tokens", "Zero data retention is not required by Open Trestle", "zero data retention not required by Open Trestle", "Review finished", "openrouter_zero_data_retention_not_required")
	for _, controls := range transport.providers {
		if controls != nil {
			t.Fatalf("a request without zero data retention carried provider controls: %v", controls)
		}
	}
	saved := initReadOpenRouterSetup(t, dir)
	if saved.bootstrap["provider"] != "openrouter" || saved.policy["schema_version"] != float64(2) {
		t.Fatalf("saved setup is not the route without zero data retention: %v", saved.bootstrap)
	}
	for _, manifest := range saved.manifests {
		if manifest["openrouter_route"].(map[string]any)["zero_data_retention"] != "not_required_by_open_trestle" {
			t.Fatalf("route record lost its label: %v", manifest)
		}
	}
	initAssertNotLabelledZDR(t, saved, result.stdout)
}

func TestInitOpenRouterUserDeclinesZDR(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	fakeOpenRouter(t, initOpenRouterModels()...)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1", "generator", "1", "", "other/verifier",
		"n", // do not require zero data retention
		"y", // continue without it
		"", "", "yes", "", "n",
	)
	if result.code != initExitDone {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertOutput(t, result, "Both models have zero-data-retention endpoints", "may keep your prompts under its own terms", "Zero data retention is not required by Open Trestle")
	saved := initReadOpenRouterSetup(t, dir)
	if saved.bootstrap["provider"] != "openrouter" {
		t.Fatalf("declined ZDR saved %v", saved.bootstrap["provider"])
	}
	initAssertNotLabelledZDR(t, saved, result.stdout)
}

func TestInitOpenRouterNoInputUsesDetectionAndFlags(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	fakeOpenRouter(t, initOpenRouterModels()...)
	checkout := remoteBootstrapCheckout(t)
	base := []string{"--no-input", "--base", "refs/heads/base", "--head", "refs/heads/review", "--generation-model", "vendor/generator", "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER", "--max-cost-micro-usd", "1000000", "--declare-remote-route"}
	run := func(extra ...string) (initRun, string) {
		dir := filepath.Join(t.TempDir(), "setup")
		return runInitScript(t, checkout, append(append([]string{"--directory", dir}, base...), extra...)), dir
	}
	result, dir := run("--provider", "openrouter", "--verification-model", "other/verifier")
	if result.code != initExitDone || initReadOpenRouterSetup(t, dir).bootstrap["provider"] != "openrouter-zdr" {
		t.Fatalf("both ZDR: exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	result, dir = run("--provider", "openrouter", "--verification-model", "other/verifier", "--context-tokens", "9000", "--generation-provider-slug", "fixture-cloud")
	saved := initReadOpenRouterSetup(t, dir)
	if result.code != initExitDone || !strings.Contains(saved.raw, `"max_context_tokens":9000`) || !strings.Contains(saved.raw, `"provider_slug_source":"operator"`) {
		t.Fatalf("flags did not override detection: exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	result, dir = run("--provider", "openrouter", "--verification-model", "plain/verifier")
	if result.code != initExitUsage || !strings.Contains(result.stderr, "Pass --without-zdr") {
		t.Fatalf("a model without ZDR was accepted silently: exit=%d %s", result.code, result.stderr)
	}
	initAssertAbsent(t, dir)
	result, dir = run("--provider", "openrouter", "--verification-model", "plain/verifier", "--without-zdr")
	if result.code != initExitDone {
		t.Fatalf("--without-zdr: exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertNotLabelledZDR(t, initReadOpenRouterSetup(t, dir), result.stdout)
	result, dir = run("--provider", "openrouter-zdr", "--verification-model", "plain/verifier")
	if result.code != initExitUsage || !strings.Contains(result.stderr, "needs zero-data-retention endpoints for both models") {
		t.Fatalf("openrouter-zdr accepted a model without ZDR: exit=%d %s", result.code, result.stderr)
	}
	initAssertAbsent(t, dir)
	result, _ = run("--provider", "openrouter-zdr", "--verification-model", "other/verifier", "--without-zdr")
	if result.code != initExitUsage || !strings.Contains(result.stderr, "cannot be combined") {
		t.Fatalf("contradictory flags: exit=%d %s", result.code, result.stderr)
	}
}

func TestInitOpenRouterUnreachableAPIFallsBackToTypedAnswers(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	api := fakeOpenRouter(t, initOpenRouterModels()...)
	api.zdr = ""
	transport := &remoteModelTransport{t: t, target: "https://openrouter.ai/api/v1/chat/completions", models: map[string]string{"vendor/generator": "[]", "other/verifier": "[]"}}
	remoteModelClient(t, transport)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1", "vendor/generator", "other/verifier",
		"",               // require zero data retention
		"128000", "8192", // typed limits
		"3", "15", "1", // typed prices and cost limit
		"", "yes", "", "y",
	)
	if result.code != initExitDone {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertOutput(t, result, "Could not read OpenRouter's API", "HTTP status 503", "cannot check which models have zero-data-retention", "Review finished")
	for _, controls := range transport.providers {
		if string(controls["zdr"]) != "true" {
			t.Fatalf("an unpinned ZDR request lost zdr: %v", controls)
		}
	}
	for _, manifest := range initReadOpenRouterSetup(t, dir).manifests {
		witness := manifest["openrouter_privacy"].(map[string]any)
		if witness["observation"] != nil || witness["provider_slug_source"] != "none" || len(witness["provider_slugs"].([]any)) != 0 {
			t.Fatalf("an unobserved witness claimed an observation: %v", witness)
		}
	}
}
