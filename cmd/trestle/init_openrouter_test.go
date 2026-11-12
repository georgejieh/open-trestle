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
		if !initHas(result.stdout, want) {
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
		if initHas(shown, forbidden) {
			t.Fatalf("a setup without zero data retention showed %q:\n%s", forbidden, shown)
		}
	}
}

func TestInitOpenRouterBothModelsWithZDRRequiresItByDefault(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	api := fakeOpenRouter(t, initOpenRouterModels()...)
	// The checker's only endpoint allows 16000 output tokens, under the 16384
	// target, so it is pinned anyway and the allowance is 16000.
	transport := &remoteModelTransport{t: t, target: "https://openrouter.ai/api/v1/chat/completions", models: map[string]string{"vendor/generator": `["fixture-cloud","fixture-cloud/us"]`, "other/verifier": `["fixture-host/fp8"]`}, maxTokens: 16000}
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
		"",    // use the settings shown
		"yes", // consent
		"y",   // run the review
	)
	if result.code != initExitDone {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertOutput(t, result, "46 models listed; 2 have zero-data-retention endpoints", "same model as the finder",
		"zero data retention on 2 endpoints (fixture-cloud, fixture-cloud/us)", "zero data retention on 1 endpoint (fixture-host/fp8)",
		"Limits: context 128000 and output 16000 tokens, the smallest that any pinned endpoint of either model allows",
		"other/verifier has no zero-data-retention endpoint that allows 16384 output tokens, so its usable endpoints are pinned and each model request may write up to 16000 tokens.",
		"Prices: up to $3.30 input and $16.50 output", "[0.69]", "Endpoints that may keep prompts for Safety Retention are left out.",
		"The limit applies to each model request. A review sends two, one to each model, so it costs at most twice the limit", "Most one model request may cost, in USD",
		"most $0.69 a request ($1.38 a review)",
		"Zero data retention is required on every request", "Review finished: 1 confirmed finding",
		"A review sends the selected source to OpenRouter (https://openrouter.ai/api/v1), zero data retention required on every request")
	if initHas(result.stdout, "openrouter_zero_data_retention_not_required") {
		t.Fatal("a ZDR review was labelled as not requiring zero data retention")
	}
	for _, asked := range []string{"provider slug for", "Evidence:", "How many days", "review window", "SHA-256 of the copy"} {
		if initHas(result.stdout, asked) {
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
	if saved.policy["schema_version"] != float64(8) || saved.policy["max_output_tokens"] != float64(16000) || saved.bootstrap["provider"] != "openrouter-zdr" || strings.Contains(saved.raw, remoteTestKey) {
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

func TestInitOpenRouterFilterRanksExactIDFirstAndCountsOnlyMatches(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	longer := fakeORFinder
	longer.id = "vendor/generator-pro"
	models := append([]fakeORModel{longer}, initOpenRouterModels()...)
	fakeOpenRouter(t, models...)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1",                     // OpenRouter
		"vendor/generator", "1", // the exact ID is listed first, ahead of a longer name
		"model", "other/verifier", // 43 fillers match; 40 are listed
		"",    // require zero data retention
		"",    // accept the proposed cost limit
		"",    // use the settings shown
		"yes", // consent
		"n",   // no review
	)
	if result.code != initExitDone {
		t.Fatalf("init exit=%d\nstdout:\n%s\nstderr:\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertOutput(t, result, "1) vendor/generator (context 200000", "2) vendor/generator-pro", "Finder vendor/generator", "... 3 more match; type more of the name, or an exact ID.")
	if initHas(result.stdout, "more; type an exact ID") {
		t.Fatalf("a filtered list counted models that do not match:\n%s", result.stdout)
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
		"", "", "yes", "n",
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
	// Without zero data retention the allowance is the 16384 target within
	// the smaller listed output of the two models (8192).
	transport := &remoteModelTransport{t: t, target: "https://openrouter.ai/api/v1/chat/completions", models: map[string]string{"vendor/generator": "", "plain/verifier": ""}, maxTokens: 8192}
	remoteModelClient(t, transport)
	checkout := remoteBootstrapCheckout(t)
	// Declining to continue writes nothing.
	declined := filepath.Join(t.TempDir(), "setup")
	stopped := runInitScript(t, checkout, []string{"--directory", declined, "--base", "refs/heads/base", "--head", "refs/heads/review"}, "1", "generator", "1", "plain", "1", "n", "")
	if stopped.code != initExitRefused || !initHas(stopped.stderr, "nothing was written") {
		t.Fatalf("declining did not stop: exit=%d %s", stopped.code, stopped.stderr)
	}
	initAssertAbsent(t, declined)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1", "generator", "1", "plain", "1",
		"n", // keep the model without zero data retention
		"y", // continue without zero data retention
		"", "", "yes", "y",
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
		"", "", "yes", "n",
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
	if result.code != initExitUsage || !initHas(result.stderr, "Pass --without-zdr") {
		t.Fatalf("a model without ZDR was accepted silently: exit=%d %s", result.code, result.stderr)
	}
	initAssertAbsent(t, dir)
	result, dir = run("--provider", "openrouter", "--verification-model", "plain/verifier", "--without-zdr")
	if result.code != initExitDone {
		t.Fatalf("--without-zdr: exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertNotLabelledZDR(t, initReadOpenRouterSetup(t, dir), result.stdout)
	result, dir = run("--provider", "openrouter-zdr", "--verification-model", "plain/verifier")
	if result.code != initExitUsage || !initHas(result.stderr, "needs zero-data-retention endpoints for both models") {
		t.Fatalf("openrouter-zdr accepted a model without ZDR: exit=%d %s", result.code, result.stderr)
	}
	initAssertAbsent(t, dir)
	result, _ = run("--provider", "openrouter-zdr", "--verification-model", "other/verifier", "--without-zdr")
	if result.code != initExitUsage || !initHas(result.stderr, "cannot be combined") {
		t.Fatalf("contradictory flags: exit=%d %s", result.code, result.stderr)
	}
}

func TestInitOpenRouterUnreachableAPIFallsBackToTypedAnswers(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	api := fakeOpenRouter(t, initOpenRouterModels()...)
	api.zdr = ""
	// The typed output limit (8192) bounds the 16384 target.
	transport := &remoteModelTransport{t: t, target: "https://openrouter.ai/api/v1/chat/completions", models: map[string]string{"vendor/generator": "[]", "other/verifier": "[]"}, maxTokens: 8192}
	remoteModelClient(t, transport)
	checkout := remoteBootstrapCheckout(t)
	dir := filepath.Join(t.TempDir(), "setup")
	result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review"},
		"1", "vendor/generator", "other/verifier",
		"",               // require zero data retention
		"128000", "8192", // typed limits
		"3", "15", "1", // typed prices and cost limit
		"", "yes", "y",
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

// --provider openrouter-zdr has already chosen zero data retention, so the
// wizard does not ask again, even when the API cannot be read.
func TestInitOpenRouterZDRProviderDoesNotAskAgain(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	api := fakeOpenRouter(t, initOpenRouterModels()...)
	checkout := remoteBootstrapCheckout(t)
	for _, reachable := range []bool{true, false} {
		script := []string{"generator", "1", "", "other/verifier", "", "", "yes", "n"}
		if !reachable {
			api.zdr = ""
			script = []string{"vendor/generator", "other/verifier", "128000", "8192", "3", "15", "1", "", "yes", "n"}
		}
		dir := filepath.Join(t.TempDir(), "setup")
		result := runInitScript(t, checkout, []string{"--directory", dir, "--base", "refs/heads/base", "--head", "refs/heads/review", "--provider", "openrouter-zdr"}, script...)
		if result.code != initExitDone || initHas(result.stdout, "Require zero data retention on every request") || initReadOpenRouterSetup(t, dir).bootstrap["provider"] != "openrouter-zdr" {
			t.Fatalf("reachable=%t exit=%d\n%s\n%s", reachable, result.code, result.stdout, result.stderr)
		}
	}
}

func TestInitHangingWrapIndentsContinuationUnderTheValue(t *testing.T) {
	got := initHangingWrap("limitations: loose_and_pack_index_v1_subset, empty_memory_index, bounded_source_context, no_publication", 56)
	want := []string{
		"limitations: loose_and_pack_index_v1_subset,",
		"             empty_memory_index, bounded_source_context,",
		"             no_publication",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("hanging wrap:\n%q\nwant\n%q", got, want)
	}
	for _, line := range []string{"No label on this line, which is long enough that it has to wrap onto another line", "comprehensive clearance: false", "Status: failed"} {
		if got, flush := initHangingWrap(line, 56), initWrapWords(line, 56); !slices.Equal(got, flush) {
			t.Fatalf("%q wrapped %q, want flush %q", line, got, flush)
		}
	}
	for _, line := range initHangingWrap("hint: "+strings.Repeat("word ", 30), 56) {
		if len(line) > 56 {
			t.Fatalf("line longer than the width: %q", line)
		}
	}
}

func TestInitFormatUSDShowsWholeCents(t *testing.T) {
	for micro, want := range map[uint64]string{0: "$0.00", 100_000: "$0.10", 3_300_000: "$3.30", 16_500_000: "$16.50", 490_000: "$0.49", 48_692: "$0.048692", 1: "$0.000001", 2_000_000: "$2.00"} {
		if got := initFormatUSD(micro); got != want {
			t.Fatalf("initFormatUSD(%d) = %q, want %q", micro, got, want)
		}
	}
}
