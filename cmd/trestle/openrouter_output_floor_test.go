package main

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Every model, endpoint, price and limit below is a synthetic offline fixture
// served by fakeOpenRouter. The finder has two endpoints that allow 32768
// output tokens and two that allow less (4096 and 8192, the most expensive
// first in price), as the live gpt-oss-120b list had; the checker's endpoints
// all allow 65536, one with a smaller context; fixture/short has no endpoint
// that reaches the 16384 target.
var (
	floorFinder = fakeORModel{id: "fixture/oss", context: 131072, output: 32768, prompt: "0.0000001", completion: "0.0000005", zdr: []fakeOREndpoint{
		{tag: "fx-a", provider: "Fixture A", context: 131072, output: 32768, prompt: "0.0000001", completion: "0.0000005"},
		{tag: "fx-b", provider: "Fixture B", context: 131072, output: 32768, prompt: "0.00000012", completion: "0.0000006"},
		{tag: "fx-do", provider: "Fixture Small", context: 131072, output: 4096, prompt: "0.0000003", completion: "0.000002"},
		{tag: "fx-sf", provider: "Fixture Medium", context: 131072, output: 8192, prompt: "0.00000015", completion: "0.0000007"},
	}}
	floorChecker = fakeORModel{id: "fixture/glm", context: 1048576, output: 65536, prompt: "0.0000002", completion: "0.000001", zdr: []fakeOREndpoint{
		{tag: "gx-a", provider: "Fixture G", context: 1048576, output: 65536, prompt: "0.0000002", completion: "0.000001"},
		{tag: "gx-b", provider: "Fixture H", context: 262000, output: 65536, prompt: "0.00000025", completion: "0.0000011"},
	}}
	floorShort = fakeORModel{id: "fixture/short", context: 65536, output: 8192, prompt: "0.0000001", completion: "0.0000002", zdr: []fakeOREndpoint{
		{tag: "sx-a", provider: "Fixture S", context: 65536, output: 4096, prompt: "0.0000001", completion: "0.0000002"},
		{tag: "sx-b", provider: "Fixture T", context: 65536, output: 8192, prompt: "0.0000001", completion: "0.0000003"},
	}}
)

func floorPlan(t *testing.T, verifier string, given map[string]uint64, zdr bool) (openRouterPlan, map[string]*uint64, error) {
	t.Helper()
	fakeOpenRouter(t, floorFinder, floorChecker, floorShort)
	observation := readOpenRouterObservation(context.Background(), openRouterTestClock)
	numbers, set := openRouterPlanNumbers(), map[string]bool{}
	for name, value := range given {
		*numbers[name], set[name] = value, true
	}
	plan, err := planOpenRouter(observation, zdr, map[string]string{"generation": "fixture/oss", "verification": verifier}, map[string]string{}, set, numbers)
	return plan, numbers, err
}

func floorTags(endpoints []openRouterEndpoint) []string {
	tags := []string{}
	for _, endpoint := range endpoints {
		tags = append(tags, endpoint.tag)
	}
	return tags
}

func TestPlanOpenRouterPinsOnlyEndpointsThatMeetTheOutputFloor(t *testing.T) {
	plan, numbers, err := floorPlan(t, "fixture/glm", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	finder := plan.facts["generation"]
	if plan.allowance != 16384 || !slices.Equal(plan.slugs["generation"], []string{"fx-a", "fx-b"}) || !slices.Equal(floorTags(finder.outputExcluded), []string{"fx-sf", "fx-do"}) || !slices.Equal(plan.slugs["verification"], []string{"gx-a", "gx-b"}) || plan.route.excluded() != 2 {
		t.Fatalf("pinned %v and %v, left out %v, allowance %d", plan.slugs["generation"], plan.slugs["verification"], floorTags(finder.outputExcluded), plan.allowance)
	}
	// The declared limits and the prices come from the pinned endpoints only:
	// the left-out endpoints' smaller output and higher prices count nowhere.
	if *numbers["context-tokens"] != 131072 || *numbers["output-tokens"] != 32768 || *numbers["input-micro-usd-per-million-tokens"] != 250_000 || *numbers["output-micro-usd-per-million-tokens"] != 1_100_000 {
		t.Fatalf("facts: %d %d %d %d", *numbers["context-tokens"], *numbers["output-tokens"], *numbers["input-micro-usd-per-million-tokens"], *numbers["output-micro-usd-per-million-tokens"])
	}
	witness := plan.observation.witnessObservation(finder)
	excluded := witness["output_limit_endpoints_excluded"].([]map[string]any)
	if len(excluded) != 2 || excluded[0]["tag"] != "fx-sf" || excluded[0]["max_completion_tokens"] != uint64(8192) || excluded[1]["tag"] != "fx-do" || excluded[1]["max_completion_tokens"] != uint64(4096) || len(witness["zdr_endpoints"].([]map[string]any)) != 2 {
		t.Fatalf("witness exclusions: %v", witness)
	}
}

// A model none of whose endpoints reaches the target keeps its usable
// endpoints (the minimum rule) and lowers the allowance to their least
// output; the other model is then pinned with the same floor.
func TestPlanOpenRouterFallsBackWhenNoEndpointReachesTheTarget(t *testing.T) {
	plan, numbers, err := floorPlan(t, "fixture/short", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if plan.allowance != 4096 || !slices.Equal(plan.route.short, []string{"verification"}) || !slices.Equal(plan.slugs["verification"], []string{"sx-a", "sx-b"}) || !slices.Equal(plan.slugs["generation"], []string{"fx-a", "fx-b", "fx-sf", "fx-do"}) || plan.route.excluded() != 0 {
		t.Fatalf("fallback pinned %v and %v, short %v, allowance %d", plan.slugs["generation"], plan.slugs["verification"], plan.route.short, plan.allowance)
	}
	if *numbers["output-tokens"] != 4096 || *numbers["input-micro-usd-per-million-tokens"] != 300_000 || *numbers["output-micro-usd-per-million-tokens"] != 2_000_000 {
		t.Fatalf("fallback facts: %d %d %d", *numbers["output-tokens"], *numbers["input-micro-usd-per-million-tokens"], *numbers["output-micro-usd-per-million-tokens"])
	}
}

func TestPlanOpenRouterLetsTheOutputFlagsSetTheTarget(t *testing.T) {
	for _, test := range []struct {
		name      string
		given     map[string]uint64
		allowance uint64
	}{
		{"max-output-tokens", map[string]uint64{"max-output-tokens": 8192}, 8192},
		{"output-tokens", map[string]uint64{"output-tokens": 8192}, 8192},
	} {
		t.Run(test.name, func(t *testing.T) {
			plan, _, err := floorPlan(t, "fixture/glm", test.given, true)
			if err != nil || plan.allowance != test.allowance || !slices.Equal(plan.slugs["generation"], []string{"fx-a", "fx-b", "fx-sf"}) || !slices.Equal(floorTags(plan.facts["generation"].outputExcluded), []string{"fx-do"}) {
				t.Fatalf("%v pinned %v, allowance %d", err, plan.slugs["generation"], plan.allowance)
			}
		})
	}
	// An allowance no endpoint of a model reaches is refused, never lowered.
	if _, _, err := floorPlan(t, "fixture/glm", map[string]uint64{"max-output-tokens": 40000}, true); err == nil || !strings.Contains(err.Error(), "--max-output-tokens 40000 is more than any zero-data-retention endpoint of fixture/oss that Open Trestle can use allows (at most 32768 output tokens") {
		t.Fatalf("an unreachable --max-output-tokens: %v", err)
	}
	// Without zero data retention nothing is pinned; the target is bounded by
	// the smaller listed output of the two models.
	plan, numbers, err := floorPlan(t, "fixture/glm", nil, false)
	if err != nil || plan.allowance != 16384 || *numbers["output-tokens"] != 32768 || len(plan.slugs) != 0 {
		t.Fatalf("non-ZDR: %v allowance %d output %d slugs %v", err, plan.allowance, *numbers["output-tokens"], plan.slugs)
	}
	plan, _, err = floorPlan(t, "fixture/short", nil, false)
	if err != nil || plan.allowance != 8192 {
		t.Fatalf("non-ZDR with a small listed output: %v allowance %d", err, plan.allowance)
	}
}

func floorBootstrapArgs(t *testing.T, provider, verifier string, extra ...string) ([]string, string) {
	t.Helper()
	args, dir := remoteBootstrapArgs(t, provider)
	fakeOpenRouter(t, floorFinder, floorChecker, floorShort)
	args = replaceLocalGitChangeValue(args, "--generation-model", "fixture/oss")
	args = replaceLocalGitChangeValue(args, "--verification-model", verifier)
	return append(args, extra...), dir
}

func TestSetupBootstrapOpenRouterRecordsTheOutputFloor(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_REMOTE_TEST", remoteTestKey)
	for _, test := range []struct {
		name, verifier string
		extra          []string
		allowance      float64
		output         string
		generation     []string
		excluded       []string
		timeout        string
	}{
		{"default target", "fixture/glm", nil, 16384, `"max_output_tokens":32768`, []string{"fx-a", "fx-b"}, []string{"fx-sf", "fx-do"}, "12m"},
		{"flag wins", "fixture/glm", []string{"--max-output-tokens", "8192"}, 8192, `"max_output_tokens":8192`, []string{"fx-a", "fx-b", "fx-sf"}, []string{"fx-do"}, "10m"},
		{"fallback", "fixture/short", nil, 4096, `"max_output_tokens":4096`, []string{"fx-a", "fx-b", "fx-sf", "fx-do"}, nil, "10m"},
	} {
		t.Run(test.name, func(t *testing.T) {
			args, dir := floorBootstrapArgs(t, "openrouter-zdr", test.verifier, test.extra...)
			remoteBootstrapInvoke(t, args, 0)
			saved := initReadOpenRouterSetup(t, dir)
			if saved.policy["max_output_tokens"] != test.allowance || !strings.Contains(saved.raw, test.output) {
				t.Fatalf("policy allowance %v, routes %s", saved.policy["max_output_tokens"], saved.raw)
			}
			connection := saved.policy["connections"].([]any)[0].(map[string]any)
			slugs := []string{}
			for _, slug := range connection["brokered_route_authority"].(map[string]any)["provider_slugs"].([]any) {
				slugs = append(slugs, slug.(string))
			}
			observation := saved.manifests[0]["openrouter_privacy"].(map[string]any)["observation"].(map[string]any)
			excluded := []string{}
			for _, entry := range observation["output_limit_endpoints_excluded"].([]any) {
				excluded = append(excluded, entry.(map[string]any)["tag"].(string))
			}
			if !slices.Equal(slugs, test.generation) || !slices.Equal(excluded, append([]string{}, test.excluded...)) || len(observation["zdr_endpoints"].([]any)) != len(test.generation) {
				t.Fatalf("pinned %v, recorded as left out %v", slugs, excluded)
			}
			// The review command leaves room for two requests that each run to
			// the deadline their allowance gives them.
			command := []string{}
			for _, argument := range saved.bootstrap["review_command"].([]any) {
				command = append(command, argument.(string))
			}
			if index := slices.Index(command, "--timeout"); index < 0 || command[index+1] != test.timeout {
				t.Fatalf("review command %v, want --timeout %s", command, test.timeout)
			}
		})
	}
	// A flag no endpoint reaches is refused before anything is written.
	args, dir := floorBootstrapArgs(t, "openrouter-zdr", "fixture/glm", "--max-output-tokens", "40000")
	refused, _ := remoteBootstrapInvoke(t, args, 4)
	if !strings.Contains(strings.Join(refused.Messages, " "), "--max-output-tokens 40000 is more than any zero-data-retention endpoint of fixture/oss") {
		t.Fatalf("refusal: %+v", refused)
	}
	initAssertAbsent(t, filepath.Join(dir, "policy.json"))
	// Without zero data retention the allowance follows the listed outputs.
	args, dir = floorBootstrapArgs(t, "openrouter", "fixture/glm")
	remoteBootstrapInvoke(t, args, 0)
	if saved := initReadOpenRouterSetup(t, dir); saved.policy["max_output_tokens"] != float64(16384) {
		t.Fatalf("non-ZDR allowance %v", saved.policy["max_output_tokens"])
	}
}

func TestInitOpenRouterSaysWhichEndpointsTheOutputFloorLeavesOut(t *testing.T) {
	remoteScannerInstalled(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_OPENROUTER", remoteTestKey)
	fakeOpenRouter(t, append(initOpenRouterModels(), floorFinder, floorChecker, floorShort)...)
	checkout := remoteBootstrapCheckout(t)
	run := func(verifier string, extra ...string) (initRun, string) {
		dir := filepath.Join(t.TempDir(), "setup")
		args := []string{"--directory", dir, "--no-input", "--provider", "openrouter", "--base", "refs/heads/base", "--head", "refs/heads/review", "--generation-model", "fixture/oss", "--verification-model", verifier, "--credential-env", "OPEN_TRESTLE_PROVIDER_OPENROUTER", "--max-cost-micro-usd", "1000000", "--declare-remote-route"}
		return runInitScript(t, checkout, append(args, extra...)), dir
	}
	result, dir := run("fixture/glm")
	if result.code != initExitDone {
		t.Fatalf("init exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertOutput(t, result, "zero data retention on 2 endpoints (fx-a, fx-b)", "2 endpoints that allow less than 16384 output tokens are left out.",
		"Limits: context 131072 and output 32768 tokens, the smallest that any pinned endpoint of either model allows.", "Each model request may write up to 16384 tokens.")
	if saved := initReadOpenRouterSetup(t, dir); saved.policy["max_output_tokens"] != float64(16384) || !strings.Contains(saved.raw, `"provider_slugs":["fx-a","fx-b"]`) {
		t.Fatalf("saved allowance %v", saved.policy["max_output_tokens"])
	}
	result, dir = run("fixture/short")
	if result.code != initExitDone {
		t.Fatalf("fallback init exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertOutput(t, result, "fixture/short has no zero-data-retention endpoint that allows 16384 output tokens, so its usable endpoints are pinned and each model request may write up to 4096 tokens.")
	if initHas(result.stdout, "output tokens are left out") || initHas(result.stdout, "output tokens is left out") {
		t.Fatalf("a fallback named endpoints as left out:\n%s", result.stdout)
	}
	if saved := initReadOpenRouterSetup(t, dir); saved.policy["max_output_tokens"] != float64(4096) {
		t.Fatalf("fallback allowance %v", saved.policy["max_output_tokens"])
	}
	result, dir = run("fixture/glm", "--max-output-tokens", "8192")
	if result.code != initExitDone {
		t.Fatalf("flag init exit=%d\n%s\n%s", result.code, result.stdout, result.stderr)
	}
	initAssertOutput(t, result, "1 endpoint that allows less than 8192 output tokens is left out.", "Each model request may write up to 8192 tokens (--max-output-tokens).")
	if saved := initReadOpenRouterSetup(t, dir); saved.policy["max_output_tokens"] != float64(8192) {
		t.Fatalf("flag allowance %v", saved.policy["max_output_tokens"])
	}
	result, dir = run("fixture/glm", "--max-output-tokens", "40000")
	if result.code != initExitUsage || !initHas(result.stderr, "--max-output-tokens 40000 is more than any zero-data-retention endpoint of fixture/oss") {
		t.Fatalf("an unreachable flag: exit=%d %s", result.code, result.stderr)
	}
	initAssertAbsent(t, dir)
}

func TestRemoteReviewTimeoutCoversTwoRequestsAtTheirDeadline(t *testing.T) {
	for allowance, want := range map[uint64]string{4096: "10m", 8192: "10m", 9000: "11m", 10240: "12m", 16384: "12m", 1 << 40: "12m"} {
		if got := remoteReviewTimeout(allowance); got != want {
			t.Fatalf("remoteReviewTimeout(%d) = %s, want %s", allowance, got, want)
		}
	}
}
