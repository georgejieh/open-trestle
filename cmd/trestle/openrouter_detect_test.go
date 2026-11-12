package main

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"
)

var openRouterTestClock = fixedSetupClock{at: time.Date(2026, 11, 10, 21, 0, 0, 0, time.UTC)}

func TestOpenRouterMicroUSDRoundsUpAndRefusesNonDecimals(t *testing.T) {
	for value, want := range map[string]uint64{"0": 0, "0.000003": 3_000_000, "0.0000044": 4_400_000, "0.0000000825": 82_500, "0.0000000000001": 1, "0.00000000000010": 1, "1": 1_000_000_000_000} {
		if got, ok := openRouterMicroUSD(value); !ok || got != want {
			t.Fatalf("%s = %d, %t; want %d", value, got, ok, want)
		}
	}
	// "2" is two dollars per token: more than the bounded price allows.
	for _, value := range []string{"", "-1", "1e-6", "0x1", " 0.1", "0.1.2", "abc", "2"} {
		if got, ok := openRouterMicroUSD(value); ok {
			t.Fatalf("%q accepted as %d", value, got)
		}
	}
}

func TestOpenRouterObservationReadsBothListsOnceWithoutCredentials(t *testing.T) {
	fake := fakeOpenRouter(t, fakeORFinder, fakeORChecker, fakeORNoZDR)
	observation := readOpenRouterObservation(context.Background(), openRouterTestClock)
	if observation.err != nil {
		t.Fatal(observation.err)
	}
	if !slices.Equal(fake.requests, []string{"https://openrouter.ai/api/v1/endpoints/zdr", "https://openrouter.ai/api/v1/models"}) {
		t.Fatalf("requests: %v", fake.requests)
	}
	if observation.zdr.digest != initSHA256(fake.zdr) || observation.models.digest != initSHA256(fake.models) || !observation.retrievedAt.Equal(openRouterTestClock.at) || observation.zdrModelCount != 2 || len(observation.catalog) != 3 {
		t.Fatalf("observation lost the exact response digests or counts: %+v", observation)
	}
	if !strings.Contains(observation.label(), "as reported by OpenRouter's API at 2026-11-10T21:00:00Z") || !strings.Contains(observation.label(), "not reviewed or verified") {
		t.Fatalf("label: %s", observation.label())
	}
	finder := observation.facts("vendor/generator")
	if !slices.Equal(finder.slugs(), []string{"fixture-cloud", "fixture-cloud/us"}) || !slices.Equal(finder.safetyExcluded, []string{"fixture-safety/global"}) {
		t.Fatalf("finder ZDR endpoints: %v excluded %v", finder.slugs(), finder.safetyExcluded)
	}
	if context, output, ok := finder.capacity(true); !ok || context != 200000 || output != 64000 {
		t.Fatalf("capacity %d %d %t", context, output, ok)
	}
	if input, output, ok := finder.prices(true); !ok || input != 3_300_000 || output != 16_500_000 || !finder.structured(true) {
		t.Fatalf("prices %d %d %t", input, output, ok)
	}
	if plain := observation.facts("plain/verifier"); plain.hasZDR() || !plain.listed {
		t.Fatalf("a model without ZDR endpoints reported some: %+v", plain)
	}
	for _, model := range observation.catalog {
		want := map[string]uint64{"vendor/generator": 2, "other/verifier": 1, "plain/verifier": 0}[model.Selector]
		if initMetadataNumber(model.Metadata, "zero_data_retention_endpoints") != want || initMetadataNumber(model.Metadata, "context_length") == 0 {
			t.Fatalf("picker metadata for %s: %s", model.Selector, model.Metadata)
		}
	}
}

func TestOpenRouterObservationExcludesEndpointsThatCannotServeAReview(t *testing.T) {
	model := fakeORModel{id: "vendor/odd", context: 32000, output: 8000, prompt: "0.000001", completion: "0.000001", zdr: []fakeOREndpoint{
		{tag: "no-max-tokens", provider: "A", context: 32000, output: 8000, prompt: "0.000001", completion: "0.000001", noMaxTokens: true},
		{tag: "short-output", provider: "B", context: 32000, output: 1024, prompt: "0.000001", completion: "0.000001"},
		{tag: "variable-price", provider: "C", context: 32000, output: 8000, prompt: "-1", completion: "-1"},
		{tag: "safety", provider: "D", context: 32000, output: 8000, prompt: "0.000001", completion: "0.000001", safety: true},
	}}
	fakeOpenRouter(t, model)
	facts := readOpenRouterObservation(context.Background(), openRouterTestClock).facts("vendor/odd")
	if facts.hasZDR() || !slices.Equal(facts.safetyExcluded, []string{"safety"}) {
		t.Fatalf("unusable endpoints pinned: %v excluded %v", facts.slugs(), facts.safetyExcluded)
	}
}

func TestOpenRouterObservationNamesAnUnreachableOrMalformedAPI(t *testing.T) {
	for name, mutate := range map[string]func(*fakeOpenRouterAPI){
		"zdr unavailable":    func(f *fakeOpenRouterAPI) { f.zdr = "" },
		"models unavailable": func(f *fakeOpenRouterAPI) { f.models = "" },
		"zdr malformed":      func(f *fakeOpenRouterAPI) { f.zdr = `{"data":"no"}` },
		"models without data": func(f *fakeOpenRouterAPI) {
			f.models = `{"total_count":0}`
		},
	} {
		t.Run(name, func(t *testing.T) {
			fake := fakeOpenRouter(t, fakeORFinder)
			mutate(fake)
			observation := readOpenRouterObservation(context.Background(), openRouterTestClock)
			if observation.err == nil || !strings.Contains(observation.err.Error(), "openrouter.ai/api/v1/") || observation.facts("vendor/generator").hasZDR() {
				t.Fatalf("failure not reported: %v", observation.err)
			}
		})
	}
}

func openRouterPlanNumbers() map[string]*uint64 {
	numbers := map[string]*uint64{}
	for _, name := range remoteBootstrapUintFlags {
		numbers[name] = new(uint64)
	}
	return numbers
}

func TestPlanOpenRouterFillsFactsAndPinsDetectedSlugs(t *testing.T) {
	fakeOpenRouter(t, fakeORFinder, fakeORChecker, fakeORNoZDR)
	observation := readOpenRouterObservation(context.Background(), openRouterTestClock)
	models := map[string]string{"generation": "vendor/generator", "verification": "other/verifier"}
	numbers := openRouterPlanNumbers()
	plan, err := planOpenRouter(observation, true, models, map[string]string{}, map[string]bool{}, numbers)
	if err != nil {
		t.Fatal(err)
	}
	if *numbers["context-tokens"] != 128000 || *numbers["output-tokens"] != 16000 || *numbers["input-micro-usd-per-million-tokens"] != 3_300_000 || *numbers["output-micro-usd-per-million-tokens"] != 16_500_000 {
		t.Fatalf("facts: %d %d %d %d", *numbers["context-tokens"], *numbers["output-tokens"], *numbers["input-micro-usd-per-million-tokens"], *numbers["output-micro-usd-per-million-tokens"])
	}
	if !slices.Equal(plan.slugs["verification"], []string{"fixture-host/fp8"}) || plan.slugSource["generation"] != "openrouter_api" || plan.allowance != 16000 {
		t.Fatalf("slugs: %v %v allowance %d", plan.slugs, plan.slugSource, plan.allowance)
	}
	// Flags override detection; the facts of operator slugs are those of
	// the endpoints they name.
	numbers = openRouterPlanNumbers()
	*numbers["context-tokens"] = 9000
	plan, err = planOpenRouter(observation, true, models, map[string]string{"generation": "fixture-cloud/us"}, map[string]bool{"context-tokens": true}, numbers)
	if err != nil || *numbers["context-tokens"] != 9000 || plan.slugSource["generation"] != "operator" || !slices.Equal(plan.slugs["generation"], []string{"fixture-cloud/us"}) || *numbers["input-micro-usd-per-million-tokens"] != 3_300_000 {
		t.Fatalf("override: %v %v %d", err, plan.slugs, *numbers["context-tokens"])
	}
	// A slug the API does not list for the model has no known facts.
	numbers = openRouterPlanNumbers()
	if _, err := planOpenRouter(observation, true, models, map[string]string{"verification": "fixture-host/fp8,another"}, map[string]bool{}, numbers); err == nil || !strings.Contains(err.Error(), "pass --context-tokens, --output-tokens, --input-micro-usd-per-million-tokens, --output-micro-usd-per-million-tokens") {
		t.Fatalf("an unlisted operator slug borrowed detected facts: %v", err)
	}
	numbers = openRouterPlanNumbers()
	*numbers["context-tokens"], *numbers["output-tokens"], *numbers["input-micro-usd-per-million-tokens"], *numbers["output-micro-usd-per-million-tokens"] = 9000, 8192, 1, 1
	plan, err = planOpenRouter(observation, true, models, map[string]string{"verification": "fixture-host/fp8,another"}, map[string]bool{"context-tokens": true, "output-tokens": true, "input-micro-usd-per-million-tokens": true, "output-micro-usd-per-million-tokens": true}, numbers)
	if err != nil || plan.slugSource["verification"] != "operator" || !slices.Equal(plan.slugs["verification"], []string{"fixture-host/fp8", "another"}) || plan.allowance != 8192 {
		t.Fatalf("operator slugs with typed facts: %v %v %d", err, plan.slugs, plan.allowance)
	}
	// Without zero data retention the listed and ZDR prices both bound the cost.
	numbers = openRouterPlanNumbers()
	models["verification"] = "plain/verifier"
	if plan, err := planOpenRouter(observation, false, models, map[string]string{}, map[string]bool{}, numbers); err != nil || *numbers["context-tokens"] != 64000 || *numbers["output-tokens"] != 8192 || *numbers["input-micro-usd-per-million-tokens"] != 3_300_000 || plan.allowance != 8192 {
		t.Fatalf("non-ZDR facts: %v %d %d %d allowance %d", err, *numbers["context-tokens"], *numbers["output-tokens"], *numbers["input-micro-usd-per-million-tokens"], plan.allowance)
	}
}

func TestPlanOpenRouterRefusesWhatItCannotFill(t *testing.T) {
	fake := fakeOpenRouter(t, fakeORFinder, fakeORNoZDR)
	observation := readOpenRouterObservation(context.Background(), openRouterTestClock)
	models := map[string]string{"generation": "vendor/generator", "verification": "plain/verifier"}
	if _, err := planOpenRouter(observation, true, models, map[string]string{}, map[string]bool{}, openRouterPlanNumbers()); err == nil || !strings.Contains(err.Error(), "plain/verifier has no zero-data-retention endpoint") || !strings.Contains(err.Error(), "--provider openrouter") {
		t.Fatalf("a model without ZDR was pinned: %v", err)
	}
	models["verification"] = "missing/model"
	if _, err := planOpenRouter(observation, false, models, map[string]string{}, map[string]bool{}, openRouterPlanNumbers()); err == nil || !strings.Contains(err.Error(), "does not list the model missing/model") {
		t.Fatalf("an unlisted model was accepted: %v", err)
	}
	fake.zdr = ""
	unreachable := readOpenRouterObservation(context.Background(), openRouterTestClock)
	models["verification"] = "plain/verifier"
	plan, err := planOpenRouter(unreachable, true, models, map[string]string{}, map[string]bool{}, openRouterPlanNumbers())
	if err == nil || !strings.Contains(err.Error(), "could not be read") || !strings.Contains(err.Error(), "--context-tokens, --output-tokens, --input-micro-usd-per-million-tokens, --output-micro-usd-per-million-tokens") {
		t.Fatalf("unreachable API: %v", err)
	}
	given := map[string]bool{"context-tokens": true, "output-tokens": true, "input-micro-usd-per-million-tokens": true, "output-micro-usd-per-million-tokens": true}
	if plan, err = planOpenRouter(unreachable, true, models, map[string]string{}, given, openRouterPlanNumbers()); err != nil || plan.slugSource["verification"] != "none" || len(plan.slugs["verification"]) != 0 || plan.observed() {
		t.Fatalf("typed fallback: %v %+v", err, plan)
	}
}
