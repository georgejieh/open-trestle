package localreview

import (
	"bytes"
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func tokenUsageJSON(t *testing.T, usage TokenUsage) string {
	t.Helper()
	encoded, err := json.Marshal(usage)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

func TestAccountRouteAttemptsSumsTokensAndSettledCost(t *testing.T) {
	generation, verification := tokenStageGeneration, tokenStageVerification
	// One micro-USD per input token and two per output token.
	pricing, err := provider.NewRoutePricing(1_000_000, 2_000_000)
	if err != nil {
		t.Fatal(err)
	}
	attempt := func(input, output, cached uint64) observedAttempt {
		usage := observerUsage(t, input, output, cached)
		cost, err := provider.CalculateActualRouteCost(pricing, usage)
		if err != nil {
			t.Fatal(err)
		}
		return observedAttempt{usage: usage, cost: cost}
	}
	unreported, err := provider.CalculateActualRouteCost(pricing, provider.NewUnknownRouteTokenUsage())
	if err != nil {
		t.Fatal(err)
	}
	stage := func(id string) tokenStage {
		if strings.HasPrefix(id, "generation") {
			return generation
		}
		if strings.HasPrefix(id, "verification") {
			return verification
		}
		return tokenStageUnattributed
	}
	observed := map[string]observedAttempt{
		"verification-failed":     attempt(30, 4096, 10),
		"verification-unsettled":  attempt(30, 4096, 10),
		"verification-unreported": {usage: provider.NewUnknownRouteTokenUsage(), cost: unreported},
		"other-observed":          attempt(5, 5, 0),
	}
	lookup := func(id string) (observedAttempt, bool) { value, ok := observed[id]; return value, ok }
	settled := func(id string) bool { return id != "verification-unsettled" }
	record := func(value observedAttempt, stage tokenStage) recordedAttempt {
		return recordedAttempt{usage: value.usage, cost: value.cost, stage: stage}
	}
	generationOnly := map[string]recordedAttempt{"generation": record(attempt(100, 60, 40), generation)}
	both := map[string]recordedAttempt{"generation": generationOnly["generation"], "verification": record(attempt(50, 20, 0), verification)}
	const (
		generationTokens = `"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":60,"cached_input_tokens":40}`
		bothTokens       = `{"known":true,"route_attempts":2,"input_tokens":150,"output_tokens":80,"cached_input_tokens":40,` + generationTokens + `,"verification":{"known":true,"route_attempts":1,"input_tokens":50,"output_tokens":20,"cached_input_tokens":0}}`
		failedTokens     = `{"known":true,"route_attempts":2,"input_tokens":130,"output_tokens":4156,"cached_input_tokens":50,` + generationTokens + `,"verification":{"known":true,"route_attempts":1,"input_tokens":30,"output_tokens":4096,"cached_input_tokens":10}}`
		unknownTokens    = `{"known":false,"route_attempts":2,` + generationTokens + `,"verification":{"known":false,"route_attempts":1}}`
	)
	for _, test := range []struct {
		name      string
		claims    []string
		recorded  map[string]recordedAttempt
		tokens    string
		costKnown bool
		cost      uint64
	}{
		{"none", nil, nil, `{"known":true,"route_attempts":0,"input_tokens":0,"output_tokens":0,"cached_input_tokens":0,"generation":{"known":true,"route_attempts":0,"input_tokens":0,"output_tokens":0,"cached_input_tokens":0},"verification":{"known":true,"route_attempts":0,"input_tokens":0,"output_tokens":0,"cached_input_tokens":0}}`, true, 0},
		{"recorded", []string{"generation", "verification"}, both, bothTokens, true, 220 + 90},
		{"settled failed attempt that reported usage", []string{"generation", "verification-failed"}, generationOnly, failedTokens, true, 220 + 8222},
		{"failed attempt with no settlement", []string{"generation", "verification-unsettled"}, generationOnly, failedTokens, false, 0},
		{"attempt without reported usage", []string{"generation", "verification-unreported"}, generationOnly, unknownTokens, false, 0},
		{"claim with no observed result", []string{"generation", "verification-never-dispatched"}, generationOnly, unknownTokens, false, 0},
		{"attempt of no known stage", []string{"generation", "other-observed"}, generationOnly, `{"known":true,"route_attempts":2,"input_tokens":105,"output_tokens":65,"cached_input_tokens":40,"generation":{"known":false,"route_attempts":1},"verification":{"known":false,"route_attempts":0}}`, true, 220 + 15},
		{"recorded attempt without a claim", []string{"generation"}, both, bothTokens, true, 220 + 90},
		{"repeated claim", []string{"generation", "generation", "verification"}, both, bothTokens, true, 220 + 90},
	} {
		t.Run(test.name, func(t *testing.T) {
			account := accountRouteAttempts(test.claims, test.recorded, stage, lookup, settled)
			if got := tokenUsageJSON(t, account.tokens); got != test.tokens {
				t.Fatalf("token usage\n got %s\nwant %s", got, test.tokens)
			}
			if account.costKnown != test.costKnown || account.costMicroUSD != test.cost {
				t.Fatalf("cost known=%t %d, want known=%t %d", account.costKnown, account.costMicroUSD, test.costKnown, test.cost)
			}
		})
	}
}

// tokenResultRun runs the real nine-task review with the given model modes.
func tokenResultRun(t *testing.T, name string, options rmModelFixtureOptions) Result {
	t.Helper()
	f := newRmModelFixture(t, options)
	sessionOptions := rmOptions(t, f, rmNewClock())
	sessionOptions.ArtifactCapacity = 1024
	s, err := NewSession(sessionOptions)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rmClose(t, s) })
	result, err := s.Run(context.Background(), rmPrepare(t, s, f, "token-result-"+name))
	if err != nil {
		t.Fatal(err)
	}
	return result
}

const reportedStage = `{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0}`

func TestResultReportsTokensOfTheDispatchedRouteAttempts(t *testing.T) {
	for _, test := range []struct {
		name             string
		options          rmModelFixtureOptions
		runStatus, json  string
		text             string
		usageKnown       bool
		generationCalled bool
	}{
		{
			name: "reported", runStatus: "succeeded", usageKnown: true,
			json: `"token_usage":{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":0,"generation":` + reportedStage + `,"verification":` + reportedStage + `}`,
			text: "tokens: input=200 output=200 cached_input=0 over 2 route attempts\n",
		},
		{
			name: "cached", options: rmModelFixtureOptions{generationMode: "cached"}, runStatus: "succeeded", usageKnown: true,
			json: `"token_usage":{"known":true,"route_attempts":2,"input_tokens":200,"output_tokens":200,"cached_input_tokens":40,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":40},"verification":` + reportedStage + `}`,
			text: "tokens: input=200 output=200 cached_input=40 over 2 route attempts\n",
		},
		{
			name: "unreported", options: rmModelFixtureOptions{verificationMode: "unreported"}, runStatus: "succeeded",
			json: `"token_usage":{"known":false,"route_attempts":2,"generation":` + reportedStage + `,"verification":{"known":false,"route_attempts":1}}`,
			text: "tokens: unknown over 2 route attempts (not every attempt reported usage)\n",
		},
		{
			name: "rejected generation", options: rmModelFixtureOptions{generationMode: "malformed"}, runStatus: "failed", usageKnown: true,
			json: `"token_usage":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0,"generation":` + reportedStage + `,"verification":{"known":true,"route_attempts":0,"input_tokens":0,"output_tokens":0,"cached_input_tokens":0}}`,
			text: "tokens: input=100 output=100 cached_input=0 over 1 route attempt\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := tokenResultRun(t, strings.ReplaceAll(test.name, " ", "-"), test.options)
			if result.wire.RunStatus != test.runStatus || result.wire.Version != tokenUsageResultVersion || result.wire.UsageKnown != test.usageKnown {
				t.Fatalf("run=%s version=%d usage_known=%t", result.wire.RunStatus, result.wire.Version, result.wire.UsageKnown)
			}
			// Cost is known exactly when every claimed attempt has a known
			// settlement, as tokens are when every attempt reported usage.
			if slices.Contains(result.wire.Limitations, "unknown_final_usage") == test.usageKnown || result.wire.UsageKnown != result.wire.TokenUsage.Known {
				t.Fatalf("usage_known=%t tokens known=%t limitations=%v", result.wire.UsageKnown, result.wire.TokenUsage.Known, result.wire.Limitations)
			}
			encoded, err := EncodeResult(result)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(encoded, []byte(`"schema_version":6,`)) || !bytes.Contains(encoded, []byte(`,"actual_cost_micro_usd":0,`+test.json+`,"lease_renewals":`)) {
				t.Fatalf("JSON result lacks %s:\n%s", test.json, encoded)
			}
			var text bytes.Buffer
			if err := RenderResult(&text, result); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(text.String(), test.text+"comprehensive clearance: false\n") {
				t.Fatalf("text result lacks %q before the clearance line:\n%s", test.text, text.String())
			}
			report, err := result.Report()
			if err != nil || report.TokenUsage == nil || tokenUsageJSON(t, *report.TokenUsage) != strings.TrimPrefix(test.json, `"token_usage":`) {
				t.Fatalf("report token usage = %+v (%v)", report.TokenUsage, err)
			}
		})
	}
}

func TestUnstartedResultsReportNoTokenUsage(t *testing.T) {
	result, err := NewUnstartedResult("refused")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeResult(result)
	if err != nil || bytes.Contains(encoded, []byte("token_usage")) || !bytes.Contains(encoded, []byte(`"schema_version":1,`)) {
		t.Fatalf("unstarted result: %s (%v)", encoded, err)
	}
	var text bytes.Buffer
	if err := RenderResult(&text, result); err != nil || strings.Contains(text.String(), "tokens:") {
		t.Fatalf("unstarted text: %q (%v)", text.String(), err)
	}
	if report, err := result.Report(); err != nil || report.TokenUsage != nil {
		t.Fatalf("unstarted report token usage = %+v (%v)", report.TokenUsage, err)
	}
}

// earlierVersion removes the version 6 members of a version 6 result (token
// usage, the recorded judgement and the walkthrough) and labels it
// version, as an earlier build recorded it.
func earlierVersion(t *testing.T, result Result, encoded []byte, version string) []byte {
	t.Helper()
	tokens := `,"token_usage":` + tokenUsageJSON(t, *result.wire.TokenUsage)
	earlier := bytes.Replace(encoded, []byte(tokens), nil, 1)
	earlier = bytes.Replace(earlier, []byte(`"schema_version":6,`), []byte(`"schema_version":`+version+`,`), 1)
	if bytes.Equal(earlier, encoded) || bytes.Contains(earlier, []byte("token_usage")) {
		t.Fatal("fixture did not remove the token usage")
	}
	var wire resultWire
	if err := json.Unmarshal(earlier, &wire); err != nil {
		t.Fatal(err)
	}
	wire.Rank, wire.PreExisting, wire.Anchors, wire.Walkthrough = nil, nil, nil, nil
	stripped, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	return append(stripped, '\n')
}

func TestCompletedResultImportReadsVersion6AndEarlierVersionsUnchanged(t *testing.T) {
	result := tokenResultRun(t, "import", rmModelFixtureOptions{})
	encoded, err := EncodeResult(result)
	if err != nil {
		t.Fatal(err)
	}
	for name, recorded := range map[string][]byte{"version 6": encoded, "version 4": earlierVersion(t, result, encoded, "4")} {
		imported, err := ParseCompletedResult(recorded)
		if err != nil {
			t.Fatalf("%s does not import: %v", name, err)
		}
		again, err := EncodeResult(imported)
		if err != nil || !bytes.Equal(again, recorded) {
			t.Fatalf("%s readback changed its bytes: %v", name, err)
		}
		if _, err := imported.CompletedMetadata(); err != nil {
			t.Fatalf("%s metadata: %v", name, err)
		}
		report, err := imported.Report()
		if err != nil || (report.TokenUsage != nil) != (name == "version 6") {
			t.Fatalf("%s report token usage = %+v (%v)", name, report.TokenUsage, err)
		}
	}
	usage := tokenUsageJSON(t, *result.wire.TokenUsage)
	for name, tampered := range map[string][]byte{
		"version 6 without token usage":   bytes.Replace(earlierVersion(t, result, encoded, "4"), []byte(`"schema_version":4,`), []byte(`"schema_version":6,`), 1),
		"version 4 with token usage":      bytes.Replace(encoded, []byte(`"schema_version":6,`), []byte(`"schema_version":4,`), 1),
		"version 5 with token usage":      bytes.Replace(encoded, []byte(`"schema_version":6,`), []byte(`"schema_version":5,`), 1),
		"unknown counts with numbers":     bytes.Replace(encoded, []byte(`{"known":true,"route_attempts":2,`), []byte(`{"known":false,"route_attempts":2,`), 1),
		"known total without numbers":     bytes.Replace(encoded, []byte(usage), []byte(`{"known":true,"route_attempts":2,"generation":`+reportedStage+`,"verification":`+reportedStage+`}`), 1),
		"total that is not the sum":       bytes.Replace(encoded, []byte(`"input_tokens":200,`), []byte(`"input_tokens":201,`), 1),
		"third route attempt":             bytes.Replace(encoded, []byte(`"route_attempts":2,`), []byte(`"route_attempts":3,`), 1),
		"unknown total beside known cost": bytes.Replace(encoded, []byte(usage), []byte(`{"known":false,"route_attempts":2,"generation":`+reportedStage+`,"verification":{"known":false,"route_attempts":1}}`), 1),
		"cached above input":              bytes.Replace(encoded, []byte(`"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0}`), []byte(`"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":101}`), 1),
	} {
		if bytes.Equal(tampered, encoded) {
			t.Fatalf("%s fixture did not change the result", name)
		}
		if _, err := ParseCompletedResult(tampered); err == nil {
			t.Fatalf("%s imported", name)
		}
	}
}
