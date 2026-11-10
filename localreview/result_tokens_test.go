package localreview

import (
	"bytes"
	"context"
	"encoding/json"
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

func TestAccountTokenUsageSumsReportedAttemptsAndPropagatesUnknown(t *testing.T) {
	generation, verification := tokenStageGeneration, tokenStageVerification
	known := func(input, output, cached uint64) provider.RouteTokenUsage {
		return observerUsage(t, input, output, cached)
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
	observed := map[string]provider.RouteTokenUsage{
		"verification-failed":     known(30, 4096, 10),
		"verification-unreported": provider.NewUnknownRouteTokenUsage(),
		"other-observed":          known(5, 5, 0),
	}
	lookup := func(id string) (provider.RouteTokenUsage, bool) { usage, ok := observed[id]; return usage, ok }
	generationOnly := map[string]recordedTokenUsage{"generation": {known(100, 60, 40), generation}}
	both := map[string]recordedTokenUsage{"generation": generationOnly["generation"], "verification": {known(50, 20, 0), verification}}
	for _, test := range []struct {
		name     string
		claims   []string
		recorded map[string]recordedTokenUsage
		want     string
	}{
		{"none", nil, nil, `{"known":true,"route_attempts":0,"input_tokens":0,"output_tokens":0,"cached_input_tokens":0,"generation":{"known":true,"route_attempts":0,"input_tokens":0,"output_tokens":0,"cached_input_tokens":0},"verification":{"known":true,"route_attempts":0,"input_tokens":0,"output_tokens":0,"cached_input_tokens":0}}`},
		{"recorded", []string{"generation", "verification"}, both, `{"known":true,"route_attempts":2,"input_tokens":150,"output_tokens":80,"cached_input_tokens":40,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":60,"cached_input_tokens":40},"verification":{"known":true,"route_attempts":1,"input_tokens":50,"output_tokens":20,"cached_input_tokens":0}}`},
		{"failed attempt that reported usage", []string{"generation", "verification-failed"}, generationOnly, `{"known":true,"route_attempts":2,"input_tokens":130,"output_tokens":4156,"cached_input_tokens":50,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":60,"cached_input_tokens":40},"verification":{"known":true,"route_attempts":1,"input_tokens":30,"output_tokens":4096,"cached_input_tokens":10}}`},
		{"attempt without reported usage", []string{"generation", "verification-unreported"}, generationOnly, `{"known":false,"route_attempts":2,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":60,"cached_input_tokens":40},"verification":{"known":false,"route_attempts":1}}`},
		{"claim with no observed result", []string{"generation", "verification-never-dispatched"}, generationOnly, `{"known":false,"route_attempts":2,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":60,"cached_input_tokens":40},"verification":{"known":false,"route_attempts":1}}`},
		{"attempt of no known stage", []string{"generation", "other-observed"}, generationOnly, `{"known":true,"route_attempts":2,"input_tokens":105,"output_tokens":65,"cached_input_tokens":40,"generation":{"known":false,"route_attempts":1},"verification":{"known":false,"route_attempts":0}}`},
		{"recorded attempt without a claim", []string{"generation"}, both, `{"known":true,"route_attempts":2,"input_tokens":150,"output_tokens":80,"cached_input_tokens":40,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":60,"cached_input_tokens":40},"verification":{"known":true,"route_attempts":1,"input_tokens":50,"output_tokens":20,"cached_input_tokens":0}}`},
		{"repeated claim", []string{"generation", "generation", "verification"}, both, `{"known":true,"route_attempts":2,"input_tokens":150,"output_tokens":80,"cached_input_tokens":40,"generation":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":60,"cached_input_tokens":40},"verification":{"known":true,"route_attempts":1,"input_tokens":50,"output_tokens":20,"cached_input_tokens":0}}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := tokenUsageJSON(t, accountTokenUsage(test.claims, test.recorded, stage, lookup)); got != test.want {
				t.Fatalf("token usage\n got %s\nwant %s", got, test.want)
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
			name: "rejected generation", options: rmModelFixtureOptions{generationMode: "malformed"}, runStatus: "failed",
			json: `"token_usage":{"known":true,"route_attempts":1,"input_tokens":100,"output_tokens":100,"cached_input_tokens":0,"generation":` + reportedStage + `,"verification":{"known":true,"route_attempts":0,"input_tokens":0,"output_tokens":0,"cached_input_tokens":0}}`,
			text: "tokens: input=100 output=100 cached_input=0 over 1 route attempt\n",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := tokenResultRun(t, strings.ReplaceAll(test.name, " ", "-"), test.options)
			if result.wire.RunStatus != test.runStatus || result.wire.Version != tokenUsageResultVersion || result.wire.UsageKnown != test.usageKnown {
				t.Fatalf("run=%s version=%d usage_known=%t", result.wire.RunStatus, result.wire.Version, result.wire.UsageKnown)
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
			if !strings.Contains(text.String(), test.text+"limitations: ") {
				t.Fatalf("text result lacks %q before limitations:\n%s", test.text, text.String())
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

// earlierVersion removes the token usage of a version 6 result and labels it
// version, as an earlier build recorded it.
func earlierVersion(t *testing.T, result Result, encoded []byte, version string) []byte {
	t.Helper()
	tokens := `,"token_usage":` + tokenUsageJSON(t, *result.wire.TokenUsage)
	earlier := bytes.Replace(encoded, []byte(tokens), nil, 1)
	earlier = bytes.Replace(earlier, []byte(`"schema_version":6,`), []byte(`"schema_version":`+version+`,`), 1)
	if bytes.Equal(earlier, encoded) || bytes.Contains(earlier, []byte("token_usage")) {
		t.Fatal("fixture did not remove the token usage")
	}
	return earlier
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
