package openai

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func consoleResponseFixture() string {
	return `{"id":"console-test","object":"chat.completion","model":"model","choices":[{"index":0,"message":{"role":"assistant","content":"{\"schema_version\":1,\"candidates\":[]}","reasoning_content":"DISCARD_REASONING"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1200,"completion_tokens":300,"cost":0.00412,"opencode":{"billing_source":"balance","list_cost":0.00412,"tokens":{"input":1200,"output":300,"reasoning":120,"cache_read":8000,"cache_write_5m":0,"cache_write_1h":0}}}}`
}

func TestOpenCodeConsoleResponseWithholdsNativeUsageWithPositiveBalanceCost(t *testing.T) {
	body := []byte(consoleResponseFixture())
	r, err := normalizeOpenCodeConsoleResponse(body, testRoute(t, "model", ""))
	if err != nil {
		t.Fatal(err)
	}
	if r.Usage().IsKnown() || bytes.Contains(r.Parts()[0].Payload(), []byte("DISCARD_REASONING")) {
		t.Fatal("native usage or assistant output changed")
	}
	if _, err := normalizeOpenCodeGoResponse(body, testRoute(t, "model", "")); err == nil {
		t.Fatal("Go accepted balance spending")
	}
}

func TestOpenCodeConsoleMoneyRoundsUpWithoutFloatUnderflow(t *testing.T) {
	for _, tt := range []struct {
		raw   string
		want  uint64
		valid bool
	}{
		{"0", 0, true}, {"0.00412", 4120, true}, {"0.0000001", 1, true}, {"1e-20", 1, true}, {"1.0000001", 1000001, true}, {"2.4e-6", 3, true}, {"null", 0, false}, {`"1"`, 0, false}, {"-0", 0, false}, {"1e309", 0, false}, {"1e-999", 0, false}, {"18446744073710", 0, false},
	} {
		t.Run(tt.raw, func(t *testing.T) {
			got, err := parseOpenCodeConsoleMicroUSD(json.RawMessage(tt.raw))
			if (err == nil) != tt.valid || tt.valid && got != tt.want {
				t.Fatalf("got %d, %v", got, err)
			}
		})
	}
}

func TestOpenCodeConsoleResponseRefusesWrongBillingAndMalformedUsage(t *testing.T) {
	valid := consoleResponseFixture()
	for name, body := range map[string]string{
		"go":                strings.Replace(valid, `"balance"`, `"go"`, 1),
		"free":              strings.Replace(valid, `"balance"`, `"free"`, 1),
		"byok":              strings.Replace(valid, `"balance"`, `"byok"`, 1),
		"allowance":         strings.Replace(valid, `"list_cost":0.00412`, `"allowance":0.00412,"list_cost":0.00412`, 1),
		"estimated":         strings.Replace(valid, `"list_cost":0.00412`, `"estimated":true,"list_cost":0.00412`, 1),
		"null billing":      strings.Replace(valid, `"opencode":{"billing_source":"balance","list_cost":0.00412,"tokens":{"input":1200,"output":300,"reasoning":120,"cache_read":8000,"cache_write_5m":0,"cache_write_1h":0}}`, `"opencode":null`, 1),
		"partial native":    strings.Replace(valid, `"prompt_tokens":1200,`, "", 1),
		"total mismatch":    strings.Replace(valid, `"cost":0.00412`, `"total_tokens":1501,"cost":0.00412`, 1),
		"negative cost":     strings.Replace(valid, `"cost":0.00412`, `"cost":-1`, 1),
		"null billed count": strings.Replace(valid, `"cache_read":8000`, `"cache_read":null`, 1),
		"overflow":          strings.Replace(valid, `"cache_read":8000`, `"cache_read":18446744073709551615`, 1),
		"reasoning bound":   strings.Replace(valid, `"reasoning":120`, `"reasoning":301`, 1),
		"duplicate":         strings.Replace(valid, `"cost":0.00412`, `"cost":0,"cost":0.00412`, 1),
		"wrong model":       strings.Replace(valid, `"model":"model"`, `"model":"other"`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeOpenCodeConsoleResponse([]byte(body), testRoute(t, "model", "")); err == nil {
				t.Fatal("invalid Console reply accepted")
			}
		})
	}
}

func TestOpenCodeConsoleUsageUnknownAndOptionalCharge(t *testing.T) {
	for _, absent := range []bool{false, true} {
		var root map[string]json.RawMessage
		if err := json.Unmarshal([]byte(consoleResponseFixture()), &root); err != nil {
			t.Fatal(err)
		}
		if !absent {
			root["usage"] = json.RawMessage("null")
		} else {
			delete(root, "usage")
		}
		body, err := json.Marshal(root)
		if err != nil {
			t.Fatal(err)
		}
		r, err := normalizeOpenCodeConsoleResponse(body, testRoute(t, "model", ""))
		if err != nil || r.Usage().IsKnown() {
			t.Fatalf("unknown usage changed: %v", err)
		}
	}
	for _, replacement := range []string{`"cost":null`, `"cost":0`, `"cost":0.00000001`} {
		body := strings.Replace(consoleResponseFixture(), `"cost":0.00412`, replacement, 1)
		if _, err := normalizeOpenCodeConsoleResponse([]byte(body), testRoute(t, "model", "")); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOpenCodeConsoleReportedDebitUpperBoundEligibility(t *testing.T) {
	for _, tt := range []struct {
		name, cost    string
		qualification bool
		present       bool
		want          uint64
	}{
		{"positive", `"cost":0.00412,`, true, true, 4120},
		{"zero", `"cost":0,`, true, true, 0},
		{"ceil", `"cost":0.00000001,`, true, true, 1},
		{"null", `"cost":null,`, true, false, 0},
		{"missing", "", true, false, 0},
		{"unqualified", `"cost":0.00412,`, false, false, 0},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.Replace(consoleResponseFixture(), `"cost":0.00412,`, tt.cost, 1)
			if !tt.qualification {
				body = strings.Replace(body, `,"opencode":{"billing_source":"balance","list_cost":0.00412,"tokens":{"input":1200,"output":300,"reasoning":120,"cache_read":8000,"cache_write_5m":0,"cache_write_1h":0}}`, "", 1)
			}
			response, err := normalizeOpenCodeConsoleResponse([]byte(body), testRoute(t, "model", ""))
			if err != nil || response.Usage().IsKnown() || response.ReportedDebitUpperBound().IsPresent() != tt.present || response.ReportedDebitUpperBound().MicroUSD() != tt.want {
				t.Fatalf("bound mismatch: %v", err)
			}
		})
	}
	body := strings.Replace(consoleResponseFixture(), `"cost":0.00412`, `"cost":4611686018427.387905`, 1)
	if _, err := normalizeOpenCodeConsoleResponse([]byte(body), testRoute(t, "model", "")); err == nil {
		t.Fatal("unsupported money accepted")
	}
}
