package openai

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func goResponseFixture() string {
	return `{"id":"go-test","object":"chat.completion","model":"model","choices":[{"index":0,"message":{"role":"assistant","content":"{\"schema_version\":1,\"candidates\":[]}","reasoning_content":"DISCARD_REASONING"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1200,"completion_tokens":300,"cost":0,"opencode":{"billing_source":"go","list_cost":0.001,"allowance":0.001,"tokens":{"input":1200,"output":300,"reasoning":120,"cache_read":8000,"cache_write_5m":0,"cache_write_1h":0}}}}`
}

func TestOpenCodeGoResponseRetainsNativeUsageAndDiscardsReasoning(t *testing.T) {
	body := []byte(goResponseFixture())
	response, err := normalizeOpenCodeGoResponse(body, testRoute(t, "model", ""))
	if err != nil {
		t.Fatal(err)
	}
	usage := response.Usage()
	if !usage.IsKnown() || usage.InputTokens() != 1200 || usage.OutputTokens() != 300 || usage.CachedInputTokens() != 0 || response.PartCount() != 1 || bytes.Contains(response.Parts()[0].Payload(), []byte("DISCARD_REASONING")) {
		t.Fatal("native usage or assistant content changed")
	}
	if _, err := normalizeChatResponse(body, testRoute(t, "model", "")); err == nil {
		t.Fatal("generic parser widened")
	}
	for _, detail := range []string{`"total_tokens":1500,`, `"total_tokens":1500,"prompt_tokens_details":{"cached_tokens":100},`} {
		changed := strings.Replace(string(body), `"cost":0,`, detail+`"cost":0,`, 1)
		r, err := normalizeOpenCodeGoResponse([]byte(changed), testRoute(t, "model", ""))
		if err != nil {
			t.Fatal(err)
		}
		if !r.Usage().IsKnown() || strings.Contains(detail, "cached_tokens") && r.Usage().CachedInputTokens() != 100 {
			t.Fatal("top-level details lost")
		}
	}
}

func TestOpenCodeGoResponseAbsentUsageIsUnknown(t *testing.T) {
	for _, absent := range []bool{false, true} {
		var wire map[string]json.RawMessage
		if err := json.Unmarshal([]byte(goResponseFixture()), &wire); err != nil {
			t.Fatal(err)
		}
		if absent {
			delete(wire, "usage")
		} else {
			wire["usage"] = json.RawMessage("null")
		}
		body, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		r, err := normalizeOpenCodeGoResponse(body, testRoute(t, "model", ""))
		if err != nil || r.Usage().IsKnown() {
			t.Fatalf("unknown usage: %v", err)
		}
	}
}

func TestOpenCodeGoResponseRefusesMalformedBillingCountsAndActions(t *testing.T) {
	valid := goResponseFixture()
	cases := map[string]string{
		"byok":               strings.Replace(valid, `"billing_source":"go"`, `"billing_source":"byok"`, 1),
		"balance":            strings.Replace(valid, `"billing_source":"go"`, `"billing_source":"balance"`, 1),
		"free":               strings.Replace(valid, `"billing_source":"go"`, `"billing_source":"free"`, 1),
		"go-plus":            strings.Replace(valid, `"billing_source":"go"`, `"billing_source":"go-plus"`, 1),
		"estimated":          strings.Replace(valid, `"list_cost":0.001`, `"estimated":true,"list_cost":0.001`, 1),
		"null estimated":     strings.Replace(valid, `"list_cost":0.001`, `"estimated":null,"list_cost":0.001`, 1),
		"cost positive":      strings.Replace(valid, `"cost":0`, `"cost":0.01`, 1),
		"cost underflow":     strings.Replace(valid, `"cost":0`, `"cost":1e-999`, 1),
		"cost negative":      strings.Replace(valid, `"cost":0`, `"cost":-1e-999`, 1),
		"infinite allowance": strings.Replace(valid, `"allowance":0.001`, `"allowance":1e309`, 1),
		"quoted list":        strings.Replace(valid, `"list_cost":0.001`, `"list_cost":"0.001"`, 1),
		"negative list":      strings.Replace(valid, `"list_cost":0.001`, `"list_cost":-1`, 1),
		"missing allowance":  strings.Replace(valid, `"allowance":0.001,`, ``, 1),
		"null list":          strings.Replace(valid, `"list_cost":0.001`, `"list_cost":null`, 1),
		"unknown billing":    strings.Replace(valid, `"list_cost":0.001`, `"extra":0.001`, 1),
		"unknown token":      strings.Replace(valid, `"cache_write_1h":0`, `"cache_write_1h":0,"extra":0`, 1),
		"null count":         strings.Replace(valid, `"cache_read":8000`, `"cache_read":null`, 1),
		"fractional count":   strings.Replace(valid, `"cache_read":8000`, `"cache_read":0.5`, 1),
		"negative count":     strings.Replace(valid, `"cache_read":8000`, `"cache_read":-1`, 1),
		"sum overflow":       strings.Replace(valid, `"cache_read":8000`, `"cache_read":18446744073709551615`, 1),
		"missing count":      strings.Replace(valid, `,"cache_write_1h":0`, ``, 1),
		"reasoning bound":    strings.Replace(valid, `"reasoning":120`, `"reasoning":301`, 1),
		"native total":       strings.Replace(valid, `"cost":0`, `"total_tokens":1501,"cost":0`, 1),
		"null total":         strings.Replace(valid, `"cost":0`, `"total_tokens":null,"cost":0`, 1),
		"native overflow":    strings.Replace(valid, `"prompt_tokens":1200`, `"prompt_tokens":18446744073709551615`, 1),
		"native partial":     strings.Replace(valid, `"prompt_tokens":1200,`, ``, 1),
		"native fractional":  strings.Replace(valid, `"completion_tokens":300`, `"completion_tokens":300.5`, 1),
		"case alias":         strings.Replace(valid, `"billing_source"`, `"Billing_source"`, 1),
		"duplicate":          strings.Replace(valid, `"cost":0`, `"cost":0,"cost":0`, 1),
		"unknown top":        strings.Replace(valid, `"id":"go-test"`, `"id":"go-test","extra":null`, 1),
		"tools":              strings.Replace(valid, `"role":"assistant"`, `"role":"assistant","tool_calls":[{"id":"call"}]`, 1),
		"function call":      strings.Replace(valid, `"role":"assistant"`, `"role":"assistant","function_call":{}`, 1),
		"reasoning object":   strings.Replace(valid, `"reasoning_content":"DISCARD_REASONING"`, `"reasoning_content":{}`, 1),
		"wrong model":        strings.Replace(valid, `"model":"model"`, `"model":"other"`, 1),
		"streaming":          strings.Replace(valid, `"object":"chat.completion"`, `"object":"chat.completion.chunk"`, 1),
		"null billing":       strings.Replace(valid, `"opencode":{"billing_source":"go","list_cost":0.001,"allowance":0.001,"tokens":{"input":1200,"output":300,"reasoning":120,"cache_read":8000,"cache_write_5m":0,"cache_write_1h":0}}`, `"opencode":null`, 1),
		"null tokens":        strings.Replace(valid, `"tokens":{"input":1200,"output":300,"reasoning":120,"cache_read":8000,"cache_write_5m":0,"cache_write_1h":0}`, `"tokens":null`, 1),
		"trailing":           valid + ` {}`,
		"oversized":          strings.Repeat(" ", maximumResponseBytes) + valid,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := normalizeOpenCodeGoResponse([]byte(body), testRoute(t, "model", "")); err == nil {
				t.Fatal("unsafe Go response accepted")
			}
		})
	}
}

func TestOpenCodeGoResponseAcceptsIndependentBilledOutput(t *testing.T) {
	for _, change := range []struct{ old, new string }{
		{`"output":300`, `"output":400`},
		{`"reasoning_content":"DISCARD_REASONING"`, `"reasoning_content":null`},
		{`"cost":0`, `"cost":null`},
		{`"list_cost":0.001`, `"estimated":false,"list_cost":0.001`},
	} {
		body := strings.Replace(goResponseFixture(), change.old, change.new, 1)
		r, err := normalizeOpenCodeGoResponse([]byte(body), testRoute(t, "model", ""))
		if err != nil || !r.Usage().IsKnown() {
			t.Fatalf("valid independent metadata: %v", err)
		}
	}
}
