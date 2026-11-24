package openai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func openRouterV2Config(t *testing.T, slugs []string) Config {
	t.Helper()
	route, err := provider.NewRouteReference(provider.ProviderZoneBrokeredRemote, "openrouter", "openrouter-generation", "openrouter/generation", "vendor/model", "")
	if err != nil {
		t.Fatal(err)
	}
	clock := &goProfileClock{at: time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)}
	return Config{Protocol: ProtocolChatCompletions, RequestProfile: RequestProfileOpenRouterZDRChatV2, CredentialMode: CredentialModeBearer, AdapterID: route.AdapterID(), ProviderID: route.ProviderID(), ConnectionID: route.ConnectionID(), Zone: route.Zone(), ContentLoggingMode: provider.ContentLoggingDisabled, Endpoint: "https://openrouter.ai/api/v1", Credentials: &credentialProvider{key: testKey(t)}, CredentialIdentity: strings.Repeat("a", 64), HTTPClient: &http.Client{Transport: &goProfileTransport{}, Timeout: time.Minute}, HTTPClientIdentity: strings.Repeat("b", 64), Clock: clock,
		OpenRouterAuthority: &OpenRouterRouteAuthority{Route: route, RouteRecordIdentity: strings.Repeat("c", 64), EvidenceIdentity: strings.Repeat("d", 64), CredentialIdentity: strings.Repeat("a", 64), TenantID: "tenant-a", RepositoryID: "repository-a", ProviderSlugs: slugs}}
}

func openRouterRequestProvider(t *testing.T, adapter *Adapter) map[string]json.RawMessage {
	t.Helper()
	request, err := adapter.newRequest(context.Background(), APIKey{value: "synthetic"}, "vendor/model", 4096, "fixed host instructions", []byte(`{"task":"fixture"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(request.Body)
	var wire struct {
		Provider map[string]json.RawMessage `json:"provider"`
	}
	if json.Unmarshal(body, &wire) != nil {
		t.Fatalf("request body: %s", body)
	}
	return wire.Provider
}

func TestOpenRouterV2ProfileRequiresZDRAndPinsObservedSlugs(t *testing.T) {
	for _, slugs := range [][]string{{"fixture-a/fp8", "fixture-b"}, {}} {
		adapter, err := New(openRouterV2Config(t, slugs))
		if err != nil || !adapter.serviceProfileCurrent() {
			t.Fatalf("observed authority refused: %v", err)
		}
		controls := openRouterRequestProvider(t, adapter)
		if string(controls["zdr"]) != "true" || string(controls["allow_fallbacks"]) != "true" || string(controls["require_parameters"]) != "true" {
			t.Fatalf("provider controls lost: %v", controls)
		}
		encoded, _ := json.Marshal(slugs)
		if len(slugs) == 0 {
			if _, pinned := controls["only"]; pinned || controls["order"] != nil {
				t.Fatalf("an unpinned route sent a slug list: %v", controls)
			}
		} else if string(controls["only"]) != string(encoded) {
			t.Fatalf("slugs not pinned: %v", controls)
		} else if _, ordered := controls["order"]; ordered {
			t.Fatalf("a V2 request fixed the endpoint order: %v", controls)
		}
	}
	pinned, _ := New(openRouterV2Config(t, []string{"fixture-a"}))
	unpinned, _ := New(openRouterV2Config(t, []string{}))
	if pinned.ConfigurationIdentity() == unpinned.ConfigurationIdentity() || pinned.ConfigurationIdentity() == "" {
		t.Fatal("the slug list is not part of the configuration identity")
	}
}

func TestOpenRouterV2ProfileRefusesReviewedFields(t *testing.T) {
	for _, name := range []string{"account", "single slug", "window", "nil slugs", "duplicate slug", "bad slug", "v1 with slugs", "v1 with reasoning"} {
		config := openRouterV2Config(t, []string{"fixture-a"})
		authority := config.OpenRouterAuthority
		switch name {
		case "account":
			authority.AccountPolicyIdentity = strings.Repeat("e", 64)
		case "single slug":
			authority.ProviderSlug = "fixture-a"
		case "window":
			authority.ValidFrom, authority.ValidUntil = time.Unix(1, 0), time.Unix(2, 0)
		case "nil slugs":
			authority.ProviderSlugs = nil
		case "duplicate slug":
			authority.ProviderSlugs = []string{"fixture-a", "fixture-a"}
		case "bad slug":
			authority.ProviderSlugs = []string{"Fixture"}
		case "v1 with slugs":
			config.RequestProfile = RequestProfileOpenRouterZDRChatV1
			authority.AccountPolicyIdentity, authority.ProviderSlug = strings.Repeat("e", 64), "fixture-a"
			authority.ValidFrom, authority.ValidUntil = time.Unix(1, 0), time.Unix(2_000_000_000, 0)
		case "v1 with reasoning":
			config.RequestProfile = RequestProfileOpenRouterZDRChatV1
			authority.AccountPolicyIdentity, authority.ProviderSlug, authority.ProviderSlugs, authority.Reasoning = strings.Repeat("e", 64), "fixture-a", nil, true
			authority.ValidFrom, authority.ValidUntil = time.Unix(1, 0), time.Unix(2_000_000_000, 0)
		}
		if adapter, err := New(config); err == nil && adapter.Validate() == nil {
			t.Fatalf("%s admitted", name)
		}
	}
}

func TestGenericOpenRouterConnectionReadsOpenRouterUsage(t *testing.T) {
	endpoint, err := provider.ParseServiceEndpoint("https://openrouter.ai/api/v1")
	if err != nil {
		t.Fatal(err)
	}
	a := &Adapter{protocol: ProtocolChatCompletions, endpoint: endpoint}
	response, err := a.normalizeProviderResponse(openRouterDocumentedChatResponse("model"), testRoute(t, "model", ""))
	if err != nil || !response.Usage().IsKnown() {
		t.Fatalf("generic OpenRouter response refused: %v", err)
	}
	other, _ := provider.ParseServiceEndpoint("https://provider.example/v1")
	if _, err := (&Adapter{protocol: ProtocolChatCompletions, endpoint: other}).normalizeProviderResponse(openRouterDocumentedChatResponse("model"), testRoute(t, "model", "")); err == nil {
		t.Fatal("another provider accepted the OpenRouter usage extension")
	}
}

func requestReasoning(t *testing.T, adapter *Adapter) string {
	t.Helper()
	request, err := adapter.newRequest(context.Background(), APIKey{value: "synthetic"}, "vendor/model", 4096, "fixed host instructions", []byte(`{"task":"fixture"}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(request.Body)
	var wire struct {
		Reasoning json.RawMessage `json:"reasoning"`
	}
	if json.Unmarshal(body, &wire) != nil {
		t.Fatalf("request body: %s", body)
	}
	return string(wire.Reasoning)
}

func TestOpenRouterRequestsAskForLowReasoningOnlyWhereAccepted(t *testing.T) {
	plain, _ := New(openRouterV2Config(t, []string{"fixture-a"}))
	if got := requestReasoning(t, plain); got != "" {
		t.Fatalf("a route whose endpoints may not accept reasoning sent %s", got)
	}
	config := openRouterV2Config(t, []string{"fixture-a"})
	config.OpenRouterAuthority.Reasoning = true
	reasoning, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	if got := requestReasoning(t, reasoning); got != `{"effort":"low"}` {
		t.Fatalf("reasoning route sent %q", got)
	}
	if reasoning.ConfigurationIdentity() == plain.ConfigurationIdentity() {
		t.Fatal("the reasoning effort is not part of the configuration identity")
	}
	unpinned := openRouterV2Config(t, []string{})
	unpinned.OpenRouterAuthority.Reasoning = true
	if adapter, err := New(unpinned); err == nil && adapter.Validate() == nil {
		t.Fatal("reasoning admitted without pinned endpoints")
	}
	openRouter, _ := provider.ParseServiceEndpoint("https://openrouter.ai/api/v1")
	if got := requestReasoning(t, &Adapter{protocol: ProtocolChatCompletions, endpoint: openRouter}); got != `{"effort":"low"}` {
		t.Fatalf("generic OpenRouter connection sent %q", got)
	}
	other, _ := provider.ParseServiceEndpoint("https://provider.example/v1")
	if got := requestReasoning(t, &Adapter{protocol: ProtocolChatCompletions, endpoint: other}); got != "" {
		t.Fatalf("another provider was sent %s", got)
	}
}
