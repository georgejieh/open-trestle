package runtimecatalog

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func structuredPolicy(t *testing.T, inventory runtimeconfig.RouteInventory, enabled bool, input uint64, noAuth ...bool) runtimeconfig.RuntimePolicy {
	t.Helper()
	return localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", func(doc map[string]any) {
		doc["schema_version"] = 6
		var connections []map[string]any
		for _, old := range doc["connections"].([]map[string]string) {
			c := map[string]any{}
			for k, v := range old {
				c[k] = v
			}
			c["implementation"] = "openai_chat_completions"
			c["local_structured_output"] = enabled
			if len(noAuth) > 0 && noAuth[0] {
				delete(c, "credential_environment")
				c["credential_mode"] = "none"
			}
			connections = append(connections, c)
		}
		doc["connections"] = connections
		doc["estimated_input_tokens"] = input
	})
}

type structuredTransport struct {
	calls         int
	body          []byte
	authorization string
}

func (r *structuredTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	r.calls++
	r.authorization = request.Header.Get("Authorization")
	r.body, _ = io.ReadAll(request.Body)
	return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":"local","object":"chat.completion","model":"1","choices":[{"index":0,"message":{"role":"assistant","content":"{\"schema_version\":2,\"candidates\":[]}"},"finish_reason":"stop"}]}`))}, nil
}

func TestLocalStructuredOutputFactoriesBindOption(t *testing.T) {
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewEnvironmentOpenAICredentialResolver(func(string) string { t.Fatal("credentials retrieved at construction"); return "" })
	if err != nil {
		t.Fatal(err)
	}
	enabled := structuredPolicy(t, inventory, true, 20000)
	disabled := structuredPolicy(t, inventory, false, 20000)
	for _, build := range []func(runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy, OpenAICredentialResolver) (gateway.RouteDispatcherCatalog, error){NewOpenAIRouteDispatcherCatalogFromRuntimePolicy, NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy} {
		current, err := build(inventory, enabled, resolver)
		if err != nil {
			t.Fatal(err)
		}
		legacy, err := build(inventory, disabled, resolver)
		if err != nil {
			t.Fatal(err)
		}
		if current.Identity() == legacy.Identity() {
			t.Fatal("factory lost schema option")
		}
		for _, connection := range enabled.Connections() {
			actual, ok := current.Resolve(connection.AdapterID())
			if !ok {
				t.Fatal("missing adapter")
			}
			prior, _ := legacy.Resolve(connection.AdapterID())
			if actual.ConfigurationIdentity() == prior.ConfigurationIdentity() {
				t.Fatal("option lost on adapter")
			}
		}
	}
}

// The local generation route plan reserves the schema framing itself, so even a
// declared estimate below what the adapter sends is dispatched with the exact
// host-pinned schema. The adapter-level refusal of an undersized approval is
// covered by the adapter package.
func TestLocalStructuredOutputDispatchReservesSchemaBytes(t *testing.T) {
	scope, request := readableGenerationRequest(t)
	inner, err := review.SanitizedCandidatePayload(request, scope.Identity())
	if err != nil {
		t.Fatal(err)
	}
	schema, err := review.TrustedModelRequestOutputSchema(inner)
	if err != nil {
		t.Fatal(err)
	}
	format := struct {
		Type       string `json:"type"`
		JSONSchema struct {
			Name   string          `json:"name"`
			Strict bool            `json:"strict"`
			Schema json.RawMessage `json:"schema"`
		} `json:"json_schema"`
	}{Type: "json_schema"}
	format.JSONSchema.Name = "open_trestle_review"
	format.JSONSchema.Strict = true
	format.JSONSchema.Schema = schema
	encoded, _ := json.Marshal(struct {
		Format any `json:"response_format"`
	}{format})
	trusted, err := review.TrustedModelRequestInstructions(inner)
	if err != nil {
		t.Fatal(err)
	}
	required := uint64(len(inner) + len(trusted) + len(encoded) + 256)
	if required <= uint64(len(request.Payload())+len(trusted)+256) {
		t.Fatal("fixture does not expose added schema reservation")
	}
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, noAuth := range []bool{false, true} {
		for _, input := range []uint64{1, required - 1, required} {
			policy := structuredPolicy(t, inventory, true, input, noAuth)
			pair, err := ResolveLocalGenerationRoutePair(policy, inventory)
			if err != nil {
				t.Fatal(err)
			}
			plan, err := PlanLocalGenerationRoute(context.Background(), scope, request, policy, inventory, pair)
			if err != nil {
				t.Fatal(err)
			}
			credentials := 0
			resolver, err := NewEnvironmentOpenAICredentialResolver(func(string) string { credentials++; return "test-secret" })
			if err != nil {
				t.Fatal(err)
			}
			transport := &structuredTransport{}
			catalog, err := NewOpenAIRouteDispatcherCatalogWithOptions(inventory, policy, resolver, OpenAICatalogOptions{HTTPClient: &http.Client{Transport: transport}, HTTPClientIdentity: strings.Repeat("a", 64)})
			if err != nil {
				t.Fatal(err)
			}
			adapter, _ := catalog.Resolve(pair.GenerationRoute().AdapterID())
			result, err := gateway.DispatchAuthorizedRoute(context.Background(), adapter, plan.authorization, request)
			if err != nil {
				t.Fatal(err)
			}
			if uint64(plan.authorization.CostBudget().EstimatedInputTokens()) < required {
				t.Fatalf("plan reserved %d input below the %d the adapter sends", plan.authorization.CostBudget().EstimatedInputTokens(), required)
			}
			expectedCredentials := 1
			if noAuth {
				expectedCredentials = 0
			}
			if result.Status() != gateway.RouteDispatchSucceeded || transport.calls != 1 || credentials != expectedCredentials {
				t.Fatalf("planned reservation refused: %#v calls %d creds %d", result, transport.calls, credentials)
			}
			expectedAuthorization := "Bearer test-secret"
			if noAuth {
				expectedAuthorization = ""
			}
			if transport.authorization != expectedAuthorization {
				t.Fatal("credential mode changed")
			}
			var wire map[string]json.RawMessage
			if json.Unmarshal(transport.body, &wire) != nil || !bytes.Equal(wire["response_format"], encoded[len(`{"response_format":`):len(encoded)-1]) {
				t.Fatal("factory wire schema differs")
			}
		}
	}
}
