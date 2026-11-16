package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestModelRequestTransportFollowsThePlannedRoutesConnections(t *testing.T) {
	inventory := bindingInventory(t, bindingInventoryDocument(t))
	template := bytes.ReplaceAll(bindingTemplate(t), []byte("openai_responses"), []byte("openai_chat_completions"))
	var doc map[string]any
	if json.Unmarshal(template, &doc) != nil {
		t.Fatal("template")
	}
	doc["schema_version"] = 6
	routes := map[string]gateway.ObservedRouteCandidate{}
	for _, candidate := range inventory.Candidates() {
		routes[candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().AdapterID()] = candidate
	}
	for _, structured := range []string{"", "adapter-a"} {
		for _, c := range doc["connections"].([]any) {
			connection := c.(map[string]any)
			connection["local_structured_output"] = connection["adapter_id"] == structured
		}
		bound, err := bindRuntimePolicy(context.Background(), inventory, bindingMarshal(t, doc), "adapter-a", "adapter-b")
		if err != nil {
			t.Fatal(err)
		}
		policy, err := DecodeRuntimePolicy(context.Background(), bytes.NewReader(bound), inventory)
		if err != nil {
			t.Fatal(err)
		}
		want := func(adapters ...string) review.ModelRequestTransport {
			for _, adapter := range adapters {
				if adapter == structured {
					return review.ModelRequestTransportLocalStructuredOutput
				}
			}
			return review.ModelRequestTransportStandard
		}
		for _, adapters := range [][]string{nil, {"adapter-a"}, {"adapter-b"}, {"adapter-b", "adapter-a"}} {
			planned := make([]gateway.ObservedRouteCandidate, 0, len(adapters))
			for _, adapter := range adapters {
				route, ok := routes[adapter]
				if !ok {
					t.Fatalf("inventory lacks %s", adapter)
				}
				planned = append(planned, route)
			}
			if got := policy.ModelRequestTransport(planned); got != want(adapters...) {
				t.Fatalf("structured connection %q: routes %v plan %s", structured, adapters, got)
			}
		}
	}
}
