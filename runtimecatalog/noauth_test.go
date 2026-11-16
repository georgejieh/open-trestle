package runtimecatalog

import (
	"context"
	"testing"

	"github.com/georgejieh/open-trestle/adapters/providers/openai"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

type noAuthForbiddenResolver struct{ calls int }

func (r *noAuthForbiddenResolver) ResolveOpenAICredentials(string) (openai.APIKeyProvider, error) {
	r.calls++
	return nil, ErrInvalidRouteAuthority
}

func TestNoAuthRuntimePolicyCatalogSkipsCredentialResolver(t *testing.T) {
	inventory, err := runtimeconfig.NewRouteInventory(context.Background(), localPairDefinitions(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, implementation := range []string{"openai_responses", "openai_chat_completions"} {
		t.Run(implementation, func(t *testing.T) {
			policy := localPairPolicy(t, inventory, true, []string{"adapter-b"}, "distinct_provider", func(doc map[string]any) {
				for _, c := range doc["connections"].([]map[string]string) {
					c["implementation"] = implementation
					c["credential_mode"] = "none"
					delete(c, "credential_environment")
				}
			})
			for _, c := range policy.Connections() {
				if c.CredentialMode() != "none" || c.CredentialEnvironment() != "" || c.CredentialIdentity() != "" {
					t.Fatal("NO_AUTH retained credential authority")
				}
			}
			resolver := &noAuthForbiddenResolver{}
			for _, build := range []func(runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy, OpenAICredentialResolver) (gateway.RouteDispatcherCatalog, error){NewOpenAIRouteDispatcherCatalogFromRuntimePolicy, NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy} {
				catalog, err := build(inventory, policy, resolver)
				if err != nil || catalog.Validate() != nil || catalog.Len() != 2 {
					t.Fatalf("NO_AUTH catalog: %v", err)
				}
			}
			if resolver.calls != 0 {
				t.Fatal("NO_AUTH construction called credential resolver")
			}
			if _, err := ResolveLocalGenerationRoutePair(policy, inventory); err != nil {
				t.Fatal(err)
			}
		})
	}
}
