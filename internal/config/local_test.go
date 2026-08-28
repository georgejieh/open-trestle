package config

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/policy"
)

func TestDefaultLocalRejectsEffectfulCapabilities(t *testing.T) {
	configuration := DefaultLocal()
	if configuration.ProviderRoute() != ProviderRouteLocal {
		t.Fatalf("ProviderRoute() = %q, want %q", configuration.ProviderRoute(), ProviderRouteLocal)
	}

	capabilities := []policy.Capability{
		policy.CapabilityRemoteProvider,
		policy.CapabilitySourceMutation,
		policy.CapabilityPublication,
		policy.CapabilityDynamicValidation,
		policy.CapabilityCommandExecution,
	}
	for _, capability := range capabilities {
		t.Run(string(capability), func(t *testing.T) {
			decision, err := configuration.Decide(capability)
			if err != nil {
				t.Fatalf("Decide(%q) error = %v", capability, err)
			}
			if decision.Outcome() != policy.DecisionDeny {
				t.Fatalf("Decide(%q).Outcome() = %q, want %q", capability, decision.Outcome(), policy.DecisionDeny)
			}
		})
	}
}

func TestDefaultLocalRejectsUnknownCapability(t *testing.T) {
	if _, err := DefaultLocal().Decide(policy.Capability("unknown")); err == nil {
		t.Fatal("Decide(unknown) error = nil, want validation error")
	}
}
