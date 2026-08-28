package policy

import "testing"

func TestNewDecisionCreatesTypedDenial(t *testing.T) {
	decision, err := NewDecision(CapabilityPublication, DecisionDeny, "disabled by local policy")
	if err != nil {
		t.Fatalf("NewDecision() error = %v", err)
	}

	if decision.Capability() != CapabilityPublication {
		t.Fatalf("Capability() = %q, want %q", decision.Capability(), CapabilityPublication)
	}
	if decision.Outcome() != DecisionDeny {
		t.Fatalf("Outcome() = %q, want %q", decision.Outcome(), DecisionDeny)
	}
	if decision.Reason() != "disabled by local policy" {
		t.Fatalf("Reason() = %q, want %q", decision.Reason(), "disabled by local policy")
	}
}

func TestNewDecisionRejectsUnknownOrIncompleteInput(t *testing.T) {
	testCases := []struct {
		name       string
		capability Capability
		outcome    DecisionOutcome
		reason     string
	}{
		{name: "unknown capability", capability: Capability("unknown"), outcome: DecisionDeny, reason: "denied"},
		{name: "unknown outcome", capability: CapabilityPublication, outcome: DecisionOutcome("unknown"), reason: "denied"},
		{name: "missing reason", capability: CapabilityPublication, outcome: DecisionDeny},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewDecision(testCase.capability, testCase.outcome, testCase.reason); err == nil {
				t.Fatal("NewDecision() error = nil, want validation error")
			}
		})
	}
}
