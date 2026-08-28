package policy

import "fmt"

// Capability identifies a policy-controlled runtime effect.
type Capability string

const (
	// CapabilityRemoteProvider permits routing review data to a remote provider.
	CapabilityRemoteProvider Capability = "remote_provider"
	// CapabilitySourceMutation permits changes to reviewed source.
	CapabilitySourceMutation Capability = "source_mutation"
	// CapabilityPublication permits writes to an external review surface.
	CapabilityPublication Capability = "publication"
	// CapabilityDynamicValidation permits separately authorized dynamic checks.
	CapabilityDynamicValidation Capability = "dynamic_validation"
	// CapabilityCommandExecution permits execution of an approved command.
	CapabilityCommandExecution Capability = "command_execution"
)

// DecisionOutcome identifies whether policy permits a capability.
type DecisionOutcome string

const (
	// DecisionAllow permits a capability.
	DecisionAllow DecisionOutcome = "allow"
	// DecisionDeny rejects a capability.
	DecisionDeny DecisionOutcome = "deny"
)

// PolicyDecision records a typed policy outcome and reason.
type PolicyDecision struct {
	capability Capability
	outcome    DecisionOutcome
	reason     string
}

// NewDecision creates a policy decision.
func NewDecision(capability Capability, outcome DecisionOutcome, reason string) (PolicyDecision, error) {
	if !isKnownCapability(capability) {
		return PolicyDecision{}, fmt.Errorf("unknown capability: %q", capability)
	}
	if outcome != DecisionAllow && outcome != DecisionDeny {
		return PolicyDecision{}, fmt.Errorf("unknown decision outcome: %q", outcome)
	}
	if reason == "" {
		return PolicyDecision{}, fmt.Errorf("policy decision reason is required")
	}
	return PolicyDecision{capability: capability, outcome: outcome, reason: reason}, nil
}

func isKnownCapability(capability Capability) bool {
	switch capability {
	case CapabilityRemoteProvider,
		CapabilitySourceMutation,
		CapabilityPublication,
		CapabilityDynamicValidation,
		CapabilityCommandExecution:
		return true
	default:
		return false
	}
}

// Capability returns the evaluated capability.
func (d PolicyDecision) Capability() Capability {
	return d.capability
}

// Outcome returns the policy outcome.
func (d PolicyDecision) Outcome() DecisionOutcome {
	return d.outcome
}

// Reason returns the policy decision reason.
func (d PolicyDecision) Reason() string {
	return d.reason
}
