package policy

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestNewEffectAuthorizationBindsExplicitPublicationGrant(t *testing.T) {
	issued := time.UnixMilli(1_700_000_000_000)
	authorization, err := NewEffectAuthorization(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), CapabilityPublication, DecisionAllow, AuthorizationExplicitUserApproval, issued, issued.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if authorization.Identity() == "" || authorization.PolicyIdentity() != strings.Repeat("a", 64) || authorization.PrincipalIdentity() != strings.Repeat("b", 64) || authorization.ScopeIdentity() != strings.Repeat("c", 64) || authorization.Capability() != CapabilityPublication || authorization.Outcome() != DecisionAllow || authorization.Reason() != AuthorizationExplicitUserApproval || !authorization.Allows(CapabilityPublication, strings.Repeat("c", 64), issued.Add(time.Minute)) || authorization.Allows(CapabilitySourceMutation, strings.Repeat("c", 64), issued.Add(time.Minute)) || authorization.Validate() != nil {
		t.Fatalf("authorization did not round trip: %#v", authorization)
	}
	if authorization.Allows(CapabilityPublication, strings.Repeat("c", 64), issued.Add(2*time.Hour)) {
		t.Fatal("expired authorization allowed publication")
	}
	if fmt.Sprint(authorization) != "policy effect authorization" || strings.Contains(fmt.Sprintf("%v", authorization), strings.Repeat("a", 64)) {
		t.Fatalf("authorization formatting leaked: %v", authorization)
	}
}

func TestEffectAuthorizationDenialNeverAllows(t *testing.T) {
	issued := time.UnixMilli(1_700_000_000_000)
	denial, err := NewEffectAuthorization(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), CapabilityPublication, DecisionDeny, AuthorizationRepositoryPolicy, issued, issued.Add(time.Hour))
	if err != nil || denial.Allows(CapabilityPublication, strings.Repeat("c", 64), issued.Add(time.Minute)) || denial.Validate() != nil {
		t.Fatalf("denial = (%#v, %v)", denial, err)
	}
}

func TestNewEffectAuthorizationRejectsInvalidInputs(t *testing.T) {
	issued := time.UnixMilli(1_700_000_000_000)
	valid := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, policyID, principalID, scopeID string
		capability                           Capability
		outcome                              DecisionOutcome
		reason                               AuthorizationReason
		issued, expires                      time.Time
		want                                 error
	}{
		{"policy", "bad", valid, valid, CapabilityPublication, DecisionAllow, AuthorizationExplicitUserApproval, issued, issued.Add(time.Hour), ErrInvalidEffectAuthorizationIdentity},
		{"capability", valid, valid, valid, Capability("bad"), DecisionAllow, AuthorizationExplicitUserApproval, issued, issued.Add(time.Hour), ErrInvalidEffectAuthorizationCapability},
		{"outcome", valid, valid, valid, CapabilityPublication, DecisionOutcome("bad"), AuthorizationExplicitUserApproval, issued, issued.Add(time.Hour), ErrInvalidEffectAuthorizationOutcome},
		{"reason", valid, valid, valid, CapabilityPublication, DecisionAllow, 0, issued, issued.Add(time.Hour), ErrInvalidAuthorizationReason},
		{"time", valid, valid, valid, CapabilityPublication, DecisionAllow, AuthorizationExplicitUserApproval, issued, issued, ErrInvalidEffectAuthorizationTime},
		{"lifetime", valid, valid, valid, CapabilityPublication, DecisionAllow, AuthorizationExplicitUserApproval, issued, issued.Add(maxEffectAuthorizationLifetime + time.Millisecond), ErrInvalidEffectAuthorizationTime},
	} {
		t.Run(test.name, func(t *testing.T) {
			authorization, err := NewEffectAuthorization(test.policyID, test.principalID, test.scopeID, test.capability, test.outcome, test.reason, test.issued, test.expires)
			if !errors.Is(err, test.want) || authorization.Identity() != "" {
				t.Fatalf("NewEffectAuthorization() = (%#v, %v), want %v", authorization, err, test.want)
			}
		})
	}
}

func TestEffectAuthorizationIdentityRejectsTampering(t *testing.T) {
	issued := time.UnixMilli(1_700_000_000_000)
	authorization, _ := NewEffectAuthorization(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), CapabilityPublication, DecisionAllow, AuthorizationAdministratorPolicy, issued, issued.Add(time.Hour))
	forged := authorization
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidEffectAuthorizationRecordIdentity) {
		t.Fatal("forged authorization accepted")
	}
}

func TestEffectAuthorizationLifetimeCannotOverflow(t *testing.T) {
	issued := time.UnixMilli(1_700_000_000_000)
	for _, expiry := range []int64{
		11_700_000_000_000,
		issued.UnixMilli() + 9_223_372_036_855,
		maxEffectAuthorizationUnixMilliseconds,
	} {
		t.Run(fmt.Sprint(expiry), func(t *testing.T) {
			authorization, err := NewEffectAuthorization(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), CapabilityPublication, DecisionAllow, AuthorizationExplicitUserApproval, issued, time.UnixMilli(expiry))
			if !errors.Is(err, ErrInvalidEffectAuthorizationTime) || authorization.Identity() != "" {
				t.Fatalf("excessive lifetime accepted: expiry=%d err=%v", expiry, err)
			}
		})
	}
	maximum, err := NewEffectAuthorization(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), CapabilityPublication, DecisionAllow, AuthorizationExplicitUserApproval, issued, issued.Add(24*time.Hour))
	if err != nil || maximum.Validate() != nil || !maximum.Allows(CapabilityPublication, strings.Repeat("c", 64), issued.Add(24*time.Hour-time.Millisecond)) || maximum.Allows(CapabilityPublication, strings.Repeat("c", 64), issued.Add(24*time.Hour)) {
		t.Fatalf("exact lifetime boundary failed: %v", err)
	}
}
