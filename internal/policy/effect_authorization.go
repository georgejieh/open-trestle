package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	maxEffectAuthorizationLifetime         = 24 * time.Hour
	maxEffectAuthorizationUnixMilliseconds = int64(253_402_300_799_999)
)

var (
	// ErrInvalidEffectAuthorizationIdentity identifies a malformed policy, principal, or scope identity.
	ErrInvalidEffectAuthorizationIdentity = errors.New("invalid effect authorization identity")
	// ErrInvalidEffectAuthorizationCapability identifies an unknown governed effect.
	ErrInvalidEffectAuthorizationCapability = errors.New("invalid effect authorization capability")
	// ErrInvalidEffectAuthorizationOutcome identifies an unknown allow or deny result.
	ErrInvalidEffectAuthorizationOutcome = errors.New("invalid effect authorization outcome")
	// ErrInvalidAuthorizationReason identifies an unknown authorization source.
	ErrInvalidAuthorizationReason = errors.New("invalid effect authorization reason")
	// ErrInvalidEffectAuthorizationTime identifies a missing, reversed, or excessive validity interval.
	ErrInvalidEffectAuthorizationTime = errors.New("invalid effect authorization time")
	// ErrInvalidEffectAuthorizationRecordIdentity identifies authorization content inconsistent with its identity.
	ErrInvalidEffectAuthorizationRecordIdentity = errors.New("invalid effect authorization record identity")
)

// AuthorizationReason identifies the trusted control that produced an effect decision.
type AuthorizationReason uint8

const (
	AuthorizationExplicitUserApproval AuthorizationReason = iota + 1
	AuthorizationRepositoryPolicy
	AuthorizationAdministratorPolicy
)

func (r AuthorizationReason) String() string {
	switch r {
	case AuthorizationExplicitUserApproval:
		return "explicit_user_approval"
	case AuthorizationRepositoryPolicy:
		return "repository_policy"
	case AuthorizationAdministratorPolicy:
		return "administrator_policy"
	default:
		return ""
	}
}

func (r AuthorizationReason) Validate() error {
	if r.String() == "" {
		return ErrInvalidAuthorizationReason
	}
	return nil
}

// EffectAuthorization is an expiring content-addressed allow or deny decision.
type EffectAuthorization struct {
	identity                  string
	policyIdentity            string
	principalIdentity         string
	scopeIdentity             string
	capability                Capability
	outcome                   DecisionOutcome
	reason                    AuthorizationReason
	issuedAtUnixMilliseconds  int64
	expiresAtUnixMilliseconds int64
}

// NewEffectAuthorization creates one bounded effect decision from trusted policy evaluation.
func NewEffectAuthorization(policyIdentity, principalIdentity, scopeIdentity string, capability Capability, outcome DecisionOutcome, reason AuthorizationReason, issuedAt, expiresAt time.Time) (EffectAuthorization, error) {
	authorization := EffectAuthorization{
		policyIdentity: strings.Clone(policyIdentity), principalIdentity: strings.Clone(principalIdentity),
		scopeIdentity: strings.Clone(scopeIdentity), capability: capability, outcome: outcome, reason: reason,
		issuedAtUnixMilliseconds: issuedAt.UnixMilli(), expiresAtUnixMilliseconds: expiresAt.UnixMilli(),
	}
	if err := authorization.validateFields(); err != nil {
		return EffectAuthorization{}, err
	}
	authorization.identity = deriveEffectAuthorizationIdentity(authorization)
	return authorization, nil
}

func (a EffectAuthorization) Identity() string                 { return a.identity }
func (a EffectAuthorization) PolicyIdentity() string           { return a.policyIdentity }
func (a EffectAuthorization) PrincipalIdentity() string        { return a.principalIdentity }
func (a EffectAuthorization) ScopeIdentity() string            { return a.scopeIdentity }
func (a EffectAuthorization) Capability() Capability           { return a.capability }
func (a EffectAuthorization) Outcome() DecisionOutcome         { return a.outcome }
func (a EffectAuthorization) Reason() AuthorizationReason      { return a.reason }
func (a EffectAuthorization) IssuedAtUnixMilliseconds() int64  { return a.issuedAtUnixMilliseconds }
func (a EffectAuthorization) ExpiresAtUnixMilliseconds() int64 { return a.expiresAtUnixMilliseconds }
func (a EffectAuthorization) String() string                   { return "policy effect authorization" }
func (a EffectAuthorization) GoString() string                 { return "policy.EffectAuthorization{<redacted>}" }
func (a EffectAuthorization) Format(state fmt.State, verb rune) {
	formatted := "policy effect authorization"
	if verb == 'q' {
		formatted = `"policy effect authorization"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "policy.EffectAuthorization{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Allows reports whether this exact scope and capability is allowed at the supplied time.
func (a EffectAuthorization) Allows(capability Capability, scopeIdentity string, at time.Time) bool {
	if a.Validate() != nil || a.outcome != DecisionAllow || a.capability != capability || a.scopeIdentity != scopeIdentity {
		return false
	}
	value := at.UnixMilli()
	return value >= a.issuedAtUnixMilliseconds && value < a.expiresAtUnixMilliseconds
}

// Validate verifies closed fields, lifetime bounds, and content identity.
func (a EffectAuthorization) Validate() error {
	if err := a.validateFields(); err != nil {
		return err
	}
	if a.identity != deriveEffectAuthorizationIdentity(a) {
		return ErrInvalidEffectAuthorizationRecordIdentity
	}
	return nil
}

func (a EffectAuthorization) validateFields() error {
	for _, identity := range []string{a.policyIdentity, a.principalIdentity, a.scopeIdentity} {
		if !validEffectIdentity(identity) {
			return ErrInvalidEffectAuthorizationIdentity
		}
	}
	if !isKnownCapability(a.capability) {
		return ErrInvalidEffectAuthorizationCapability
	}
	if a.outcome != DecisionAllow && a.outcome != DecisionDeny {
		return ErrInvalidEffectAuthorizationOutcome
	}
	if err := a.reason.Validate(); err != nil {
		return err
	}
	validTimes := a.issuedAtUnixMilliseconds > 0 && a.expiresAtUnixMilliseconds > a.issuedAtUnixMilliseconds && a.expiresAtUnixMilliseconds <= maxEffectAuthorizationUnixMilliseconds
	if !validTimes || a.expiresAtUnixMilliseconds-a.issuedAtUnixMilliseconds > maxEffectAuthorizationLifetime.Milliseconds() {
		return ErrInvalidEffectAuthorizationTime
	}
	return nil
}

func validEffectIdentity(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func deriveEffectAuthorizationIdentity(authorization EffectAuthorization) string {
	preimage := struct {
		Contract   string          `json:"contract"`
		Version    int             `json:"version"`
		Policy     string          `json:"policy"`
		Principal  string          `json:"principal"`
		Scope      string          `json:"scope"`
		Capability Capability      `json:"capability"`
		Outcome    DecisionOutcome `json:"outcome"`
		Reason     string          `json:"reason"`
		IssuedAt   int64           `json:"issued_at"`
		ExpiresAt  int64           `json:"expires_at"`
	}{
		Contract: "open-trestle/effect-authorization", Version: 1,
		Policy: authorization.policyIdentity, Principal: authorization.principalIdentity,
		Scope: authorization.scopeIdentity, Capability: authorization.capability,
		Outcome: authorization.outcome, Reason: authorization.reason.String(),
		IssuedAt: authorization.issuedAtUnixMilliseconds, ExpiresAt: authorization.expiresAtUnixMilliseconds,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
