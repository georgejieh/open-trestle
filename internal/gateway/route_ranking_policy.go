package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/provider"
)

const maxRouteRankingPreferences = 64

var (
	// ErrInvalidRouteRankingPolicyIdentity identifies a policy whose identity does not match its fields.
	ErrInvalidRouteRankingPolicyIdentity = errors.New("invalid route ranking policy identity")
	// ErrTooManyRoutePreferences identifies a preference list beyond the deterministic bound.
	ErrTooManyRoutePreferences = errors.New("too many route preferences")
	// ErrDuplicateRoutePreference identifies a repeated exact route reference.
	ErrDuplicateRoutePreference = errors.New("duplicate route preference")
	// ErrPinnedRouteRepeatedInPreferences identifies a pin also present in the lower-priority preference list.
	ErrPinnedRouteRepeatedInPreferences = errors.New("pinned route repeated in preferences")
)

// RouteRankingPolicy binds an optional exact pin and ordered exact route preferences.
type RouteRankingPolicy struct {
	identity        string
	hasPinnedRoute  bool
	pinnedRoute     provider.RouteReference
	preferredRoutes []provider.RouteReference
}

// NewRouteRankingPolicy creates an unpinned ranking policy.
func NewRouteRankingPolicy(preferred []provider.RouteReference) (RouteRankingPolicy, error) {
	return newRouteRankingPolicy(false, provider.RouteReference{}, preferred)
}

// NewPinnedRouteRankingPolicy creates a ranking policy with one exact route pin.
func NewPinnedRouteRankingPolicy(pinned provider.RouteReference, preferred []provider.RouteReference) (RouteRankingPolicy, error) {
	return newRouteRankingPolicy(true, pinned, preferred)
}

func newRouteRankingPolicy(hasPin bool, pinned provider.RouteReference, preferred []provider.RouteReference) (RouteRankingPolicy, error) {
	policy := RouteRankingPolicy{
		hasPinnedRoute:  hasPin,
		pinnedRoute:     pinned,
		preferredRoutes: append([]provider.RouteReference(nil), preferred...),
	}
	if err := validateRouteRankingPolicyFields(policy.hasPinnedRoute, policy.pinnedRoute, policy.preferredRoutes); err != nil {
		return RouteRankingPolicy{}, err
	}
	identity, err := deriveRouteRankingPolicyIdentity(policy.hasPinnedRoute, policy.pinnedRoute, policy.preferredRoutes)
	if err != nil {
		return RouteRankingPolicy{}, err
	}
	policy.identity = identity
	return policy, nil
}

// Identity returns the canonical SHA-256 policy identity.
func (p RouteRankingPolicy) Identity() string { return p.identity }

// PinnedRoute returns the exact pin and whether one is present.
func (p RouteRankingPolicy) PinnedRoute() (provider.RouteReference, bool) {
	return p.pinnedRoute, p.hasPinnedRoute
}

// PreferredRoutes returns a defensive copy in declared preference order.
func (p RouteRankingPolicy) PreferredRoutes() []provider.RouteReference {
	if len(p.preferredRoutes) == 0 {
		return nil
	}
	return append([]provider.RouteReference(nil), p.preferredRoutes...)
}

// String returns a redacted ranking-policy description.
func (p RouteRankingPolicy) String() string { return "route ranking policy" }

// GoString returns a redacted Go-syntax ranking-policy description.
func (p RouteRankingPolicy) GoString() string {
	return "gateway.RouteRankingPolicy{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (p RouteRankingPolicy) Format(state fmt.State, verb rune) {
	formatted := "route ranking policy"
	if verb == 'q' {
		formatted = `"route ranking policy"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteRankingPolicy{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies policy fields and their content-derived identity.
func (p RouteRankingPolicy) Validate() error {
	if err := validateRouteRankingPolicyFields(p.hasPinnedRoute, p.pinnedRoute, p.preferredRoutes); err != nil {
		return err
	}
	identity, err := deriveRouteRankingPolicyIdentity(p.hasPinnedRoute, p.pinnedRoute, p.preferredRoutes)
	if err != nil {
		return err
	}
	if p.identity != identity {
		return ErrInvalidRouteRankingPolicyIdentity
	}
	return nil
}

func validateRouteRankingPolicyFields(hasPin bool, pinned provider.RouteReference, preferred []provider.RouteReference) error {
	if len(preferred) > maxRouteRankingPreferences {
		return ErrTooManyRoutePreferences
	}
	if hasPin {
		if err := pinned.Validate(); err != nil {
			return err
		}
	} else if pinned != (provider.RouteReference{}) {
		return ErrInvalidRouteRankingPolicyIdentity
	}
	seen := make(map[provider.RouteReference]struct{}, len(preferred))
	for _, reference := range preferred {
		if err := reference.Validate(); err != nil {
			return err
		}
		if _, exists := seen[reference]; exists {
			return ErrDuplicateRoutePreference
		}
		if hasPin && reference == pinned {
			return ErrPinnedRouteRepeatedInPreferences
		}
		seen[reference] = struct{}{}
	}
	return nil
}

type canonicalRouteReference struct {
	Zone         string `json:"zone"`
	ProviderID   string `json:"provider_id"`
	AdapterID    string `json:"adapter_id"`
	ConnectionID string `json:"connection_id"`
	ModelID      string `json:"model_id"`
	ModelVersion string `json:"model_version"`
}

func deriveRouteRankingPolicyIdentity(hasPin bool, pinned provider.RouteReference, preferred []provider.RouteReference) (string, error) {
	preimage := struct {
		Contract    string                    `json:"contract"`
		Version     int                       `json:"version"`
		Pinned      *canonicalRouteReference  `json:"pinned"`
		Preferences []canonicalRouteReference `json:"preferences"`
	}{
		Contract: "open-trestle/route-ranking-policy",
		Version:  1,
	}
	if hasPin {
		canonical := canonicalRankingRouteReference(pinned)
		preimage.Pinned = &canonical
	}
	if len(preferred) > 0 {
		preimage.Preferences = make([]canonicalRouteReference, len(preferred))
		for index, reference := range preferred {
			preimage.Preferences[index] = canonicalRankingRouteReference(reference)
		}
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return "", fmt.Errorf("encode route ranking policy identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}

func canonicalRankingRouteReference(reference provider.RouteReference) canonicalRouteReference {
	return canonicalRouteReference{
		Zone:         reference.Zone().String(),
		ProviderID:   reference.ProviderID(),
		AdapterID:    reference.AdapterID(),
		ConnectionID: reference.ConnectionID(),
		ModelID:      reference.ModelID(),
		ModelVersion: reference.ModelVersion(),
	}
}
