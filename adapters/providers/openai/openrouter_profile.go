package openai

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// RequestProfile selects a closed service-specific request contract.
type RequestProfile string

const RequestProfileOpenRouterZDRChatV1 RequestProfile = "openrouter_zdr_chat_v1"

// OpenRouterRouteAuthority binds host-reviewed route, privacy and account evidence.
// Runtime composition must establish approval and scope before constructing it.
type OpenRouterRouteAuthority struct {
	Route                 provider.RouteReference
	RouteRecordIdentity   string
	EvidenceIdentity      string
	AccountPolicyIdentity string
	CredentialIdentity    string
	TenantID              string
	RepositoryID          string
	ProviderSlug          string
	ValidFrom             time.Time
	ValidUntil            time.Time
}

func cloneOpenRouterAuthority(value *OpenRouterRouteAuthority) *OpenRouterRouteAuthority {
	if value == nil {
		return nil
	}
	copy := *value
	copy.ValidFrom = copy.ValidFrom.Round(0).UTC()
	copy.ValidUntil = copy.ValidUntil.Round(0).UTC()
	return &copy
}

func (a *Adapter) validRequestProfile() bool {
	if a.requestProfile == "" {
		return a.openRouterAuthority == nil && a.clock == nil
	}
	if a.requestProfile != RequestProfileOpenRouterZDRChatV1 || a.openRouterAuthority == nil || nilInterface(a.clock) || a.endpoint == nil ||
		a.protocol != ProtocolChatCompletions || a.credentialMode != CredentialModeBearer ||
		a.zone != provider.ProviderZoneBrokeredRemote || a.providerID != "openrouter" ||
		a.contentLoggingMode != provider.ContentLoggingDisabled || a.endpoint.String() != "https://openrouter.ai/api/v1" {
		return false
	}
	authority := a.openRouterAuthority
	route := authority.Route
	if route.Validate() != nil || !a.routeMatches(route) ||
		!validConfigurationIdentity(authority.RouteRecordIdentity) || !validConfigurationIdentity(authority.EvidenceIdentity) ||
		!validConfigurationIdentity(authority.AccountPolicyIdentity) ||
		authority.CredentialIdentity != a.credentialIdentity || !validOpenRouterSlug(authority.ProviderSlug) ||
		authority.ValidFrom.IsZero() || authority.ValidUntil.IsZero() || authority.ValidFrom.Year() < 1 || authority.ValidUntil.Year() > 9999 || !authority.ValidUntil.After(authority.ValidFrom) {
		return false
	}
	_, err := audit.NewReviewScope(authority.TenantID, authority.RepositoryID, "authority-validation")
	return err == nil
}

func validOpenRouterSlug(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, char := range segment {
			if !(char >= 'a' && char <= 'z' || char >= '0' && char <= '9' || char == '-' || char == '_' || char == '.') {
				return false
			}
		}
	}
	return true
}

func (a *Adapter) profileAuthorityCurrent() bool {
	if a.requestProfile == "" {
		return true
	}
	if !a.validRequestProfile() {
		return false
	}
	now := a.clock.Now()
	return !now.Before(a.openRouterAuthority.ValidFrom) && now.Before(a.openRouterAuthority.ValidUntil)
}

func (a *Adapter) profileAuthorityMatches(route provider.RouteReference) bool {
	return a.requestProfile == "" || a.profileAuthorityCurrent() && a.openRouterAuthority.Route == route
}

func (a *Adapter) profileIdentityPreimage(configuration []byte) []byte {
	authority := a.openRouterAuthority
	encoded, _ := json.Marshal(struct {
		Contract          string          `json:"contract"`
		Version           int             `json:"version"`
		Configuration     json.RawMessage `json:"configuration"`
		Profile           RequestProfile  `json:"request_profile"`
		Protocol          Protocol        `json:"protocol"`
		CredentialMode    CredentialMode  `json:"credential_mode"`
		Route             []string        `json:"route"`
		Record            string          `json:"route_record_identity"`
		Evidence          string          `json:"evidence_identity"`
		Account           string          `json:"account_policy_identity"`
		Tenant            string          `json:"tenant_id"`
		Repository        string          `json:"repository_id"`
		ProviderSlug      string          `json:"provider_slug"`
		ValidFrom         time.Time       `json:"valid_from"`
		ValidUntil        time.Time       `json:"valid_until"`
		ZDR               bool            `json:"zdr"`
		AllowFallbacks    bool            `json:"allow_fallbacks"`
		RequireParameters bool            `json:"require_parameters"`
	}{"open-trestle/openrouter-zdr-chat-adapter", 2, configuration, a.requestProfile, a.protocol, a.credentialMode,
		[]string{authority.Route.Zone().String(), authority.Route.ProviderID(), authority.Route.AdapterID(), authority.Route.ConnectionID(), authority.Route.ModelID(), authority.Route.ModelVersion()}, authority.RouteRecordIdentity, authority.EvidenceIdentity, authority.AccountPolicyIdentity,
		authority.TenantID, authority.RepositoryID, authority.ProviderSlug, authority.ValidFrom, authority.ValidUntil, true, false, true})
	return encoded
}

type openRouterProviderPreferences struct {
	ZDR               bool     `json:"zdr"`
	Only              []string `json:"only"`
	Order             []string `json:"order"`
	AllowFallbacks    bool     `json:"allow_fallbacks"`
	RequireParameters bool     `json:"require_parameters"`
}

type openRouterChatRequestWire struct {
	chatRequestWire
	Provider openRouterProviderPreferences `json:"provider"`
}
