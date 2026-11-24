package openai

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// RequestProfile selects a closed service-specific request contract.
type RequestProfile string

const RequestProfileOpenRouterZDRChatV1 RequestProfile = "openrouter_zdr_chat_v1"

// RequestProfileOpenRouterZDRChatV2 sets provider.zdr on every request and
// limits it to ProviderSlugs when that list is not empty. Its authority comes
// from a witness setup recorded from OpenRouter's API; it has no account
// review, single slug or validity window.
const RequestProfileOpenRouterZDRChatV2 RequestProfile = "openrouter_zdr_chat_v2"

// maxOpenRouterSlugs matches runtimeconfig.MaxOpenRouterProviderSlugs.
const maxOpenRouterSlugs = 32

// OpenRouterRouteAuthority binds host-reviewed route, privacy and account evidence.
// Runtime composition must establish approval and scope before constructing it.
// The V1 profile uses ProviderSlug, AccountPolicyIdentity and the window; the
// V2 profile uses ProviderSlugs and leaves those empty.
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
	ProviderSlugs         []string
	// Reasoning is a V2 route whose every pinned endpoint accepts the
	// reasoning parameter; its requests ask for low reasoning effort.
	Reasoning bool
}

func cloneOpenRouterAuthority(value *OpenRouterRouteAuthority) *OpenRouterRouteAuthority {
	if value == nil {
		return nil
	}
	copy := *value
	copy.ValidFrom = copy.ValidFrom.Round(0).UTC()
	copy.ValidUntil = copy.ValidUntil.Round(0).UTC()
	copy.ProviderSlugs = slices.Clone(value.ProviderSlugs)
	return &copy
}

func (a *Adapter) openRouterProfile() bool {
	return a.requestProfile == RequestProfileOpenRouterZDRChatV1 || a.requestProfile == RequestProfileOpenRouterZDRChatV2
}

func validOpenRouterSlugList(slugs []string) bool {
	if len(slugs) > maxOpenRouterSlugs {
		return false
	}
	for i, slug := range slugs {
		if !validOpenRouterSlug(slug) || slices.Contains(slugs[:i], slug) {
			return false
		}
	}
	return true
}

func (a *Adapter) validRequestProfile() bool {
	if a.requestProfile == "" {
		return a.openRouterAuthority == nil && a.clock == nil
	}
	if !a.openRouterProfile() || a.openRouterAuthority == nil || nilInterface(a.clock) || a.endpoint == nil ||
		a.protocol != ProtocolChatCompletions || a.credentialMode != CredentialModeBearer ||
		a.zone != provider.ProviderZoneBrokeredRemote || a.providerID != "openrouter" ||
		a.contentLoggingMode != provider.ContentLoggingDisabled || a.endpoint.String() != "https://openrouter.ai/api/v1" {
		return false
	}
	authority := a.openRouterAuthority
	route := authority.Route
	if route.Validate() != nil || !a.routeMatches(route) ||
		!validConfigurationIdentity(authority.RouteRecordIdentity) || !validConfigurationIdentity(authority.EvidenceIdentity) ||
		authority.CredentialIdentity != a.credentialIdentity {
		return false
	}
	if a.requestProfile == RequestProfileOpenRouterZDRChatV2 {
		if authority.AccountPolicyIdentity != "" || authority.ProviderSlug != "" || !authority.ValidFrom.IsZero() || !authority.ValidUntil.IsZero() || authority.ProviderSlugs == nil || !validOpenRouterSlugList(authority.ProviderSlugs) || authority.Reasoning && len(authority.ProviderSlugs) == 0 {
			return false
		}
	} else if !validConfigurationIdentity(authority.AccountPolicyIdentity) || !validOpenRouterSlug(authority.ProviderSlug) || authority.ProviderSlugs != nil || authority.Reasoning ||
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
	if a.requestProfile == RequestProfileOpenRouterZDRChatV2 {
		return true
	}
	now := a.clock.Now()
	return !now.Before(a.openRouterAuthority.ValidFrom) && now.Before(a.openRouterAuthority.ValidUntil)
}

func (a *Adapter) profileAuthorityMatches(route provider.RouteReference) bool {
	return a.requestProfile == "" || a.profileAuthorityCurrent() && a.openRouterAuthority.Route == route
}

func (a *Adapter) profileIdentityPreimage(configuration []byte) []byte {
	authority := a.openRouterAuthority
	if a.requestProfile == RequestProfileOpenRouterZDRChatV2 {
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
			Tenant            string          `json:"tenant_id"`
			Repository        string          `json:"repository_id"`
			ProviderSlugs     []string        `json:"provider_slugs"`
			ZDR               bool            `json:"zdr"`
			PinnedOrder       bool            `json:"pinned_order"`
			AllowFallbacks    bool            `json:"allow_fallbacks"`
			RequireParameters bool            `json:"require_parameters"`
			ReasoningEffort   string          `json:"reasoning_effort,omitempty"`
		}{"open-trestle/openrouter-zdr-chat-adapter", 5, configuration, a.requestProfile, a.protocol, a.credentialMode,
			[]string{authority.Route.Zone().String(), authority.Route.ProviderID(), authority.Route.AdapterID(), authority.Route.ConnectionID(), authority.Route.ModelID(), authority.Route.ModelVersion()}, authority.RouteRecordIdentity, authority.EvidenceIdentity,
			authority.TenantID, authority.RepositoryID, append([]string{}, authority.ProviderSlugs...), true, false, true, true, a.reasoningEffort()})
		return encoded
	}
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

// The V1 profile always pins one slug, so omitting an empty list leaves its
// request bytes unchanged; an unpinned V2 request sends neither list.
type openRouterProviderPreferences struct {
	ZDR               bool     `json:"zdr"`
	Only              []string `json:"only,omitempty"`
	Order             []string `json:"order,omitempty"`
	AllowFallbacks    bool     `json:"allow_fallbacks"`
	RequireParameters bool     `json:"require_parameters"`
}

// openRouterPreferences returns the fixed provider controls of both OpenRouter
// profiles: zero data retention, no endpoint outside the pinned slugs, and
// only endpoints that accept every request parameter. V1 pins its one slug
// with only and order and allows no fallback. V2 sends only, without order,
// so OpenRouter balances requests across the pinned ZDR endpoints instead of
// sending every request to the first one (a fixed cheapest-first order sends
// every request to one endpoint, whose serving faults then decide every
// result), and allows fallback, which only keeps inside the pinned slugs (a
// model outside only is refused with HTTP 404 even with allow_fallbacks true).
// Without it, OpenRouter serves a request only from its top-ranked endpoint,
// and that endpoint's errors fail runs.
func (a *Adapter) openRouterPreferences() openRouterProviderPreferences {
	if a.requestProfile == RequestProfileOpenRouterZDRChatV2 {
		return openRouterProviderPreferences{ZDR: true, Only: slices.Clone(a.openRouterAuthority.ProviderSlugs), AllowFallbacks: true, RequireParameters: true}
	}
	slugs := []string{a.openRouterAuthority.ProviderSlug}
	return openRouterProviderPreferences{ZDR: true, Only: slugs, Order: slices.Clone(slugs), AllowFallbacks: false, RequireParameters: true}
}

// openRouterEndpoint is the one OpenRouter API base both profiles and a
// generic connection to OpenRouter use.
const openRouterEndpoint = "https://openrouter.ai/api/v1"

type openRouterChatRequestWire struct {
	chatRequestWire
	Provider openRouterProviderPreferences `json:"provider"`
}

// openRouterReasoningEffort is the reasoning effort OpenRouter requests ask
// for. Reasoning counts against max_tokens, and low leaves most of the output
// allowance for the answer.
const openRouterReasoningEffort = "low"

type chatReasoning struct {
	Effort string `json:"effort"`
}

// reasoningEffort is the effort a request asks for, or "" for none. A V2
// request sets require_parameters, so it asks only when every pinned endpoint
// accepts the reasoning parameter. A generic OpenRouter connection sets no
// provider controls, and an endpoint without the parameter ignores it.
func (a *Adapter) reasoningEffort() string {
	if a.requestProfile == RequestProfileOpenRouterZDRChatV2 && a.openRouterAuthority != nil && a.openRouterAuthority.Reasoning ||
		a.requestProfile == "" && a.protocol == ProtocolChatCompletions && a.endpoint != nil && a.endpoint.String() == openRouterEndpoint {
		return openRouterReasoningEffort
	}
	return ""
}
