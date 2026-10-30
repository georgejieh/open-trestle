package openai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const RequestProfileOpenCodeGoChatV1 RequestProfile = "opencode_go_chat_v1"
const openCodeGoUserAgent = "open-trestle/1"
const openCodeGoSessionDomain = "open-trestle/opencode-go-session/v1/"

// OpenCodeGoRouteAuthority is a host-reviewed declaration, not a provider attestation.
type OpenCodeGoRouteAuthority struct {
	Route                 provider.RouteReference
	RouteRecordIdentity   string
	EvidenceIdentity      string
	AccountPolicyIdentity string
	CredentialIdentity    string
	TenantID              string
	RepositoryID          string
	ValidFrom             time.Time
	ValidUntil            time.Time
}

func cloneOpenCodeGoAuthority(value *OpenCodeGoRouteAuthority) *OpenCodeGoRouteAuthority {
	if value == nil {
		return nil
	}
	copy := *value
	copy.ValidFrom = copy.ValidFrom.Round(0).UTC()
	copy.ValidUntil = copy.ValidUntil.Round(0).UTC()
	return &copy
}

func (a *Adapter) validServiceProfile() bool {
	if a.requestProfile != RequestProfileOpenCodeGoChatV1 {
		return a.openCodeGoAuthority == nil && a.validRequestProfile()
	}
	if a.openCodeGoAuthority == nil || a.openRouterAuthority != nil || nilInterface(a.clock) || a.endpoint == nil || a.protocol != ProtocolChatCompletions || a.credentialMode != CredentialModeBearer || a.zone != provider.ProviderZoneBrokeredRemote || a.providerID != "opencode-go" || a.contentLoggingMode != provider.ContentLoggingDisabled || a.endpoint.String() != "https://opencode.ai/inference/go/openai/v1" {
		return false
	}
	authority := a.openCodeGoAuthority
	if authority.Route.Validate() != nil || !a.routeMatches(authority.Route) || !validConfigurationIdentity(authority.RouteRecordIdentity) || !validConfigurationIdentity(authority.EvidenceIdentity) || !validConfigurationIdentity(authority.AccountPolicyIdentity) || authority.CredentialIdentity != a.credentialIdentity || authority.ValidFrom.IsZero() || authority.ValidUntil.IsZero() || authority.ValidFrom.Year() < 1 || authority.ValidUntil.Year() > 9999 || !authority.ValidUntil.After(authority.ValidFrom) {
		return false
	}
	_, err := audit.NewReviewScope(authority.TenantID, authority.RepositoryID, "authority-validation")
	return err == nil
}

func (a *Adapter) serviceProfileCurrent() bool {
	if a.requestProfile != RequestProfileOpenCodeGoChatV1 {
		return a.profileAuthorityCurrent()
	}
	if !a.validServiceProfile() {
		return false
	}
	now := a.clock.Now()
	return !now.Before(a.openCodeGoAuthority.ValidFrom) && now.Before(a.openCodeGoAuthority.ValidUntil)
}

func (a *Adapter) serviceProfileMatches(route provider.RouteReference) bool {
	if a.requestProfile != RequestProfileOpenCodeGoChatV1 {
		return a.profileAuthorityMatches(route)
	}
	return a.serviceProfileCurrent() && a.openCodeGoAuthority.Route == route
}

func (a *Adapter) serviceProfileRecord() string {
	if a.requestProfile == RequestProfileOpenCodeGoChatV1 {
		return a.openCodeGoAuthority.RouteRecordIdentity
	}
	return a.openRouterAuthority.RouteRecordIdentity
}

func (a *Adapter) serviceProofMatches(proof modelhandler.SanitizedDispatchProof, scope, request string) bool {
	if a.requestProfile == "" {
		return true
	}
	if !a.validServiceProfile() {
		return false
	}
	if a.requestProfile == RequestProfileOpenCodeGoChatV1 {
		return proof.ValidateRepositoryScope(a.openCodeGoAuthority.TenantID, a.openCodeGoAuthority.RepositoryID, scope, request) == nil
	}
	return proof.ValidateRepositoryScope(a.openRouterAuthority.TenantID, a.openRouterAuthority.RepositoryID, scope, request) == nil
}

func (a *Adapter) serviceIdentityPreimage(configuration []byte) []byte {
	if a.requestProfile != RequestProfileOpenCodeGoChatV1 {
		return a.profileIdentityPreimage(configuration)
	}
	authority := a.openCodeGoAuthority
	encoded, _ := json.Marshal(struct {
		Contract       string          `json:"contract"`
		Version        int             `json:"version"`
		Configuration  json.RawMessage `json:"configuration"`
		Profile        RequestProfile  `json:"request_profile"`
		Protocol       Protocol        `json:"protocol"`
		CredentialMode CredentialMode  `json:"credential_mode"`
		Route          []string        `json:"route"`
		Record         string          `json:"route_record_identity"`
		Evidence       string          `json:"evidence_identity"`
		Account        string          `json:"account_policy_identity"`
		Tenant         string          `json:"tenant_id"`
		Repository     string          `json:"repository_id"`
		ValidFrom      time.Time       `json:"valid_from"`
		ValidUntil     time.Time       `json:"valid_until"`
		UserAgent      string          `json:"user_agent"`
		SessionDomain  string          `json:"session_domain"`
	}{"open-trestle/opencode-go-chat-adapter", 1, configuration, a.requestProfile, a.protocol, a.credentialMode,
		[]string{authority.Route.Zone().String(), authority.Route.ProviderID(), authority.Route.AdapterID(), authority.Route.ConnectionID(), authority.Route.ModelID(), authority.Route.ModelVersion()}, authority.RouteRecordIdentity, authority.EvidenceIdentity, authority.AccountPolicyIdentity, authority.TenantID, authority.RepositoryID, authority.ValidFrom, authority.ValidUntil, openCodeGoUserAgent, openCodeGoSessionDomain})
	return encoded
}

func (a *Adapter) setOpenCodeGoHeaders(request *http.Request, proof modelhandler.SanitizedDispatchProof, scope, requestIdentity string) error {
	if !a.serviceProfileCurrent() || !a.serviceProofMatches(proof, scope, requestIdentity) {
		return ErrInvalidConfig
	}
	digest := sha256.Sum256([]byte(openCodeGoSessionDomain + scope))
	request.Header.Set("User-Agent", openCodeGoUserAgent)
	request.Header.Set("x-opencode-session", "trestle_"+hex.EncodeToString(digest[:]))
	return nil
}
