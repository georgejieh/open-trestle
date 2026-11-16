package openai

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const RequestProfileOpenCodeConsoleChatV1 RequestProfile = "opencode_console_chat_v1"
const openCodeConsoleUserAgent = "open-trestle/1"
const openCodeConsoleSessionDomain = "open-trestle/opencode-console-session/v1/"

// OpenCodeConsoleRouteAuthority is a host-reviewed declaration, not a provider attestation.
type OpenCodeConsoleRouteAuthority struct {
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

func cloneOpenCodeConsoleAuthority(value *OpenCodeConsoleRouteAuthority) *OpenCodeConsoleRouteAuthority {
	if value == nil {
		return nil
	}
	copy := *value
	copy.ValidFrom = copy.ValidFrom.Round(0).UTC()
	copy.ValidUntil = copy.ValidUntil.Round(0).UTC()
	return &copy
}

func (a *Adapter) validOpenCodeConsoleProfile() bool {
	if a.requestProfile != RequestProfileOpenCodeConsoleChatV1 || a.openCodeConsoleAuthority == nil || a.openCodeGoAuthority != nil || a.openRouterAuthority != nil || nilInterface(a.clock) || a.endpoint == nil || a.protocol != ProtocolChatCompletions || a.credentialMode != CredentialModeBearer || a.zone != provider.ProviderZoneBrokeredRemote || a.providerID != "opencode-console" || a.contentLoggingMode != provider.ContentLoggingDisabled || a.endpoint.String() != "https://opencode.ai/inference/openai/v1" {
		return false
	}
	authority := a.openCodeConsoleAuthority
	if authority.Route.Validate() != nil || strings.HasSuffix(modelSelector(authority.Route), "-free") || modelSelector(authority.Route) == "big-pickle" || !a.routeMatches(authority.Route) || !validConfigurationIdentity(authority.RouteRecordIdentity) || !validConfigurationIdentity(authority.EvidenceIdentity) || !validConfigurationIdentity(authority.AccountPolicyIdentity) || authority.CredentialIdentity != a.credentialIdentity || authority.ValidFrom.IsZero() || authority.ValidUntil.IsZero() || authority.ValidFrom.Year() < 1 || authority.ValidUntil.Year() > 9999 || !authority.ValidUntil.After(authority.ValidFrom) {
		return false
	}
	_, err := audit.NewReviewScope(authority.TenantID, authority.RepositoryID, "authority-validation")
	return err == nil
}

func (a *Adapter) openCodeConsoleProfileCurrent() bool {
	if !a.validOpenCodeConsoleProfile() {
		return false
	}
	now := a.clock.Now()
	return !now.Before(a.openCodeConsoleAuthority.ValidFrom) && now.Before(a.openCodeConsoleAuthority.ValidUntil)
}

func (a *Adapter) openCodeConsoleProfileMatches(route provider.RouteReference) bool {
	return a.openCodeConsoleProfileCurrent() && a.openCodeConsoleAuthority.Route == route
}

func (a *Adapter) openCodeConsoleProofMatches(proof modelhandler.SanitizedDispatchProof, scope, request string) bool {
	if !a.validOpenCodeConsoleProfile() {
		return false
	}
	return proof.ValidateRepositoryScope(a.openCodeConsoleAuthority.TenantID, a.openCodeConsoleAuthority.RepositoryID, scope, request) == nil
}

func (a *Adapter) openCodeConsoleIdentityPreimage(configuration []byte) []byte {
	authority := a.openCodeConsoleAuthority
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
	}{"open-trestle/opencode-console-chat-adapter", 1, configuration, a.requestProfile, a.protocol, a.credentialMode,
		[]string{authority.Route.Zone().String(), authority.Route.ProviderID(), authority.Route.AdapterID(), authority.Route.ConnectionID(), authority.Route.ModelID(), authority.Route.ModelVersion()}, authority.RouteRecordIdentity, authority.EvidenceIdentity, authority.AccountPolicyIdentity, authority.TenantID, authority.RepositoryID, authority.ValidFrom, authority.ValidUntil, openCodeConsoleUserAgent, openCodeConsoleSessionDomain})
	return encoded
}

func (a *Adapter) setOpenCodeConsoleHeaders(request *http.Request, proof modelhandler.SanitizedDispatchProof, scope, requestIdentity string) error {
	if !a.openCodeConsoleProfileCurrent() || !a.openCodeConsoleProofMatches(proof, scope, requestIdentity) {
		return ErrInvalidConfig
	}
	digest := sha256.Sum256([]byte(openCodeConsoleSessionDomain + scope))
	request.Header.Set("User-Agent", openCodeConsoleUserAgent)
	request.Header.Set("x-opencode-session", "trestle_"+hex.EncodeToString(digest[:]))
	return nil
}
