package runtimeconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

type openCodeConsolePrivacyRoute struct {
	Zone              string `json:"zone"`
	ProviderID        string `json:"provider_id"`
	AdapterID         string `json:"adapter_id"`
	ConnectionID      string `json:"connection_id"`
	ModelID           string `json:"model_id"`
	ModelVersion      string `json:"model_version"`
	EffectiveSelector string `json:"effective_selector"`
}

func (r *openCodeConsolePrivacyRoute) UnmarshalJSON(encoded []byte) error {
	type routeValue openCodeConsolePrivacyRoute
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil || fields["model_version"] == nil || bytes.Equal(bytes.TrimSpace(fields["model_version"]), []byte("null")) {
		return ErrInvalidRouteInventory
	}
	var value routeValue
	if decodeOpenRouterPrivacyJSON(encoded, &value) != nil {
		return ErrInvalidRouteInventory
	}
	*r = openCodeConsolePrivacyRoute(value)
	return nil
}

type openCodeConsolePrivacyAccount struct {
	AuthorityLabel              string                  `json:"authority_label"`
	CredentialReferenceIdentity string                  `json:"credential_reference_identity"`
	BillingMode                 string                  `json:"billing_mode"`
	KeyKind                     string                  `json:"key_kind"`
	ModelsRequest               bool                    `json:"models_request"`
	WorkspaceMembership         string                  `json:"workspace_membership"`
	PrivacyTraining             string                  `json:"privacy_training"`
	AutoRecharge                string                  `json:"auto_recharge"`
	ReviewEvidence              openRouterPrivacySource `json:"review_evidence"`
}

func (a openCodeConsolePrivacyAccount) valid() bool {
	return validPrivacyLabel(a.AuthorityLabel) && nonzeroDigest(a.CredentialReferenceIdentity) && a.BillingMode == "prepaid_balance" && a.KeyKind == "personal" && a.ModelsRequest && a.WorkspaceMembership == "single_member" && a.PrivacyTraining == "disabled" && a.AutoRecharge == "disabled" && a.ReviewEvidence.valid()
}
func (a openCodeConsolePrivacyAccount) identity() string {
	if !a.valid() {
		return ""
	}
	encoded, err := json.Marshal(struct {
		Contract string                        `json:"contract"`
		Version  int                           `json:"version"`
		Account  openCodeConsolePrivacyAccount `json:"account"`
	}{"open-trestle/opencode-console-account-policy", 1, a})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

type openCodeConsolePrivacyWitness struct {
	Contract       string                      `json:"contract"`
	SchemaVersion  int                         `json:"schema_version"`
	Route          openCodeConsolePrivacyRoute `json:"route"`
	Endpoint       string                      `json:"endpoint"`
	RequestProfile string                      `json:"request_profile"`
	Protocol       string                      `json:"protocol"`
	CredentialMode string                      `json:"credential_mode"`
	ModelPrivacy   openCodeConsoleModelPrivacy `json:"model_privacy"`
	BrokerPrivacy  struct {
		RetentionContract string                  `json:"retention_contract"`
		Evidence          openRouterPrivacySource `json:"evidence"`
	} `json:"broker_privacy"`
	Account      openCodeConsolePrivacyAccount `json:"account"`
	TenantID     string                        `json:"tenant_id"`
	RepositoryID string                        `json:"repository_id"`
	ReviewedAt   string                        `json:"reviewed_at"`
	ValidFrom    string                        `json:"valid_from"`
	ValidUntil   string                        `json:"valid_until"`
	BYOK         string                        `json:"byok"`
	Tools        string                        `json:"tools"`
	Plugins      string                        `json:"plugins"`
	Streaming    string                        `json:"streaming"`
	Client       struct {
		UserAgent         string `json:"user_agent"`
		SessionDerivation string `json:"session_derivation"`
	} `json:"client"`
}
type openCodeConsoleModelPrivacy struct {
	Training      string                  `json:"training"`
	RetentionDays uint64                  `json:"retention_days"`
	Evidence      openRouterPrivacySource `json:"evidence"`
}

func (m *openCodeConsoleModelPrivacy) UnmarshalJSON(encoded []byte) error {
	type modelValue openCodeConsoleModelPrivacy
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil || fields["retention_days"] == nil || bytes.Equal(bytes.TrimSpace(fields["retention_days"]), []byte("null")) {
		return ErrInvalidRouteInventory
	}
	var value modelValue
	if decodeOpenRouterPrivacyJSON(encoded, &value) != nil {
		return ErrInvalidRouteInventory
	}
	*m = openCodeConsoleModelPrivacy(value)
	return nil
}

type openCodeConsolePrivacyProjection struct {
	witness          openCodeConsolePrivacyWitness
	record, evidence string
}

func extractOpenCodeConsolePrivacy(manifest []byte, record provider.RouteRegistryRecord) openCodeConsolePrivacyProjection {
	route := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
	if route.Zone() != provider.ProviderZoneBrokeredRemote || route.ProviderID() != "opencode-console" || !utf8.Valid(manifest) || validateUniqueJSONKeys(manifest) != nil {
		return openCodeConsolePrivacyProjection{}
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(manifest, &members) != nil || members == nil {
		return openCodeConsolePrivacyProjection{}
	}
	var w openCodeConsolePrivacyWitness
	if decodeOpenRouterPrivacyJSON(members["opencode_console_privacy"], &w) != nil {
		return openCodeConsolePrivacyProjection{}
	}
	projection := openCodeConsolePrivacyProjection{w, record.Identity(), record.EvidenceManifestDigest()}
	if !projection.matchesRecord(record) {
		return openCodeConsolePrivacyProjection{}
	}
	return projection
}
func (w openCodeConsolePrivacyWitness) routeReference() (provider.RouteReference, bool) {
	r := w.Route
	if r.Zone != "brokered_remote" || r.ProviderID != "opencode-console" {
		return provider.RouteReference{}, false
	}
	route, err := provider.NewRouteReference(provider.ProviderZoneBrokeredRemote, r.ProviderID, r.AdapterID, r.ConnectionID, r.ModelID, r.ModelVersion)
	selector := r.ModelVersion
	if selector == "" {
		selector = r.ModelID
	}
	return route, err == nil && r.EffectiveSelector == selector && !strings.HasSuffix(selector, "-free") && selector != "big-pickle"
}
func (w openCodeConsolePrivacyWitness) valid() bool {
	if w.Contract != "open-trestle/opencode-console-privacy-witness" || w.SchemaVersion != 1 || w.Endpoint != "https://opencode.ai/inference/openai/v1" || w.RequestProfile != OpenCodeConsoleChatProfile || w.Protocol != "openai_chat_completions" || w.CredentialMode != "bearer" || w.ModelPrivacy.Training != "disabled" || w.ModelPrivacy.RetentionDays != 0 || w.BrokerPrivacy.RetentionContract != "model_specific_documented_zero_days" || !w.Account.valid() || w.BYOK != "excluded" || w.Tools != "excluded" || w.Plugins != "excluded" || w.Streaming != "excluded" || w.Client.UserAgent != "open-trestle/1" || w.Client.SessionDerivation != "authorized_review_scope_sha256_v1" {
		return false
	}
	if _, err := audit.NewReviewScope(w.TenantID, w.RepositoryID, "profile-validation"); err != nil {
		return false
	}
	if _, valid := w.routeReference(); !valid {
		return false
	}
	reviewed, reviewOK := canonicalPrivacyTime(w.ReviewedAt)
	from, fromOK := canonicalPrivacyTime(w.ValidFrom)
	until, untilOK := canonicalPrivacyTime(w.ValidUntil)
	if !reviewOK || !fromOK || !untilOK || reviewed.After(from) || !until.After(from) {
		return false
	}
	for _, source := range []openRouterPrivacySource{w.ModelPrivacy.Evidence, w.BrokerPrivacy.Evidence, w.Account.ReviewEvidence} {
		if !source.valid() {
			return false
		}
		retrieved, _ := canonicalPrivacyTime(source.RetrievedAt)
		if retrieved.After(reviewed) {
			return false
		}
	}
	return true
}
func (p openCodeConsolePrivacyProjection) matchesRecord(record provider.RouteRegistryRecord) bool {
	if record.Validate() != nil || p.record != record.Identity() || p.evidence != record.EvidenceManifestDigest() || !p.witness.valid() {
		return false
	}
	route, valid := p.witness.routeReference()
	return valid && route == record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
}
func (p openCodeConsolePrivacyProjection) matchesConnection(c ProviderConnection) bool {
	w, a := p.witness, c.openCodeConsoleAuthority
	return w.valid() && p.record == a.record && p.evidence == a.evidence && w.Endpoint == c.endpoint && w.RequestProfile == c.requestProfile && w.Protocol == c.implementation && w.CredentialMode == c.credentialMode && w.Account.CredentialReferenceIdentity == c.credentialIdentity && w.Account.identity() == a.account && w.TenantID == a.tenant && w.RepositoryID == a.repository && w.ValidFrom == a.from.Format(time.RFC3339Nano) && w.ValidUntil == a.until.Format(time.RFC3339Nano)
}

// OpenCodeConsolePrivacyCurrent checks the retained declaration, not provider conduct.
func (i RouteInventory) OpenCodeConsolePrivacyCurrent(recordIdentity string, now time.Time) bool {
	if now.IsZero() || i.Validate() != nil {
		return false
	}
	for index, candidate := range i.candidates {
		if candidate.ResolvedRecord().RouteRegistryRecord().Identity() == recordIdentity {
			p := i.openCodeConsolePrivacy[index]
			if p == (openCodeConsolePrivacyProjection{}) {
				return false
			}
			from, _ := canonicalPrivacyTime(p.witness.ValidFrom)
			until, _ := canonicalPrivacyTime(p.witness.ValidUntil)
			return !now.Before(from) && now.Before(until)
		}
	}
	return false
}
