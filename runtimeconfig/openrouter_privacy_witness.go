package runtimeconfig

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const openRouterRetentionContract = "openrouter_zdr_with_documented_exceptions"

type openRouterPrivacySource struct {
	URL           string `json:"url"`
	RetrievedAt   string `json:"retrieved_at"`
	ContentSHA256 string `json:"content_sha256"`
}

type openRouterPrivacyRoute struct {
	Zone              string `json:"zone"`
	ProviderID        string `json:"provider_id"`
	AdapterID         string `json:"adapter_id"`
	ConnectionID      string `json:"connection_id"`
	ModelID           string `json:"model_id"`
	ModelVersion      string `json:"model_version"`
	EffectiveSelector string `json:"effective_selector"`
}

func (r *openRouterPrivacyRoute) UnmarshalJSON(encoded []byte) error {
	type routeValue openRouterPrivacyRoute
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil || fields["model_version"] == nil || bytes.Equal(bytes.TrimSpace(fields["model_version"]), []byte("null")) {
		return ErrInvalidRouteInventory
	}
	var value routeValue
	if decodeOpenRouterPrivacyJSON(encoded, &value) != nil {
		return ErrInvalidRouteInventory
	}
	*r = openRouterPrivacyRoute(value)
	return nil
}

type openRouterPrivacyAccount struct {
	AuthorityLabel              string                  `json:"authority_label"`
	CredentialReferenceIdentity string                  `json:"credential_reference_identity"`
	ContentLogging              string                  `json:"content_logging"`
	Training                    string                  `json:"training"`
	ReviewEvidence              openRouterPrivacySource `json:"review_evidence"`
}

type openRouterPrivacyWitness struct {
	Contract          string                 `json:"contract"`
	SchemaVersion     int                    `json:"schema_version"`
	Route             openRouterPrivacyRoute `json:"route"`
	Endpoint          string                 `json:"endpoint"`
	RequestProfile    string                 `json:"request_profile"`
	Protocol          string                 `json:"protocol"`
	CredentialMode    string                 `json:"credential_mode"`
	ProviderSlug      string                 `json:"provider_slug"`
	ProviderSlugScope string                 `json:"provider_slug_scope"`
	Upstream          struct {
		RetentionContract string                  `json:"retention_contract"`
		Training          string                  `json:"training"`
		Evidence          openRouterPrivacySource `json:"evidence"`
	} `json:"upstream"`
	Broker struct {
		RetentionContract string                  `json:"retention_contract"`
		Evidence          openRouterPrivacySource `json:"evidence"`
	} `json:"broker"`
	SlugEvidence              openRouterPrivacySource  `json:"slug_evidence"`
	Account                   openRouterPrivacyAccount `json:"account"`
	TenantID                  string                   `json:"tenant_id"`
	RepositoryID              string                   `json:"repository_id"`
	AcceptedRetentionContract string                   `json:"accepted_retention_contract"`
	ReviewedAt                string                   `json:"reviewed_at"`
	ValidFrom                 string                   `json:"valid_from"`
	ValidUntil                string                   `json:"valid_until"`
	BYOK                      string                   `json:"byok"`
	PrivateEndpoints          string                   `json:"private_endpoints"`
	Tools                     string                   `json:"tools"`
	Plugins                   string                   `json:"plugins"`
}

type openRouterPrivacyProjection struct {
	witness  openRouterPrivacyWitness
	record   string
	evidence string
}

func decodeOpenRouterPrivacyJSON(encoded []byte, value any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if decoder.Decode(value) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return ErrInvalidRouteInventory
	}
	return nil
}

func extractOpenRouterPrivacy(manifest []byte, record provider.RouteRegistryRecord) openRouterPrivacyProjection {
	route := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
	if route.Zone() != provider.ProviderZoneBrokeredRemote || route.ProviderID() != "openrouter" || !utf8.Valid(manifest) || validateUniqueJSONKeys(manifest) != nil {
		return openRouterPrivacyProjection{}
	}
	var members map[string]json.RawMessage
	if json.Unmarshal(manifest, &members) != nil || members == nil {
		return openRouterPrivacyProjection{}
	}
	var witness openRouterPrivacyWitness
	if decodeOpenRouterPrivacyJSON(members["openrouter_privacy"], &witness) != nil {
		return openRouterPrivacyProjection{}
	}
	projection := openRouterPrivacyProjection{witness: witness, record: record.Identity(), evidence: record.EvidenceManifestDigest()}
	if !projection.matchesRecord(record) {
		return openRouterPrivacyProjection{}
	}
	return projection
}

func canonicalPrivacyTime(value string) (time.Time, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return parsed, err == nil && !parsed.IsZero() && parsed.Year() >= 1 && parsed.Year() <= 9999 && parsed.Location() == time.UTC && parsed.Format(time.RFC3339Nano) == value
}

func validPrivacyLabel(value string) bool {
	if len(value) == 0 || len(value) > 256 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func (s openRouterPrivacySource) valid() bool {
	if len(s.URL) == 0 || len(s.URL) > 2048 || !utf8.ValidString(s.URL) || !nonzeroDigest(s.ContentSHA256) {
		return false
	}
	parsed, err := url.Parse(s.URL)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || parsed.RawFragment != "" || strings.Contains(s.URL, "#") {
		return false
	}
	_, valid := canonicalPrivacyTime(s.RetrievedAt)
	return valid
}

func (a openRouterPrivacyAccount) valid() bool {
	return validPrivacyLabel(a.AuthorityLabel) && nonzeroDigest(a.CredentialReferenceIdentity) && a.ContentLogging == "disabled" && a.Training == "disabled" && a.ReviewEvidence.valid()
}

func (a openRouterPrivacyAccount) identity() string {
	if !a.valid() {
		return ""
	}
	encoded, err := json.Marshal(struct {
		Contract string                   `json:"contract"`
		Version  int                      `json:"version"`
		Account  openRouterPrivacyAccount `json:"account"`
	}{"open-trestle/openrouter-account-policy", 1, a})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (w openRouterPrivacyWitness) valid() bool {
	if w.Contract != "open-trestle/openrouter-privacy-witness" || w.SchemaVersion != 1 || w.Endpoint != "https://openrouter.ai/api/v1" || w.RequestProfile != OpenRouterZDRChatProfile || w.Protocol != "openai_chat_completions" || w.CredentialMode != "bearer" || !validBrokeredSlug(w.ProviderSlug) || w.ProviderSlugScope != "all_zdr_eligible_matches" || w.Upstream.RetentionContract != openRouterRetentionContract || w.Broker.RetentionContract != openRouterRetentionContract || w.AcceptedRetentionContract != openRouterRetentionContract || w.Upstream.Training != "disabled" || !w.Account.valid() || w.BYOK != "excluded" || w.PrivateEndpoints != "excluded" || w.Tools != "excluded" || w.Plugins != "excluded" {
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
	for _, source := range []openRouterPrivacySource{w.Upstream.Evidence, w.Broker.Evidence, w.SlugEvidence, w.Account.ReviewEvidence} {
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

func (w openRouterPrivacyWitness) routeReference() (provider.RouteReference, bool) {
	r := w.Route
	if r.Zone != "brokered_remote" || r.ProviderID != "openrouter" {
		return provider.RouteReference{}, false
	}
	route, err := provider.NewRouteReference(provider.ProviderZoneBrokeredRemote, r.ProviderID, r.AdapterID, r.ConnectionID, r.ModelID, r.ModelVersion)
	selector := r.ModelVersion
	if selector == "" {
		selector = r.ModelID
	}
	return route, err == nil && r.EffectiveSelector == selector
}

func (p openRouterPrivacyProjection) matchesRecord(record provider.RouteRegistryRecord) bool {
	if record.Validate() != nil || p.record != record.Identity() || p.evidence != record.EvidenceManifestDigest() || !p.witness.valid() {
		return false
	}
	route, valid := p.witness.routeReference()
	return valid && route == record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
}

func (p openRouterPrivacyProjection) matchesConnection(c ProviderConnection) bool {
	w, authority := p.witness, c.brokeredAuthority
	return w.valid() && p.record == authority.record && p.evidence == authority.evidence && w.Endpoint == c.endpoint && w.RequestProfile == c.requestProfile && w.Protocol == c.implementation && w.CredentialMode == c.credentialMode && w.Account.CredentialReferenceIdentity == c.credentialIdentity && w.Account.identity() == authority.account && w.TenantID == authority.tenant && w.RepositoryID == authority.repository && w.ProviderSlug == authority.slug && w.ValidFrom == authority.from.Format(time.RFC3339Nano) && w.ValidUntil == authority.until.Format(time.RFC3339Nano)
}

// OpenRouterPrivacyCurrent checks the retained declaration, not provider conduct.
func (i RouteInventory) OpenRouterPrivacyCurrent(recordIdentity string, now time.Time) bool {
	if now.IsZero() || i.Validate() != nil {
		return false
	}
	for index, candidate := range i.candidates {
		if candidate.ResolvedRecord().RouteRegistryRecord().Identity() == recordIdentity {
			projection := i.openRouterPrivacy[index]
			if projection == (openRouterPrivacyProjection{}) {
				return false
			}
			from, _ := canonicalPrivacyTime(projection.witness.ValidFrom)
			until, _ := canonicalPrivacyTime(projection.witness.ValidUntil)
			return !now.Before(from) && now.Before(until)
		}
	}
	return false
}
