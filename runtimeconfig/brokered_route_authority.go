package runtimeconfig

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const OpenRouterZDRChatProfile = "openrouter_zdr_chat_v1"

// BrokeredRouteAuthority is an operator declaration, not a provider attestation.
// The openrouter_zdr_chat_v1 form binds one reviewed slug, an account review
// and a validity window. The observed openrouter_zdr_chat_v2 form binds a
// list of provider slugs (possibly empty) and has no account or window.
type BrokeredRouteAuthority struct {
	record, evidence, account, tenant, repository, slug string
	from, until                                         time.Time
	slugs                                               string // observed form: slugs joined by newlines
	observed                                            bool
	// structuredVerification is an observed form for the policy's
	// verification route whose every pinned endpoint supports structured
	// outputs. It is read from the bound witness, not from the policy.
	structuredVerification bool
}

// StructuredVerification reports that verification requests on this route
// carry the request's output schema as response_format.
func (a BrokeredRouteAuthority) StructuredVerification() bool { return a.structuredVerification }

func (a BrokeredRouteAuthority) RouteRecordIdentity() string    { return a.record }
func (a BrokeredRouteAuthority) EvidenceManifestDigest() string { return a.evidence }
func (a BrokeredRouteAuthority) AccountPolicyIdentity() string  { return a.account }
func (a BrokeredRouteAuthority) TenantID() string               { return a.tenant }
func (a BrokeredRouteAuthority) RepositoryID() string           { return a.repository }
func (a BrokeredRouteAuthority) ProviderSlug() string           { return a.slug }
func (a BrokeredRouteAuthority) ValidFrom() time.Time           { return a.from }
func (a BrokeredRouteAuthority) ValidUntil() time.Time          { return a.until }

// ProviderSlugs returns the observed form's slugs, or nil for an empty list
// or the reviewed form.
func (a BrokeredRouteAuthority) ProviderSlugs() []string { return splitOpenRouterSlugs(a.slugs) }

// Observed reports the openrouter_zdr_chat_v2 form, which has no validity window.
func (a BrokeredRouteAuthority) Observed() bool { return a.observed }

func (a BrokeredRouteAuthority) Current(now time.Time) bool {
	if a.observed {
		return a.valid()
	}
	return a.valid() && !now.Before(a.from) && now.Before(a.until)
}

func (a BrokeredRouteAuthority) valid() bool {
	if a.observed {
		if !nonzeroDigest(a.record) || !nonzeroDigest(a.evidence) || a.account != "" || a.slug != "" || !a.from.IsZero() || !a.until.IsZero() || !validOpenRouterSlugList(splitOpenRouterSlugs(a.slugs)) {
			return false
		}
		_, err := audit.NewReviewScope(a.tenant, a.repository, "profile-validation")
		return err == nil
	}
	if a.slugs != "" {
		return false
	}
	if !nonzeroDigest(a.record) || !nonzeroDigest(a.evidence) || !nonzeroDigest(a.account) || !validBrokeredSlug(a.slug) || a.from.IsZero() || a.until.IsZero() || a.from.Year() < 1 || a.until.Year() > 9999 || !a.until.After(a.from) {
		return false
	}
	_, err := audit.NewReviewScope(a.tenant, a.repository, "profile-validation")
	return err == nil
}

func validBrokeredSlug(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
				return false
			}
		}
	}
	return true
}

// Every reviewed-form value is nonempty, so omitempty keeps that form's
// encoding, and every identity preimage built from it, byte for byte.
type brokeredRouteAuthorityWire struct {
	Record     string    `json:"route_record_identity"`
	Evidence   string    `json:"evidence_manifest_digest"`
	Account    string    `json:"account_policy_identity,omitempty"`
	Tenant     string    `json:"tenant_id"`
	Repository string    `json:"repository_id"`
	Slug       string    `json:"provider_slug,omitempty"`
	From       string    `json:"valid_from,omitempty"`
	Until      string    `json:"valid_until,omitempty"`
	Slugs      *[]string `json:"provider_slugs,omitempty"`
}

func (a BrokeredRouteAuthority) wire() *brokeredRouteAuthorityWire {
	if !a.valid() {
		return nil
	}
	if a.observed {
		slugs := append([]string{}, a.ProviderSlugs()...)
		return &brokeredRouteAuthorityWire{Record: a.record, Evidence: a.evidence, Tenant: a.tenant, Repository: a.repository, Slugs: &slugs}
	}
	return &brokeredRouteAuthorityWire{Record: a.record, Evidence: a.evidence, Account: a.account, Tenant: a.tenant, Repository: a.repository, Slug: a.slug, From: a.from.Format(time.RFC3339Nano), Until: a.until.Format(time.RFC3339Nano)}
}

// decodeObservedBrokeredAuthority reads the five-member openrouter_zdr_chat_v2
// authority. validateV8PolicyProfileFields has already required its members.
func decodeObservedBrokeredAuthority(w *brokeredRouteAuthorityWire) (BrokeredRouteAuthority, bool) {
	if w == nil || w.Slugs == nil || w.Account != "" || w.Slug != "" || w.From != "" || w.Until != "" {
		return BrokeredRouteAuthority{}, false
	}
	a := BrokeredRouteAuthority{record: w.Record, evidence: w.Evidence, tenant: w.Tenant, repository: w.Repository, slugs: joinOpenRouterSlugs(*w.Slugs), observed: true}
	return a, validOpenRouterSlugList(*w.Slugs) && a.valid()
}

func decodeBrokeredAuthority(w *brokeredRouteAuthorityWire) (BrokeredRouteAuthority, bool) {
	if w == nil || w.Slugs != nil {
		return BrokeredRouteAuthority{}, false
	}
	from, err := time.Parse(time.RFC3339Nano, w.From)
	if err != nil || from.Location() != time.UTC || from.Format(time.RFC3339Nano) != w.From {
		return BrokeredRouteAuthority{}, false
	}
	until, err := time.Parse(time.RFC3339Nano, w.Until)
	if err != nil || until.Location() != time.UTC || until.Format(time.RFC3339Nano) != w.Until {
		return BrokeredRouteAuthority{}, false
	}
	a := BrokeredRouteAuthority{record: w.Record, evidence: w.Evidence, account: w.Account, tenant: w.Tenant, repository: w.Repository, slug: w.Slug, from: from, until: until}
	return a, a.valid()
}

func validatePolicyProfileFields(encoded []byte, version int) bool {
	if version == openRouterObservedPolicyVersion {
		return validateV8PolicyProfileFields(encoded)
	}
	if version == ollamaSigninPolicyVersion {
		return validateV7PolicyProfileFields(encoded)
	}
	if version == 5 {
		return validateV5PolicyProfileFields(encoded)
	}
	var historical struct {
		Connections []map[string]json.RawMessage `json:"connections"`
	}
	if json.Unmarshal(encoded, &historical) != nil {
		return false
	}
	for _, c := range historical.Connections {
		if _, present := c["opencode_console_authority"]; present {
			return false
		}
	}
	if version == 4 {
		return validateV4PolicyProfileFields(encoded)
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		return false
	}
	var connections []map[string]json.RawMessage
	if json.Unmarshal(fields["connections"], &connections) != nil {
		return false
	}
	allowed := map[string]bool{"route_record_identity": true, "evidence_manifest_digest": true, "account_policy_identity": true, "tenant_id": true, "repository_id": true, "provider_slug": true, "valid_from": true, "valid_until": true}
	for _, c := range connections {
		if _, present := c["opencode_go_authority"]; present {
			return false
		}
		for key := range c {
			if strings.EqualFold(key, "request_profile") && key != "request_profile" || strings.EqualFold(key, "brokered_route_authority") && key != "brokered_route_authority" {
				return false
			}
		}
		profileRaw, profilePresent := c["request_profile"]
		authorityRaw, authorityPresent := c["brokered_route_authority"]
		if !profilePresent && !authorityPresent {
			continue
		}
		var profile string
		var authority map[string]json.RawMessage
		if version != 3 || !profilePresent || !authorityPresent || json.Unmarshal(profileRaw, &profile) != nil || profile != OpenRouterZDRChatProfile || json.Unmarshal(authorityRaw, &authority) != nil || len(authority) != len(allowed) {
			return false
		}
		for key, value := range authority {
			if !allowed[key] || string(value) == "null" {
				return false
			}
		}
	}
	return true
}

func validConnectionProfile(c ProviderConnection, version int) bool {
	if version == ollamaSigninPolicyVersion || c.requestProfile == OllamaSigninChatProfile {
		return validOllamaSigninConnection(c, version)
	}
	if c.requestProfile == OpenRouterZDRChatV2Profile || c.brokeredAuthority.observed {
		return validObservedOpenRouterConnection(c, version)
	}
	if c.requestProfile == "" {
		return c.brokeredAuthority == (BrokeredRouteAuthority{}) && c.openCodeGoAuthority == (OpenCodeGoRouteAuthority{}) && c.openCodeConsoleAuthority == (OpenCodeConsoleRouteAuthority{})
	}
	if c.requestProfile == OpenCodeConsoleChatProfile {
		return version == 5 && c.brokeredAuthority == (BrokeredRouteAuthority{}) && c.openCodeGoAuthority == (OpenCodeGoRouteAuthority{}) && c.openCodeConsoleAuthority.valid() && c.implementation == "openai_chat_completions" && c.credentialMode == "bearer" && c.endpoint == "https://opencode.ai/inference/openai/v1"
	}
	if c.openCodeConsoleAuthority != (OpenCodeConsoleRouteAuthority{}) {
		return false
	}
	if c.requestProfile == OpenCodeGoChatProfile {
		return (version == 4 || version == 5) && c.brokeredAuthority == (BrokeredRouteAuthority{}) && c.openCodeGoAuthority.valid() && c.implementation == "openai_chat_completions" && c.credentialMode == "bearer" && c.endpoint == "https://opencode.ai/inference/go/openai/v1"
	}
	return (version == 3 || version == 4 || version == 5) && c.openCodeGoAuthority == (OpenCodeGoRouteAuthority{}) && c.requestProfile == OpenRouterZDRChatProfile && c.brokeredAuthority.valid() && c.implementation == "openai_chat_completions" && c.credentialMode == "bearer" && c.endpoint == "https://openrouter.ai/api/v1"
}

func (c ProviderConnection) RequestProfile() string { return c.requestProfile }

// RequiresZeroDataRetention reports whether every request of this connection
// sets OpenRouter's provider.zdr. It is a request-side fact, not a statement
// about what any provider retains.
func (c ProviderConnection) RequiresZeroDataRetention() bool {
	return c.requestProfile == OpenRouterZDRChatProfile || c.requestProfile == OpenRouterZDRChatV2Profile
}

func (c ProviderConnection) BrokeredAuthority() BrokeredRouteAuthority { return c.brokeredAuthority }

func validBrokeredInventoryBinding(c ProviderConnection, inventory RouteInventory) bool {
	count := 0
	for index, observed := range inventory.candidates {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		declaration := record.RouteCandidateDeclaration()
		route := declaration.RouteCapabilityDeclaration().RouteReference()
		if route.AdapterID() != c.adapterID {
			continue
		}
		count++
		if index >= len(inventory.openRouterPrivacy) || !inventory.openRouterPrivacy[index].matchesRecord(record) || !inventory.openRouterPrivacy[index].matchesConnection(c) {
			return false
		}
		if record.Identity() != c.brokeredAuthority.record || record.EvidenceManifestDigest() != c.brokeredAuthority.evidence || record.Status() != provider.RouteRegistryApproved || route.Zone() != provider.ProviderZoneBrokeredRemote || route.ProviderID() != "openrouter" || declaration.ContentLoggingMode() != provider.ContentLoggingDisabled {
			return false
		}
	}
	return count == 1
}
