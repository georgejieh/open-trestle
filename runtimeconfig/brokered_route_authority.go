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
type BrokeredRouteAuthority struct {
	record, evidence, account, tenant, repository, slug string
	from, until                                         time.Time
}

func (a BrokeredRouteAuthority) RouteRecordIdentity() string    { return a.record }
func (a BrokeredRouteAuthority) EvidenceManifestDigest() string { return a.evidence }
func (a BrokeredRouteAuthority) AccountPolicyIdentity() string  { return a.account }
func (a BrokeredRouteAuthority) TenantID() string               { return a.tenant }
func (a BrokeredRouteAuthority) RepositoryID() string           { return a.repository }
func (a BrokeredRouteAuthority) ProviderSlug() string           { return a.slug }
func (a BrokeredRouteAuthority) ValidFrom() time.Time           { return a.from }
func (a BrokeredRouteAuthority) ValidUntil() time.Time          { return a.until }
func (a BrokeredRouteAuthority) Current(now time.Time) bool {
	return a.valid() && !now.Before(a.from) && now.Before(a.until)
}

func (a BrokeredRouteAuthority) valid() bool {
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

type brokeredRouteAuthorityWire struct {
	Record     string `json:"route_record_identity"`
	Evidence   string `json:"evidence_manifest_digest"`
	Account    string `json:"account_policy_identity"`
	Tenant     string `json:"tenant_id"`
	Repository string `json:"repository_id"`
	Slug       string `json:"provider_slug"`
	From       string `json:"valid_from"`
	Until      string `json:"valid_until"`
}

func (a BrokeredRouteAuthority) wire() *brokeredRouteAuthorityWire {
	if !a.valid() {
		return nil
	}
	return &brokeredRouteAuthorityWire{a.record, a.evidence, a.account, a.tenant, a.repository, a.slug, a.from.Format(time.RFC3339Nano), a.until.Format(time.RFC3339Nano)}
}

func decodeBrokeredAuthority(w *brokeredRouteAuthorityWire) (BrokeredRouteAuthority, bool) {
	if w == nil {
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
	a := BrokeredRouteAuthority{w.Record, w.Evidence, w.Account, w.Tenant, w.Repository, w.Slug, from, until}
	return a, a.valid()
}

func validatePolicyProfileFields(encoded []byte, version int) bool {
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
	if c.requestProfile == "" {
		return c.brokeredAuthority == (BrokeredRouteAuthority{}) && c.openCodeGoAuthority == (OpenCodeGoRouteAuthority{})
	}
	if c.requestProfile == OpenCodeGoChatProfile {
		return version == 4 && c.brokeredAuthority == (BrokeredRouteAuthority{}) && c.openCodeGoAuthority.valid() && c.implementation == "openai_chat_completions" && c.credentialMode == "bearer" && c.endpoint == "https://opencode.ai/inference/go/openai/v1"
	}
	return (version == 3 || version == 4) && c.openCodeGoAuthority == (OpenCodeGoRouteAuthority{}) && c.requestProfile == OpenRouterZDRChatProfile && c.brokeredAuthority.valid() && c.implementation == "openai_chat_completions" && c.credentialMode == "bearer" && c.endpoint == "https://openrouter.ai/api/v1"
}

func (c ProviderConnection) RequestProfile() string                    { return c.requestProfile }
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
