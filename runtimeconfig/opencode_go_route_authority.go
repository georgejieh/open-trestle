package runtimeconfig

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const OpenCodeGoChatProfile = "opencode_go_chat_v1"

// OpenCodeGoRouteAuthority is an operator declaration, not a provider attestation.
type OpenCodeGoRouteAuthority struct {
	record, evidence, account, tenant, repository string
	from, until                                   time.Time
}

func (a OpenCodeGoRouteAuthority) RouteRecordIdentity() string    { return a.record }
func (a OpenCodeGoRouteAuthority) EvidenceManifestDigest() string { return a.evidence }
func (a OpenCodeGoRouteAuthority) AccountPolicyIdentity() string  { return a.account }
func (a OpenCodeGoRouteAuthority) TenantID() string               { return a.tenant }
func (a OpenCodeGoRouteAuthority) RepositoryID() string           { return a.repository }
func (a OpenCodeGoRouteAuthority) ValidFrom() time.Time           { return a.from }
func (a OpenCodeGoRouteAuthority) ValidUntil() time.Time          { return a.until }
func (a OpenCodeGoRouteAuthority) Current(now time.Time) bool {
	return a.valid() && !now.Before(a.from) && now.Before(a.until)
}
func (a OpenCodeGoRouteAuthority) valid() bool {
	if !nonzeroDigest(a.record) || !nonzeroDigest(a.evidence) || !nonzeroDigest(a.account) || a.from.IsZero() || a.until.IsZero() || a.from.Year() < 1 || a.until.Year() > 9999 || !a.until.After(a.from) {
		return false
	}
	_, err := audit.NewReviewScope(a.tenant, a.repository, "profile-validation")
	return err == nil
}

type openCodeGoRouteAuthorityWire struct {
	Record     string `json:"route_record_identity"`
	Evidence   string `json:"evidence_manifest_digest"`
	Account    string `json:"account_policy_identity"`
	Tenant     string `json:"tenant_id"`
	Repository string `json:"repository_id"`
	From       string `json:"valid_from"`
	Until      string `json:"valid_until"`
}

func (a OpenCodeGoRouteAuthority) wire() *openCodeGoRouteAuthorityWire {
	if !a.valid() {
		return nil
	}
	return &openCodeGoRouteAuthorityWire{a.record, a.evidence, a.account, a.tenant, a.repository, a.from.Format(time.RFC3339Nano), a.until.Format(time.RFC3339Nano)}
}
func decodeOpenCodeGoAuthority(w *openCodeGoRouteAuthorityWire) (OpenCodeGoRouteAuthority, bool) {
	if w == nil {
		return OpenCodeGoRouteAuthority{}, false
	}
	from, fromOK := canonicalPrivacyTime(w.From)
	until, untilOK := canonicalPrivacyTime(w.Until)
	a := OpenCodeGoRouteAuthority{w.Record, w.Evidence, w.Account, w.Tenant, w.Repository, from, until}
	return a, fromOK && untilOK && a.valid()
}
func (c ProviderConnection) OpenCodeGoAuthority() OpenCodeGoRouteAuthority {
	return c.openCodeGoAuthority
}

func validateV4PolicyProfileFields(encoded []byte) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		return false
	}
	var connections []map[string]json.RawMessage
	if json.Unmarshal(fields["connections"], &connections) != nil {
		return false
	}
	for _, c := range connections {
		profileRaw, profilePresent := c["request_profile"]
		routerRaw, routerPresent := c["brokered_route_authority"]
		goRaw, goPresent := c["opencode_go_authority"]
		if !profilePresent && !routerPresent && !goPresent {
			continue
		}
		var profile string
		if !profilePresent || json.Unmarshal(profileRaw, &profile) != nil {
			return false
		}
		switch profile {
		case OpenRouterZDRChatProfile:
			if !routerPresent || goPresent || !closedProfileAuthority(routerRaw, true) {
				return false
			}
		case OpenCodeGoChatProfile:
			if !goPresent || routerPresent || !closedProfileAuthority(goRaw, false) {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func closedProfileAuthority(encoded json.RawMessage, router bool) bool {
	var fields map[string]json.RawMessage
	if json.Unmarshal(encoded, &fields) != nil {
		return false
	}
	expected := 7
	if router {
		expected = 8
	}
	if len(fields) != expected {
		return false
	}
	for key, value := range fields {
		switch key {
		case "route_record_identity", "evidence_manifest_digest", "account_policy_identity", "tenant_id", "repository_id", "valid_from", "valid_until":
		case "provider_slug":
			if !router {
				return false
			}
		default:
			return false
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}
func validOpenCodeGoInventoryBinding(c ProviderConnection, inventory RouteInventory) bool {
	count := 0
	for index, observed := range inventory.candidates {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		declaration := record.RouteCandidateDeclaration()
		route := declaration.RouteCapabilityDeclaration().RouteReference()
		if route.AdapterID() != c.adapterID {
			continue
		}
		count++
		if index >= len(inventory.openCodeGoPrivacy) || !inventory.openCodeGoPrivacy[index].matchesRecord(record) || !inventory.openCodeGoPrivacy[index].matchesConnection(c) {
			return false
		}
		if record.Identity() != c.openCodeGoAuthority.record || record.EvidenceManifestDigest() != c.openCodeGoAuthority.evidence || record.Status() != provider.RouteRegistryApproved || route.Zone() != provider.ProviderZoneBrokeredRemote || route.ProviderID() != "opencode-go" || declaration.ContentLoggingMode() != provider.ContentLoggingDisabled {
			return false
		}
	}
	return count == 1
}
