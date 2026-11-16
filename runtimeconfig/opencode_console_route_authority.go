package runtimeconfig

import (
	"encoding/json"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const OpenCodeConsoleChatProfile = "opencode_console_chat_v1"

// OpenCodeConsoleRouteAuthority is an operator declaration, not a provider attestation.
type OpenCodeConsoleRouteAuthority struct {
	record, evidence, account, tenant, repository string
	from, until                                   time.Time
}

func (a OpenCodeConsoleRouteAuthority) RouteRecordIdentity() string    { return a.record }
func (a OpenCodeConsoleRouteAuthority) EvidenceManifestDigest() string { return a.evidence }
func (a OpenCodeConsoleRouteAuthority) AccountPolicyIdentity() string  { return a.account }
func (a OpenCodeConsoleRouteAuthority) TenantID() string               { return a.tenant }
func (a OpenCodeConsoleRouteAuthority) RepositoryID() string           { return a.repository }
func (a OpenCodeConsoleRouteAuthority) ValidFrom() time.Time           { return a.from }
func (a OpenCodeConsoleRouteAuthority) ValidUntil() time.Time          { return a.until }
func (a OpenCodeConsoleRouteAuthority) Current(now time.Time) bool {
	return a.valid() && !now.Before(a.from) && now.Before(a.until)
}
func (a OpenCodeConsoleRouteAuthority) valid() bool {
	if !nonzeroDigest(a.record) || !nonzeroDigest(a.evidence) || !nonzeroDigest(a.account) || a.from.IsZero() || a.until.IsZero() || a.from.Year() < 1 || a.until.Year() > 9999 || !a.until.After(a.from) {
		return false
	}
	_, err := audit.NewReviewScope(a.tenant, a.repository, "profile-validation")
	return err == nil
}

type openCodeConsoleRouteAuthorityWire struct {
	Record     string `json:"route_record_identity"`
	Evidence   string `json:"evidence_manifest_digest"`
	Account    string `json:"account_policy_identity"`
	Tenant     string `json:"tenant_id"`
	Repository string `json:"repository_id"`
	From       string `json:"valid_from"`
	Until      string `json:"valid_until"`
}

func (a OpenCodeConsoleRouteAuthority) wire() *openCodeConsoleRouteAuthorityWire {
	if !a.valid() {
		return nil
	}
	return &openCodeConsoleRouteAuthorityWire{a.record, a.evidence, a.account, a.tenant, a.repository, a.from.Format(time.RFC3339Nano), a.until.Format(time.RFC3339Nano)}
}
func decodeOpenCodeConsoleAuthority(w *openCodeConsoleRouteAuthorityWire) (OpenCodeConsoleRouteAuthority, bool) {
	if w == nil {
		return OpenCodeConsoleRouteAuthority{}, false
	}
	from, fromOK := canonicalPrivacyTime(w.From)
	until, untilOK := canonicalPrivacyTime(w.Until)
	a := OpenCodeConsoleRouteAuthority{w.Record, w.Evidence, w.Account, w.Tenant, w.Repository, from, until}
	return a, fromOK && untilOK && a.valid()
}
func (c ProviderConnection) OpenCodeConsoleAuthority() OpenCodeConsoleRouteAuthority {
	return c.openCodeConsoleAuthority
}

func validateV5PolicyProfileFields(encoded []byte) bool {
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
		_, routerPresent := c["brokered_route_authority"]
		_, goPresent := c["opencode_go_authority"]
		consoleRaw, consolePresent := c["opencode_console_authority"]
		if !profilePresent && !routerPresent && !goPresent && !consolePresent {
			continue
		}
		var profile string
		if !profilePresent || json.Unmarshal(profileRaw, &profile) != nil {
			return false
		}
		switch profile {
		case OpenCodeConsoleChatProfile:
			if !consolePresent || goPresent || routerPresent || !closedProfileAuthority(consoleRaw, false) {
				return false
			}
		case OpenCodeGoChatProfile:
			if consolePresent || routerPresent || !goPresent || !closedProfileAuthority(c["opencode_go_authority"], false) {
				return false
			}
		case OpenRouterZDRChatProfile:
			if consolePresent || goPresent || !routerPresent || !closedProfileAuthority(c["brokered_route_authority"], true) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

func validOpenCodeConsoleInventoryBinding(c ProviderConnection, inventory RouteInventory) bool {
	count := 0
	for index, observed := range inventory.candidates {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		declaration := record.RouteCandidateDeclaration()
		route := declaration.RouteCapabilityDeclaration().RouteReference()
		if route.AdapterID() != c.adapterID {
			continue
		}
		count++
		if index >= len(inventory.openCodeConsolePrivacy) || !inventory.openCodeConsolePrivacy[index].matchesRecord(record) || !inventory.openCodeConsolePrivacy[index].matchesConnection(c) {
			return false
		}
		if record.Identity() != c.openCodeConsoleAuthority.record || record.EvidenceManifestDigest() != c.openCodeConsoleAuthority.evidence || record.Status() != provider.RouteRegistryApproved || route.Zone() != provider.ProviderZoneBrokeredRemote || route.ProviderID() != "opencode-console" || declaration.ContentLoggingMode() != provider.ContentLoggingDisabled {
			return false
		}
	}
	return count == 1
}
