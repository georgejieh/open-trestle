package setup

import (
	"time"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func setupConnectionEndpointMatchesZone(connection runtimeconfig.ProviderConnection, zone provider.ProviderZone) bool {
	if zone != provider.ProviderZoneBrokeredRemote {
		return connection.RequestProfile() == "" && endpointMatchesZone(connection.Endpoint(), zone)
	}
	if connection.Implementation() != "openai_chat_completions" || connection.CredentialMode() != "bearer" {
		return false
	}
	switch connection.RequestProfile() {
	case runtimeconfig.OpenRouterZDRChatProfile, runtimeconfig.OpenRouterZDRChatV2Profile:
		return connection.Endpoint() == "https://openrouter.ai/api/v1"
	case runtimeconfig.OpenCodeGoChatProfile:
		return connection.Endpoint() == "https://opencode.ai/inference/go/openai/v1"
	case runtimeconfig.OpenCodeConsoleChatProfile:
		return connection.Endpoint() == "https://opencode.ai/inference/openai/v1"
	default:
		return false
	}
}

func setupBrokeredRoutePairMatches(plan Plan, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy, now time.Time) bool {
	if plan.Profile() != ProfileControlledHybrid && plan.Profile() != ProfileKubernetesHA || plan.Posture().Inference() != InferenceApprovedRemote || plan.Posture().Egress() != EgressAllowlisted || policy.Independence().Level() != gateway.RouteIndependenceDistinctProvider || policy.Publication().MinimumIndependence() != gateway.RouteIndependenceDistinctProvider || len(inventory.Candidates()) != 2 || len(policy.Connections()) != 2 {
		return false
	}
	pinned, hasPin := policy.Ranking().PinnedRoute()
	if !hasPin || pinned.Zone() != provider.ProviderZoneBrokeredRemote || (pinned.ProviderID() != "openrouter" && pinned.ProviderID() != "opencode-go" && pinned.ProviderID() != "opencode-console") {
		return false
	}
	connections := map[string]runtimeconfig.ProviderConnection{}
	for _, connection := range policy.Connections() {
		connections[connection.AdapterID()] = connection
	}
	generation, verification := 0, 0
	for _, observed := range inventory.Candidates() {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		reference := record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
		connection, found := connections[reference.AdapterID()]
		if !found || !routeReadyForPolicy(observed, policy) || connection.CredentialMode() != "bearer" || !setupConnectionEndpointMatchesZone(connection, reference.Zone()) {
			return false
		}
		if reference == pinned {
			switch pinned.ProviderID() {
			case "openrouter":
				authority := connection.BrokeredAuthority()
				if !connection.RequiresZeroDataRetention() || !authority.Current(now) || authority.TenantID() != plan.TenantID() || authority.RepositoryID() != plan.RepositoryID() || authority.RouteRecordIdentity() != record.Identity() || authority.EvidenceManifestDigest() != record.EvidenceManifestDigest() {
					return false
				}
			case "opencode-go":
				authority := connection.OpenCodeGoAuthority()
				if connection.RequestProfile() != runtimeconfig.OpenCodeGoChatProfile || !authority.Current(now) || !inventory.OpenCodeGoPrivacyCurrent(record.Identity(), now) || authority.TenantID() != plan.TenantID() || authority.RepositoryID() != plan.RepositoryID() || authority.RouteRecordIdentity() != record.Identity() || authority.EvidenceManifestDigest() != record.EvidenceManifestDigest() {
					return false
				}
			case "opencode-console":
				authority := connection.OpenCodeConsoleAuthority()
				if connection.RequestProfile() != runtimeconfig.OpenCodeConsoleChatProfile || !authority.Current(now) || !inventory.OpenCodeConsolePrivacyCurrent(record.Identity(), now) || authority.TenantID() != plan.TenantID() || authority.RepositoryID() != plan.RepositoryID() || authority.RouteRecordIdentity() != record.Identity() || authority.EvidenceManifestDigest() != record.EvidenceManifestDigest() {
					return false
				}
			default:
				return false
			}
			generation++
		} else if record.Identity() == policy.VerificationRouteRecordIdentity() && reference.Zone() == provider.ProviderZonePrivateRemote && reference.ProviderID() != pinned.ProviderID() && connection.RequestProfile() == "" {
			verification++
		} else {
			return false
		}
	}
	return generation == 1 && verification == 1 && hasAuthorizedRemoteProvider(inventory, policy)
}
