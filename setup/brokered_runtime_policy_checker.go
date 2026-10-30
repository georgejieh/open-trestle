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
	return connection.RequestProfile() == runtimeconfig.OpenRouterZDRChatProfile && connection.Implementation() == "openai_chat_completions" && connection.CredentialMode() == "bearer" && connection.Endpoint() == "https://openrouter.ai/api/v1"
}

func setupBrokeredRoutePairMatches(plan Plan, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy, now time.Time) bool {
	if plan.Profile() != ProfileControlledHybrid && plan.Profile() != ProfileKubernetesHA || plan.Posture().Inference() != InferenceApprovedRemote || plan.Posture().Egress() != EgressAllowlisted || policy.Independence().Level() != gateway.RouteIndependenceDistinctProvider || policy.Publication().MinimumIndependence() != gateway.RouteIndependenceDistinctProvider || len(inventory.Candidates()) != 2 || len(policy.Connections()) != 2 {
		return false
	}
	pinned, hasPin := policy.Ranking().PinnedRoute()
	if !hasPin || pinned.Zone() != provider.ProviderZoneBrokeredRemote || pinned.ProviderID() != "openrouter" {
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
			authority := connection.BrokeredAuthority()
			if connection.RequestProfile() != runtimeconfig.OpenRouterZDRChatProfile || !authority.Current(now) || authority.TenantID() != plan.TenantID() || authority.RepositoryID() != plan.RepositoryID() || authority.RouteRecordIdentity() != record.Identity() || authority.EvidenceManifestDigest() != record.EvidenceManifestDigest() {
				return false
			}
			generation++
		} else if record.Identity() == policy.VerificationRouteRecordIdentity() && reference.Zone() == provider.ProviderZonePrivateRemote && reference.ProviderID() != "openrouter" && connection.RequestProfile() == "" {
			verification++
		} else {
			return false
		}
	}
	return generation == 1 && verification == 1 && hasAuthorizedRemoteProvider(inventory, policy)
}
