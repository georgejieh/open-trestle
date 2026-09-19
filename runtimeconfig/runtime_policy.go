package runtimeconfig

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
)

type ProviderConnection struct{ implementation, adapterID, endpoint, credentialEnvironment, credentialIdentity string }

func (c ProviderConnection) Implementation() string        { return c.implementation }
func (c ProviderConnection) AdapterID() string             { return c.adapterID }
func (c ProviderConnection) Endpoint() string              { return c.endpoint }
func (c ProviderConnection) CredentialEnvironment() string { return c.credentialEnvironment }
func (c ProviderConnection) CredentialIdentity() string    { return c.credentialIdentity }

type RuntimePolicy struct {
	identity, inventoryIdentity, reviewPolicyIdentity string
	requirements                                      provider.ModelRequirements
	constraints                                       policy.ProviderDataConstraints
	budget                                            provider.ModelCostBudget
	ranking                                           gateway.RouteRankingPolicy
	independence                                      gateway.RouteIndependencePolicy
	publication                                       review.PublicationPolicy
	connections                                       []ProviderConnection
}

func (p RuntimePolicy) Identity() string                              { return p.identity }
func (p RuntimePolicy) InventoryIdentity() string                     { return p.inventoryIdentity }
func (p RuntimePolicy) ReviewPolicyIdentity() string                  { return p.reviewPolicyIdentity }
func (p RuntimePolicy) Requirements() provider.ModelRequirements      { return p.requirements }
func (p RuntimePolicy) Constraints() policy.ProviderDataConstraints   { return p.constraints }
func (p RuntimePolicy) Budget() provider.ModelCostBudget              { return p.budget }
func (p RuntimePolicy) Ranking() gateway.RouteRankingPolicy           { return p.ranking }
func (p RuntimePolicy) Independence() gateway.RouteIndependencePolicy { return p.independence }
func (p RuntimePolicy) Publication() review.PublicationPolicy         { return p.publication }
func (p RuntimePolicy) Connections() []ProviderConnection {
	return append([]ProviderConnection(nil), p.connections...)
}
func (p RuntimePolicy) Validate() error {
	if !nonzeroDigest(p.inventoryIdentity) || !nonzeroDigest(p.reviewPolicyIdentity) || p.requirements.Validate() != nil || p.constraints.Validate() != nil || p.budget.Validate() != nil || p.ranking.Validate() != nil || p.independence.Validate() != nil || p.publication.Validate() != nil || len(p.connections) == 0 || len(p.connections) > 64 || p.identity != runtimePolicyIdentity(p) {
		return ErrInvalidRouteInventory
	}
	seen := map[string]struct{}{}
	for _, c := range p.connections {
		if c.implementation != "openai_responses" || provider.ValidateAdapterID(c.adapterID) != nil || !validProviderConnectionEndpoint(c.endpoint) || !validCredentialEnvironment(c.credentialEnvironment) || c.credentialIdentity != credentialEnvironmentIdentity(c.credentialEnvironment) {
			return ErrInvalidRouteInventory
		}
		if _, ok := seen[c.adapterID]; ok {
			return ErrInvalidRouteInventory
		}
		seen[c.adapterID] = struct{}{}
	}
	return nil
}

// ValidateAgainstInventory verifies that every adapter connection names one unambiguous full route namespace in the bound inventory.
func (p RuntimePolicy) ValidateAgainstInventory(inventory RouteInventory) error {
	if p.Validate() != nil || inventory.Validate() != nil || p.inventoryIdentity != inventory.Identity() {
		return ErrInvalidRouteInventory
	}
	type namespace struct {
		zone                     provider.ProviderZone
		providerID, connectionID string
		logging                  provider.ContentLoggingMode
	}
	namespaces := map[string]namespace{}
	for _, observed := range inventory.Candidates() {
		candidate := observed.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration()
		reference := candidate.RouteCapabilityDeclaration().RouteReference()
		value := namespace{reference.Zone(), reference.ProviderID(), reference.ConnectionID(), candidate.ContentLoggingMode()}
		if prior, found := namespaces[reference.AdapterID()]; found && prior != value {
			return ErrInvalidRouteInventory
		}
		namespaces[reference.AdapterID()] = value
	}
	if len(namespaces) != len(p.connections) {
		return ErrInvalidRouteInventory
	}
	for _, connection := range p.connections {
		namespace, found := namespaces[connection.adapterID]
		if !found {
			return ErrInvalidRouteInventory
		}
		locality, err := provider.ClassifyServiceEndpoint(connection.endpoint)
		zoneMatches := namespace.zone == provider.ProviderZoneLocal && locality == provider.ServiceEndpointLoopback || namespace.zone == provider.ProviderZonePrivateRemote && locality == provider.ServiceEndpointRemote
		if err != nil || !zoneMatches {
			return ErrInvalidRouteInventory
		}
	}
	return nil
}

func validProviderConnectionEndpoint(raw string) bool {
	_, err := provider.ParseServiceEndpoint(raw)
	return err == nil
}

type runtimePolicyWire struct {
	SchemaVersion                  int                      `json:"schema_version"`
	InventoryIdentity              string                   `json:"inventory_identity"`
	ReviewPolicyIdentity           string                   `json:"review_policy_identity"`
	MinContextTokens               uint64                   `json:"min_context_tokens"`
	MinOutputTokens                uint64                   `json:"min_output_tokens"`
	RequiredFeatures               []string                 `json:"required_features"`
	Classification                 string                   `json:"classification"`
	AllowedZones                   []string                 `json:"allowed_zones"`
	ContentLoggingAllowed          bool                     `json:"content_logging_allowed"`
	EstimatedInputTokens           uint64                   `json:"estimated_input_tokens"`
	MaxOutputTokens                uint64                   `json:"max_output_tokens"`
	MaxCostMicroUSD                uint64                   `json:"max_cost_micro_usd"`
	PinnedRouteRecordIdentity      string                   `json:"pinned_route_record_identity"`
	PreferredRouteRecordIdentities []string                 `json:"preferred_route_record_identities"`
	VerificationIndependence       string                   `json:"verification_independence"`
	PublicationMinimumSeverity     string                   `json:"publication_minimum_severity"`
	PublicationMaxInlineFindings   uint8                    `json:"publication_max_inline_findings"`
	PublicationMinimumIndependence string                   `json:"publication_minimum_independence"`
	PublicationBlockOnInconclusive bool                     `json:"publication_block_on_inconclusive"`
	Connections                    []providerConnectionWire `json:"connections"`
}
type providerConnectionWire struct {
	Implementation        string `json:"implementation"`
	AdapterID             string `json:"adapter_id"`
	Endpoint              string `json:"endpoint"`
	CredentialEnvironment string `json:"credential_environment"`
}

func DecodeRuntimePolicy(ctx context.Context, reader io.Reader, inventory RouteInventory) (RuntimePolicy, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil || inventory.Validate() != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	encoded, err := io.ReadAll(io.LimitReader(reader, 1<<20))
	if err != nil || len(encoded) == 0 || len(encoded) >= 1<<20 || validateUniqueJSONKeys(encoded) != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire runtimePolicyWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.SchemaVersion != 1 || wire.InventoryIdentity != inventory.Identity() || !nonzeroDigest(wire.ReviewPolicyIdentity) {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	features := make([]provider.ModelFeature, len(wire.RequiredFeatures))
	for i, v := range wire.RequiredFeatures {
		features[i], err = provider.ParseModelFeature(v)
		if err != nil {
			return RuntimePolicy{}, ErrInvalidRouteInventory
		}
	}
	requirements, err := provider.NewModelRequirements(wire.MinContextTokens, wire.MinOutputTokens, features)
	if err != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	classification := policy.DataClassification(wire.Classification)
	if classification.Validate() != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	zones := make([]provider.ProviderZone, len(wire.AllowedZones))
	for i, v := range wire.AllowedZones {
		zones[i], err = provider.ParseProviderZone(v)
		if err != nil {
			return RuntimePolicy{}, ErrInvalidRouteInventory
		}
	}
	allowed, err := policy.NewAllowedProviderZones(zones...)
	if err != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	constraints, err := policy.NewProviderDataConstraints(classification, allowed, wire.ContentLoggingAllowed)
	if err != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	budget, err := provider.NewModelCostBudget(wire.EstimatedInputTokens, wire.MaxOutputTokens, wire.MaxCostMicroUSD)
	if err != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	records := map[string]provider.RouteReference{}
	for _, candidate := range inventory.Candidates() {
		record := candidate.ResolvedRecord().RouteRegistryRecord()
		records[record.Identity()] = record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
	}
	preferred := make([]provider.RouteReference, len(wire.PreferredRouteRecordIdentities))
	for i, id := range wire.PreferredRouteRecordIdentities {
		var ok bool
		preferred[i], ok = records[id]
		if !ok {
			return RuntimePolicy{}, ErrInvalidRouteInventory
		}
	}
	var ranking gateway.RouteRankingPolicy
	if wire.PinnedRouteRecordIdentity != "" {
		pinned, ok := records[wire.PinnedRouteRecordIdentity]
		if !ok {
			return RuntimePolicy{}, ErrInvalidRouteInventory
		}
		ranking, err = gateway.NewPinnedRouteRankingPolicy(pinned, preferred)
	} else {
		ranking, err = gateway.NewRouteRankingPolicy(preferred)
	}
	if err != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	level, err := gateway.ParseRouteIndependenceLevel(wire.VerificationIndependence)
	if err != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	independence, err := gateway.NewRouteIndependencePolicy(level)
	if err != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	publicationLevel, err := gateway.ParseRouteIndependenceLevel(wire.PublicationMinimumIndependence)
	if err != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	publicationPolicy, err := review.NewPublicationPolicy(review.Severity(wire.PublicationMinimumSeverity), wire.PublicationMaxInlineFindings, publicationLevel, wire.PublicationBlockOnInconclusive)
	if err != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	connections := make([]ProviderConnection, len(wire.Connections))
	for i, v := range wire.Connections {
		connections[i] = ProviderConnection{v.Implementation, v.AdapterID, v.Endpoint, v.CredentialEnvironment, credentialEnvironmentIdentity(v.CredentialEnvironment)}
	}
	sort.Slice(connections, func(i, j int) bool { return connections[i].adapterID < connections[j].adapterID })
	value := RuntimePolicy{inventoryIdentity: inventory.Identity(), reviewPolicyIdentity: wire.ReviewPolicyIdentity, requirements: requirements, constraints: constraints, budget: budget, ranking: ranking, independence: independence, publication: publicationPolicy, connections: connections}
	value.identity = runtimePolicyIdentity(value)
	if value.Validate() != nil || value.ValidateAgainstInventory(inventory) != nil {
		return RuntimePolicy{}, ErrInvalidRouteInventory
	}
	return value, nil
}
func runtimePolicyIdentity(p RuntimePolicy) string {
	connections := make([]providerConnectionWire, len(p.connections))
	for i, c := range p.connections {
		connections[i] = providerConnectionWire{c.implementation, c.adapterID, c.endpoint, c.credentialEnvironment}
	}
	encoded, _ := json.Marshal(struct {
		Contract                                                                                 string `json:"contract"`
		Version                                                                                  int    `json:"version"`
		Inventory, Policy, Requirements, Constraints, Budget, Ranking, Independence, Publication string
		Connections                                                                              []providerConnectionWire `json:"connections"`
	}{"open-trestle/runtime-policy", 1, p.inventoryIdentity, p.reviewPolicyIdentity, requirementsIdentity(p.requirements), constraintsIdentity(p.constraints), budgetIdentity(p.budget), p.ranking.Identity(), p.independence.Identity(), p.publication.Identity(), connections})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func requirementsIdentity(v provider.ModelRequirements) string {
	return strings.Join([]string{fmtUint(uint64(v.MinContextTokens())), fmtUint(uint64(v.MinOutputTokens())), featureList(v.RequiredFeatures())}, "/")
}
func constraintsIdentity(v policy.ProviderDataConstraints) string {
	zones := ""
	for z := provider.ProviderZoneLocal; z <= provider.ProviderZoneSubscriptionOAuth; z++ {
		if v.AllowedProviderZones().Allows(z) {
			zones += z.String() + ","
		}
	}
	return string(v.Classification()) + "/" + zones + "/" + fmtBool(v.ContentLoggingAllowed())
}
func budgetIdentity(v provider.ModelCostBudget) string {
	return fmtUint(uint64(v.EstimatedInputTokens())) + "/" + fmtUint(uint64(v.MaxOutputTokens())) + "/" + fmtUint(v.MaxCostMicroUSD())
}
func featureList(values []provider.ModelFeature) string {
	tokens := make([]string, len(values))
	for i, v := range values {
		tokens[i] = v.String()
	}
	return strings.Join(tokens, ",")
}
func validCredentialEnvironment(value string) bool {
	if len(value) < 23 || len(value) > 128 || !strings.HasPrefix(value, "OPEN_TRESTLE_PROVIDER_") {
		return false
	}
	for _, r := range value {
		if r != '_' && (r < 'A' || r > 'Z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}
func credentialEnvironmentIdentity(value string) string {
	sum := sha256.Sum256([]byte("open-trestle/provider-credential-environment/" + value))
	return hex.EncodeToString(sum[:])
}
func nonzeroDigest(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	for _, v := range decoded {
		if v != 0 {
			return true
		}
	}
	return false
}
func fmtUint(v uint64) string { return strconv.FormatUint(v, 10) }
func fmtBool(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
