package setup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

const maxSetupRuntimeConfigurationBytes = 8 << 20

type runtimePolicyLoadState uint8

const (
	runtimePolicyLoadValid runtimePolicyLoadState = iota + 1
	runtimePolicyLoadBlocked
	runtimePolicyLoadUnavailable
)

// RuntimePolicyApproval binds one explicit local approval to an exact setup root and policy identities.
type RuntimePolicyApproval struct{ identity, rootIdentity, tenantID, repositoryID, inventoryIdentity, runtimePolicyIdentity, reviewPolicyIdentity, approvedBy string }

// NewRuntimePolicyApproval records explicit approval of exact non-secret configuration identities by the named setup recovery owner.
func NewRuntimePolicyApproval(plan Plan, inventoryIdentity, runtimePolicyIdentity, reviewPolicyIdentity, approvedBy string) (RuntimePolicyApproval, error) {
	if plan.Validate() != nil || !nonzeroSetupDigest(inventoryIdentity) || !nonzeroSetupDigest(runtimePolicyIdentity) || !nonzeroSetupDigest(reviewPolicyIdentity) || !validSetupLabel(approvedBy) || approvedBy != plan.RecoveryOwner() {
		return RuntimePolicyApproval{}, ErrInvalidCheckerRuntime
	}
	value := RuntimePolicyApproval{rootIdentity: plan.RootIdentity(), tenantID: plan.TenantID(), repositoryID: plan.RepositoryID(), inventoryIdentity: inventoryIdentity, runtimePolicyIdentity: runtimePolicyIdentity, reviewPolicyIdentity: reviewPolicyIdentity, approvedBy: approvedBy}
	value.identity = runtimePolicyApprovalIdentity(value)
	return value, nil
}
func (a RuntimePolicyApproval) Identity() string { return a.identity }
func (a RuntimePolicyApproval) validate(plan Plan, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy) bool {
	return plan.Validate() == nil && a.identity == runtimePolicyApprovalIdentity(a) && a.rootIdentity == plan.RootIdentity() && a.tenantID == plan.TenantID() && a.repositoryID == plan.RepositoryID() && a.approvedBy == plan.RecoveryOwner() && a.inventoryIdentity == inventory.Identity() && a.runtimePolicyIdentity == policy.Identity() && a.reviewPolicyIdentity == policy.ReviewPolicyIdentity()
}
func runtimePolicyApprovalIdentity(a RuntimePolicyApproval) string {
	encoded, _ := json.Marshal(struct {
		Contract      string `json:"contract"`
		Version       int    `json:"version"`
		Root          string `json:"root_identity"`
		Tenant        string `json:"tenant_id"`
		Repository    string `json:"repository_id"`
		Inventory     string `json:"inventory_identity"`
		RuntimePolicy string `json:"runtime_policy_identity"`
		ReviewPolicy  string `json:"review_policy_identity"`
		ApprovedBy    string `json:"approved_by"`
	}{"open-trestle/setup-runtime-policy-approval", 1, a.rootIdentity, a.tenantID, a.repositoryID, a.inventoryIdentity, a.runtimePolicyIdentity, a.reviewPolicyIdentity, a.approvedBy})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}
func (a RuntimePolicyApproval) String() string   { return "setup runtime policy approval" }
func (a RuntimePolicyApproval) GoString() string { return "setup.RuntimePolicyApproval{<redacted>}" }
func (a RuntimePolicyApproval) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, a.String(), a.GoString())
}

// RuntimePolicyChecker validates an exact route inventory and runtime policy against a setup posture without resolving credentials or contacting providers.
type RuntimePolicyChecker struct {
	inventory                                        runtimeconfig.RouteInventory
	policy                                           runtimeconfig.RuntimePolicy
	approval                                         RuntimePolicyApproval
	inventoryPath, policyPath, configurationIdentity string
	fromFiles                                        bool
}

// NewRuntimePolicyChecker binds already decoded immutable runtime configuration and its explicit approval.
func NewRuntimePolicyChecker(inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy, approval RuntimePolicyApproval) (*RuntimePolicyChecker, error) {
	if inventory.Validate() != nil || policy.Validate() != nil || policy.ValidateAgainstInventory(inventory) != nil || policy.InventoryIdentity() != inventory.Identity() || !validRuntimePolicyApproval(approval) || approval.inventoryIdentity != inventory.Identity() || approval.runtimePolicyIdentity != policy.Identity() || approval.reviewPolicyIdentity != policy.ReviewPolicyIdentity() {
		return nil, ErrInvalidCheckerRuntime
	}
	identity := checkerConfigIdentity(CheckPolicyValidated, inventory.Identity()+"\x00"+policy.Identity()+"\x00"+approval.Identity())
	return &RuntimePolicyChecker{inventory: inventory, policy: policy, approval: approval, configurationIdentity: identity}, nil
}

// NewRuntimePolicyFileChecker binds two exact protected configuration paths and an explicit expected authority. Files are read only while the check runs.
func NewRuntimePolicyFileChecker(inventoryPath, policyPath string, approval RuntimePolicyApproval) (*RuntimePolicyChecker, error) {
	inventoryAbsolute, err := filepath.Abs(inventoryPath)
	if err != nil || inventoryPath == "" || !validRuntimePolicyApproval(approval) {
		return nil, ErrInvalidCheckerRuntime
	}
	policyAbsolute, err := filepath.Abs(policyPath)
	if err != nil || policyPath == "" || policyAbsolute == inventoryAbsolute {
		return nil, ErrInvalidCheckerRuntime
	}
	identity := checkerConfigIdentity(CheckPolicyValidated, inventoryAbsolute+"\x00"+policyAbsolute+"\x00"+approval.Identity())
	return &RuntimePolicyChecker{approval: approval, inventoryPath: inventoryAbsolute, policyPath: policyAbsolute, configurationIdentity: identity, fromFiles: true}, nil
}
func (c *RuntimePolicyChecker) immutableConfigurationValid() bool {
	if c == nil || !validRuntimePolicyApproval(c.approval) {
		return false
	}
	expected := ""
	if c.fromFiles {
		if c.inventoryPath == "" || c.policyPath == "" || c.inventoryPath == c.policyPath {
			return false
		}
		expected = checkerConfigIdentity(CheckPolicyValidated, c.inventoryPath+"\x00"+c.policyPath+"\x00"+c.approval.Identity())
	} else {
		if c.inventory.Validate() != nil || c.policy.Validate() != nil || c.policy.ValidateAgainstInventory(c.inventory) != nil {
			return false
		}
		expected = checkerConfigIdentity(CheckPolicyValidated, c.inventory.Identity()+"\x00"+c.policy.Identity()+"\x00"+c.approval.Identity())
	}
	return c.configurationIdentity == expected
}
func validRuntimePolicyApproval(a RuntimePolicyApproval) bool {
	return nonzeroSetupDigest(a.identity) && a.identity == runtimePolicyApprovalIdentity(a) && nonzeroSetupDigest(a.rootIdentity) && validSetupScope(a.tenantID, a.repositoryID) && nonzeroSetupDigest(a.inventoryIdentity) && nonzeroSetupDigest(a.runtimePolicyIdentity) && nonzeroSetupDigest(a.reviewPolicyIdentity) && validSetupLabel(a.approvedBy)
}
func (c *RuntimePolicyChecker) Key() CheckKey { return CheckPolicyValidated }
func (c *RuntimePolicyChecker) CheckerIdentity() string {
	return builtInCheckerIdentity(CheckPolicyValidated)
}
func (c *RuntimePolicyChecker) Check(ctx context.Context, plan Plan) CheckResult {
	state, outcome := CheckBlocked, "invalid"
	configurationIdentity := ""
	if c != nil {
		configurationIdentity = c.configurationIdentity
	}
	if c != nil && ctx != nil && ctx.Err() == nil && plan.Validate() == nil {
		inventory, policy, loadedIdentity, loadState := c.load(ctx)
		if loadedIdentity != "" {
			configurationIdentity = loadedIdentity
		}
		switch loadState {
		case runtimePolicyLoadUnavailable:
			state, outcome = CheckUnavailable, "unavailable"
		case runtimePolicyLoadBlocked:
			outcome = "configuration_invalid"
		case runtimePolicyLoadValid:
			if c.approval.validate(plan, inventory, policy) && runtimePolicyMatchesSetup(plan, inventory, policy) {
				state, outcome = CheckPassed, "valid"
			} else {
				outcome = "posture_mismatch"
			}
		}
	}
	evidence := checkerEvidenceIdentity(plan.Identity(), builtInCheckerIdentity(CheckPolicyValidated), configurationIdentity, outcome)
	if state == CheckPassed {
		return NewPassedCheckResult(evidence)
	}
	return NewFailedCheckResult(CheckPolicyValidated, state, evidence)
}
func (c *RuntimePolicyChecker) load(ctx context.Context) (runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy, string, runtimePolicyLoadState) {
	if !c.fromFiles {
		if c.inventory.Validate() != nil || c.policy.Validate() != nil || c.policy.InventoryIdentity() != c.inventory.Identity() {
			return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, c.configurationIdentity, runtimePolicyLoadBlocked
		}
		return c.inventory, c.policy, c.configurationIdentity, runtimePolicyLoadValid
	}
	inventoryBytes, inventoryState := readProtectedConfiguration(c.inventoryPath, maxSetupRuntimeConfigurationBytes)
	if inventoryState != runtimePolicyLoadValid {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, c.configurationIdentity, inventoryState
	}
	policyBytes, policyState := readProtectedConfiguration(c.policyPath, 1<<20)
	contentIdentity := checkerConfigIdentity(CheckPolicyValidated, runtimeConfigurationContentIdentity(inventoryBytes, policyBytes)+"\x00"+c.approval.Identity())
	if policyState != runtimePolicyLoadValid {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, contentIdentity, policyState
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(ctx, bytes.NewReader(inventoryBytes))
	if err != nil {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, contentIdentity, runtimePolicyLoadBlocked
	}
	policy, err := runtimeconfig.DecodeRuntimePolicy(ctx, bytes.NewReader(policyBytes), inventory)
	if err != nil {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, contentIdentity, runtimePolicyLoadBlocked
	}
	return inventory, policy, contentIdentity, runtimePolicyLoadValid
}
func runtimeConfigurationContentIdentity(inventory, policy []byte) string {
	inventoryDigest := sha256.Sum256(inventory)
	policyDigest := sha256.Sum256(policy)
	return checkerConfigIdentity(CheckPolicyValidated, hex.EncodeToString(inventoryDigest[:])+"\x00"+hex.EncodeToString(policyDigest[:]))
}

type setupRouteConnectionAuthority struct {
	zone                                provider.ProviderZone
	providerID, adapterID, connectionID string
	logging                             provider.ContentLoggingMode
}

func (a setupRouteConnectionAuthority) matches(reference provider.RouteReference, logging provider.ContentLoggingMode) bool {
	return a.zone == reference.Zone() && a.providerID == reference.ProviderID() && a.adapterID == reference.AdapterID() && a.connectionID == reference.ConnectionID() && a.logging == logging
}
func setupRouteConnectionAuthorities(inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy) (map[string]setupRouteConnectionAuthority, bool) {
	connections := map[string]runtimeconfig.ProviderConnection{}
	for _, connection := range policy.Connections() {
		if _, exists := connections[connection.AdapterID()]; exists {
			return nil, false
		}
		connections[connection.AdapterID()] = connection
	}
	authorities := map[string]setupRouteConnectionAuthority{}
	for _, observed := range inventory.Candidates() {
		candidate := observed.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration()
		reference := candidate.RouteCapabilityDeclaration().RouteReference()
		authority := setupRouteConnectionAuthority{reference.Zone(), reference.ProviderID(), reference.AdapterID(), reference.ConnectionID(), candidate.ContentLoggingMode()}
		if existing, found := authorities[reference.AdapterID()]; found && !existing.matches(reference, candidate.ContentLoggingMode()) {
			return nil, false
		}
		authorities[reference.AdapterID()] = authority
		if _, found := connections[reference.AdapterID()]; !found {
			return nil, false
		}
	}
	return authorities, len(authorities) == len(connections)
}
func runtimePolicyMatchesSetup(plan Plan, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy) bool {
	posture := plan.Posture()
	if inventory.Validate() != nil || policy.Validate() != nil || policy.ValidateAgainstInventory(inventory) != nil || policy.InventoryIdentity() != inventory.Identity() || policy.Constraints().ContentLoggingAllowed() != posture.ContentLoggingAllowed() || policy.Budget().MaxCostMicroUSD() > posture.MaxModelRequestCostMicroUSD() || posture.PublicationEnabled() || posture.DynamicValidationEnabled() || posture.ProviderFallbackEnabled() || !policy.Publication().BlocksOnInconclusive() || policy.Publication().MinimumIndependence() < policy.Independence().Level() {
		return false
	}
	authorities, validAuthorities := setupRouteConnectionAuthorities(inventory, policy)
	if !validAuthorities {
		return false
	}
	connections := map[string]runtimeconfig.ProviderConnection{}
	for _, connection := range policy.Connections() {
		connections[connection.AdapterID()] = connection
	}
	zones := map[provider.ProviderZone]bool{}
	eligible := []provider.RouteReference{}
	for _, observed := range inventory.Candidates() {
		record := observed.ResolvedRecord().RouteRegistryRecord()
		candidate := record.RouteCandidateDeclaration()
		reference := candidate.RouteCapabilityDeclaration().RouteReference()
		zones[reference.Zone()] = true
		authority, found := authorities[reference.AdapterID()]
		connection, connected := connections[reference.AdapterID()]
		if !found || !connected || !authority.matches(reference, candidate.ContentLoggingMode()) || !policy.Constraints().AllowedProviderZones().Allows(reference.Zone()) || candidate.ContentLoggingMode() != provider.ContentLoggingDisabled || !endpointMatchesZone(connection.Endpoint(), reference.Zone()) {
			return false
		}
		if routeReadyForPolicy(observed, policy) {
			eligible = append(eligible, reference)
		}
	}
	for zone := provider.ProviderZoneLocal; zone <= provider.ProviderZoneSubscriptionOAuth; zone++ {
		if policy.Constraints().AllowedProviderZones().Allows(zone) != zones[zone] {
			return false
		}
	}
	if posture.Inference() == InferenceLocalOnly {
		if len(zones) != 1 || !zones[provider.ProviderZoneLocal] {
			return false
		}
	} else if posture.Inference() == InferenceApprovedRemote {
		remote := false
		for zone := range zones {
			remote = remote || zone != provider.ProviderZoneLocal
		}
		if !remote {
			return false
		}
	} else {
		return false
	}
	if _, pinned := policy.Ranking().PinnedRoute(); pinned {
		return false
	}
	return hasIndependentRoutePair(eligible, policy.Independence().Level())
}
func routeReadyForPolicy(observed gateway.ObservedRouteCandidate, policy runtimeconfig.RuntimePolicy) bool {
	record := observed.ResolvedRecord().RouteRegistryRecord()
	candidate := record.RouteCandidateDeclaration()
	capabilities := candidate.RouteCapabilityDeclaration().ModelCapabilities()
	requirements := policy.Requirements()
	if record.Status() != provider.RouteRegistryApproved || observed.OperationalState().Health() != provider.RouteHealthHealthy || observed.OperationalState().Quota() != provider.RouteQuotaAvailable || capabilities.MaxContextTokens() < requirements.MinContextTokens() || capabilities.MaxOutputTokens() < requirements.MinOutputTokens() {
		return false
	}
	for _, feature := range requirements.RequiredFeatures() {
		if !capabilities.Supports(feature) {
			return false
		}
	}
	estimate, err := provider.EstimateMaximumRouteCost(candidate.RoutePricing(), policy.Budget())
	return err == nil && estimate.MaximumCostMicroUSD() <= policy.Budget().MaxCostMicroUSD()
}
func endpointMatchesZone(raw string, zone provider.ProviderZone) bool {
	locality, err := provider.ClassifyServiceEndpoint(raw)
	if err != nil {
		return false
	}
	switch zone {
	case provider.ProviderZoneLocal:
		return locality == provider.ServiceEndpointLoopback
	case provider.ProviderZonePrivateRemote:
		return locality == provider.ServiceEndpointRemote
	default:
		return false
	}
}
func hasIndependentRoutePair(routes []provider.RouteReference, level gateway.RouteIndependenceLevel) bool {
	for i := 0; i < len(routes); i++ {
		for j := i + 1; j < len(routes); j++ {
			switch level {
			case gateway.RouteIndependenceDistinctRoute:
				if routes[i] != routes[j] {
					return true
				}
			case gateway.RouteIndependenceDistinctModel:
				if routes[i].ProviderID() != routes[j].ProviderID() || routes[i].ModelID() != routes[j].ModelID() || routes[i].ModelVersion() != routes[j].ModelVersion() {
					return true
				}
			case gateway.RouteIndependenceDistinctProvider:
				if routes[i].ProviderID() != routes[j].ProviderID() {
					return true
				}
			}
		}
	}
	return false
}
func readProtectedConfiguration(path string, limit int) ([]byte, runtimePolicyLoadState) {
	if !fileOwnershipSupported() {
		return nil, runtimePolicyLoadUnavailable
	}
	first, state := readProtectedConfigurationOnce(path, limit)
	if state != runtimePolicyLoadValid {
		return nil, state
	}
	second, state := readProtectedConfigurationOnce(path, limit)
	if state != runtimePolicyLoadValid {
		return nil, state
	}
	if !bytes.Equal(first, second) {
		return nil, runtimePolicyLoadBlocked
	}
	return first, runtimePolicyLoadValid
}
func readProtectedConfigurationOnce(path string, limit int) ([]byte, runtimePolicyLoadState) {
	type pinned struct {
		path string
		info os.FileInfo
	}
	chain := []pinned{}
	current := path
	for {
		info, err := os.Lstat(current)
		if err != nil {
			return nil, runtimePolicyLoadUnavailable
		}
		if current == path {
			if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o022 != 0 || !fileOwnedByTrustedProcessOrRoot(info) {
				return nil, runtimePolicyLoadBlocked
			}
		} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, runtimePolicyLoadBlocked
		}
		chain = append(chain, pinned{current, info})
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	for i := 1; i < len(chain); i++ {
		if !stableConfigurationAncestorAuthority(chain[i].info, chain[i-1].info) {
			return nil, runtimePolicyLoadBlocked
		}
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, runtimePolicyLoadUnavailable
	}
	if resolved != path {
		return nil, runtimePolicyLoadBlocked
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, runtimePolicyLoadUnavailable
	}
	content, readErr := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	openedInfo, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil || statErr != nil || closeErr != nil {
		return nil, runtimePolicyLoadUnavailable
	}
	if len(content) == 0 || len(content) > limit || !os.SameFile(openedInfo, chain[0].info) {
		return nil, runtimePolicyLoadBlocked
	}
	for i, value := range chain {
		again, err := os.Lstat(value.path)
		if err != nil || !os.SameFile(again, value.info) {
			return nil, runtimePolicyLoadBlocked
		}
		if i == 0 {
			if !again.Mode().IsRegular() || again.Mode().Perm()&0o022 != 0 || !fileOwnedByTrustedProcessOrRoot(again) {
				return nil, runtimePolicyLoadBlocked
			}
		} else if !again.IsDir() || again.Mode()&os.ModeSymlink != 0 || !stableConfigurationAncestorAuthority(again, chain[i-1].info) {
			return nil, runtimePolicyLoadBlocked
		}
	}
	return content, runtimePolicyLoadValid
}
func stableConfigurationAncestorAuthority(parent, child os.FileInfo) bool {
	if !fileOwnedByTrustedProcessOrRoot(parent) {
		return false
	}
	if parent.Mode().Perm()&0o022 == 0 {
		return true
	}
	return parent.Mode()&os.ModeSticky != 0 && fileOwnedByTrustedProcessOrRoot(child)
}
func (c *RuntimePolicyChecker) String() string   { return "setup runtime policy checker" }
func (c *RuntimePolicyChecker) GoString() string { return "setup.RuntimePolicyChecker{<redacted>}" }
func (c *RuntimePolicyChecker) Format(state fmt.State, verb rune) {
	writeSetupFormat(state, verb, c.String(), c.GoString())
}
