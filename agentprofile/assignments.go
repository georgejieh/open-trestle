package agentprofile

import (
	"errors"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// Assignments wire contract and bounds.
const (
	AssignmentsSchema  = "open-trestle/agent-profile-assignments"
	AssignmentsVersion = 1

	// MaxAssignmentsBytes bounds one encoded assignments document.
	MaxAssignmentsBytes = 64 << 10

	maxTotalTokenBudget = 1 << 40
)

var (
	// ErrInvalidAssignments identifies a malformed or inconsistent assignments document.
	ErrInvalidAssignments = errors.New("invalid agent profile assignments")
	// ErrAssignmentsTooLarge identifies an encoded assignments document beyond MaxAssignmentsBytes.
	ErrAssignmentsTooLarge = errors.New("agent profile assignments too large")
)

// ProfileAssignmentSpec overrides the global tier routes for one profile.
type ProfileAssignmentSpec struct {
	Tiers         map[Tier]provider.RouteReference
	VerifierTiers map[Tier]provider.RouteReference
}

// AssignmentsSpec is caller input for NewAssignments.
type AssignmentsSpec struct {
	// Independence is the minimum generator/verifier separation (gateway vocabulary). Required.
	Independence gateway.RouteIndependenceLevel
	// Tiers maps tiers to exact generator routes for every profile.
	Tiers map[Tier]provider.RouteReference
	// VerifierTiers maps tiers to exact verifier routes for every profile.
	VerifierTiers map[Tier]provider.RouteReference
	// Profiles holds per-profile overrides.
	Profiles map[ProfileID]ProfileAssignmentSpec
	// EscalationOrder, when set, lets an unassigned tier borrow the next assigned tier listed after it.
	// Without it, an unassigned tier omits the profile. Every borrow is recorded in the plan.
	EscalationOrder []Tier
	// TotalTokenBudget caps the summed planned tokens; zero means no cap.
	TotalTokenBudget uint64
}

// Assignments is the immutable, content-identified user mapping of tiers to exact routes.
type Assignments struct {
	identity         string
	independence     gateway.RouteIndependencePolicy
	tiers            map[Tier]provider.RouteReference
	verifierTiers    map[Tier]provider.RouteReference
	profiles         map[ProfileID]ProfileAssignmentSpec
	escalationOrder  []Tier
	totalTokenBudget uint64
}

// NewAssignments validates assignments against the catalog they will be planned with.
func NewAssignments(catalog Catalog, spec AssignmentsSpec) (Assignments, error) {
	invalid := func(detail string) (Assignments, error) {
		return Assignments{}, fmt.Errorf("%w: %s", ErrInvalidAssignments, detail)
	}
	if err := catalog.Validate(); err != nil {
		return Assignments{}, err
	}
	independence, err := gateway.NewRouteIndependencePolicy(spec.Independence)
	if err != nil {
		return invalid("independence must be distinct_route, distinct_model, or distinct_provider")
	}
	if spec.TotalTokenBudget > maxTotalTokenBudget {
		return invalid("total token budget exceeds bound")
	}
	assignments := Assignments{independence: independence, totalTokenBudget: spec.TotalTokenBudget}
	if assignments.tiers, err = cloneTierRoutes(spec.Tiers); err != nil {
		return invalid("tiers: " + err.Error())
	}
	if assignments.verifierTiers, err = cloneTierRoutes(spec.VerifierTiers); err != nil {
		return invalid("verifier_tiers: " + err.Error())
	}
	if len(spec.Profiles) > len(knownProfileIDs) {
		return invalid("too many profile overrides")
	}
	assignments.profiles = make(map[ProfileID]ProfileAssignmentSpec, len(spec.Profiles))
	for id, override := range spec.Profiles {
		profile, ok := catalog.Profile(id)
		if !ok {
			return invalid(fmt.Sprintf("profile override %q is not in the catalog", id))
		}
		if profile.modelCall == ModelCallNone {
			return invalid(fmt.Sprintf("profile %q makes no model call and takes no routes", id))
		}
		generator, err := cloneTierRoutes(override.Tiers)
		if err != nil {
			return invalid(fmt.Sprintf("profiles.%s.tiers: %v", id, err))
		}
		verifier, err := cloneTierRoutes(override.VerifierTiers)
		if err != nil {
			return invalid(fmt.Sprintf("profiles.%s.verifier_tiers: %v", id, err))
		}
		if len(generator) == 0 && len(verifier) == 0 {
			return invalid(fmt.Sprintf("profile override %q assigns no route", id))
		}
		assignments.profiles[id] = ProfileAssignmentSpec{Tiers: generator, VerifierTiers: verifier}
	}
	seen := map[Tier]struct{}{}
	for _, tier := range spec.EscalationOrder {
		if tier.rank() < 0 {
			return invalid("escalation order contains an unknown tier")
		}
		if _, duplicate := seen[tier]; duplicate {
			return invalid("escalation order repeats a tier")
		}
		seen[tier] = struct{}{}
		assignments.escalationOrder = append(assignments.escalationOrder, tier)
	}
	hasGenerator := len(assignments.tiers) > 0
	for _, override := range assignments.profiles {
		hasGenerator = hasGenerator || len(override.Tiers) > 0
	}
	if !hasGenerator {
		return invalid("at least one generator tier route is required")
	}
	if len(assignments.escalationOrder) == 1 {
		return invalid("escalation order needs at least two tiers")
	}
	assignments.identity = deriveIdentity(assignments.wire())
	return assignments, nil
}

func cloneTierRoutes(routes map[Tier]provider.RouteReference) (map[Tier]provider.RouteReference, error) {
	out := make(map[Tier]provider.RouteReference, len(routes))
	for tier, route := range routes {
		if tier.rank() < 0 {
			return nil, ErrInvalidTier
		}
		if err := route.Validate(); err != nil {
			return nil, err
		}
		out[tier] = route
	}
	return out, nil
}

// Identity returns the SHA-256 identity of the canonical assignments document.
func (a Assignments) Identity() string { return a.identity }

// Independence returns the generator/verifier separation policy.
func (a Assignments) Independence() gateway.RouteIndependencePolicy { return a.independence }

// EscalationOrder returns the configured tier escalation order, or nil when none is configured.
func (a Assignments) EscalationOrder() []Tier { return append([]Tier(nil), a.escalationOrder...) }

// TotalTokenBudget returns the token cap, or zero when uncapped.
func (a Assignments) TotalTokenBudget() uint64 { return a.totalTokenBudget }

// String returns a redacted description.
func (a Assignments) String() string { return "agent profile assignments" }

// GoString returns a redacted Go-syntax description.
func (a Assignments) GoString() string { return "agentprofile.Assignments{<redacted>}" }

// Validate verifies the independence policy and content-derived identity.
func (a Assignments) Validate() error {
	if err := a.independence.Validate(); err != nil {
		return err
	}
	if a.identity == "" || a.identity != deriveIdentity(a.wire()) {
		return ErrInvalidAssignments
	}
	return nil
}

// routeSource records where a route came from.
type routeSource string

const (
	routeSourceProfileOverride routeSource = "profile_override"
	routeSourceGlobal          routeSource = "global"
)

// routeSelection is one resolved tier route and its provenance.
type routeSelection struct {
	route         provider.RouteReference
	tier          Tier
	source        routeSource
	escalatedFrom Tier
}

// lookup returns the exact route for one tier, preferring a profile override.
func (a Assignments) lookup(id ProfileID, tier Tier, verifier bool) (provider.RouteReference, routeSource, bool) {
	override := a.profiles[id]
	profileRoutes, globalRoutes := override.Tiers, a.tiers
	if verifier {
		profileRoutes, globalRoutes = override.VerifierTiers, a.verifierTiers
	}
	if route, ok := profileRoutes[tier]; ok {
		return route, routeSourceProfileOverride, true
	}
	if route, ok := globalRoutes[tier]; ok {
		return route, routeSourceGlobal, true
	}
	return provider.RouteReference{}, "", false
}

// resolve returns the route for the wanted tier, or the first assigned tier
// after it in the configured escalation order. It never borrows without one.
func (a Assignments) resolve(id ProfileID, wanted Tier, verifier bool) (routeSelection, bool) {
	if route, source, ok := a.lookup(id, wanted, verifier); ok {
		return routeSelection{route: route, tier: wanted, source: source}, true
	}
	position := -1
	for index, tier := range a.escalationOrder {
		if tier == wanted {
			position = index
		}
	}
	if position < 0 {
		return routeSelection{}, false
	}
	for _, tier := range a.escalationOrder[position+1:] {
		if route, source, ok := a.lookup(id, tier, verifier); ok {
			return routeSelection{route: route, tier: tier, source: source, escalatedFrom: wanted}, true
		}
	}
	return routeSelection{}, false
}

// Wire encoding.

type routeWire struct {
	Zone         string `json:"zone"`
	ProviderID   string `json:"provider_id"`
	AdapterID    string `json:"adapter_id"`
	ConnectionID string `json:"connection_id"`
	ModelID      string `json:"model_id"`
	ModelVersion string `json:"model_version"`
}

func routeToWire(route provider.RouteReference) routeWire {
	return routeWire{
		Zone: route.Zone().String(), ProviderID: route.ProviderID(), AdapterID: route.AdapterID(),
		ConnectionID: route.ConnectionID(), ModelID: route.ModelID(), ModelVersion: route.ModelVersion(),
	}
}

func (w routeWire) route() (provider.RouteReference, error) {
	zone, err := provider.ParseProviderZone(w.Zone)
	if err != nil {
		return provider.RouteReference{}, err
	}
	return provider.NewRouteReference(zone, w.ProviderID, w.AdapterID, w.ConnectionID, w.ModelID, w.ModelVersion)
}

type profileAssignmentWire struct {
	Tiers         map[string]routeWire `json:"tiers,omitempty"`
	VerifierTiers map[string]routeWire `json:"verifier_tiers,omitempty"`
}

type assignmentsWire struct {
	Schema           string                           `json:"schema"`
	Version          int                              `json:"version"`
	Independence     string                           `json:"independence"`
	Tiers            map[string]routeWire             `json:"tiers,omitempty"`
	VerifierTiers    map[string]routeWire             `json:"verifier_tiers,omitempty"`
	Profiles         map[string]profileAssignmentWire `json:"profiles,omitempty"`
	EscalationOrder  []string                         `json:"escalation_order,omitempty"`
	TotalTokenBudget uint64                           `json:"total_token_budget,omitempty"`
}

func tierRoutesWire(routes map[Tier]provider.RouteReference) map[string]routeWire {
	if len(routes) == 0 {
		return nil
	}
	out := make(map[string]routeWire, len(routes))
	for tier, route := range routes {
		out[string(tier)] = routeToWire(route)
	}
	return out
}

// wire returns the canonical form; encoding/json sorts map keys.
func (a Assignments) wire() assignmentsWire {
	wire := assignmentsWire{
		Schema: AssignmentsSchema, Version: AssignmentsVersion, Independence: a.independence.Level().String(),
		Tiers: tierRoutesWire(a.tiers), VerifierTiers: tierRoutesWire(a.verifierTiers),
		EscalationOrder: stringsOf(a.escalationOrder), TotalTokenBudget: a.totalTokenBudget,
	}
	if len(wire.EscalationOrder) == 0 {
		wire.EscalationOrder = nil
	}
	if len(a.profiles) > 0 {
		wire.Profiles = make(map[string]profileAssignmentWire, len(a.profiles))
		for id, override := range a.profiles {
			wire.Profiles[string(id)] = profileAssignmentWire{Tiers: tierRoutesWire(override.Tiers), VerifierTiers: tierRoutesWire(override.VerifierTiers)}
		}
	}
	return wire
}

func parseTierRoutes(wire map[string]routeWire) (map[Tier]provider.RouteReference, error) {
	if len(wire) == 0 {
		return nil, nil
	}
	keys := make([]string, 0, len(wire))
	for key := range wire {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make(map[Tier]provider.RouteReference, len(wire))
	for _, key := range keys {
		tier, err := ParseTier(key)
		if err != nil {
			return nil, err
		}
		route, err := wire[key].route()
		if err != nil {
			return nil, fmt.Errorf("tier %s: %w", key, err)
		}
		out[tier] = route
	}
	return out, nil
}

// ParseAssignments strictly decodes one versioned assignments document and validates it against the catalog.
func ParseAssignments(catalog Catalog, encoded []byte) (Assignments, error) {
	if len(encoded) > MaxAssignmentsBytes {
		return Assignments{}, ErrAssignmentsTooLarge
	}
	var wire assignmentsWire
	if err := decodeStrictJSON(encoded, &wire); err != nil {
		return Assignments{}, fmt.Errorf("%w: %v", ErrInvalidAssignments, err)
	}
	if wire.Schema != AssignmentsSchema || wire.Version != AssignmentsVersion {
		return Assignments{}, fmt.Errorf("%w: unsupported schema or version", ErrInvalidAssignments)
	}
	level, err := gateway.ParseRouteIndependenceLevel(wire.Independence)
	if err != nil {
		return Assignments{}, fmt.Errorf("%w: independence must be distinct_route, distinct_model, or distinct_provider", ErrInvalidAssignments)
	}
	spec := AssignmentsSpec{Independence: level, TotalTokenBudget: wire.TotalTokenBudget}
	if spec.Tiers, err = parseTierRoutes(wire.Tiers); err != nil {
		return Assignments{}, fmt.Errorf("%w: tiers: %v", ErrInvalidAssignments, err)
	}
	if spec.VerifierTiers, err = parseTierRoutes(wire.VerifierTiers); err != nil {
		return Assignments{}, fmt.Errorf("%w: verifier_tiers: %v", ErrInvalidAssignments, err)
	}
	if len(wire.Profiles) > len(knownProfileIDs) {
		return Assignments{}, fmt.Errorf("%w: too many profile overrides", ErrInvalidAssignments)
	}
	if len(wire.Profiles) > 0 {
		spec.Profiles = make(map[ProfileID]ProfileAssignmentSpec, len(wire.Profiles))
		for key, override := range wire.Profiles {
			id, err := ParseProfileID(key)
			if err != nil {
				return Assignments{}, fmt.Errorf("%w: profiles: %v", ErrInvalidAssignments, err)
			}
			generator, err := parseTierRoutes(override.Tiers)
			if err != nil {
				return Assignments{}, fmt.Errorf("%w: profiles.%s.tiers: %v", ErrInvalidAssignments, key, err)
			}
			verifier, err := parseTierRoutes(override.VerifierTiers)
			if err != nil {
				return Assignments{}, fmt.Errorf("%w: profiles.%s.verifier_tiers: %v", ErrInvalidAssignments, key, err)
			}
			spec.Profiles[id] = ProfileAssignmentSpec{Tiers: generator, VerifierTiers: verifier}
		}
	}
	if len(wire.EscalationOrder) > len(Tiers()) {
		return Assignments{}, fmt.Errorf("%w: escalation order is too long", ErrInvalidAssignments)
	}
	for _, token := range wire.EscalationOrder {
		tier, err := ParseTier(token)
		if err != nil {
			return Assignments{}, fmt.Errorf("%w: escalation order: %v", ErrInvalidAssignments, err)
		}
		spec.EscalationOrder = append(spec.EscalationOrder, tier)
	}
	return NewAssignments(catalog, spec)
}
