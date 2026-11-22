package review

import (
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/georgejieh/open-trestle/agentprofile"
)

// ErrInvalidContextSpecialist identifies an unknown, non-model, or altered specialist profile.
var ErrInvalidContextSpecialist = errors.New("invalid review context specialist")

var packagedSpecialistCatalog = sync.OnceValues(agentprofile.DefaultCatalog)

// ContextSpecialist is one packaged specialist profile bound into a candidate-generation
// context. Its instructions are operator-packaged product content from the embedded
// agentprofile catalog, never repository evidence. The context payload carries
// only the profile identity fields; the skill text is sent solely through the
// trusted system channel (TrustedModelRequestInstructions). The zero value
// means no specialist.
type ContextSpecialist struct {
	profileID, profileIdentity, catalogIdentity, instructions string
}

// NewContextSpecialist selects one packaged model-calling profile by exact ID.
func NewContextSpecialist(profileID string) (ContextSpecialist, error) {
	catalog, err := packagedSpecialistCatalog()
	if err != nil {
		return ContextSpecialist{}, ErrInvalidContextSpecialist
	}
	id, err := agentprofile.ParseProfileID(profileID)
	if err != nil {
		return ContextSpecialist{}, fmt.Errorf("%w: unknown profile", ErrInvalidContextSpecialist)
	}
	profile, ok := catalog.Profile(id)
	if !ok || !directReviewSpecialist(profile) {
		return ContextSpecialist{}, fmt.Errorf("%w: profile is not a model-calling defect-review profile", ErrInvalidContextSpecialist)
	}
	return ContextSpecialist{profileID: string(profile.ID()), profileIdentity: profile.Identity(), catalogIdentity: catalog.Identity(), instructions: profile.Skill()}, nil
}

// nonDefectSpecialists are model-calling profiles whose packaged output is not a
// defect claim. The candidate batch contract carries only defect claims that an
// independent verifier checks, so a test proposal would either overflow the
// claim bound or be verified as a finding. They stay planning-only until a
// proposal contract exists.
var nonDefectSpecialists = map[agentprofile.ProfileID]struct{}{"test_author": {}}

// directReviewSpecialist reports whether a profile may steer candidate generation.
func directReviewSpecialist(profile agentprofile.Profile) bool {
	if _, excluded := nonDefectSpecialists[profile.ID()]; excluded {
		return false
	}
	return profile.ModelCall() == agentprofile.ModelCallRequired && profile.Authority().CandidatesOnly() && profile.Authority().RequiresIndependentVerification()
}

// ContextSpecialistProfileIDs returns the profile IDs NewContextSpecialist accepts, sorted.
func ContextSpecialistProfileIDs() []string {
	catalog, err := packagedSpecialistCatalog()
	if err != nil {
		return nil
	}
	ids := []string{}
	for _, profile := range catalog.Profiles() {
		if directReviewSpecialist(profile) {
			ids = append(ids, string(profile.ID()))
		}
	}
	sort.Strings(ids)
	return ids
}

func (s ContextSpecialist) IsZero() bool            { return s == ContextSpecialist{} }
func (s ContextSpecialist) ProfileID() string       { return s.profileID }
func (s ContextSpecialist) ProfileIdentity() string { return s.profileIdentity }
func (s ContextSpecialist) CatalogIdentity() string { return s.catalogIdentity }
func (s ContextSpecialist) Instructions() string    { return s.instructions }
func (s ContextSpecialist) String() string          { return "review context specialist" }
func (s ContextSpecialist) GoString() string        { return "review.ContextSpecialist{<redacted>}" }

// Validate re-derives the specialist from the embedded catalog and requires an exact match.
func (s ContextSpecialist) Validate() error {
	expected, err := NewContextSpecialist(s.profileID)
	if err != nil || expected != s {
		return ErrInvalidContextSpecialist
	}
	return nil
}

// contextSpecialistWire binds request identity to one packaged profile. It
// carries no instruction text and no authority label: the payload is untrusted
// data, so instruction prose there would only look like authority.
type contextSpecialistWire struct {
	ProfileID       string `json:"profile_id"`
	ProfileIdentity string `json:"profile_identity"`
	CatalogIdentity string `json:"catalog_identity"`
}

func (s ContextSpecialist) wire() *contextSpecialistWire {
	return &contextSpecialistWire{ProfileID: s.profileID, ProfileIdentity: s.profileIdentity, CatalogIdentity: s.catalogIdentity}
}

// contextSpecialistFromWire selects the profile from the embedded catalog by
// exact ID and requires the recorded profile and catalog identities to match.
// The skill text always comes from the catalog, never from the payload.
func contextSpecialistFromWire(wire *contextSpecialistWire) (ContextSpecialist, bool) {
	if wire == nil {
		return ContextSpecialist{}, false
	}
	value, err := NewContextSpecialist(wire.ProfileID)
	if err != nil || value.profileID != wire.ProfileID || value.profileIdentity != wire.ProfileIdentity || value.catalogIdentity != wire.CatalogIdentity {
		return ContextSpecialist{}, false
	}
	return value, true
}

// validGenerationContextSpecialist requires a specialist block, when present,
// to re-derive exactly from the embedded catalog.
func validGenerationContextSpecialist(wire contextPacketWire) bool {
	if wire.Specialist == nil {
		return true
	}
	_, ok := contextSpecialistFromWire(wire.Specialist)
	return ok
}

// RecordedContextSpecialist returns the specialist bound into exact recorded
// generation-context bytes. It returns false for a context without a specialist.
func RecordedContextSpecialist(payload []byte) (ContextSpecialist, bool, error) {
	if len(payload) == 0 || len(payload) > maxProviderContextPacketBytes {
		return ContextSpecialist{}, false, ErrInvalidContextPacketRequest
	}
	wire, err := decodeGenerationContextWire(payload)
	if err != nil || wire.Contract != "open-trestle/review-context-packet" || !validGenerationContextSpecialist(wire) ||
		!validModelOutputContract(wire.SchemaVersion, wire.Instructions, wire.InstructionsIdentity, wire.OutputSchema, false) ||
		wire.OutputSchemaIdentity != ModelCandidateBatchSchemaIdentity {
		return ContextSpecialist{}, false, ErrInvalidContextPacketRequest
	}
	if wire.Specialist == nil {
		return ContextSpecialist{}, false, nil
	}
	value, _ := contextSpecialistFromWire(wire.Specialist)
	return value, true, nil
}
