package diagnostics

// ContextRefusalReason is the closed route reason a failed full review's
// context task recorded before any model effect.
type ContextRefusalReason string

const (
	// ContextRefusalRouteContextInsufficient means the request's byte-based
	// reservation exceeded the route's declared context.
	ContextRefusalRouteContextInsufficient ContextRefusalReason = "route_context_insufficient"
	// ContextRefusalNoEligibleRoute is any other route refusal.
	ContextRefusalNoEligibleRoute ContextRefusalReason = "no_eligible_route"
)

// ContextRefusal is a content-free copy of a refused context task's recorded
// reason and, for route_context_insufficient, its counts. RequiredTokens is
// EstimatedInputTokens plus MaxOutputTokens and exceeds DeclaredContextTokens.
type ContextRefusal struct {
	Reason                                                       ContextRefusalReason
	RequiredTokens                                               uint64
	EstimatedInputTokens, MaxOutputTokens, DeclaredContextTokens uint32
}

func (r ContextRefusal) valid() bool {
	switch r.Reason {
	case ContextRefusalRouteContextInsufficient:
		return r.EstimatedInputTokens != 0 && r.MaxOutputTokens != 0 && r.DeclaredContextTokens != 0 && r.RequiredTokens == uint64(r.EstimatedInputTokens)+uint64(r.MaxOutputTokens) && uint64(r.DeclaredContextTokens) < r.RequiredTokens
	case ContextRefusalNoEligibleRoute:
		return r.RequiredTokens == 0 && r.EstimatedInputTokens == 0 && r.MaxOutputTokens == 0 && r.DeclaredContextTokens == 0
	default:
		return false
	}
}

// ContextRefusal returns the refusal a failed full-review set records.
func (s Set) ContextRefusal() (ContextRefusal, bool) {
	return s.contextRefusal, s.contextRefusal.Reason != ""
}

// WithContextRefusal binds a refused context task's reason to a failed v7 set
// without verified evidence, and derives the new identity.
func (s Set) WithContextRefusal(refusal ContextRefusal) (Set, error) {
	if s.schemaVersion != 7 || s.finalOutcome != FinalOutcomeFailed || s.verifiedSetIdentity != "" || s.contextRefusal.Reason != "" || !refusal.valid() {
		return Set{}, ErrInvalidSet
	}
	s.contextRefusal = refusal
	return finalizeFinalSet(s)
}

type contextRefusalRecord struct {
	Reason           ContextRefusalReason    `json:"reason"`
	ContextShortfall *contextShortfallRecord `json:"context_shortfall,omitempty"`
}

type contextShortfallRecord struct {
	RequiredTokens        uint64 `json:"required_tokens"`
	EstimatedInputTokens  uint32 `json:"estimated_input_tokens"`
	MaxOutputTokens       uint32 `json:"max_output_tokens"`
	DeclaredContextTokens uint32 `json:"declared_context_tokens"`
}

func contextRefusalToRecord(r ContextRefusal) *contextRefusalRecord {
	if r.Reason == "" {
		return nil
	}
	record := &contextRefusalRecord{Reason: r.Reason}
	if r.Reason == ContextRefusalRouteContextInsufficient {
		record.ContextShortfall = &contextShortfallRecord{r.RequiredTokens, r.EstimatedInputTokens, r.MaxOutputTokens, r.DeclaredContextTokens}
	}
	return record
}

func contextRefusalFromRecord(r *contextRefusalRecord) (ContextRefusal, bool) {
	if r == nil || (r.ContextShortfall != nil) != (r.Reason == ContextRefusalRouteContextInsufficient) {
		return ContextRefusal{}, false
	}
	refusal := ContextRefusal{Reason: r.Reason}
	if s := r.ContextShortfall; s != nil {
		refusal.RequiredTokens, refusal.EstimatedInputTokens, refusal.MaxOutputTokens, refusal.DeclaredContextTokens = s.RequiredTokens, s.EstimatedInputTokens, s.MaxOutputTokens, s.DeclaredContextTokens
	}
	return refusal, refusal.valid()
}
