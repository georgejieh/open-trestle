package gateway

import (
	"errors"
	"fmt"

	"github.com/georgejieh/open-trestle/internal/provider"
)

const maxRouteFilterCandidates = 64

var (
	// ErrInvalidRouteRejectionReason identifies an unknown compatibility rejection.
	ErrInvalidRouteRejectionReason = errors.New("invalid route rejection reason")
	// ErrInvalidRouteFilterRevision identifies a missing registry revision.
	ErrInvalidRouteFilterRevision = errors.New("invalid route filter revision")
	// ErrTooManyRouteCandidates identifies an input beyond the deterministic filter bound.
	ErrTooManyRouteCandidates = errors.New("too many route candidates")
	// ErrRouteCandidateRevisionMismatch identifies a record from another registry snapshot.
	ErrRouteCandidateRevisionMismatch = errors.New("route candidate registry revision mismatch")
	// ErrDuplicateRouteCandidate identifies a repeated registry record.
	ErrDuplicateRouteCandidate = errors.New("duplicate route candidate")
	// ErrUnexpectedRouteCompatibilityError identifies an evaluator failure without a stable rejection reason.
	ErrUnexpectedRouteCompatibilityError = errors.New("unexpected route compatibility error")
)

// RouteRejectionReason identifies why a structurally valid registry record was incompatible.
type RouteRejectionReason uint8

const (
	RouteRejectedZone RouteRejectionReason = iota + 1
	RouteRejectedContentLogging
	RouteRejectedNotApproved
	RouteRejectedMissingFeature
	RouteRejectedInsufficientContext
	RouteRejectedInsufficientOutput
	RouteRejectedUnhealthy
	RouteRejectedHealthUnknown
	RouteRejectedQuotaExhausted
	RouteRejectedQuotaUnknown
	RouteRejectedUnknownPricing
	RouteRejectedCostBudget
)

// String returns the stable rejection token or an empty string for unknown values.
func (r RouteRejectionReason) String() string {
	switch r {
	case RouteRejectedZone:
		return "zone_not_allowed"
	case RouteRejectedContentLogging:
		return "content_logging_not_allowed"
	case RouteRejectedNotApproved:
		return "not_approved"
	case RouteRejectedMissingFeature:
		return "missing_model_feature"
	case RouteRejectedInsufficientContext:
		return "insufficient_model_context"
	case RouteRejectedInsufficientOutput:
		return "insufficient_model_output"
	case RouteRejectedUnhealthy:
		return "route_unhealthy"
	case RouteRejectedHealthUnknown:
		return "route_health_unknown"
	case RouteRejectedQuotaExhausted:
		return "route_quota_exhausted"
	case RouteRejectedQuotaUnknown:
		return "route_quota_unknown"
	case RouteRejectedUnknownPricing:
		return "route_pricing_unknown"
	case RouteRejectedCostBudget:
		return "route_cost_exceeds_budget"
	default:
		return ""
	}
}

// ParseRouteRejectionReason parses one exact stable rejection token.
func ParseRouteRejectionReason(value string) (RouteRejectionReason, error) {
	switch value {
	case "zone_not_allowed":
		return RouteRejectedZone, nil
	case "content_logging_not_allowed":
		return RouteRejectedContentLogging, nil
	case "not_approved":
		return RouteRejectedNotApproved, nil
	case "missing_model_feature":
		return RouteRejectedMissingFeature, nil
	case "insufficient_model_context":
		return RouteRejectedInsufficientContext, nil
	case "insufficient_model_output":
		return RouteRejectedInsufficientOutput, nil
	case "route_unhealthy":
		return RouteRejectedUnhealthy, nil
	case "route_health_unknown":
		return RouteRejectedHealthUnknown, nil
	case "route_quota_exhausted":
		return RouteRejectedQuotaExhausted, nil
	case "route_quota_unknown":
		return RouteRejectedQuotaUnknown, nil
	case "route_pricing_unknown":
		return RouteRejectedUnknownPricing, nil
	case "route_cost_exceeds_budget":
		return RouteRejectedCostBudget, nil
	default:
		return 0, fmt.Errorf("parse route rejection reason: %w", ErrInvalidRouteRejectionReason)
	}
}

// Validate verifies that the rejection reason is known.
func (r RouteRejectionReason) Validate() error {
	if r.String() == "" {
		return fmt.Errorf("validate route rejection reason: %w", ErrInvalidRouteRejectionReason)
	}
	return nil
}

// RouteRejection binds a registry record identity to a stable incompatibility reason.
type RouteRejection struct {
	recordIdentity      string
	operationalRevision uint64
	reason              RouteRejectionReason
}

// RecordIdentity returns the rejected registry record identity.
func (r RouteRejection) RecordIdentity() string { return r.recordIdentity }

// OperationalRevision returns the readiness observation revision, or zero for structural-only filtering.
func (r RouteRejection) OperationalRevision() uint64 { return r.operationalRevision }

// Reason returns the stable incompatibility reason.
func (r RouteRejection) Reason() RouteRejectionReason { return r.reason }

// String returns a redacted rejection description.
func (r RouteRejection) String() string { return "route rejection" }

// GoString returns a redacted Go-syntax rejection description.
func (r RouteRejection) GoString() string { return "gateway.RouteRejection{<redacted>}" }

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (r RouteRejection) Format(state fmt.State, verb rune) {
	formatted := "route rejection"
	if verb == 'q' {
		formatted = `"route rejection"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.RouteRejection{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

func routeRejectionReason(err error) (RouteRejectionReason, bool) {
	switch {
	case errors.Is(err, ErrRouteZoneNotAllowed):
		return RouteRejectedZone, true
	case errors.Is(err, ErrRouteContentLoggingNotAllowed):
		return RouteRejectedContentLogging, true
	case errors.Is(err, ErrRouteRegistryRecordNotApproved):
		return RouteRejectedNotApproved, true
	case errors.Is(err, provider.ErrMissingModelFeature):
		return RouteRejectedMissingFeature, true
	case errors.Is(err, provider.ErrInsufficientModelContext):
		return RouteRejectedInsufficientContext, true
	case errors.Is(err, provider.ErrInsufficientModelOutput):
		return RouteRejectedInsufficientOutput, true
	case errors.Is(err, ErrRouteUnhealthy):
		return RouteRejectedUnhealthy, true
	case errors.Is(err, ErrRouteHealthUnknown):
		return RouteRejectedHealthUnknown, true
	case errors.Is(err, ErrRouteQuotaExhausted):
		return RouteRejectedQuotaExhausted, true
	case errors.Is(err, ErrRouteQuotaUnknown):
		return RouteRejectedQuotaUnknown, true
	case errors.Is(err, provider.ErrUnknownRoutePricing):
		return RouteRejectedUnknownPricing, true
	case errors.Is(err, ErrRouteCostExceedsBudget):
		return RouteRejectedCostBudget, true
	default:
		return 0, false
	}
}
