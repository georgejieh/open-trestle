package provider

import "errors"

// ErrInvalidRouteReportedDebitUpperBound identifies malformed or unsupported debit evidence.
var ErrInvalidRouteReportedDebitUpperBound = errors.New("invalid route reported debit upper bound")

// RouteReportedDebitUpperBound is optional evidence bounding an attempt's eventual
// account debit. It is not actual cost or authority to release a reservation.
// Its zero value is absent; present zero is a reported bound of zero.
type RouteReportedDebitUpperBound struct {
	present  bool
	microUSD uint64
}

// NewRouteReportedDebitUpperBoundMicroUSD validates a present microUSD bound.
// Callers must separately qualify the provider's per-attempt debit semantics.
func NewRouteReportedDebitUpperBoundMicroUSD(microUSD uint64) (RouteReportedDebitUpperBound, error) {
	bound := RouteReportedDebitUpperBound{present: true, microUSD: microUSD}
	if err := bound.Validate(); err != nil {
		return RouteReportedDebitUpperBound{}, err
	}
	return bound, nil
}

func (b RouteReportedDebitUpperBound) IsPresent() bool  { return b.present }
func (b RouteReportedDebitUpperBound) MicroUSD() uint64 { return b.microUSD }

func (b RouteReportedDebitUpperBound) Validate() error {
	if b.microUSD > maxModelCostMicroUSD || !b.present && b.microUSD != 0 {
		return ErrInvalidRouteReportedDebitUpperBound
	}
	return nil
}

type reportedDebitUpperBoundIdentity struct {
	MicroUSD uint64 `json:"micro_usd"`
}

func reportedDebitUpperBoundIdentityValue(bound RouteReportedDebitUpperBound) *reportedDebitUpperBoundIdentity {
	if !bound.IsPresent() {
		return nil
	}
	return &reportedDebitUpperBoundIdentity{MicroUSD: bound.MicroUSD()}
}
