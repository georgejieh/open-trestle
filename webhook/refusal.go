package webhook

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"time"
)

var (
	// ErrDeliveryRefused identifies an accepted delivery that the current
	// planner deterministically refuses. Processing it again yields the same
	// refusal, so intake records it and moves on instead of retrying.
	ErrDeliveryRefused = errors.New("webhook delivery refused")
	// ErrInvalidRefusalRecord identifies a malformed or cross-wired refusal record.
	ErrInvalidRefusalRecord = errors.New("invalid webhook delivery refusal record")
	// ErrRefusalConflict identifies a different refusal already recorded for the same delivery and planner.
	ErrRefusalConflict = errors.New("webhook delivery refusal conflict")
)

// Reasons recorded when the processor, rather than the planner, refuses.
const (
	RefusalReasonPlanningRefused = "planning_refused"
	RefusalReasonRunPlanNotBound = "run_plan_not_bound"
	RefusalReasonRunPlanConflict = "run_plan_conflict"
	// RefusalReasonRunOpenedByIncompatibleRelease records a delivery whose run
	// an earlier release opened with task handlers this daemon does not run,
	// so the run can neither be adopted nor make progress.
	RefusalReasonRunOpenedByIncompatibleRelease = "run_opened_by_incompatible_release"
	// RefusalReasonRetriesExhausted records a delivery whose own failures
	// outlasted its bounded retries while intake stayed available.
	RefusalReasonRetriesExhausted = "retries_exhausted"
	// RefusalReasonRetryCapacityExhausted records a delivery whose own failure
	// could not be counted because the inbox had no room for its retry state,
	// so it could not be held to its bound.
	RefusalReasonRetryCapacityExhausted = "retry_capacity_exhausted"
)

var refusalReasonPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)

// DeliveryRefusal is a deterministic, content-free refusal of one delivery.
// A planner may return one to name its reason; the processor wraps every
// other planning error as RefusalReasonPlanningRefused.
type DeliveryRefusal struct {
	reason, message string
	cause           error
}

// NewDeliveryRefusal returns a refusal with a fixed reason token and message.
func NewDeliveryRefusal(reason, message string) *DeliveryRefusal {
	if !refusalReasonPattern.MatchString(reason) {
		reason = RefusalReasonPlanningRefused
	}
	return &DeliveryRefusal{reason: reason, message: message}
}

func refuseDelivery(reason string, cause error) *DeliveryRefusal {
	return &DeliveryRefusal{reason: reason, message: "webhook delivery refused: " + reason, cause: cause}
}

func (r *DeliveryRefusal) Error() string        { return r.message }
func (r *DeliveryRefusal) Reason() string       { return r.reason }
func (r *DeliveryRefusal) Unwrap() error        { return r.cause }
func (r *DeliveryRefusal) Is(target error) bool { return target == ErrDeliveryRefused }
func (r *DeliveryRefusal) String() string       { return "webhook delivery refusal" }
func (r *DeliveryRefusal) GoString() string     { return "webhook.DeliveryRefusal{<redacted>}" }

// RefusalExplanation explains a recorded refusal reason in fixed host words.
func RefusalExplanation(reason string) string {
	switch reason {
	case "invalid_pull_request_payload":
		return "the pull request payload cannot be planned"
	case RefusalReasonPlanningRefused:
		return "the planner refused the delivery"
	case RefusalReasonRunPlanNotBound:
		return "the plan was outside the delivery's lineage"
	case RefusalReasonRunPlanConflict:
		return "the run scope holds a plan the planner did not produce for this delivery"
	case RefusalReasonRunOpenedByIncompatibleRelease:
		return "an earlier release opened this delivery's run with task handlers this daemon does not run; push a new commit or reopen the pull request for a fresh review"
	case RefusalReasonRetriesExhausted:
		return "the delivery kept failing on its own until its retries were spent"
	case RefusalReasonRetryCapacityExhausted:
		return "the delivery failed and the inbox had no room to record its retry state"
	default:
		return "recorded by the planner"
	}
}

// RefusalSummary is the one content-free sentence every read surface uses to
// report a refused delivery.
func RefusalSummary(record RefusalRecord) string {
	return "No review run was opened: intake refused this delivery: " + record.reason + " (" + RefusalExplanation(record.reason) + ")."
}

// DeliveryRefusalReason returns the reason of a refusal error.
func DeliveryRefusalReason(err error) (string, bool) {
	var refusal *DeliveryRefusal
	if !errors.As(err, &refusal) || !errors.Is(err, ErrDeliveryRefused) {
		return "", false
	}
	return refusal.reason, true
}

// RefusalRecord durably records that one stored delivery was refused by one
// planner identity. It carries identities and a reason token only.
type RefusalRecord struct {
	identity, deliveryIdentity, deduplicationKey string
	plannerIdentity, reason                      string
	scope                                        RepositoryScope
	source                                       Source
	refusedAtMillis                              int64
}

// NewRefusalRecord records a refusal of the stored delivery by plannerIdentity.
func NewRefusalRecord(stored StoredDelivery, plannerIdentity, reason string, at time.Time) (RefusalRecord, error) {
	if stored.Validate() != nil {
		return RefusalRecord{}, ErrInvalidRefusalRecord
	}
	delivery := stored.Delivery()
	record := RefusalRecord{
		deliveryIdentity: delivery.Identity(), deduplicationKey: delivery.DeduplicationKey(),
		plannerIdentity: plannerIdentity, reason: reason, scope: delivery.Scope(), source: delivery.Source(), refusedAtMillis: at.UnixMilli(),
	}
	if at.Before(stored.Receipt().AcceptedAt()) || record.validateFields() != nil {
		return RefusalRecord{}, ErrInvalidRefusalRecord
	}
	record.identity = deriveRefusalIdentity(record)
	return record, nil
}

// RestoreRefusalRecord rebuilds a stored refusal from its fields and accepts
// it only when its recorded identity matches.
func RestoreRefusalRecord(scope RepositoryScope, source Source, deduplicationKey, deliveryIdentity, plannerIdentity, reason string, refusedAtMillis int64, identity string) (RefusalRecord, error) {
	record := RefusalRecord{identity: identity, deliveryIdentity: deliveryIdentity, deduplicationKey: deduplicationKey, plannerIdentity: plannerIdentity, reason: reason, scope: scope, source: source, refusedAtMillis: refusedAtMillis}
	if record.Validate() != nil {
		return RefusalRecord{}, ErrInvalidRefusalRecord
	}
	return record, nil
}

func (r RefusalRecord) Identity() string         { return r.identity }
func (r RefusalRecord) DeliveryIdentity() string { return r.deliveryIdentity }
func (r RefusalRecord) DeduplicationKey() string { return r.deduplicationKey }
func (r RefusalRecord) PlannerIdentity() string  { return r.plannerIdentity }
func (r RefusalRecord) Reason() string           { return r.reason }
func (r RefusalRecord) Scope() RepositoryScope   { return r.scope }
func (r RefusalRecord) Source() Source           { return r.source }
func (r RefusalRecord) RefusedAt() time.Time     { return time.UnixMilli(r.refusedAtMillis).UTC() }
func (r RefusalRecord) RefusedAtMillis() int64   { return r.refusedAtMillis }
func (r RefusalRecord) String() string           { return "webhook delivery refusal record" }
func (r RefusalRecord) GoString() string         { return "webhook.RefusalRecord{<redacted>}" }

// SameRefusal reports whether two records refuse the same delivery for the same
// planner and reason, regardless of when each was recorded.
func (r RefusalRecord) SameRefusal(other RefusalRecord) bool {
	return r.deliveryIdentity == other.deliveryIdentity && r.deduplicationKey == other.deduplicationKey && r.plannerIdentity == other.plannerIdentity &&
		r.reason == other.reason && r.scope.Identity() == other.scope.Identity() && r.source == other.source
}

func (r RefusalRecord) Validate() error {
	if err := r.validateFields(); err != nil {
		return err
	}
	if r.identity != deriveRefusalIdentity(r) {
		return ErrInvalidRefusalRecord
	}
	return nil
}

func (r RefusalRecord) validateFields() error {
	if !validWebhookDigest(r.deliveryIdentity) || !validWebhookDigest(r.deduplicationKey) || !validWebhookDigest(r.plannerIdentity) || !refusalReasonPattern.MatchString(r.reason) ||
		r.scope.Validate() != nil || r.source.Validate() != nil || r.refusedAtMillis <= 0 {
		return ErrInvalidRefusalRecord
	}
	return nil
}

type refusalRecordWire struct {
	Contract         string `json:"contract"`
	SchemaVersion    int    `json:"schema_version"`
	Identity         string `json:"identity"`
	TenantID         string `json:"tenant_id"`
	RepositoryID     string `json:"repository_id"`
	Source           string `json:"source"`
	DeduplicationKey string `json:"deduplication_key"`
	DeliveryIdentity string `json:"delivery_identity"`
	PlannerIdentity  string `json:"planner_identity"`
	Reason           string `json:"reason"`
	RefusedAtMillis  int64  `json:"refused_at_milliseconds"`
}

func refusalRecordWireValue(r RefusalRecord) refusalRecordWire {
	return refusalRecordWire{
		Contract: "open-trestle/webhook-delivery-refusal", SchemaVersion: 1, Identity: r.identity,
		TenantID: r.scope.TenantID(), RepositoryID: r.scope.RepositoryID(), Source: r.source.String(),
		DeduplicationKey: r.deduplicationKey, DeliveryIdentity: r.deliveryIdentity, PlannerIdentity: r.plannerIdentity,
		Reason: r.reason, RefusedAtMillis: r.refusedAtMillis,
	}
}

func deriveRefusalIdentity(r RefusalRecord) string {
	wire := refusalRecordWireValue(r)
	wire.Identity = ""
	encoded, _ := json.Marshal(wire)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// EncodeRefusalRecord returns the one canonical JSON representation.
func EncodeRefusalRecord(r RefusalRecord) ([]byte, error) {
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(refusalRecordWireValue(r))
}

// ParseRefusalRecord accepts only the canonical representation.
func ParseRefusalRecord(encoded []byte) (RefusalRecord, error) {
	if len(encoded) == 0 || len(encoded) > 4096 {
		return RefusalRecord{}, ErrInvalidRefusalRecord
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire refusalRecordWire
	if decoder.Decode(&wire) != nil || !errors.Is(decoder.Decode(&struct{}{}), io.EOF) || wire.Contract != "open-trestle/webhook-delivery-refusal" || wire.SchemaVersion != 1 {
		return RefusalRecord{}, ErrInvalidRefusalRecord
	}
	scope, err := NewRepositoryScope(wire.TenantID, wire.RepositoryID)
	if err != nil {
		return RefusalRecord{}, ErrInvalidRefusalRecord
	}
	source, err := parseSource(wire.Source)
	if err != nil {
		return RefusalRecord{}, ErrInvalidRefusalRecord
	}
	record := RefusalRecord{
		identity: wire.Identity, deliveryIdentity: wire.DeliveryIdentity, deduplicationKey: wire.DeduplicationKey,
		plannerIdentity: wire.PlannerIdentity, reason: wire.Reason, scope: scope, source: source, refusedAtMillis: wire.RefusedAtMillis,
	}
	if record.Validate() != nil {
		return RefusalRecord{}, ErrInvalidRefusalRecord
	}
	canonical, err := EncodeRefusalRecord(record)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return RefusalRecord{}, ErrInvalidRefusalRecord
	}
	return record, nil
}

// RefusalStore durably records refusals beside the deliveries it stores, at
// most one per delivery, naming the planner identity that recorded it.
// RecordRefusal creates a record for a stored delivery once; recording the
// same refusal again returns the first record unchanged, a different reason
// for the same delivery and planner is ErrRefusalConflict, and a refusal by
// another planner identity replaces the superseded record. Refusal returns
// the record only for the planner that recorded it; RecordedRefusal returns it
// whichever planner did, and ClearRefusal removes it only for its planner.
type RefusalStore interface {
	RecordRefusal(context.Context, RefusalRecord) (RefusalRecord, bool, error)
	Refusal(ctx context.Context, scope RepositoryScope, source Source, deduplicationKey, plannerIdentity string) (RefusalRecord, bool, error)
	RecordedRefusal(ctx context.Context, scope RepositoryScope, source Source, deduplicationKey string) (RefusalRecord, bool, error)
	ClearRefusal(ctx context.Context, scope RepositoryScope, source Source, deduplicationKey, plannerIdentity string) error
}
