package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

const (
	maxAuditScopeIdentifierBytes  = 128
	maxAuditCausalParents         = 16
	maxEncodedAuditEventBytes     = 32 << 10
	maxAuditEventUnixMilliseconds = int64(253_402_300_799_999)
)

var (
	// ErrInvalidAuditScopeIdentifier identifies a missing or noncanonical tenant, repository, or run ID.
	ErrInvalidAuditScopeIdentifier = errors.New("invalid audit scope identifier")
	// ErrInvalidAuditScopeIdentity identifies scope content inconsistent with its identity.
	ErrInvalidAuditScopeIdentity = errors.New("invalid audit scope identity")
	// ErrInvalidAuditEventKind identifies an unknown audit transition.
	ErrInvalidAuditEventKind = errors.New("invalid audit event kind")
	// ErrInvalidAuditSequence identifies a zero or non-next stream sequence.
	ErrInvalidAuditSequence = errors.New("invalid audit event sequence")
	// ErrInvalidAuditPreviousIdentity identifies a missing, malformed, or unexpected predecessor.
	ErrInvalidAuditPreviousIdentity = errors.New("invalid audit previous identity")
	// ErrInvalidAuditSubjectIdentity identifies a malformed receipt identity.
	ErrInvalidAuditSubjectIdentity = errors.New("invalid audit subject identity")
	// ErrTooManyAuditCausalParents identifies an event beyond the reference-count bound.
	ErrTooManyAuditCausalParents = errors.New("too many audit causal parents")
	// ErrDuplicateAuditCausalParent identifies duplicate or noncanonical references.
	ErrDuplicateAuditCausalParent = errors.New("duplicate audit causal parent")
	// ErrInvalidAuditEventTime identifies a missing or out-of-range timestamp.
	ErrInvalidAuditEventTime = errors.New("invalid audit event time")
	// ErrInvalidAuditEventIdentity identifies event content inconsistent with its identity.
	ErrInvalidAuditEventIdentity = errors.New("invalid audit event identity")
	// ErrInvalidAuditEventEncoding identifies noncanonical or excessive serialized data.
	ErrInvalidAuditEventEncoding = errors.New("invalid audit event encoding")
)

// ReviewScope identifies one tenant-owned repository review stream.
type ReviewScope struct {
	identity     string
	tenantID     string
	repositoryID string
	reviewRunID  string
}

// NewReviewScope creates one immutable tenant, repository, and review-run scope.
func NewReviewScope(tenantID, repositoryID, reviewRunID string) (ReviewScope, error) {
	for _, identifier := range []string{tenantID, repositoryID, reviewRunID} {
		if !validAuditScopeIdentifier(identifier) {
			return ReviewScope{}, ErrInvalidAuditScopeIdentifier
		}
	}
	scope := ReviewScope{
		tenantID: strings.Clone(tenantID), repositoryID: strings.Clone(repositoryID), reviewRunID: strings.Clone(reviewRunID),
	}
	scope.identity = deriveReviewScopeIdentity(scope)
	return scope, nil
}

func (s ReviewScope) Identity() string     { return s.identity }
func (s ReviewScope) TenantID() string     { return s.tenantID }
func (s ReviewScope) RepositoryID() string { return s.repositoryID }
func (s ReviewScope) ReviewRunID() string  { return s.reviewRunID }
func (s ReviewScope) String() string       { return "audit review scope" }
func (s ReviewScope) GoString() string     { return "audit.ReviewScope{<redacted>}" }
func (s ReviewScope) Format(state fmt.State, verb rune) {
	formatted := "audit review scope"
	if verb == 'q' {
		formatted = `"audit review scope"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "audit.ReviewScope{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

func (s ReviewScope) Validate() error {
	for _, identifier := range []string{s.tenantID, s.repositoryID, s.reviewRunID} {
		if !validAuditScopeIdentifier(identifier) {
			return ErrInvalidAuditScopeIdentifier
		}
	}
	if s.identity != deriveReviewScopeIdentity(s) {
		return ErrInvalidAuditScopeIdentity
	}
	return nil
}

func validAuditScopeIdentifier(value string) bool {
	if len(value) == 0 || len(value) > maxAuditScopeIdentifierBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	first, last := value[0], value[len(value)-1]
	return isAuditIdentifierAlphaNumeric(first) && isAuditIdentifierAlphaNumeric(last)
}

func isAuditIdentifierAlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}

func deriveReviewScopeIdentity(scope ReviewScope) string {
	preimage := struct {
		Contract   string `json:"contract"`
		Version    int    `json:"version"`
		Tenant     string `json:"tenant"`
		Repository string `json:"repository"`
		ReviewRun  string `json:"review_run"`
	}{
		Contract: "open-trestle/audit-review-scope", Version: 1,
		Tenant: scope.tenantID, Repository: scope.repositoryID, ReviewRun: scope.reviewRunID,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// EventKind identifies one content-free review runtime audit transition.
type EventKind uint8

const (
	EventRouteSelected EventKind = iota + 1
	EventRouteAttemptClaimed
	EventRouteDispatchCompleted
	EventRouteCostReconciled
	EventRouteContinuationPlanned
	EventContextSourcesSelected
	EventContextPacketAssembled
	EventCandidateBatchAdmitted
	EventVerificationContextAssembled
	EventVerificationBatchAdmitted
	EventIndependentVerificationCompleted
	EventPublicationReadinessEvaluated
	EventPublicationAuthorized
	EventPublicationClaimed
	EventPublicationHeadReconciled
	EventPublicationCompleted
	EventPublicationRetryAuthorized
	EventReviewSnapshotBound
	EventContextAcquisitionBound
	EventArtifactDeleted
	EventInvestigationToolClaimed
	EventInvestigationToolCompleted
)

func (k EventKind) String() string {
	switch k {
	case EventRouteSelected:
		return "route_selected"
	case EventRouteAttemptClaimed:
		return "route_attempt_claimed"
	case EventRouteDispatchCompleted:
		return "route_dispatch_completed"
	case EventRouteCostReconciled:
		return "route_cost_reconciled"
	case EventRouteContinuationPlanned:
		return "route_continuation_planned"
	case EventContextSourcesSelected:
		return "context_sources_selected"
	case EventContextPacketAssembled:
		return "context_packet_assembled"
	case EventCandidateBatchAdmitted:
		return "candidate_batch_admitted"
	case EventVerificationContextAssembled:
		return "verification_context_assembled"
	case EventVerificationBatchAdmitted:
		return "verification_batch_admitted"
	case EventIndependentVerificationCompleted:
		return "independent_verification_completed"
	case EventPublicationReadinessEvaluated:
		return "publication_readiness_evaluated"
	case EventPublicationAuthorized:
		return "publication_authorized"
	case EventPublicationClaimed:
		return "publication_claimed"
	case EventPublicationHeadReconciled:
		return "publication_head_reconciled"
	case EventPublicationCompleted:
		return "publication_completed"
	case EventPublicationRetryAuthorized:
		return "publication_retry_authorized"
	case EventReviewSnapshotBound:
		return "review_snapshot_bound"
	case EventContextAcquisitionBound:
		return "context_acquisition_bound"
	case EventArtifactDeleted:
		return "artifact_deleted"
	case EventInvestigationToolClaimed:
		return "investigation_tool_claimed"
	case EventInvestigationToolCompleted:
		return "investigation_tool_completed"
	default:
		return ""
	}
}

func ParseEventKind(value string) (EventKind, error) {
	for kind := EventRouteSelected; kind <= EventInvestigationToolCompleted; kind++ {
		if kind.String() == value {
			return kind, nil
		}
	}
	return 0, fmt.Errorf("parse audit event kind: %w", ErrInvalidAuditEventKind)
}

func (k EventKind) Validate() error {
	if k.String() == "" {
		return ErrInvalidAuditEventKind
	}
	return nil
}

// Event is one immutable content-addressed member of an append-only review stream.
type Event struct {
	identity                   string
	scope                      ReviewScope
	sequence                   uint64
	previousIdentity           string
	kind                       EventKind
	subjectIdentity            string
	causalParentIdentities     []string
	occurredAtUnixMilliseconds int64
}

// NewEvent creates one event with canonical causal-parent ordering.
func NewEvent(scope ReviewScope, sequence uint64, previousIdentity string, kind EventKind, subjectIdentity string, causalParentIdentities []string, occurredAt time.Time) (Event, error) {
	parents := append([]string(nil), causalParentIdentities...)
	if len(parents) > maxAuditCausalParents {
		return Event{}, ErrTooManyAuditCausalParents
	}
	sort.Strings(parents)
	event := Event{
		scope: scope, sequence: sequence, previousIdentity: strings.Clone(previousIdentity), kind: kind,
		subjectIdentity: strings.Clone(subjectIdentity), causalParentIdentities: parents,
		occurredAtUnixMilliseconds: occurredAt.UnixMilli(),
	}
	if err := event.validateFields(); err != nil {
		return Event{}, err
	}
	event.identity = deriveEventIdentity(event)
	return event, nil
}

func (e Event) Identity() string                  { return e.identity }
func (e Event) Scope() ReviewScope                { return e.scope }
func (e Event) Sequence() uint64                  { return e.sequence }
func (e Event) PreviousIdentity() string          { return e.previousIdentity }
func (e Event) Kind() EventKind                   { return e.kind }
func (e Event) SubjectIdentity() string           { return e.subjectIdentity }
func (e Event) OccurredAtUnixMilliseconds() int64 { return e.occurredAtUnixMilliseconds }
func (e Event) CausalParentIdentities() []string {
	return append([]string(nil), e.causalParentIdentities...)
}
func (e Event) String() string   { return "audit event" }
func (e Event) GoString() string { return "audit.Event{<redacted>}" }
func (e Event) Format(state fmt.State, verb rune) {
	formatted := "audit event"
	if verb == 'q' {
		formatted = `"audit event"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "audit.Event{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

func (e Event) Validate() error {
	if err := e.validateFields(); err != nil {
		return err
	}
	if e.identity != deriveEventIdentity(e) {
		return ErrInvalidAuditEventIdentity
	}
	return nil
}

func (e Event) validateFields() error {
	if err := e.scope.Validate(); err != nil {
		return err
	}
	if e.sequence == 0 {
		return ErrInvalidAuditSequence
	}
	if e.sequence == 1 && e.previousIdentity != "" || e.sequence > 1 && !validAuditIdentity(e.previousIdentity) {
		return ErrInvalidAuditPreviousIdentity
	}
	if err := e.kind.Validate(); err != nil {
		return err
	}
	if !validAuditIdentity(e.subjectIdentity) {
		return ErrInvalidAuditSubjectIdentity
	}
	if len(e.causalParentIdentities) > maxAuditCausalParents {
		return ErrTooManyAuditCausalParents
	}
	previous := ""
	for _, identity := range e.causalParentIdentities {
		if !validAuditIdentity(identity) {
			return ErrInvalidAuditSubjectIdentity
		}
		if previous != "" && identity <= previous {
			return ErrDuplicateAuditCausalParent
		}
		previous = identity
	}
	if e.occurredAtUnixMilliseconds <= 0 || e.occurredAtUnixMilliseconds > maxAuditEventUnixMilliseconds {
		return ErrInvalidAuditEventTime
	}
	return nil
}

func validAuditIdentity(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for index := range value {
		character := value[index]
		if character >= '0' && character <= '9' || character >= 'a' && character <= 'f' {
			continue
		}
		return false
	}
	return true
}

func deriveEventIdentity(event Event) string {
	record := eventRecordFromEvent(event)
	record.Identity = ""
	encoded, _ := json.Marshal(record)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

type eventRecord struct {
	Identity                   string   `json:"identity"`
	ScopeIdentity              string   `json:"scope_identity"`
	TenantID                   string   `json:"tenant_id"`
	RepositoryID               string   `json:"repository_id"`
	ReviewRunID                string   `json:"review_run_id"`
	Sequence                   uint64   `json:"sequence"`
	PreviousIdentity           string   `json:"previous_identity"`
	Kind                       string   `json:"kind"`
	SubjectIdentity            string   `json:"subject_identity"`
	CausalParentIdentities     []string `json:"causal_parent_identities"`
	OccurredAtUnixMilliseconds int64    `json:"occurred_at_unix_milliseconds"`
}

func eventRecordFromEvent(event Event) eventRecord {
	return eventRecord{
		Identity: event.identity, ScopeIdentity: event.scope.identity,
		TenantID: event.scope.tenantID, RepositoryID: event.scope.repositoryID, ReviewRunID: event.scope.reviewRunID,
		Sequence: event.sequence, PreviousIdentity: event.previousIdentity, Kind: event.kind.String(),
		SubjectIdentity:            event.subjectIdentity,
		CausalParentIdentities:     append([]string(nil), event.causalParentIdentities...),
		OccurredAtUnixMilliseconds: event.occurredAtUnixMilliseconds,
	}
}

// EncodeEvent returns the canonical bounded JSON storage record.
func EncodeEvent(event Event) ([]byte, error) {
	if err := event.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(eventRecordFromEvent(event))
	if err != nil {
		return nil, fmt.Errorf("encode audit event: %w", err)
	}
	return encoded, nil
}

// ParseEvent validates one strict canonical JSON storage record.
func ParseEvent(encoded []byte) (Event, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedAuditEventBytes {
		return Event{}, ErrInvalidAuditEventEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record eventRecord
	if err := decoder.Decode(&record); err != nil {
		return Event{}, fmt.Errorf("%w: %v", ErrInvalidAuditEventEncoding, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Event{}, ErrInvalidAuditEventEncoding
	}
	if len(record.CausalParentIdentities) == 0 {
		record.CausalParentIdentities = nil
	}
	kind, err := ParseEventKind(record.Kind)
	if err != nil {
		return Event{}, err
	}
	scope := ReviewScope{
		identity: record.ScopeIdentity, tenantID: record.TenantID,
		repositoryID: record.RepositoryID, reviewRunID: record.ReviewRunID,
	}
	event := Event{
		identity: record.Identity, scope: scope, sequence: record.Sequence,
		previousIdentity: record.PreviousIdentity, kind: kind, subjectIdentity: record.SubjectIdentity,
		causalParentIdentities:     append([]string(nil), record.CausalParentIdentities...),
		occurredAtUnixMilliseconds: record.OccurredAtUnixMilliseconds,
	}
	if err := event.Validate(); err != nil {
		return Event{}, err
	}
	canonical, err := json.Marshal(eventRecordFromEvent(event))
	if err != nil || !bytes.Equal(encoded, canonical) {
		return Event{}, ErrInvalidAuditEventEncoding
	}
	return event, nil
}
