package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

func investigationAuditKind(t *testing.T, token string) EventKind {
	t.Helper()
	kind, err := ParseEventKind(token)
	if err != nil || kind.String() != token || kind.Validate() != nil {
		t.Fatalf("audit token %q is not recognized", token)
	}
	return kind
}

// These are inert event-codec fixtures, not issued operation claims or tool results.
func investigationAuditEvent(t *testing.T, scope ReviewScope, sequence uint64, previous, token, subject string, parents []string) Event {
	t.Helper()
	value, err := NewEvent(scope, sequence, previous, investigationAuditKind(t, token), subject, parents, time.UnixMilli(100+int64(sequence)))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestInvestigationAuditTokensRoundTripCompleteEventSyntax(t *testing.T) {
	scope, err := NewReviewScope("tenant-a", "repo-a", "run-token")
	if err != nil {
		t.Fatal(err)
	}
	operation, result := strings.Repeat("9", 64), strings.Repeat("8", 64)
	claimed := investigationAuditEvent(t, scope, 1, "", "investigation_tool_claimed", operation,
		[]string{strings.Repeat("e", 64), strings.Repeat("d", 64), strings.Repeat("c", 64), strings.Repeat("b", 64), strings.Repeat("a", 64)})
	completed := investigationAuditEvent(t, scope, 2, claimed.Identity(), "investigation_tool_completed", result,
		[]string{operation, strings.Repeat("c", 64), strings.Repeat("b", 64)})
	for i, value := range []Event{claimed, completed} {
		if uint8(value.Kind()) != uint8(21+i) || value.Validate() != nil {
			t.Fatal("new audit kinds did not append after the existing twenty values")
		}
		encoded, err := EncodeEvent(value)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := ParseEvent(encoded)
		if err != nil || !reflect.DeepEqual(parsed, value) {
			t.Fatal("new audit token lost exact event fields or identity")
		}
		reencoded, err := EncodeEvent(parsed)
		if err != nil || !bytes.Equal(encoded, reencoded) {
			t.Fatal("new audit token readback was not canonical")
		}
		parents := parsed.CausalParentIdentities()
		for j := 1; j < len(parents); j++ {
			if parents[j-1] >= parents[j] {
				t.Fatal("event causal parents lost canonical ordering")
			}
		}
		parents[0] = strings.Repeat("f", 64)
		encoded[0] = 'x'
		if parsed.Validate() != nil || !reflect.DeepEqual(parsed, value) {
			t.Fatal("event readback aliases caller storage")
		}
	}
	if claimed.SubjectIdentity() != operation || completed.SubjectIdentity() != result || completed.PreviousIdentity() != claimed.Identity() {
		t.Fatal("token codec changed subjects or chain linkage")
	}
}

func TestInvestigationAuditTokenNearMissesRefuse(t *testing.T) {
	for _, token := range []string{"", "investigation_tool_claim", "investigation_tool_complete", "investigation_tool_result", "tool_claimed", "Investigation_tool_claimed", "investigation-tool-claimed", " investigation_tool_claimed", "investigation_tool_completed\n", "investigation_tool_completed\x00"} {
		kind, err := ParseEventKind(token)
		if !errors.Is(err, ErrInvalidAuditEventKind) || kind != 0 {
			t.Fatal("unknown or near-miss audit token admitted")
		}
	}
}

func TestInvestigationAuditEventsKeepScopeSubjectParentAndTimeBounds(t *testing.T) {
	scope, err := NewReviewScope("tenant-a", "repo-a", "run-token")
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{"investigation_tool_claimed", "investigation_tool_completed"} {
		value := investigationAuditEvent(t, scope, 1, "", token, strings.Repeat("a", 64), []string{strings.Repeat("b", 64), strings.Repeat("c", 64)})
		for name, change := range map[string]func(*eventRecord){
			"scope":          func(r *eventRecord) { r.TenantID = "tenant-b" },
			"subject":        func(r *eventRecord) { r.SubjectIdentity = strings.Repeat("d", 64) },
			"subject syntax": func(r *eventRecord) { r.SubjectIdentity = "not-an-identity" },
			"parent":         func(r *eventRecord) { r.CausalParentIdentities[0] = strings.Repeat("d", 64) },
			"parent order": func(r *eventRecord) {
				r.CausalParentIdentities[0], r.CausalParentIdentities[1] = r.CausalParentIdentities[1], r.CausalParentIdentities[0]
			},
			"duplicate parent":    func(r *eventRecord) { r.CausalParentIdentities[0] = r.CausalParentIdentities[1] },
			"first predecessor":   func(r *eventRecord) { r.PreviousIdentity = strings.Repeat("d", 64) },
			"missing predecessor": func(r *eventRecord) { r.Sequence = 2 },
			"zero sequence":       func(r *eventRecord) { r.Sequence = 0 },
			"zero time":           func(r *eventRecord) { r.OccurredAtUnixMilliseconds = 0 },
			"time ceiling":        func(r *eventRecord) { r.OccurredAtUnixMilliseconds = 253402300800000 },
			"unknown kind":        func(r *eventRecord) { r.Kind = "investigation_unknown" },
		} {
			t.Run(token+"/"+name, func(t *testing.T) {
				wire := eventRecordFromEvent(value)
				change(&wire)
				encoded, err := json.Marshal(wire)
				if err != nil {
					t.Fatal(err)
				}
				if parsed, err := ParseEvent(encoded); err == nil || parsed.Identity() != "" {
					t.Fatal("inconsistent event syntax admitted")
				}
			})
		}
		kind := value.Kind()
		if event, err := NewEvent(ReviewScope{}, 1, "", kind, value.SubjectIdentity(), nil, time.UnixMilli(100)); err == nil || event.Identity() != "" {
			t.Fatal("new token bypassed scope validation")
		}
		parents := make([]string, 17)
		for i := 0; i < 16; i++ {
			parents[i] = strings.Repeat("a", 63) + string("0123456789abcdef"[i])
		}
		if bounded, err := NewEvent(scope, 1, "", kind, value.SubjectIdentity(), parents[:16], time.UnixMilli(100)); err != nil || bounded.Validate() != nil {
			t.Fatal("exact causal-parent count boundary refused")
		}
		parents[16] = strings.Repeat("b", 64)
		if _, err := NewEvent(scope, 1, "", kind, value.SubjectIdentity(), parents, time.UnixMilli(100)); !errors.Is(err, ErrTooManyAuditCausalParents) {
			t.Fatal("new token bypassed causal-parent count bound")
		}
	}
	if maxEncodedAuditEventBytes != 32<<10 || maxAuditStreamBytes != 64<<20 || maxAuditStreamEvents != 10000 || maxAuditReadEvents != 1000 {
		t.Fatal("token extension changed existing event or stream bounds")
	}
	if _, err := ParseEvent(bytes.Repeat([]byte{' '}, (32<<10)+1)); !errors.Is(err, ErrInvalidAuditEventEncoding) {
		t.Fatal("event byte cap ignored")
	}
}

func TestInvestigationAuditFileLedgerPersistsTokensWithoutOperationDeduplication(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	ledger, err := NewFileLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	defer ledger.Close()
	scope, err := NewReviewScope("tenant-a", "repo-a", "run-token")
	if err != nil {
		t.Fatal(err)
	}
	operation := strings.Repeat("a", 64)
	first := investigationAuditEvent(t, scope, 1, "", "investigation_tool_claimed", operation, nil)
	second := investigationAuditEvent(t, scope, 2, first.Identity(), "investigation_tool_completed", strings.Repeat("b", 64), []string{operation})
	for _, event := range []Event{first, second} {
		if err := ledger.Append(ctx, event.PreviousIdentity(), event); err != nil {
			t.Fatal("actual ledger refused canonical token event")
		}
	}
	third := investigationAuditEvent(t, scope, 3, second.Identity(), "investigation_tool_claimed", operation, nil)
	if err := ledger.Append(ctx, first.Identity(), third); !errors.Is(err, ErrAuditHeadConflict) {
		t.Fatal("new token bypassed atomic expected-head checking")
	}
	wrongSequence := investigationAuditEvent(t, scope, 4, second.Identity(), "investigation_tool_claimed", operation, nil)
	if err := ledger.Append(ctx, second.Identity(), wrongSequence); !errors.Is(err, ErrAuditChainMismatch) {
		t.Fatal("new token bypassed sequence checking")
	}
	// Appendable event syntax does not implement an operation-identity claim guard.
	if err := ledger.Append(ctx, second.Identity(), third); err != nil {
		t.Fatal("generic ledger unexpectedly adjudicated repeated operation subject")
	}
	if err := ledger.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileLedger(root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	events, err := reopened.Read(ctx, scope, 0, 10)
	if err != nil || len(events) != 3 {
		t.Fatal("new audit tokens did not survive file close and reopen")
	}
	for i, expected := range []Event{first, second, third} {
		if !reflect.DeepEqual(events[i], expected) {
			t.Fatal("file readback changed token, scope, subject, parents or chain")
		}
	}
	page, err := reopened.Read(ctx, scope, 1, 1)
	if err != nil || len(page) != 1 || page[0].Identity() != second.Identity() {
		t.Fatal("token extension changed bounded pagination")
	}
	if _, err := reopened.Read(ctx, scope, 0, 1001); !errors.Is(err, ErrInvalidAuditReadLimit) {
		t.Fatal("token extension widened ledger read bounds")
	}
	other, err := NewReviewScope("tenant-b", "repo-a", "run-token")
	if err != nil {
		t.Fatal(err)
	}
	if events, err := reopened.Read(ctx, other, 0, 10); err != nil || len(events) != 0 {
		t.Fatal("new audit tokens crossed scope partitions")
	}
	contents, err := os.ReadFile(reopened.streamPath(scope))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reopened.streamPath(other), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if events, err := reopened.Read(ctx, other, 0, 10); !errors.Is(err, ErrCorruptAuditStream) || events != nil {
		t.Fatal("file readback accepted cross-scoped token records")
	}
}

func TestInvestigationAuditAdditionPreservesOldKindsAndEventRecipe(t *testing.T) {
	kinds := []EventKind{EventRouteSelected, EventRouteAttemptClaimed, EventRouteDispatchCompleted, EventRouteCostReconciled, EventRouteContinuationPlanned, EventContextSourcesSelected, EventContextPacketAssembled, EventCandidateBatchAdmitted, EventVerificationContextAssembled, EventVerificationBatchAdmitted, EventIndependentVerificationCompleted, EventPublicationReadinessEvaluated, EventPublicationAuthorized, EventPublicationClaimed, EventPublicationHeadReconciled, EventPublicationCompleted, EventPublicationRetryAuthorized, EventReviewSnapshotBound, EventContextAcquisitionBound, EventArtifactDeleted}
	tokens := []string{"route_selected", "route_attempt_claimed", "route_dispatch_completed", "route_cost_reconciled", "route_continuation_planned", "context_sources_selected", "context_packet_assembled", "candidate_batch_admitted", "verification_context_assembled", "verification_batch_admitted", "independent_verification_completed", "publication_readiness_evaluated", "publication_authorized", "publication_claimed", "publication_head_reconciled", "publication_completed", "publication_retry_authorized", "review_snapshot_bound", "context_acquisition_bound", "artifact_deleted"}
	for i, kind := range kinds {
		parsed, err := ParseEventKind(tokens[i])
		if uint8(kind) != uint8(i+1) || kind.String() != tokens[i] || err != nil || parsed != kind {
			t.Fatal("existing audit enum value or spelling changed")
		}
	}
	// Preserve the original event_test.go fixture and its exact preimage ordering.
	scope, err := NewReviewScope("tenant-1", "repo-1", "run-1")
	if err != nil {
		t.Fatal(err)
	}
	scopeDigest := sha256.Sum256([]byte(`{"contract":"open-trestle/audit-review-scope","version":1,"tenant":"tenant-1","repository":"repo-1","review_run":"run-1"}`))
	if scope.Identity() != hex.EncodeToString(scopeDigest[:]) {
		t.Fatal("old scope identity recipe changed")
	}
	a, b, subject := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	preimage := []byte(`{"identity":"","scope_identity":"` + scope.Identity() + `","tenant_id":"tenant-1","repository_id":"repo-1","review_run_id":"run-1","sequence":1,"previous_identity":"","kind":"route_selected","subject_identity":"` + subject + `","causal_parent_identities":["` + a + `","` + b + `"],"occurred_at_unix_milliseconds":1700000000123}`)
	digest := sha256.Sum256(preimage)
	identity := hex.EncodeToString(digest[:])
	canonical := bytes.Replace(preimage, []byte(`"identity":""`), []byte(`"identity":"`+identity+`"`), 1)
	old, err := NewEvent(scope, 1, "", EventRouteSelected, subject, []string{b, a}, time.UnixMilli(1700000000123))
	if err != nil || old.Identity() != identity {
		t.Fatal("old event fixture identity changed")
	}
	encoded, err := EncodeEvent(old)
	if err != nil || !bytes.Equal(encoded, canonical) {
		t.Fatal("old event fixture canonical bytes changed")
	}
	parsed, err := ParseEvent(canonical)
	if err != nil || !reflect.DeepEqual(parsed, old) {
		t.Fatal("old event fixture readback changed")
	}
}
