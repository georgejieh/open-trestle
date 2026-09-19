package audit

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNewReviewScopeIsContentAddressedAndRedacted(t *testing.T) {
	scope, err := NewReviewScope("tenant-1", "repo:42", "run_abc")
	if err != nil {
		t.Fatal(err)
	}
	if scope.Identity() == "" || scope.TenantID() != "tenant-1" || scope.RepositoryID() != "repo:42" || scope.ReviewRunID() != "run_abc" || scope.Validate() != nil {
		t.Fatalf("scope did not round trip: %#v", scope)
	}
	other, _ := NewReviewScope("tenant-1", "repo:42", "run_def")
	if other.Identity() == scope.Identity() {
		t.Fatal("scope identity ignored review run")
	}
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v"} {
		formatted := fmt.Sprintf(format, scope)
		if strings.Contains(formatted, "tenant-1") || strings.Contains(formatted, "repo:42") || strings.Contains(formatted, "run_abc") {
			t.Fatalf("scope formatting leaked identifiers: %q", formatted)
		}
	}
}

func TestNewReviewScopeRejectsInvalidIdentifiers(t *testing.T) {
	for _, test := range []struct{ tenant, repository, run string }{
		{"", "repo", "run"}, {"Tenant", "repo", "run"}, {"tenant", "../repo", "run"},
		{"tenant", "repo", "run with space"}, {strings.Repeat("a", maxAuditScopeIdentifierBytes+1), "repo", "run"},
	} {
		if scope, err := NewReviewScope(test.tenant, test.repository, test.run); !errors.Is(err, ErrInvalidAuditScopeIdentifier) || scope.Identity() != "" {
			t.Fatalf("NewReviewScope(%q,%q,%q) = (%#v, %v)", test.tenant, test.repository, test.run, scope, err)
		}
	}
}

func TestAuditEventKindsRoundTrip(t *testing.T) {
	values := []string{
		"route_selected", "route_attempt_claimed", "route_dispatch_completed", "route_cost_reconciled", "route_continuation_planned",
		"context_sources_selected", "context_packet_assembled", "candidate_batch_admitted", "verification_context_assembled",
		"verification_batch_admitted", "independent_verification_completed", "publication_readiness_evaluated",
		"publication_authorized", "publication_claimed", "publication_head_reconciled", "publication_completed", "publication_retry_authorized", "review_snapshot_bound", "context_acquisition_bound",
	}
	for _, value := range values {
		kind, err := ParseEventKind(value)
		if err != nil || kind.String() != value || kind.Validate() != nil {
			t.Fatalf("ParseEventKind(%q) = (%v, %v)", value, kind, err)
		}
	}
	if kind, err := ParseEventKind("unknown"); !errors.Is(err, ErrInvalidAuditEventKind) || kind != 0 {
		t.Fatalf("invalid kind = (%v, %v)", kind, err)
	}
}

func TestNewEventCanonicalizesCausalParentsAndRoundTripsJSON(t *testing.T) {
	scope, _ := NewReviewScope("tenant-1", "repo-1", "run-1")
	parentA := strings.Repeat("a", 64)
	parentB := strings.Repeat("b", 64)
	subject := strings.Repeat("c", 64)
	event, err := NewEvent(scope, 1, "", EventRouteSelected, subject, []string{parentB, parentA}, time.UnixMilli(1_700_000_000_123))
	if err != nil {
		t.Fatal(err)
	}
	if event.Identity() == "" || event.Scope() != scope || event.Sequence() != 1 || event.PreviousIdentity() != "" || event.Kind() != EventRouteSelected || event.SubjectIdentity() != subject || event.OccurredAtUnixMilliseconds() != 1_700_000_000_123 || event.Validate() != nil || !reflect.DeepEqual(event.CausalParentIdentities(), []string{parentA, parentB}) {
		t.Fatalf("event did not round trip: %#v", event)
	}
	parents := event.CausalParentIdentities()
	parents[0] = strings.Repeat("d", 64)
	if event.CausalParentIdentities()[0] != parentA {
		t.Fatal("event exposed mutable causal parents")
	}
	encoded, err := EncodeEvent(event)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseEvent(encoded)
	if err != nil || !reflect.DeepEqual(parsed, event) {
		t.Fatalf("ParseEvent() = (%#v, %v)", parsed, err)
	}
	if bytes := string(encoded); !strings.Contains(bytes, `"tenant_id":"tenant-1"`) || strings.Contains(bytes, "payload") {
		t.Fatalf("encoded event omitted scope or added content field: %s", bytes)
	}
}

func TestNewEventEnforcesChainAndContentBounds(t *testing.T) {
	scope, _ := NewReviewScope("tenant", "repo", "run")
	id := strings.Repeat("a", 64)
	tests := []struct {
		name     string
		sequence uint64
		previous string
		kind     EventKind
		subject  string
		parents  []string
		when     time.Time
		want     error
	}{
		{"zero sequence", 0, "", EventRouteSelected, id, nil, time.UnixMilli(1), ErrInvalidAuditSequence},
		{"first previous", 1, id, EventRouteSelected, id, nil, time.UnixMilli(1), ErrInvalidAuditPreviousIdentity},
		{"missing previous", 2, "", EventRouteSelected, id, nil, time.UnixMilli(1), ErrInvalidAuditPreviousIdentity},
		{"kind", 1, "", 0, id, nil, time.UnixMilli(1), ErrInvalidAuditEventKind},
		{"subject", 1, "", EventRouteSelected, "x", nil, time.UnixMilli(1), ErrInvalidAuditSubjectIdentity},
		{"duplicate parent", 1, "", EventRouteSelected, id, []string{id, id}, time.UnixMilli(1), ErrDuplicateAuditCausalParent},
		{"many parents", 1, "", EventRouteSelected, id, make([]string, maxAuditCausalParents+1), time.UnixMilli(1), ErrTooManyAuditCausalParents},
		{"time", 1, "", EventRouteSelected, id, nil, time.Time{}, ErrInvalidAuditEventTime},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			event, err := NewEvent(scope, test.sequence, test.previous, test.kind, test.subject, test.parents, test.when)
			if !errors.Is(err, test.want) || event.Identity() != "" {
				t.Fatalf("NewEvent() = (%#v, %v), want %v", event, err, test.want)
			}
		})
	}
}

func TestParseEventRejectsUnknownAndTamperedFields(t *testing.T) {
	scope, _ := NewReviewScope("tenant", "repo", "run")
	event, _ := NewEvent(scope, 1, "", EventRouteSelected, strings.Repeat("a", 64), nil, time.UnixMilli(1))
	encoded, _ := EncodeEvent(event)
	unknown := strings.Replace(string(encoded), `"sequence":1`, `"sequence":1,"extra":true`, 1)
	if parsed, err := ParseEvent([]byte(unknown)); !errors.Is(err, ErrInvalidAuditEventEncoding) || parsed.Identity() != "" {
		t.Fatalf("unknown field = (%#v, %v)", parsed, err)
	}
	tampered := strings.Replace(string(encoded), `"subject_identity":"`+strings.Repeat("a", 64)+`"`, `"subject_identity":"`+strings.Repeat("b", 64)+`"`, 1)
	if parsed, err := ParseEvent([]byte(tampered)); !errors.Is(err, ErrInvalidAuditEventIdentity) || parsed.Identity() != "" {
		t.Fatalf("tampered event = (%#v, %v)", parsed, err)
	}
}
