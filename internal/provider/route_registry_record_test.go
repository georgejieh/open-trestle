package provider

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

const routeRegistryEvidenceDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func mustRouteRegistryCandidate(t *testing.T, logging ContentLoggingMode) RouteCandidateDeclaration {
	t.Helper()
	candidate, err := NewRouteCandidateDeclaration(mustRouteCandidateCapability(t), logging, NewUnknownRoutePricing(), RouteQualityTier1)
	if err != nil {
		t.Fatal(err)
	}
	return candidate
}

func TestRouteRegistryStatusRoundTrips(t *testing.T) {
	statuses := []struct {
		status RouteRegistryStatus
		name   string
	}{
		{RouteRegistryPending, "pending"},
		{RouteRegistryApproved, "approved"},
		{RouteRegistryDegraded, "degraded"},
		{RouteRegistryDisabled, "disabled"},
	}
	for _, test := range statuses {
		parsed, err := ParseRouteRegistryStatus(test.name)
		if err != nil || parsed != test.status || parsed.String() != test.name || parsed.Validate() != nil {
			t.Fatalf("status %q round trip = (%v, %v, %q)", test.name, parsed, err, parsed.String())
		}
	}
	for _, value := range []string{"", "approved ", "APPROVED", "active"} {
		status, err := ParseRouteRegistryStatus(value)
		if !errors.Is(err, ErrInvalidRouteRegistryStatus) || status != 0 {
			t.Fatalf("ParseRouteRegistryStatus(%q) = (%v, %v)", value, status, err)
		}
	}
}

func TestNewRouteRegistryRecordBindsVersionedEvidence(t *testing.T) {
	candidate := mustRouteRegistryCandidate(t, ContentLoggingDisabled)
	record, err := NewRouteRegistryRecord(7, candidate, RouteRegistryApproved, routeRegistryEvidenceDigest)
	if err != nil {
		t.Fatal(err)
	}
	if record.RegistryRevision() != 7 || record.RouteCandidateDeclaration() != candidate || record.Status() != RouteRegistryApproved || record.EvidenceManifestDigest() != routeRegistryEvidenceDigest || len(record.Identity()) != 64 || record.Validate() != nil {
		t.Fatal("route registry record does not round trip")
	}
	copied := record
	if copied != record {
		t.Fatal("copied route registry record changed")
	}
}

func TestRouteRegistryRecordIdentityBindsEveryField(t *testing.T) {
	disabled := mustRouteRegistryCandidate(t, ContentLoggingDisabled)
	enabled := mustRouteRegistryCandidate(t, ContentLoggingEnabled)
	knownPricing, _ := NewRoutePricing(10, 20)
	priced, _ := NewRouteCandidateDeclaration(mustRouteCandidateCapability(t), ContentLoggingDisabled, knownPricing, RouteQualityTier1)
	otherPricing, _ := NewRoutePricing(11, 20)
	otherPriced, _ := NewRouteCandidateDeclaration(mustRouteCandidateCapability(t), ContentLoggingDisabled, otherPricing, RouteQualityTier1)
	higherQuality, _ := NewRouteCandidateDeclaration(mustRouteCandidateCapability(t), ContentLoggingDisabled, NewUnknownRoutePricing(), RouteQualityTier2)
	base, _ := NewRouteRegistryRecord(7, disabled, RouteRegistryApproved, routeRegistryEvidenceDigest)
	otherDigest := "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	alternates := []RouteRegistryRecord{}
	for _, values := range []struct {
		revision  uint64
		candidate RouteCandidateDeclaration
		status    RouteRegistryStatus
		digest    string
	}{
		{8, disabled, RouteRegistryApproved, routeRegistryEvidenceDigest},
		{7, enabled, RouteRegistryApproved, routeRegistryEvidenceDigest},
		{7, priced, RouteRegistryApproved, routeRegistryEvidenceDigest},
		{7, otherPriced, RouteRegistryApproved, routeRegistryEvidenceDigest},
		{7, higherQuality, RouteRegistryApproved, routeRegistryEvidenceDigest},
		{7, disabled, RouteRegistryPending, routeRegistryEvidenceDigest},
		{7, disabled, RouteRegistryApproved, otherDigest},
	} {
		record, err := NewRouteRegistryRecord(values.revision, values.candidate, values.status, values.digest)
		if err != nil {
			t.Fatal(err)
		}
		alternates = append(alternates, record)
	}
	for index, alternate := range alternates {
		if alternate.Identity() == base.Identity() {
			t.Fatalf("alternate %d retained base identity", index)
		}
	}
	recreated, _ := NewRouteRegistryRecord(7, disabled, RouteRegistryApproved, routeRegistryEvidenceDigest)
	if recreated.Identity() != base.Identity() || recreated != base {
		t.Fatal("equal registry record inputs produced different records")
	}
}

func TestNewRouteRegistryRecordRejectsInvalidValuesInOrder(t *testing.T) {
	candidate := mustRouteRegistryCandidate(t, ContentLoggingDisabled)
	for _, test := range []struct {
		name      string
		revision  uint64
		candidate RouteCandidateDeclaration
		status    RouteRegistryStatus
		digest    string
		want      error
	}{
		{name: "revision", candidate: candidate, status: RouteRegistryApproved, digest: routeRegistryEvidenceDigest, want: ErrInvalidRouteRegistryRevision},
		{name: "candidate", revision: 1, status: RouteRegistryApproved, digest: routeRegistryEvidenceDigest, want: ErrInvalidProviderZone},
		{name: "status", revision: 1, candidate: candidate, digest: routeRegistryEvidenceDigest, want: ErrInvalidRouteRegistryStatus},
		{name: "digest empty", revision: 1, candidate: candidate, status: RouteRegistryApproved, want: ErrInvalidRouteRegistryEvidenceDigest},
		{name: "digest short", revision: 1, candidate: candidate, status: RouteRegistryApproved, digest: "0123", want: ErrInvalidRouteRegistryEvidenceDigest},
		{name: "digest uppercase", revision: 1, candidate: candidate, status: RouteRegistryApproved, digest: strings.ToUpper(routeRegistryEvidenceDigest), want: ErrInvalidRouteRegistryEvidenceDigest},
		{name: "revision first", want: ErrInvalidRouteRegistryRevision},
	} {
		record, err := NewRouteRegistryRecord(test.revision, test.candidate, test.status, test.digest)
		if !errors.Is(err, test.want) || record != (RouteRegistryRecord{}) {
			t.Fatalf("%s = (%#v, %v), want %v", test.name, record, err, test.want)
		}
	}
}

func TestRouteRegistryRecordRejectsForgedIdentity(t *testing.T) {
	record, _ := NewRouteRegistryRecord(1, mustRouteRegistryCandidate(t, ContentLoggingDisabled), RouteRegistryApproved, routeRegistryEvidenceDigest)
	record.identity = strings.Repeat("f", 64)
	if err := record.Validate(); !errors.Is(err, ErrInvalidRouteRegistryIdentity) {
		t.Fatalf("Validate() = %v", err)
	}
	if err := (RouteRegistryRecord{}).Validate(); !errors.Is(err, ErrInvalidRouteRegistryRevision) {
		t.Fatalf("zero Validate() = %v", err)
	}
}

func TestRouteRegistryRecordFormattingRedactsLabelsAndDigests(t *testing.T) {
	record, _ := NewRouteRegistryRecord(1, mustRouteRegistryCandidate(t, ContentLoggingDisabled), RouteRegistryApproved, routeRegistryEvidenceDigest)
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
		formatted := fmt.Sprintf(format, record)
		if strings.Contains(formatted, "primary") || strings.Contains(formatted, "Model") || strings.Contains(formatted, routeRegistryEvidenceDigest) {
			t.Fatalf("format %q exposed registry fields: %q", format, formatted)
		}
	}
}
