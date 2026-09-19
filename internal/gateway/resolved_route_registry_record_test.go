package gateway

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

type routeRegistryReaderStub struct {
	record    provider.RouteRegistryRecord
	err       error
	requested string
}

func (s *routeRegistryReaderStub) LookupRouteRegistryRecord(_ context.Context, identity string) (provider.RouteRegistryRecord, error) {
	s.requested = identity
	return s.record, s.err
}

type routeEvidenceManifestReaderStub struct {
	content   []byte
	err       error
	requested string
}

func (s *routeEvidenceManifestReaderStub) OpenRouteEvidenceManifest(_ context.Context, digest string) (io.ReadCloser, error) {
	s.requested = digest
	if s.err != nil {
		return nil, s.err
	}
	return io.NopCloser(bytes.NewReader(s.content)), nil
}

func newResolutionRecord(t *testing.T, revision uint64, manifest []byte) provider.RouteRegistryRecord {
	t.Helper()
	digest := sha256.Sum256(manifest)
	candidate := newRouteCandidate(t, provider.ProviderZoneLocal, provider.ContentLoggingDisabled, 128_000, 16_000, provider.ModelFeatureStructuredOutput)
	record, err := provider.NewRouteRegistryRecord(revision, candidate, provider.RouteRegistryApproved, hex.EncodeToString(digest[:]))
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestResolveRouteRegistryRecordVerifiesRecordAndEvidence(t *testing.T) {
	manifest := []byte(`{"source":"operator","probe":"passed"}`)
	record := newResolutionRecord(t, 1, manifest)
	registry := &routeRegistryReaderStub{record: record}
	evidence := &routeEvidenceManifestReaderStub{content: manifest}

	resolved, err := ResolveRouteRegistryRecord(context.Background(), record.Identity(), registry, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.RouteRegistryRecord() != record || resolved.EvidenceManifestSizeBytes() != uint32(len(manifest)) || resolved.Validate() != nil {
		t.Fatal("resolved route registry record does not round trip")
	}
	if registry.requested != record.Identity() || evidence.requested != record.EvidenceManifestDigest() {
		t.Fatal("resolver used the wrong registry identity or evidence digest")
	}
	if err := CheckResolvedRouteRegistryRecordCompatibility(newContentLoggingInput(t, false), resolved); err != nil {
		t.Fatalf("CheckResolvedRouteRegistryRecordCompatibility() = %v", err)
	}
}

func TestResolveRouteRegistryRecordRejectsInvalidBoundaries(t *testing.T) {
	manifest := []byte("manifest")
	record := newResolutionRecord(t, 1, manifest)
	registry := &routeRegistryReaderStub{record: record}
	evidence := &routeEvidenceManifestReaderStub{content: manifest}
	for _, test := range []struct {
		name     string
		ctx      context.Context
		identity string
		registry RouteRegistryReader
		evidence RouteEvidenceManifestReader
		want     error
	}{
		{name: "context", identity: record.Identity(), registry: registry, evidence: evidence, want: ErrInvalidRouteRegistryResolutionContext},
		{name: "identity", ctx: context.Background(), identity: "bad", registry: registry, evidence: evidence, want: ErrInvalidRouteRegistryRecordIdentity},
		{name: "registry", ctx: context.Background(), identity: record.Identity(), evidence: evidence, want: ErrRouteRegistryLookupFailed},
		{name: "evidence reader", ctx: context.Background(), identity: record.Identity(), registry: registry, want: ErrRouteRegistryEvidenceReadFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := ResolveRouteRegistryRecord(test.ctx, test.identity, test.registry, test.evidence)
			if !errors.Is(err, test.want) || resolved != (ResolvedRouteRegistryRecord{}) {
				t.Fatalf("ResolveRouteRegistryRecord() = (%#v, %v), want %v", resolved, err, test.want)
			}
		})
	}
}

func TestResolveRouteRegistryRecordRedactsReaderFailures(t *testing.T) {
	manifest := []byte("manifest")
	record := newResolutionRecord(t, 1, manifest)
	for _, test := range []struct {
		name     string
		registry RouteRegistryReader
		evidence RouteEvidenceManifestReader
		want     error
	}{
		{name: "registry", registry: &routeRegistryReaderStub{err: errors.New("SENTINEL_REGISTRY_SECRET")}, evidence: &routeEvidenceManifestReaderStub{content: manifest}, want: ErrRouteRegistryLookupFailed},
		{name: "evidence", registry: &routeRegistryReaderStub{record: record}, evidence: &routeEvidenceManifestReaderStub{err: errors.New("SENTINEL_EVIDENCE_SECRET")}, want: ErrRouteRegistryEvidenceReadFailed},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, err := ResolveRouteRegistryRecord(context.Background(), record.Identity(), test.registry, test.evidence)
			if err != test.want || strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("ResolveRouteRegistryRecord() = %v, want redacted %v", err, test.want)
			}
		})
	}
}

func TestResolveRouteRegistryRecordRejectsMismatchedRecordIdentity(t *testing.T) {
	manifest := []byte("manifest")
	requested := newResolutionRecord(t, 1, manifest)
	returned := newResolutionRecord(t, 2, manifest)
	resolved, err := ResolveRouteRegistryRecord(
		context.Background(),
		requested.Identity(),
		&routeRegistryReaderStub{record: returned},
		&routeEvidenceManifestReaderStub{content: manifest},
	)
	if err != ErrRouteRegistryRecordIdentityMismatch || resolved != (ResolvedRouteRegistryRecord{}) {
		t.Fatalf("ResolveRouteRegistryRecord() = (%#v, %v)", resolved, err)
	}
}

func TestResolveRouteRegistryRecordRejectsInvalidEvidenceManifest(t *testing.T) {
	validManifest := []byte("manifest")
	record := newResolutionRecord(t, 1, validManifest)
	for _, test := range []struct {
		name    string
		content []byte
		want    error
	}{
		{name: "empty", want: ErrInvalidRouteRegistryEvidenceManifest},
		{name: "oversized", content: make([]byte, maxRouteEvidenceManifestBytes+1), want: ErrInvalidRouteRegistryEvidenceManifest},
		{name: "digest mismatch", content: []byte("other"), want: ErrRouteRegistryEvidenceDigestMismatch},
	} {
		t.Run(test.name, func(t *testing.T) {
			resolved, err := ResolveRouteRegistryRecord(
				context.Background(),
				record.Identity(),
				&routeRegistryReaderStub{record: record},
				&routeEvidenceManifestReaderStub{content: test.content},
			)
			if err != test.want || resolved != (ResolvedRouteRegistryRecord{}) {
				t.Fatalf("ResolveRouteRegistryRecord() = (%#v, %v), want %v", resolved, err, test.want)
			}
		})
	}
}

func TestResolvedRouteRegistryRecordSurfaceRetainsNoManifestBytes(t *testing.T) {
	typeOfResolved := reflect.TypeOf(ResolvedRouteRegistryRecord{})
	want := []string{"record", "evidenceManifestSizeBytes"}
	if typeOfResolved.NumField() != len(want) {
		t.Fatalf("ResolvedRouteRegistryRecord has %d fields, want %d", typeOfResolved.NumField(), len(want))
	}
	for index, name := range want {
		field := typeOfResolved.Field(index)
		if field.Name != name || field.Type.Kind() == reflect.Slice || field.Type.Kind() == reflect.String {
			t.Fatalf("field %d = (%q, %s)", index, field.Name, field.Type)
		}
	}
	if err := (ResolvedRouteRegistryRecord{}).Validate(); !errors.Is(err, provider.ErrInvalidRouteRegistryRevision) {
		t.Fatalf("zero Validate() = %v", err)
	}
}

func TestCheckResolvedRouteRegistryRecordCompatibilityRejectsZeroValue(t *testing.T) {
	input := newContentLoggingInput(t, false)
	if err := CheckResolvedRouteRegistryRecordCompatibility(input, ResolvedRouteRegistryRecord{}); !errors.Is(err, provider.ErrInvalidRouteRegistryRevision) {
		t.Fatalf("CheckResolvedRouteRegistryRecordCompatibility() = %v", err)
	}
}

func TestResolvedRouteRegistryRecordFormattingRedactsRecord(t *testing.T) {
	manifest := []byte("manifest")
	record := newResolutionRecord(t, 1, manifest)
	resolved, _ := ResolveRouteRegistryRecord(context.Background(), record.Identity(), &routeRegistryReaderStub{record: record}, &routeEvidenceManifestReaderStub{content: manifest})
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%d", "%x"} {
		formatted := fmt.Sprintf(format, resolved)
		if strings.Contains(formatted, record.Identity()) || strings.Contains(formatted, record.EvidenceManifestDigest()) {
			t.Fatalf("format %q exposed record fields: %q", format, formatted)
		}
	}
}
