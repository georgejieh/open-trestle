package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/internal/provider"
)

const maxRouteEvidenceManifestBytes = 1 << 20

var (
	// ErrInvalidRouteRegistryResolutionContext identifies a nil resolution context.
	ErrInvalidRouteRegistryResolutionContext = errors.New("invalid route registry resolution context")
	// ErrInvalidRouteRegistryRecordIdentity identifies malformed lookup input.
	ErrInvalidRouteRegistryRecordIdentity = errors.New("invalid route registry record identity")
	// ErrRouteRegistryLookupFailed identifies an unavailable or failed registry lookup.
	ErrRouteRegistryLookupFailed = errors.New("route registry lookup failed")
	// ErrRouteRegistryRecordIdentityMismatch identifies a lookup result for a different record.
	ErrRouteRegistryRecordIdentityMismatch = errors.New("route registry record identity mismatch")
	// ErrRouteRegistryEvidenceReadFailed identifies an unavailable or failed evidence read.
	ErrRouteRegistryEvidenceReadFailed = errors.New("route registry evidence read failed")
	// ErrInvalidRouteRegistryEvidenceManifest identifies an empty or oversized evidence manifest.
	ErrInvalidRouteRegistryEvidenceManifest = errors.New("invalid route registry evidence manifest")
	// ErrRouteRegistryEvidenceDigestMismatch identifies evidence bytes that do not match the registry record.
	ErrRouteRegistryEvidenceDigestMismatch = errors.New("route registry evidence digest mismatch")
)

// RouteRegistryReader reads records from the authoritative registry selected by the control plane.
type RouteRegistryReader interface {
	LookupRouteRegistryRecord(context.Context, string) (provider.RouteRegistryRecord, error)
}

// RouteEvidenceManifestReader opens immutable evidence manifests by their expected digest.
type RouteEvidenceManifestReader interface {
	OpenRouteEvidenceManifest(context.Context, string) (io.ReadCloser, error)
}

// ResolvedRouteRegistryRecord proves that a registry lookup and evidence digest check succeeded.
type ResolvedRouteRegistryRecord struct {
	record                    provider.RouteRegistryRecord
	evidenceManifestSizeBytes uint32
}

// ResolveRouteRegistryRecord verifies one authoritative registry lookup and its evidence manifest.
func ResolveRouteRegistryRecord(ctx context.Context, identity string, registry RouteRegistryReader, evidence RouteEvidenceManifestReader) (ResolvedRouteRegistryRecord, error) {
	if ctx == nil {
		return ResolvedRouteRegistryRecord{}, ErrInvalidRouteRegistryResolutionContext
	}
	if !validRequestIdentity(identity) {
		return ResolvedRouteRegistryRecord{}, ErrInvalidRouteRegistryRecordIdentity
	}
	if registry == nil {
		return ResolvedRouteRegistryRecord{}, ErrRouteRegistryLookupFailed
	}
	if evidence == nil {
		return ResolvedRouteRegistryRecord{}, ErrRouteRegistryEvidenceReadFailed
	}
	record, err := registry.LookupRouteRegistryRecord(ctx, identity)
	if err != nil {
		return ResolvedRouteRegistryRecord{}, ErrRouteRegistryLookupFailed
	}
	if err := record.Validate(); err != nil {
		return ResolvedRouteRegistryRecord{}, err
	}
	if record.Identity() != identity {
		return ResolvedRouteRegistryRecord{}, ErrRouteRegistryRecordIdentityMismatch
	}
	manifestReader, err := evidence.OpenRouteEvidenceManifest(ctx, record.EvidenceManifestDigest())
	if err != nil || manifestReader == nil {
		return ResolvedRouteRegistryRecord{}, ErrRouteRegistryEvidenceReadFailed
	}
	manifest, readErr := io.ReadAll(io.LimitReader(manifestReader, maxRouteEvidenceManifestBytes+1))
	closeErr := manifestReader.Close()
	if readErr != nil || closeErr != nil {
		return ResolvedRouteRegistryRecord{}, ErrRouteRegistryEvidenceReadFailed
	}
	if len(manifest) == 0 || len(manifest) > maxRouteEvidenceManifestBytes {
		return ResolvedRouteRegistryRecord{}, ErrInvalidRouteRegistryEvidenceManifest
	}
	digest := sha256.Sum256(manifest)
	if hex.EncodeToString(digest[:]) != record.EvidenceManifestDigest() {
		return ResolvedRouteRegistryRecord{}, ErrRouteRegistryEvidenceDigestMismatch
	}
	return ResolvedRouteRegistryRecord{
		record:                    record,
		evidenceManifestSizeBytes: uint32(len(manifest)),
	}, nil
}

// RouteRegistryRecord returns the verified structural registry record.
func (r ResolvedRouteRegistryRecord) RouteRegistryRecord() provider.RouteRegistryRecord {
	return r.record
}

// EvidenceManifestSizeBytes returns the verified manifest size without retaining its bytes.
func (r ResolvedRouteRegistryRecord) EvidenceManifestSizeBytes() uint32 {
	return r.evidenceManifestSizeBytes
}

// String returns a redacted resolved-record description.
func (r ResolvedRouteRegistryRecord) String() string { return "resolved route registry record" }

// GoString returns a redacted Go-syntax resolved-record description.
func (r ResolvedRouteRegistryRecord) GoString() string {
	return "gateway.ResolvedRouteRegistryRecord{<redacted>}"
}

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (r ResolvedRouteRegistryRecord) Format(state fmt.State, verb rune) {
	formatted := "resolved route registry record"
	if verb == 'q' {
		formatted = `"resolved route registry record"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "gateway.ResolvedRouteRegistryRecord{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies the record and bounded evidence proof metadata.
func (r ResolvedRouteRegistryRecord) Validate() error {
	if err := r.record.Validate(); err != nil {
		return err
	}
	if r.evidenceManifestSizeBytes == 0 || r.evidenceManifestSizeBytes > maxRouteEvidenceManifestBytes {
		return ErrInvalidRouteRegistryEvidenceManifest
	}
	return nil
}

// CheckResolvedRouteRegistryRecordCompatibility checks a previously resolved registry record.
func CheckResolvedRouteRegistryRecordCompatibility(input ReviewRoutingInput, resolved ResolvedRouteRegistryRecord) error {
	if err := input.Validate(); err != nil {
		return err
	}
	if err := resolved.Validate(); err != nil {
		return err
	}
	return CheckRouteRegistryRecordCompatibility(input, resolved.RouteRegistryRecord())
}
