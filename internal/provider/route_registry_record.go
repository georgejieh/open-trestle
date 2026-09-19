package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

var (
	// ErrInvalidRouteRegistryRevision identifies a missing registry snapshot revision.
	ErrInvalidRouteRegistryRevision = errors.New("invalid route registry revision")
	// ErrInvalidRouteRegistryEvidenceDigest identifies a malformed evidence-manifest digest.
	ErrInvalidRouteRegistryEvidenceDigest = errors.New("invalid route registry evidence digest")
	// ErrInvalidRouteRegistryIdentity identifies a record whose identity does not match its fields.
	ErrInvalidRouteRegistryIdentity = errors.New("invalid route registry identity")
)

// RouteRegistryRecord binds versioned structural route claims to an evidence-manifest digest.
// Trusted storage must establish registry membership, authorization, and evidence availability.
type RouteRegistryRecord struct {
	identity               string
	registryRevision       uint64
	routeCandidate         RouteCandidateDeclaration
	status                 RouteRegistryStatus
	evidenceManifestDigest string
}

// NewRouteRegistryRecord creates an immutable content-addressed structural registry record.
func NewRouteRegistryRecord(revision uint64, candidate RouteCandidateDeclaration, status RouteRegistryStatus, evidenceManifestDigest string) (RouteRegistryRecord, error) {
	if err := validateRouteRegistryRecordFields(revision, candidate, status, evidenceManifestDigest); err != nil {
		return RouteRegistryRecord{}, err
	}
	identity, err := deriveRouteRegistryRecordIdentity(revision, candidate, status, evidenceManifestDigest)
	if err != nil {
		return RouteRegistryRecord{}, err
	}
	return RouteRegistryRecord{
		identity:               identity,
		registryRevision:       revision,
		routeCandidate:         candidate,
		status:                 status,
		evidenceManifestDigest: strings.Clone(evidenceManifestDigest),
	}, nil
}

// Identity returns the versioned canonical SHA-256 record identity.
func (r RouteRegistryRecord) Identity() string { return r.identity }

// RegistryRevision returns the positive registry snapshot revision.
func (r RouteRegistryRecord) RegistryRevision() uint64 { return r.registryRevision }

// RouteCandidateDeclaration returns the bound structural route candidate.
func (r RouteRegistryRecord) RouteCandidateDeclaration() RouteCandidateDeclaration {
	return r.routeCandidate
}

// Status returns the declared registry lifecycle status.
func (r RouteRegistryRecord) Status() RouteRegistryStatus { return r.status }

// EvidenceManifestDigest returns the SHA-256 digest of the external evidence manifest.
func (r RouteRegistryRecord) EvidenceManifestDigest() string { return r.evidenceManifestDigest }

// String returns a redacted registry record description.
func (r RouteRegistryRecord) String() string { return "route registry record" }

// GoString returns a redacted Go-syntax registry record description.
func (r RouteRegistryRecord) GoString() string { return "provider.RouteRegistryRecord{<redacted>}" }

// Format writes a redacted representation for verbs dispatched through fmt.Formatter.
func (r RouteRegistryRecord) Format(state fmt.State, verb rune) {
	formatted := "route registry record"
	if verb == 'q' {
		formatted = `"route registry record"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "provider.RouteRegistryRecord{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies fields and the content-derived identity.
func (r RouteRegistryRecord) Validate() error {
	if err := validateRouteRegistryRecordFields(r.registryRevision, r.routeCandidate, r.status, r.evidenceManifestDigest); err != nil {
		return err
	}
	identity, err := deriveRouteRegistryRecordIdentity(r.registryRevision, r.routeCandidate, r.status, r.evidenceManifestDigest)
	if err != nil {
		return err
	}
	if r.identity != identity {
		return fmt.Errorf("validate route registry identity: %w", ErrInvalidRouteRegistryIdentity)
	}
	return nil
}

func validateRouteRegistryRecordFields(revision uint64, candidate RouteCandidateDeclaration, status RouteRegistryStatus, evidenceManifestDigest string) error {
	if revision == 0 {
		return fmt.Errorf("validate route registry revision: %w", ErrInvalidRouteRegistryRevision)
	}
	if err := candidate.Validate(); err != nil {
		return fmt.Errorf("validate route registry candidate: %w", err)
	}
	if err := status.Validate(); err != nil {
		return err
	}
	if len(evidenceManifestDigest) != sha256.Size*2 || evidenceManifestDigest != strings.ToLower(evidenceManifestDigest) {
		return fmt.Errorf("validate route registry evidence digest: %w", ErrInvalidRouteRegistryEvidenceDigest)
	}
	if _, err := hex.DecodeString(evidenceManifestDigest); err != nil {
		return fmt.Errorf("validate route registry evidence digest: %w", ErrInvalidRouteRegistryEvidenceDigest)
	}
	return nil
}

func deriveRouteRegistryRecordIdentity(revision uint64, candidate RouteCandidateDeclaration, status RouteRegistryStatus, evidenceManifestDigest string) (string, error) {
	capability := candidate.RouteCapabilityDeclaration()
	route := capability.RouteReference()
	model := capability.ModelCapabilities()
	features := model.SupportedFeatures()
	featureNames := make([]string, len(features))
	for index, feature := range features {
		featureNames[index] = feature.String()
	}
	preimage := struct {
		Contract               string   `json:"contract"`
		SchemaVersion          int      `json:"schema_version"`
		RegistryRevision       uint64   `json:"registry_revision"`
		ProviderZone           string   `json:"provider_zone"`
		ProviderID             string   `json:"provider_id"`
		AdapterID              string   `json:"adapter_id"`
		ConnectionID           string   `json:"connection_id"`
		ModelID                string   `json:"model_id"`
		ModelVersion           string   `json:"model_version"`
		SupportedFeatures      []string `json:"supported_features"`
		MaxContextTokens       uint32   `json:"max_context_tokens"`
		MaxOutputTokens        uint32   `json:"max_output_tokens"`
		ContentLoggingMode     string   `json:"content_logging_mode"`
		PricingKnown           bool     `json:"pricing_known"`
		InputPriceMicroUSD     uint64   `json:"input_price_micro_usd_per_million_tokens"`
		OutputPriceMicroUSD    uint64   `json:"output_price_micro_usd_per_million_tokens"`
		QualityTier            string   `json:"quality_tier"`
		Status                 string   `json:"status"`
		EvidenceManifestDigest string   `json:"evidence_manifest_digest"`
	}{
		Contract:               "open-trestle/route-registry-record",
		SchemaVersion:          1,
		RegistryRevision:       revision,
		ProviderZone:           route.Zone().String(),
		ProviderID:             route.ProviderID(),
		AdapterID:              route.AdapterID(),
		ConnectionID:           route.ConnectionID(),
		ModelID:                route.ModelID(),
		ModelVersion:           route.ModelVersion(),
		SupportedFeatures:      featureNames,
		MaxContextTokens:       model.MaxContextTokens(),
		MaxOutputTokens:        model.MaxOutputTokens(),
		ContentLoggingMode:     candidate.ContentLoggingMode().String(),
		PricingKnown:           candidate.RoutePricing().IsKnown(),
		InputPriceMicroUSD:     candidate.RoutePricing().InputMicroUSDPerMillionTokens(),
		OutputPriceMicroUSD:    candidate.RoutePricing().OutputMicroUSDPerMillionTokens(),
		QualityTier:            candidate.RouteQualityTier().String(),
		Status:                 status.String(),
		EvidenceManifestDigest: evidenceManifestDigest,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return "", fmt.Errorf("encode route registry record identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]), nil
}
