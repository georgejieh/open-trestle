package model

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

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

const maximumGenerationInputBytes = 256 << 10

var (
	// ErrInvalidGenerationInput identifies malformed or cross-wired model authority.
	ErrInvalidGenerationInput = errors.New("invalid model generation input")
	// ErrInvalidGenerationResult identifies malformed or cross-wired candidate output.
	ErrInvalidGenerationResult = errors.New("invalid model generation result")
	// ErrInvalidVerificationAuthority identifies malformed or insufficient route separation.
	ErrInvalidVerificationAuthority = errors.New("invalid model verification authority")
	// ErrInvalidVerificationResult identifies malformed or cross-wired independent verifier output.
	ErrInvalidVerificationResult = errors.New("invalid model verification result")
	// ErrInvalidGenerationHandler identifies incomplete handler dependencies or identity.
	ErrInvalidGenerationHandler = errors.New("invalid model generation handler")
	// ErrInvalidVerificationHandler identifies incomplete verifier dependencies or identity.
	ErrInvalidVerificationHandler = errors.New("invalid model verification handler")
	// ErrVerificationAuthorizationUnavailable identifies a transient route-inventory failure.
	ErrVerificationAuthorizationUnavailable = errors.New("model verification authorization unavailable")
)

// GenerationInput binds context, admission evidence, and one exact route authorization.
type GenerationInput struct {
	identity, reviewScopeIdentity                                            string
	contextArtifactIdentity, contextIdentity                                 string
	memoryScopeIdentity, memoryIdentity                                      string
	sanitizedRequestArtifactIdentity, sanitizedEgressReceiptArtifactIdentity string
	sanitizedEgressReceiptIdentity                                           string
	// outputSchemaIdentity is the candidate batch schema the bound context
	// requests: v2 for version 7 contexts, v1 for recorded earlier contexts.
	outputSchemaIdentity string
	snapshot             review.ReviewSnapshot
	evidenceItems        []evidence.EvidenceItem
	authorization        gateway.RouteAttemptAuthorization
}

// NewGenerationInput creates one durable candidate-generation authority.
func NewGenerationInput(
	contextArtifact artifact.Artifact,
	packet review.ContextPacket,
	snapshot review.ReviewSnapshot,
	authorization gateway.RouteAttemptAuthorization,
) (GenerationInput, error) {
	return newGenerationInput(contextArtifact, packet, snapshot, artifact.Artifact{}, artifact.Artifact{}, review.ScannerBinaryDigests{}, authorization)
}

func NewSanitizedGenerationInput(
	contextArtifact artifact.Artifact,
	packet review.ContextPacket,
	snapshot review.ReviewSnapshot,
	requestArtifact artifact.Artifact,
	receiptArtifact artifact.Artifact,
	expected review.ScannerBinaryDigests,
	authorization gateway.RouteAttemptAuthorization,
) (GenerationInput, error) {
	return newGenerationInput(contextArtifact, packet, snapshot, requestArtifact, receiptArtifact, expected, authorization)
}

func newGenerationInput(
	contextArtifact artifact.Artifact,
	packet review.ContextPacket,
	snapshot review.ReviewSnapshot,
	requestArtifact artifact.Artifact,
	receiptArtifact artifact.Artifact,
	expected review.ScannerBinaryDigests,
	authorization gateway.RouteAttemptAuthorization,
) (GenerationInput, error) {
	if contextArtifact.Validate() != nil || contextArtifact.Kind() != artifact.KindContextPacket ||
		contextArtifact.MediaType() != "application/json" || contextArtifact.Origin() != artifact.OriginHost ||
		packet.Validate() != nil || snapshot.Validate() != nil || authorization.Validate() != nil {
		return GenerationInput{}, ErrInvalidGenerationInput
	}
	request, err := packet.ProviderRequest()
	if err != nil || !bytes.Equal(request.Payload(), contextArtifact.Payload()) ||
		packet.SnapshotIdentity() != snapshot.Identity() ||
		packet.ReviewScopeIdentity() != contextArtifact.Scope().Identity() ||
		authorization.ReviewScopeIdentity() != contextArtifact.Scope().Identity() {
		return GenerationInput{}, ErrInvalidGenerationInput
	}
	items := packet.EvidenceItems()
	if err := review.ValidateContextPacketRequest(
		request.Payload(), packet.Identity(), contextArtifact.Scope().Identity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, items,
	); err != nil {
		return GenerationInput{}, ErrInvalidGenerationInput
	}
	requestArtifactIdentity, sanitizedEgressReceiptArtifactIdentity, sanitizedEgressReceiptIdentity := "", "", ""
	if requestArtifact.Identity() == "" && receiptArtifact.Identity() == "" {
		if authorization.RequestIdentity() != request.Identity() {
			return GenerationInput{}, ErrInvalidGenerationInput
		}
	} else {
		if review.ValidateSanitizedEgressArtifacts(contextArtifact, requestArtifact, receiptArtifact, expected) != nil {
			return GenerationInput{}, ErrInvalidGenerationInput
		}
		sanitized, parseErr := review.ParseSanitizedModelRequest(requestArtifact.Payload())
		receipt, receiptErr := review.ParseSanitizedEgressReceipt(receiptArtifact.Payload())
		if parseErr != nil || receiptErr != nil || authorization.RequestIdentity() != sanitized.SanitizedRequestIdentity() || receipt.SanitizedRequestIdentity() != authorization.RequestIdentity() {
			return GenerationInput{}, ErrInvalidGenerationInput
		}
		requestArtifactIdentity, sanitizedEgressReceiptArtifactIdentity, sanitizedEgressReceiptIdentity = requestArtifact.Identity(), receiptArtifact.Identity(), receipt.Identity()
	}
	input := GenerationInput{
		reviewScopeIdentity:     contextArtifact.Scope().Identity(),
		contextArtifactIdentity: contextArtifact.Identity(), contextIdentity: packet.Identity(), memoryScopeIdentity: packet.MemoryScopeIdentity(), memoryIdentity: packet.MemoryIdentity(),
		sanitizedRequestArtifactIdentity: requestArtifactIdentity, sanitizedEgressReceiptArtifactIdentity: sanitizedEgressReceiptArtifactIdentity, sanitizedEgressReceiptIdentity: sanitizedEgressReceiptIdentity,
		outputSchemaIdentity: packet.OutputSchemaIdentity(),
		snapshot:             snapshot, evidenceItems: append([]evidence.EvidenceItem(nil), items...),
		authorization: authorization,
	}
	input.identity = deriveGenerationInputIdentity(input)
	if err := input.Validate(); err != nil {
		return GenerationInput{}, err
	}
	return input, nil
}

func (i GenerationInput) Identity() string                { return i.identity }
func (i GenerationInput) ReviewScopeIdentity() string     { return i.reviewScopeIdentity }
func (i GenerationInput) ContextArtifactIdentity() string { return i.contextArtifactIdentity }
func (i GenerationInput) ContextIdentity() string         { return i.contextIdentity }
func (i GenerationInput) MemoryScopeIdentity() string     { return i.memoryScopeIdentity }
func (i GenerationInput) MemoryIdentity() string          { return i.memoryIdentity }
func (i GenerationInput) Snapshot() review.ReviewSnapshot { return i.snapshot }
func (i GenerationInput) EvidenceItems() []evidence.EvidenceItem {
	return append([]evidence.EvidenceItem(nil), i.evidenceItems...)
}
func (i GenerationInput) SanitizedRequestArtifactIdentity() string {
	return i.sanitizedRequestArtifactIdentity
}
func (i GenerationInput) SanitizedEgressReceiptArtifactIdentity() string {
	return i.sanitizedEgressReceiptArtifactIdentity
}
func (i GenerationInput) SanitizedEgressReceiptIdentity() string {
	return i.sanitizedEgressReceiptIdentity
}

// OutputSchemaIdentity returns the candidate batch schema identity the bound context requests.
func (i GenerationInput) OutputSchemaIdentity() string                     { return i.outputSchemaIdentity }
func (i GenerationInput) IsSanitized() bool                                { return i.sanitizedRequestArtifactIdentity != "" }
func (i GenerationInput) Authorization() gateway.RouteAttemptAuthorization { return i.authorization }
func (i GenerationInput) String() string                                   { return "model generation input" }
func (i GenerationInput) GoString() string                                 { return "model.GenerationInput{<redacted>}" }
func (i GenerationInput) Format(state fmt.State, verb rune) {
	writeModelRedacted(state, verb, "model generation input", "model.GenerationInput{<redacted>}")
}

// Validate verifies all immutable authority and admission bindings.
func (i GenerationInput) Validate() error {
	if !validDigest(i.reviewScopeIdentity) || !validDigest(i.contextArtifactIdentity) ||
		!validDigest(i.contextIdentity) || !validDigest(i.memoryScopeIdentity) || !validDigest(i.memoryIdentity) || i.snapshot.Validate() != nil ||
		i.authorization.Validate() != nil || i.authorization.ReviewScopeIdentity() != i.reviewScopeIdentity ||
		len(i.evidenceItems) > 2048 ||
		i.outputSchemaIdentity != review.ModelCandidateBatchSchemaIdentity && i.outputSchemaIdentity != review.ModelCandidateBatchV1SchemaIdentity {
		return ErrInvalidGenerationInput
	}
	sanitized := validDigest(i.sanitizedRequestArtifactIdentity) && validDigest(i.sanitizedEgressReceiptArtifactIdentity) && validDigest(i.sanitizedEgressReceiptIdentity)
	legacy := i.sanitizedRequestArtifactIdentity == "" && i.sanitizedEgressReceiptArtifactIdentity == "" && i.sanitizedEgressReceiptIdentity == ""
	if !sanitized && !legacy {
		return ErrInvalidGenerationInput
	}
	seen := make(map[string]struct{}, len(i.evidenceItems))
	for _, item := range i.evidenceItems {
		rangeValue := item.SourceRange()
		canonical, err := evidence.NewEvidenceItem(item.ID(), item.Kind(), item.Digest(), rangeValue)
		if err != nil || canonical.ID() != item.ID() || !evidenceSupported(rangeValue, i.snapshot) {
			return ErrInvalidGenerationInput
		}
		if _, exists := seen[item.ID()]; exists {
			return ErrInvalidGenerationInput
		}
		seen[item.ID()] = struct{}{}
	}
	if i.identity != deriveGenerationInputIdentity(i) {
		return ErrInvalidGenerationInput
	}
	return nil
}

// contextOutputSchemaMatches binds the input's recorded candidate schema to the
// output_schema_identity of the exact context bytes it authorizes.
func contextOutputSchemaMatches(input GenerationInput, contextPayload []byte) bool {
	var header struct {
		OutputSchemaIdentity string `json:"output_schema_identity"`
	}
	return json.Unmarshal(contextPayload, &header) == nil && header.OutputSchemaIdentity == input.outputSchemaIdentity
}

// evidenceSupported admits an evidence item inside a snapshot range, or on a
// snapshot path: removed_lines evidence carries base line numbers, so it is
// never inside a head snapshot range, and the context handler supplies it only
// beside a selected head source of the same file. The stage-aware context
// validators, which every execution and readback path also runs, check that
// such an item is a removed_lines source.
func evidenceSupported(candidate evidence.SourceRange, snapshot review.ReviewSnapshot) bool {
	if rangeSupported(candidate, snapshot) {
		return true
	}
	for _, allowed := range snapshot.Ranges() {
		if allowed.Path() == candidate.Path() {
			return true
		}
	}
	return false
}

func rangeSupported(candidate evidence.SourceRange, snapshot review.ReviewSnapshot) bool {
	for _, allowed := range snapshot.Ranges() {
		if allowed.Path() == candidate.Path() && allowed.StartLine() <= candidate.StartLine() && allowed.EndLine() >= candidate.EndLine() {
			return true
		}
	}
	return false
}

type generationRangeWire struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}
type generationEvidenceWire struct {
	ID        string `json:"id"`
	Kind      string `json:"kind"`
	Digest    string `json:"digest"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}
type generationInputWire struct {
	Contract                               string                   `json:"contract"`
	SchemaVersion                          int                      `json:"schema_version"`
	Identity                               string                   `json:"identity"`
	ReviewScopeIdentity                    string                   `json:"review_scope_identity"`
	ContextArtifactIdentity                string                   `json:"context_artifact_identity"`
	ContextIdentity                        string                   `json:"context_identity"`
	MemoryScopeIdentity                    string                   `json:"memory_scope_identity"`
	MemoryIdentity                         string                   `json:"memory_identity"`
	SanitizedRequestArtifactIdentity       string                   `json:"sanitized_request_artifact_identity,omitempty"`
	SanitizedEgressReceiptArtifactIdentity string                   `json:"sanitized_egress_receipt_artifact_identity,omitempty"`
	SanitizedEgressReceiptIdentity         string                   `json:"sanitized_egress_receipt_identity,omitempty"`
	OutputSchemaIdentity                   string                   `json:"output_schema_identity"`
	SnapshotWorkspace                      string                   `json:"snapshot_workspace"`
	SnapshotRevision                       string                   `json:"snapshot_revision"`
	SnapshotIdentity                       string                   `json:"snapshot_identity"`
	SnapshotRanges                         []generationRangeWire    `json:"snapshot_ranges"`
	Evidence                               []generationEvidenceWire `json:"evidence"`
	Authorization                          json.RawMessage          `json:"authorization"`
}

// EncodeGenerationInput returns one canonical durable authority document.
func EncodeGenerationInput(input GenerationInput) ([]byte, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}
	wire, err := generationInputWireValue(input)
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) > maximumGenerationInputBytes {
		return nil, ErrInvalidGenerationInput
	}
	return encoded, nil
}

// ParseGenerationInput accepts only one canonical durable authority document.
func ParseGenerationInput(encoded []byte) (GenerationInput, error) {
	if len(encoded) == 0 || len(encoded) > maximumGenerationInputBytes {
		return GenerationInput{}, ErrInvalidGenerationInput
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire generationInputWire
	if err := decoder.Decode(&wire); err != nil {
		return GenerationInput{}, ErrInvalidGenerationInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return GenerationInput{}, ErrInvalidGenerationInput
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) || wire.Contract != "open-trestle/model-generation-input" ||
		(wire.SchemaVersion != 1 && wire.SchemaVersion != 3) ||
		wire.OutputSchemaIdentity != review.ModelCandidateBatchSchemaIdentity && wire.OutputSchemaIdentity != review.ModelCandidateBatchV1SchemaIdentity {
		return GenerationInput{}, ErrInvalidGenerationInput
	}
	ranges := make([]evidence.SourceRange, len(wire.SnapshotRanges))
	for index, value := range wire.SnapshotRanges {
		ranges[index], err = evidence.NewSourceRange(value.Path, value.StartLine, value.EndLine)
		if err != nil {
			return GenerationInput{}, ErrInvalidGenerationInput
		}
	}
	snapshot, err := review.NewReviewSnapshot(wire.SnapshotWorkspace, wire.SnapshotRevision, ranges)
	if err != nil || snapshot.Identity() != wire.SnapshotIdentity {
		return GenerationInput{}, ErrInvalidGenerationInput
	}
	items := make([]evidence.EvidenceItem, len(wire.Evidence))
	for index, value := range wire.Evidence {
		rangeValue, rangeErr := evidence.NewSourceRange(value.Path, value.StartLine, value.EndLine)
		if rangeErr != nil {
			return GenerationInput{}, ErrInvalidGenerationInput
		}
		items[index], err = evidence.NewEvidenceItem(value.ID, evidence.EvidenceKind(value.Kind), value.Digest, rangeValue)
		if err != nil {
			return GenerationInput{}, ErrInvalidGenerationInput
		}
	}
	authorization, err := gateway.ParseRouteAttemptAuthorization(wire.Authorization)
	if err != nil {
		return GenerationInput{}, ErrInvalidGenerationInput
	}
	input := GenerationInput{
		identity: wire.Identity, reviewScopeIdentity: wire.ReviewScopeIdentity,
		contextArtifactIdentity: wire.ContextArtifactIdentity, contextIdentity: wire.ContextIdentity, memoryScopeIdentity: wire.MemoryScopeIdentity, memoryIdentity: wire.MemoryIdentity,
		sanitizedRequestArtifactIdentity: wire.SanitizedRequestArtifactIdentity, sanitizedEgressReceiptArtifactIdentity: wire.SanitizedEgressReceiptArtifactIdentity, sanitizedEgressReceiptIdentity: wire.SanitizedEgressReceiptIdentity,
		outputSchemaIdentity: wire.OutputSchemaIdentity,
		snapshot:             snapshot, evidenceItems: items, authorization: authorization,
	}
	if err := input.Validate(); err != nil {
		return GenerationInput{}, ErrInvalidGenerationInput
	}
	reencoded, err := EncodeGenerationInput(input)
	if err != nil || !bytes.Equal(reencoded, encoded) {
		return GenerationInput{}, ErrInvalidGenerationInput
	}
	return input, nil
}

func generationInputWireValue(input GenerationInput) (generationInputWire, error) {
	authorization, err := gateway.EncodeRouteAttemptAuthorization(input.authorization)
	if err != nil {
		return generationInputWire{}, err
	}
	ranges := input.snapshot.Ranges()
	wireRanges := make([]generationRangeWire, len(ranges))
	for index, value := range ranges {
		wireRanges[index] = generationRangeWire{value.Path(), value.StartLine(), value.EndLine()}
	}
	items := make([]generationEvidenceWire, len(input.evidenceItems))
	for index, value := range input.evidenceItems {
		rangeValue := value.SourceRange()
		items[index] = generationEvidenceWire{
			ID: value.ID(), Kind: string(value.Kind()), Digest: value.Digest(),
			Path: rangeValue.Path(), StartLine: rangeValue.StartLine(), EndLine: rangeValue.EndLine(),
		}
	}
	version := 1
	if input.IsSanitized() {
		version = 3
	}
	return generationInputWire{
		Contract: "open-trestle/model-generation-input", SchemaVersion: version, Identity: input.Identity(),
		ReviewScopeIdentity: input.reviewScopeIdentity, ContextArtifactIdentity: input.contextArtifactIdentity,
		ContextIdentity: input.contextIdentity, MemoryScopeIdentity: input.memoryScopeIdentity, MemoryIdentity: input.memoryIdentity,
		SanitizedRequestArtifactIdentity: input.sanitizedRequestArtifactIdentity, SanitizedEgressReceiptArtifactIdentity: input.sanitizedEgressReceiptArtifactIdentity, SanitizedEgressReceiptIdentity: input.sanitizedEgressReceiptIdentity, OutputSchemaIdentity: input.outputSchemaIdentity,
		SnapshotWorkspace: input.snapshot.Workspace(), SnapshotRevision: input.snapshot.Revision(),
		SnapshotIdentity: input.snapshot.Identity(), SnapshotRanges: wireRanges, Evidence: items,
		Authorization: json.RawMessage(authorization),
	}, nil
}

func deriveGenerationInputIdentity(input GenerationInput) string {
	wire, err := generationInputWireValue(input)
	if err != nil {
		return ""
	}
	wire.Identity = ""
	encoded, err := json.Marshal(wire)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// NewGenerationInputArtifact wraps authority with the context artifact's scope and protection.
func NewGenerationInputArtifact(
	input GenerationInput,
	contextArtifact artifact.Artifact,
	additionalProvenance []string,
	createdAt time.Time,
) (artifact.Artifact, error) {
	if input.Validate() != nil || contextArtifact.Validate() != nil ||
		contextArtifact.Identity() != input.ContextArtifactIdentity() ||
		contextArtifact.Scope().Identity() != input.ReviewScopeIdentity() ||
		contextArtifact.Kind() != artifact.KindContextPacket || contextArtifact.Origin() != artifact.OriginHost {
		return artifact.Artifact{}, ErrInvalidGenerationInput
	}
	encoded, err := EncodeGenerationInput(input)
	if err != nil {
		return artifact.Artifact{}, err
	}
	provenance := append([]string(nil), additionalProvenance...)
	provenance = append(provenance, contextArtifact.Identity(), input.Authorization().Identity())
	if input.IsSanitized() {
		provenance = append(provenance, input.SanitizedRequestArtifactIdentity(), input.SanitizedEgressReceiptArtifactIdentity())
	}
	sort.Strings(provenance)
	return artifact.New(
		contextArtifact.Scope(), artifact.KindTaskInput, "application/json",
		contextArtifact.Classification(), artifact.OriginHost, contextArtifact.Protection(),
		provenance, encoded, createdAt, contextArtifact.ExpiresAt(),
	)
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) || strings.Trim(value, "0") == "" {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func writeModelRedacted(state fmt.State, verb rune, plain, detailed string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = detailed
	}
	_, _ = state.Write([]byte(value))
}
