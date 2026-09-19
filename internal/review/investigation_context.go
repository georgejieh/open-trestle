package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	reviewschema "github.com/georgejieh/open-trestle/schemas/review"
)

var ErrInvestigationContext = errors.New("invalid investigation context claims")

const investigationSchemaIdentity = "77367fd94611f87d36e4490729096db927b8d27b9d687a4b6ab515db70e2bbc4"
const investigationInstructionsIdentity = "990e881d4038ea3c222c4c0aed5b6dad7dbff547faa5f30ff067b3ac18072c8c"

func InvestigationOutputSchema() []byte { return reviewschema.InvestigationOutputSchema() }
func InvestigationInstructions() string { return reviewschema.InvestigationInstructions() }

// InvestigationRouteContextClaim describes routing data, not approval or a claim.
type InvestigationRouteContextClaim struct {
	Record            provider.RouteRegistryRecord
	ManifestSizeBytes uint32
	Operational       provider.RouteOperationalState
}
type InvestigationContextRouting struct {
	RegistryRevision, PerformanceRevision uint64
	Generation                            InvestigationRouteContextClaim
	Verification                          []InvestigationRouteContextClaim
	Performance                           []provider.RoutePerformanceObservation
	Requirements                          provider.ModelRequirements
	Constraints                           policy.ProviderDataConstraints
	Budget                                provider.ModelCostBudget
	VerificationRanking                   gateway.RouteRankingPolicy
	Independence                          gateway.RouteIndependencePolicy
	CatalogIdentity                       string
}
type InvestigationContextBindingOptions struct {
	Scope                                              audit.ReviewScope
	HostSessionIdentity                                string
	Policy                                             InvestigationPolicy
	HeadSnapshotArtifactIdentity, HeadSnapshotIdentity string
	HeadManifestIdentity, HeadRevisionIdentity         string
	InitialContext                                     ContextPacket
	InitialSnapshot                                    ReviewSnapshot
	Deadline                                           time.Time
	Routing                                            InvestigationContextRouting
}

// InvestigationContextBinding seals caller data without establishing source custody.
type InvestigationContextBinding struct {
	identity string
	options  InvestigationContextBindingOptions
}

func NewInvestigationContextBinding(o InvestigationContextBindingOptions) (InvestigationContextBinding, error) {
	if o.Scope.Validate() != nil || o.Policy.ValidateRuntimeBudget(o.Routing.Budget) != nil || o.Deadline.UnixMilli() <= 0 || o.Deadline.UnixMilli() > 253402300799999 || o.Routing.RegistryRevision == 0 || o.Routing.PerformanceRevision == 0 || len(o.Routing.Verification) == 0 || len(o.Routing.Verification) > 64 || len(o.Routing.Performance) == 0 || len(o.Routing.Performance) > 65 || o.Routing.Requirements.Validate() != nil || o.Routing.Constraints.Validate() != nil || o.Routing.VerificationRanking.Validate() != nil || o.Routing.Independence.Validate() != nil || o.Routing.Budget.MaxOutputTokens() < o.Routing.Requirements.MinOutputTokens() {
		return InvestigationContextBinding{}, ErrInvestigationContext
	}
	for _, id := range []string{o.HostSessionIdentity, o.HeadSnapshotArtifactIdentity, o.HeadSnapshotIdentity, o.HeadManifestIdentity, o.HeadRevisionIdentity, o.Routing.CatalogIdentity} {
		if !validCandidateDigest(id) {
			return InvestigationContextBinding{}, ErrInvestigationContext
		}
	}
	if !investigationPacketMatches(o.InitialContext, o.InitialSnapshot, o.Scope.Identity(), o.HeadManifestIdentity) {
		return InvestigationContextBinding{}, ErrInvestigationContext
	}
	foundChanged := false
	for _, source := range o.InitialContext.sources {
		if source.Stage() == ContextStageChangedHunk {
			foundChanged = true
		}
	}
	if !foundChanged {
		return InvestigationContextBinding{}, ErrInvestigationContext
	}
	records := map[string]InvestigationRouteContextClaim{}
	all := make([]InvestigationRouteContextClaim, 0, 1+len(o.Routing.Verification))
	all = append(all, o.Routing.Generation)
	all = append(all, o.Routing.Verification...)
	verifierIDs := map[string]bool{}
	verifierRefs := map[provider.RouteReference]bool{}
	for i, claim := range all {
		if claim.Record.Validate() != nil || claim.Record.RegistryRevision() != o.Routing.RegistryRevision || claim.ManifestSizeBytes == 0 || claim.ManifestSizeBytes > 1<<20 || claim.Operational.Validate() != nil || claim.Operational.RecordIdentity() != claim.Record.Identity() {
			return InvestigationContextBinding{}, ErrInvestigationContext
		}
		if prior, ok := records[claim.Record.Identity()]; ok && (prior.ManifestSizeBytes != claim.ManifestSizeBytes || prior.Operational != claim.Operational) {
			return InvestigationContextBinding{}, ErrInvestigationContext
		}
		records[claim.Record.Identity()] = claim
		if i > 0 {
			ref := claim.Record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()
			if verifierIDs[claim.Record.Identity()] || verifierRefs[ref] {
				return InvestigationContextBinding{}, ErrInvestigationContext
			}
			verifierIDs[claim.Record.Identity()] = true
			verifierRefs[ref] = true
		}
	}
	if len(records) != len(o.Routing.Performance) {
		return InvestigationContextBinding{}, ErrInvestigationContext
	}
	seen := map[string]bool{}
	for _, obs := range o.Routing.Performance {
		if obs.Validate() != nil || obs.ObservationRevision() != o.Routing.PerformanceRevision || seen[obs.RecordIdentity()] {
			return InvestigationContextBinding{}, ErrInvestigationContext
		}
		if _, ok := records[obs.RecordIdentity()]; !ok {
			return InvestigationContextBinding{}, ErrInvestigationContext
		}
		seen[obs.RecordIdentity()] = true
	}
	o.Routing.Verification = append([]InvestigationRouteContextClaim(nil), o.Routing.Verification...)
	sort.Slice(o.Routing.Verification, func(i, j int) bool {
		return o.Routing.Verification[i].Record.Identity() < o.Routing.Verification[j].Record.Identity()
	})
	o.Routing.Performance = append([]provider.RoutePerformanceObservation(nil), o.Routing.Performance...)
	sort.Slice(o.Routing.Performance, func(i, j int) bool {
		return o.Routing.Performance[i].RecordIdentity() < o.Routing.Performance[j].RecordIdentity()
	})
	o.InitialContext = cloneInvestigationPacket(o.InitialContext)
	o.InitialSnapshot = cloneInvestigationSnapshot(o.InitialSnapshot)
	o.Deadline = time.UnixMilli(o.Deadline.UnixMilli()).UTC()
	value := InvestigationContextBinding{options: o}
	value.identity = deriveInvestigationBinding(o)
	return value, nil
}
func (b InvestigationContextBinding) Identity() string { return b.identity }
func (b InvestigationContextBinding) Validate() error {
	canonical, err := NewInvestigationContextBinding(b.options)
	if err != nil || b.identity != canonical.identity || !validCandidateDigest(b.identity) {
		return ErrInvestigationContext
	}
	return nil
}
func investigationRouteDescriptor(c InvestigationRouteContextClaim) []any {
	return []any{c.Record.Identity(), c.ManifestSizeBytes, c.Operational.ObservationRevision(), c.Operational.Health().String(), c.Operational.Quota().String()}
}
func deriveInvestigationBinding(o InvestigationContextBindingOptions) string {
	verifiers := []any{}
	for _, c := range o.Routing.Verification {
		verifiers = append(verifiers, investigationRouteDescriptor(c))
	}
	performance := []any{}
	for _, p := range o.Routing.Performance {
		performance = append(performance, []any{p.RecordIdentity(), p.ObservationRevision(), p.LatencyKnown(), p.P95LatencyMilliseconds(), p.SampleCount()})
	}
	features := []string{}
	for _, v := range o.Routing.Requirements.RequiredFeatures() {
		features = append(features, v.String())
	}
	zones := []string{}
	for z := provider.ProviderZoneLocal; z <= provider.ProviderZoneSubscriptionOAuth; z++ {
		if o.Routing.Constraints.AllowedProviderZones().Allows(z) {
			zones = append(zones, z.String())
		}
	}
	encoded, _ := json.Marshal([]any{"open-trestle/investigation-session", 1, "fixed_generation_route_v1", o.HostSessionIdentity, o.Scope.Identity(), o.Policy.Identity(), o.HeadSnapshotArtifactIdentity, o.HeadSnapshotIdentity, o.HeadManifestIdentity, o.HeadRevisionIdentity, o.InitialContext.Identity(), o.InitialSnapshot.Identity(), o.Deadline.UnixMilli(), o.Routing.CatalogIdentity, o.Routing.RegistryRevision, o.Routing.PerformanceRevision, investigationRouteDescriptor(o.Routing.Generation), verifiers, performance, o.Routing.VerificationRanking.Identity(), o.Routing.Independence.Identity(), o.Routing.Requirements.MinContextTokens(), o.Routing.Requirements.MinOutputTokens(), features, string(o.Routing.Constraints.Classification()), zones, o.Routing.Constraints.ContentLoggingAllowed(), o.Routing.Budget.EstimatedInputTokens(), o.Routing.Budget.MaxOutputTokens(), o.Routing.Budget.MaxCostMicroUSD()})
	return investigationContextDigest(encoded)
}

func investigationPacketMatches(p ContextPacket, s ReviewSnapshot, scope, manifest string) bool {
	if !validAcquiredReviewWorkspace(s.Workspace()) || len(p.sources) > maxSelectedContextSources || len(s.ranges) > maxSelectedContextSources || len(p.sourceOmissions) > 16384 || len(p.additionalRetrievals) >= 64 || len(p.sourceSelection.entries) > maxContextSourceCandidates {
		return false
	}
	var sourceBytes uint64
	for _, source := range p.sources {
		if uint64(source.SizeBytes()) > uint64(maxContextAggregateBytes)-sourceBytes {
			return false
		}
		sourceBytes += uint64(source.SizeBytes())
	}
	if sourceBytes > uint64(p.limits.MaxSourceBytes()) {
		return false
	}
	if len(s.ranges) == 0 || len(s.ranges) > maxSelectedContextSources || len(p.sources) == 0 || len(p.sources) > maxSelectedContextSources || s.Validate() != nil || p.Validate() != nil || p.ReviewScopeIdentity() != scope || p.SnapshotIdentity() != s.Identity() || p.Task() != ContextTaskCandidateGeneration || p.MemoryItemCount() != 0 || p.limits.MaxMemoryItems() != 0 || len(s.ranges) != len(p.sources) {
		return false
	}
	type rangeWire struct {
		Path  string `json:"path"`
		Start int    `json:"start"`
		End   int    `json:"end"`
		File  string `json:"file"`
	}
	byRange := map[evidence.SourceRange]string{}
	byPath := map[string]string{}
	bindings := map[string]bool{}
	for _, source := range p.sources {
		if !source.HasSliceBinding() || source.SliceBinding().Validate() != nil {
			return false
		}
		binding := source.SliceBinding()
		span := source.EvidenceItem().SourceRange()
		file := binding.RepositoryFileIdentity()
		if bindings[binding.Identity()] || byRange[span] != "" || byPath[span.Path()] != "" && byPath[span.Path()] != file {
			return false
		}
		bindings[binding.Identity()] = true
		byRange[span] = file
		byPath[span.Path()] = file
	}
	ranges := make([]rangeWire, len(s.ranges))
	for i, span := range s.ranges {
		file := byRange[span]
		if file == "" {
			return false
		}
		if i > 0 {
			previous := s.ranges[i-1]
			if previous.Path() > span.Path() || previous.Path() == span.Path() && (previous.StartLine() > span.StartLine() || previous.StartLine() == span.StartLine() && previous.EndLine() >= span.EndLine()) {
				return false
			}
		}
		ranges[i] = rangeWire{span.Path(), span.StartLine(), span.EndLine(), file}
	}
	// This is the existing acquired range-set recipe, using claimed file identities.
	encoded, _ := json.Marshal(struct {
		Contract string      `json:"contract"`
		Version  int         `json:"version"`
		Manifest string      `json:"manifest"`
		Ranges   []rangeWire `json:"ranges"`
	}{"open-trestle/acquired-review-range-set", 1, manifest, ranges})
	return s.Revision() == investigationContextDigest(encoded)
}
func cloneInvestigationSnapshot(s ReviewSnapshot) ReviewSnapshot {
	s.ranges = append([]evidence.SourceRange(nil), s.ranges...)
	return s
}
func cloneInvestigationPacket(p ContextPacket) ContextPacket {
	p.sources = p.Sources()
	p.sourceOmissions = p.SourceOmissions()
	p.additionalRetrievals = append([]memory.LexicalRetrieval(nil), p.additionalRetrievals...)
	p.sourceSelection.entries = p.sourceSelection.Entries()
	p.sourceSelection.selectedSources = p.sourceSelection.SelectedSources()
	return p
}

// InvestigationResultAnnotation holds canonical caller data, not tool-success proof.
type InvestigationResultAnnotation struct{ artifactIdentity, payload string }

func NewInvestigationResultAnnotation(artifactIdentity string, payload []byte) (InvestigationResultAnnotation, error) {
	if !validCandidateDigest(artifactIdentity) {
		return InvestigationResultAnnotation{}, ErrInvestigationContext
	}
	if _, err := investigationAnnotationObject(payload); err != nil {
		return InvestigationResultAnnotation{}, err
	}
	return InvestigationResultAnnotation{artifactIdentity: artifactIdentity, payload: string(payload)}, nil
}
func (a InvestigationResultAnnotation) ArtifactIdentity() string { return a.artifactIdentity }
func (a InvestigationResultAnnotation) Payload() []byte          { return []byte(a.payload) }
func investigationAnnotationObject(payload []byte) (map[string]any, error) {
	if len(payload) == 0 || len(payload) > 64<<10 || !utf8.Valid(payload) || !validProposalUnicode(payload) {
		return nil, ErrInvestigationContext
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	if !consumeInvestigationAnnotation(decoder, 0) {
		return nil, ErrInvestigationContext
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, ErrInvestigationContext
	}
	decoder = json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var value map[string]any
	if decoder.Decode(&value) != nil || value == nil {
		return nil, ErrInvestigationContext
	}
	if _, exists := value["artifact_identity"]; exists {
		return nil, ErrInvestigationContext
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, payload) {
		return nil, ErrInvestigationContext
	}
	return value, nil
}
func consumeInvestigationAnnotation(d *json.Decoder, depth int) bool {
	if depth > 32 {
		return false
	}
	token, err := d.Token()
	if err != nil {
		return false
	}
	if number, ok := token.(json.Number); ok {
		text := number.String()
		n, err := strconv.ParseUint(text, 10, 64)
		return err == nil && strconv.FormatUint(n, 10) == text
	}
	delim, container := token.(json.Delim)
	if !container {
		return true
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok || seen[name] || len(seen) >= 128 {
				return false
			}
			seen[name] = true
			if !consumeInvestigationAnnotation(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		count := 0
		for d.More() {
			count++
			if count > 1024 || !consumeInvestigationAnnotation(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim(']')
	}
	return false
}

type InvestigationContextState struct {
	Turn                                             uint8
	PreviousRequestIdentity, PreviousOutcomeIdentity string
	NewResultArtifactIdentities                      []string
	Results                                          []InvestigationResultAnnotation
	ScannedBytes, ReturnedBytes                      uint64
	ToolCallsUsed                                    uint8
}
type InvestigationGenerationContext struct {
	identity, payload string
	binding           InvestigationContextBinding
	selected          ContextPacket
	snapshot          ReviewSnapshot
	state             InvestigationContextState
}

func NewInvestigationGenerationContext(binding InvestigationContextBinding, selected ContextPacket, snapshot ReviewSnapshot, state InvestigationContextState) (InvestigationGenerationContext, error) {
	if binding.Validate() != nil {
		return InvestigationGenerationContext{}, ErrInvestigationContext
	}
	o := binding.options
	p := o.Policy
	if state.Turn == 0 || uint64(state.Turn) > p.MaxModelTurns() || uint64(state.ToolCallsUsed) > p.MaxToolCalls() || state.ToolCallsUsed != state.Turn-1 || len(state.Results) != int(state.ToolCallsUsed) || len(state.NewResultArtifactIdentities) > 1 || state.ScannedBytes > p.MaxScannedBytes() || state.ReturnedBytes > p.MaxReturnedBytes() || !investigationPacketMatches(selected, snapshot, o.Scope.Identity(), o.HeadManifestIdentity) || snapshot.Workspace() != o.InitialSnapshot.Workspace() || selected.MemoryScopeIdentity() != o.InitialContext.MemoryScopeIdentity() || selected.MemoryIdentity() != o.InitialContext.MemoryIdentity() {
		return InvestigationGenerationContext{}, ErrInvestigationContext
	}
	if state.Turn == 1 {
		if state.PreviousRequestIdentity != "" || state.PreviousOutcomeIdentity != "" || len(state.NewResultArtifactIdentities) != 0 || state.ReturnedBytes != 0 || selected.Identity() != o.InitialContext.Identity() || snapshot.Identity() != o.InitialSnapshot.Identity() {
			return InvestigationGenerationContext{}, ErrInvestigationContext
		}
	} else if !validCandidateDigest(state.PreviousRequestIdentity) || !validCandidateDigest(state.PreviousOutcomeIdentity) || len(state.NewResultArtifactIdentities) != 1 || state.NewResultArtifactIdentities[0] != state.Results[len(state.Results)-1].artifactIdentity {
		return InvestigationGenerationContext{}, ErrInvestigationContext
	}
	initial := map[string]ContextSource{}
	current := map[string]ContextSource{}
	for _, source := range o.InitialContext.sources {
		initial[source.ReferenceID()] = source
	}
	for _, source := range selected.sources {
		current[source.ReferenceID()] = source
		if original, ok := initial[source.ReferenceID()]; ok {
			if original.Identity() != source.Identity() {
				return InvestigationGenerationContext{}, ErrInvestigationContext
			}
		} else if source.Stage() != ContextStageRepositoryContext {
			return InvestigationGenerationContext{}, ErrInvestigationContext
		}
	}
	for id, source := range initial {
		if current[id].Identity() != source.Identity() {
			return InvestigationGenerationContext{}, ErrInvestigationContext
		}
	}
	omissions := map[ContextSourceOmission]bool{}
	for _, omission := range selected.sourceOmissions {
		omissions[omission] = true
	}
	for _, omission := range o.InitialContext.sourceOmissions {
		if !omissions[omission] {
			return InvestigationGenerationContext{}, ErrInvestigationContext
		}
	}
	seen := map[string]bool{}
	results := make([]any, 0, len(state.Results))
	var payloadBytes uint64
	for _, annotation := range state.Results {
		if !validCandidateDigest(annotation.artifactIdentity) || seen[annotation.artifactIdentity] || uint64(len(annotation.payload)) > p.MaxResultBytes() {
			return InvestigationGenerationContext{}, ErrInvestigationContext
		}
		seen[annotation.artifactIdentity] = true
		if uint64(len(annotation.payload)) > p.MaxReturnedBytes()-payloadBytes {
			return InvestigationGenerationContext{}, ErrInvestigationContext
		}
		payloadBytes += uint64(len(annotation.payload))
		value, err := investigationAnnotationObject([]byte(annotation.payload))
		if err != nil {
			return InvestigationGenerationContext{}, ErrInvestigationContext
		}
		value["artifact_identity"] = annotation.artifactIdentity
		results = append(results, value)
	}
	if payloadBytes > state.ReturnedBytes {
		return InvestigationGenerationContext{}, ErrInvestigationContext
	}
	canonicalBinding, err := NewInvestigationContextBinding(o)
	if err != nil {
		return InvestigationGenerationContext{}, ErrInvestigationContext
	}
	state.NewResultArtifactIdentities = append([]string{}, state.NewResultArtifactIdentities...)
	state.Results = append([]InvestigationResultAnnotation(nil), state.Results...)
	value := InvestigationGenerationContext{binding: canonicalBinding, selected: cloneInvestigationPacket(selected), snapshot: cloneInvestigationSnapshot(snapshot), state: state}
	payload, err := encodeInvestigationContext(value, results)
	if err != nil {
		return InvestigationGenerationContext{}, err
	}
	value.payload = string(payload)
	value.identity = investigationContextDigest(payload)
	return value, nil
}

func encodeInvestigationContext(value InvestigationGenerationContext, results []any) ([]byte, error) {
	schema, instructions := InvestigationOutputSchema(), InvestigationInstructions()
	if investigationContextDigest(schema) != investigationSchemaIdentity || investigationContextDigest([]byte(instructions)) != investigationInstructionsIdentity {
		return nil, ErrInvestigationContext
	}
	legacy, err := encodeContextPacket(value.selected)
	if err != nil {
		return nil, ErrInvestigationContext
	}
	var wire map[string]json.RawMessage
	if json.Unmarshal(legacy, &wire) != nil {
		return nil, ErrInvestigationContext
	}
	set := func(key string, v any) { wire[key], _ = json.Marshal(v) }
	set("schema_version", 4)
	set("instructions", instructions)
	wire["output_schema"] = json.RawMessage(schema)
	set("output_schema_identity", investigationSchemaIdentity)
	set("tool_calls", "host_admitted_snapshot_read_v1")
	if _, ok := wire["source_omissions"]; !ok {
		wire["source_omissions"] = json.RawMessage("[]")
	}
	if _, ok := wire["additional_memory"]; !ok {
		wire["additional_memory"] = json.RawMessage("[]")
	}
	o, s := value.binding.options, value.state
	snapshotRef := investigationContextDigest(mustInvestigationJSON([]any{"open-trestle/investigation-snapshot-ref", 1, value.binding.Identity(), o.Scope.Identity(), o.HeadSnapshotArtifactIdentity, o.HeadSnapshotIdentity}))
	set("investigation", map[string]any{"session_identity": value.binding.Identity(), "policy_identity": o.Policy.Identity(), "routing_mode": "fixed_generation_route_v1", "generation_route_record_identity": o.Routing.Generation.Record.Identity(), "snapshot_artifact_identity": o.HeadSnapshotArtifactIdentity, "snapshot_identity": o.HeadSnapshotIdentity, "manifest_identity": o.HeadManifestIdentity, "initial_context_identity": o.InitialContext.Identity(), "initial_selected_snapshot_identity": o.InitialSnapshot.Identity(), "snapshot_ref": snapshotRef, "turn": s.Turn, "previous_request_identity": s.PreviousRequestIdentity, "previous_outcome_identity": s.PreviousOutcomeIdentity, "previous_tool_result_identities": s.NewResultArtifactIdentities, "memory_state": "empty_not_ingested", "scanned_bytes": s.ScannedBytes, "returned_bytes": s.ReturnedBytes, "tool_calls_used": s.ToolCallsUsed, "tool_results": results})
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) == 0 || len(encoded) > maxProviderContextPacketBytes {
		return nil, ErrInvestigationContext
	}
	return encoded, nil
}
func mustInvestigationJSON(value any) []byte { encoded, _ := json.Marshal(value); return encoded }
func investigationContextDigest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
func (c InvestigationGenerationContext) Identity() string { return c.identity }
func (c InvestigationGenerationContext) Snapshot() ReviewSnapshot {
	return cloneInvestigationSnapshot(c.snapshot)
}
func (c InvestigationGenerationContext) EvidenceItems() []evidence.EvidenceItem {
	return c.selected.EvidenceItems()
}
func (c InvestigationGenerationContext) Validate() error {
	canonical, err := NewInvestigationGenerationContext(c.binding, c.selected, c.snapshot, c.state)
	if err != nil || c.identity != canonical.identity || c.payload != canonical.payload {
		return ErrInvestigationContext
	}
	return nil
}
func (c InvestigationGenerationContext) ProviderRequest() (provider.Request, error) {
	if c.Validate() != nil {
		return provider.Request{}, ErrInvestigationContext
	}
	return provider.NewRequest(provider.CapabilityReviewV1, "application/json", []byte(c.payload))
}

// NewInvestigationVerificationRequestContext projects data without authorizing a verifier.
func NewInvestigationVerificationRequestContext(final InvestigationGenerationContext, candidates CandidateBatch) (VerificationRequestContext, error) {
	if final.Validate() != nil || candidates.Validate() != nil || candidates.SnapshotIdentity() != final.snapshot.Identity() {
		return VerificationRequestContext{}, ErrInvestigationContext
	}
	p := final.selected
	allowed := map[string]evidence.EvidenceItem{}
	for _, item := range p.EvidenceItems() {
		allowed[item.ID()] = item
	}
	for _, candidate := range candidates.Findings() {
		source, ok := allowed[candidate.SourceReferenceID()]
		if !ok || !rangeContains(source.SourceRange(), candidate.SourceRange()) {
			return VerificationRequestContext{}, ErrInvestigationContext
		}
		for _, id := range candidate.EvidenceIDs() {
			if _, ok := allowed[id]; !ok {
				return VerificationRequestContext{}, ErrInvestigationContext
			}
		}
	}
	legacy, err := encodeContextPacket(p)
	if err != nil {
		return VerificationRequestContext{}, ErrInvestigationContext
	}
	control, err := NewVerificationRequestContext(legacy, p.Identity(), p.ReviewScopeIdentity(), p.MemoryScopeIdentity(), p.MemoryIdentity(), final.snapshot, p.EvidenceItems(), candidates)
	if err != nil {
		return VerificationRequestContext{}, ErrInvestigationContext
	}
	var wire verificationContextWire
	if json.Unmarshal(control.Payload(), &wire) != nil {
		return VerificationRequestContext{}, ErrInvestigationContext
	}
	wire.GenerationContextIdentity = final.Identity()
	payload, err := json.Marshal(wire)
	if err != nil || len(payload) > maxProviderContextPacketBytes {
		return VerificationRequestContext{}, ErrInvestigationContext
	}
	identity := investigationContextDigest(payload)
	summaries, err := summarizeContextSourceOmissions(wire.SourceOmissions, wire.SourceCoverage.Omitted-wire.SourceCoverage.PreselectionOmitted)
	if err != nil {
		return VerificationRequestContext{}, ErrInvestigationContext
	}
	coverage, err := newContextSourceCoverage(identity, p.ReviewScopeIdentity(), final.snapshot.Identity(), candidates.Identity(), wire.SourceCoverage.Analyzed, wire.SourceCoverage.Selected, wire.SourceCoverage.Omitted, summaries)
	if err != nil {
		return VerificationRequestContext{}, ErrInvestigationContext
	}
	result := VerificationRequestContext{identity: identity, generationContextIdentity: final.Identity(), reviewScopeIdentity: p.ReviewScopeIdentity(), snapshot: cloneInvestigationSnapshot(final.snapshot), candidates: candidates, evidenceItems: p.EvidenceItems(), sourceCoverage: coverage, payload: string(payload)}
	if result.Validate() != nil {
		return VerificationRequestContext{}, ErrInvestigationContext
	}
	return result, nil
}
func (b InvestigationContextBinding) String() string { return "investigation context binding" }
func (b InvestigationContextBinding) GoString() string {
	return "review.InvestigationContextBinding{<redacted>}"
}
func (b InvestigationContextBinding) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation context binding"))
}
func (a InvestigationResultAnnotation) String() string { return "investigation result annotation" }
func (a InvestigationResultAnnotation) GoString() string {
	return "review.InvestigationResultAnnotation{<redacted>}"
}
func (a InvestigationResultAnnotation) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation result annotation"))
}
func (c InvestigationGenerationContext) String() string { return "investigation generation context" }
func (c InvestigationGenerationContext) GoString() string {
	return "review.InvestigationGenerationContext{<redacted>}"
}
func (c InvestigationGenerationContext) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation generation context"))
}
