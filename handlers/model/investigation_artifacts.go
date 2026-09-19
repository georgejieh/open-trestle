package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	source "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/review"
)

var ErrInvestigationArtifacts = errors.New("investigation artifact witness unavailable or inconsistent")

const investigationSourceWorkLimit = 16 << 20
const investigationArtifactSources = 128

// InvestigationArtifactContext includes host-held syntax and supplied custody evidence.
type InvestigationArtifactContext struct {
	Context              review.InvestigationGenerationContext
	ContextArtifact      artifact.Artifact
	HeadSnapshotArtifact artifact.Artifact
	SourceFileArtifacts  []artifact.Artifact
	ToolResultArtifacts  []artifact.Artifact
}

// InvestigationArtifactExpectations must come from trusted host reference registration.
type InvestigationArtifactExpectations struct {
	Scope                                                                    audit.ReviewScope
	SessionIdentity, PolicyIdentity, OwnerIdentity                           string
	HeadSnapshotArtifactIdentity, HeadSnapshotIdentity, HeadManifestIdentity string
	ContextArtifactIdentity, InputArtifactIdentity, TurnArtifactIdentity     string
	ResultArtifactIdentity, PreviousTurnIdentity                             string
	ToolResultArtifactIdentities                                             []string
}

type InvestigationGenerationInput struct {
	identity, scope, contextArtifact, contextIdentity, memoryScope, memoryIdentity   string
	session, policy, owner, headArtifact, headSnapshot, headManifest, initialContext string
	schemaIdentity                                                                   string
	snapshot                                                                         review.ReviewSnapshot
	evidence                                                                         []evidence.EvidenceItem
	authorization                                                                    gateway.RouteAttemptAuthorization
}

func (i InvestigationGenerationInput) Identity() string                { return i.identity }
func (i InvestigationGenerationInput) ContextIdentity() string         { return i.contextIdentity }
func (i InvestigationGenerationInput) Snapshot() review.ReviewSnapshot { return i.snapshot }
func (i InvestigationGenerationInput) EvidenceItems() []evidence.EvidenceItem {
	return append([]evidence.EvidenceItem(nil), i.evidence...)
}
func (i InvestigationGenerationInput) Authorization() gateway.RouteAttemptAuthorization {
	return i.authorization
}

type investigationInputWire struct {
	Contract        string                   `json:"contract"`
	Version         uint8                    `json:"schema_version"`
	Identity        string                   `json:"identity"`
	Scope           string                   `json:"review_scope_identity"`
	ContextArtifact string                   `json:"context_artifact_identity"`
	ContextIdentity string                   `json:"context_identity"`
	MemoryScope     string                   `json:"memory_scope_identity"`
	MemoryIdentity  string                   `json:"memory_identity"`
	SchemaIdentity  string                   `json:"output_schema_identity"`
	Workspace       string                   `json:"snapshot_workspace"`
	Revision        string                   `json:"snapshot_revision"`
	Snapshot        string                   `json:"snapshot_identity"`
	Ranges          []generationRangeWire    `json:"snapshot_ranges"`
	Evidence        []generationEvidenceWire `json:"evidence"`
	Authorization   json.RawMessage          `json:"authorization"`
	Session         string                   `json:"investigation_session_identity"`
	Policy          string                   `json:"investigation_policy_identity"`
	Owner           string                   `json:"owner_identity"`
	HeadArtifact    string                   `json:"head_snapshot_artifact_identity"`
	HeadSnapshot    string                   `json:"head_snapshot_identity"`
	HeadManifest    string                   `json:"head_manifest_identity"`
	InitialContext  string                   `json:"initial_context_identity"`
	Tools           []string                 `json:"tool_result_artifact_identities"`
}

func (i InvestigationGenerationInput) values() (map[string]any, error) {
	authorization, err := gateway.EncodeRouteAttemptAuthorization(i.authorization)
	if err != nil {
		return nil, ErrInvestigationArtifacts
	}
	ranges := make([]generationRangeWire, len(i.snapshot.Ranges()))
	for n, r := range i.snapshot.Ranges() {
		ranges[n] = generationRangeWire{r.Path(), r.StartLine(), r.EndLine()}
	}
	items := make([]generationEvidenceWire, len(i.evidence))
	for n, item := range i.evidence {
		r := item.SourceRange()
		items[n] = generationEvidenceWire{item.ID(), string(item.Kind()), item.Digest(), r.Path(), r.StartLine(), r.EndLine()}
	}
	return map[string]any{"contract": "open-trestle/model-generation-input", "schema_version": 2, "identity": i.identity, "review_scope_identity": i.scope, "context_artifact_identity": i.contextArtifact, "context_identity": i.contextIdentity, "memory_scope_identity": i.memoryScope, "memory_identity": i.memoryIdentity, "output_schema_identity": i.schemaIdentity, "snapshot_workspace": i.snapshot.Workspace(), "snapshot_revision": i.snapshot.Revision(), "snapshot_identity": i.snapshot.Identity(), "snapshot_ranges": ranges, "evidence": items, "authorization": json.RawMessage(authorization), "investigation_session_identity": i.session, "investigation_policy_identity": i.policy, "owner_identity": i.owner, "head_snapshot_artifact_identity": i.headArtifact, "head_snapshot_identity": i.headSnapshot, "head_manifest_identity": i.headManifest, "initial_context_identity": i.initialContext, "tool_result_artifact_identities": []string{}}, nil
}
func (i InvestigationGenerationInput) Validate() error {
	for _, id := range []string{i.identity, i.scope, i.contextArtifact, i.contextIdentity, i.memoryScope, i.memoryIdentity, i.schemaIdentity, i.session, i.policy, i.owner, i.headArtifact, i.headSnapshot, i.headManifest, i.initialContext} {
		if !validDigest(id) {
			return ErrInvestigationArtifacts
		}
	}
	if len(i.snapshot.Ranges()) == 0 || len(i.snapshot.Ranges()) > investigationArtifactSources || len(i.snapshot.Workspace()) == 0 || len(i.snapshot.Workspace()) > 1024 || i.snapshot.Validate() != nil || len(i.evidence) == 0 || len(i.evidence) > investigationArtifactSources || i.authorization.Validate() != nil || i.authorization.ReviewScopeIdentity() != i.scope || i.authorization.Kind() != gateway.RouteAttemptInitial || i.authorization.PreviousOutcomeIdentity() != "" || i.schemaIdentity != artifactPayloadHash(review.InvestigationOutputSchema()) {
		return ErrInvestigationArtifacts
	}
	seen := map[string]bool{}
	for _, item := range i.evidence {
		r := item.SourceRange()
		rebuilt, err := evidence.NewEvidenceItem(item.ID(), item.Kind(), item.Digest(), r)
		if err != nil || rebuilt.ID() != item.ID() || item.Kind() != evidence.EvidenceKindSource || seen[item.ID()] || !rangeSupported(r, i.snapshot) {
			return ErrInvestigationArtifacts
		}
		seen[item.ID()] = true
	}
	values, err := i.values()
	if err != nil {
		return err
	}
	delete(values, "identity")
	encoded, err := json.Marshal(values)
	if err != nil || len(encoded) > maximumGenerationInputBytes || artifactPayloadHash(encoded) != i.identity {
		return ErrInvestigationArtifacts
	}
	return nil
}
func EncodeInvestigationGenerationInput(i InvestigationGenerationInput) ([]byte, error) {
	if i.Validate() != nil {
		return nil, ErrInvestigationArtifacts
	}
	values, err := i.values()
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(values)
	if err != nil || len(encoded) > maximumGenerationInputBytes {
		return nil, ErrInvestigationArtifacts
	}
	return encoded, nil
}

// ParseInvestigationGenerationInput decodes untrusted claims, not artifact custody.
func ParseInvestigationGenerationInput(encoded []byte) (InvestigationGenerationInput, error) {
	if len(encoded) == 0 || len(encoded) > maximumGenerationInputBytes || !utf8.Valid(encoded) {
		return InvestigationGenerationInput{}, ErrInvestigationArtifacts
	}
	var wire investigationInputWire
	if decodeInvestigationJSON(encoded, &wire) != nil || wire.Contract != "open-trestle/model-generation-input" || wire.Version != 2 || len(wire.Ranges) == 0 || len(wire.Ranges) > investigationArtifactSources || len(wire.Evidence) == 0 || len(wire.Evidence) > investigationArtifactSources || len(wire.Workspace) == 0 || len(wire.Workspace) > 1024 || wire.Tools == nil || len(wire.Tools) != 0 {
		return InvestigationGenerationInput{}, ErrInvestigationArtifacts
	}
	ranges := make([]evidence.SourceRange, len(wire.Ranges))
	for n, r := range wire.Ranges {
		var err error
		ranges[n], err = evidence.NewSourceRange(r.Path, r.StartLine, r.EndLine)
		if err != nil {
			return InvestigationGenerationInput{}, ErrInvestigationArtifacts
		}
	}
	snapshot, err := review.NewReviewSnapshot(wire.Workspace, wire.Revision, ranges)
	if err != nil || snapshot.Identity() != wire.Snapshot {
		return InvestigationGenerationInput{}, ErrInvestigationArtifacts
	}
	items := make([]evidence.EvidenceItem, len(wire.Evidence))
	for n, item := range wire.Evidence {
		r, err := evidence.NewSourceRange(item.Path, item.StartLine, item.EndLine)
		if err != nil {
			return InvestigationGenerationInput{}, ErrInvestigationArtifacts
		}
		items[n], err = evidence.NewEvidenceItem(item.ID, evidence.EvidenceKind(item.Kind), item.Digest, r)
		if err != nil {
			return InvestigationGenerationInput{}, ErrInvestigationArtifacts
		}
	}
	authorization, err := gateway.ParseRouteAttemptAuthorization(wire.Authorization)
	if err != nil {
		return InvestigationGenerationInput{}, ErrInvestigationArtifacts
	}
	value := InvestigationGenerationInput{identity: wire.Identity, scope: wire.Scope, contextArtifact: wire.ContextArtifact, contextIdentity: wire.ContextIdentity, memoryScope: wire.MemoryScope, memoryIdentity: wire.MemoryIdentity, schemaIdentity: wire.SchemaIdentity, session: wire.Session, policy: wire.Policy, owner: wire.Owner, headArtifact: wire.HeadArtifact, headSnapshot: wire.HeadSnapshot, headManifest: wire.HeadManifest, initialContext: wire.InitialContext, snapshot: snapshot, evidence: items, authorization: authorization}
	canonical, err := EncodeInvestigationGenerationInput(value)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return InvestigationGenerationInput{}, ErrInvestigationArtifacts
	}
	return value, nil
}

// investigationSourceWorkWithinLimit admits retained head/file bytes plus a decoded-file allowance.
// It is metadata only, not validity, source custody, total allocations or CPU accounting.
func investigationSourceWorkWithinLimit(c InvestigationArtifactContext) bool {
	if len(c.SourceFileArtifacts) > investigationArtifactSources {
		return false
	}
	head := c.HeadSnapshotArtifact.PayloadSizeBytes()
	if head <= 0 || head > investigationSourceWorkLimit {
		return false
	}
	remaining := investigationSourceWorkLimit - head
	for _, file := range c.SourceFileArtifacts {
		n := file.PayloadSizeBytes()
		if n <= 0 || n > remaining/2 {
			return false
		}
		remaining -= 2 * n
	}
	return true
}
func investigationExpected(e InvestigationArtifactExpectations, stage string, construct bool) bool {
	if e.Scope.Validate() != nil || len(e.ToolResultArtifactIdentities) != 0 {
		return false
	}
	for _, id := range []string{e.SessionIdentity, e.PolicyIdentity, e.OwnerIdentity, e.HeadSnapshotArtifactIdentity, e.HeadSnapshotIdentity, e.HeadManifestIdentity, e.ContextArtifactIdentity} {
		if !validDigest(id) {
			return false
		}
	}
	if e.PreviousTurnIdentity != "" && !validDigest(e.PreviousTurnIdentity) {
		return false
	}
	if stage == "input" {
		if e.TurnArtifactIdentity != "" || e.ResultArtifactIdentity != "" || e.PreviousTurnIdentity != "" {
			return false
		}
		return construct && e.InputArtifactIdentity == "" || !construct && validDigest(e.InputArtifactIdentity)
	}
	if !validDigest(e.InputArtifactIdentity) || !validDigest(e.TurnArtifactIdentity) || e.PreviousTurnIdentity != "" {
		return false
	}
	return construct && e.ResultArtifactIdentity == "" || !construct && validDigest(e.ResultArtifactIdentity)
}
func investigationArtifactMetadata(a artifact.Artifact, e InvestigationArtifactExpectations, id, kind string, origin artifact.Origin, at time.Time, reference artifact.Artifact, maximum int) bool {
	return a.Identity() == id && a.Scope().Identity() == e.Scope.Identity() && a.Kind().String() == kind && a.MediaType() == "application/json" && a.Origin() == origin && a.Classification() == reference.Classification() && a.Protection() == reference.Protection() && at.UnixMilli() > 0 && !at.Before(a.CreatedAt()) && at.Before(a.ExpiresAt()) && a.PayloadSizeBytes() > 0 && a.PayloadSizeBytes() <= maximum
}

type investigationContextReadback struct {
	Scope       string `json:"review_scope_identity"`
	MemoryScope string `json:"memory_scope_identity"`
	Snapshot    string `json:"snapshot_identity"`
	Sources     []struct {
		ID      string `json:"source_id"`
		Path    string `json:"path"`
		Start   int    `json:"start_line"`
		End     int    `json:"end_line"`
		Content string `json:"content"`
		Digest  string `json:"evidence_digest"`
	} `json:"sources"`
	Investigation struct {
		Session         string            `json:"session_identity"`
		Policy          string            `json:"policy_identity"`
		HeadArtifact    string            `json:"snapshot_artifact_identity"`
		HeadSnapshot    string            `json:"snapshot_identity"`
		Manifest        string            `json:"manifest_identity"`
		InitialContext  string            `json:"initial_context_identity"`
		Pin             string            `json:"generation_route_record_identity"`
		Turn            uint8             `json:"turn"`
		Calls           uint8             `json:"tool_calls_used"`
		Returned        uint64            `json:"returned_bytes"`
		PreviousRequest string            `json:"previous_request_identity"`
		PreviousOutcome string            `json:"previous_outcome_identity"`
		NewResults      []string          `json:"previous_tool_result_identities"`
		Results         []json.RawMessage `json:"tool_results"`
	} `json:"investigation"`
}
type investigationValidatedContext struct {
	wire            investigationContextReadback
	requestIdentity string
	payload         []byte
	memoryIdentity  string
}

func validateInvestigationArtifactContext(c InvestigationArtifactContext, e InvestigationArtifactExpectations, at time.Time) (investigationValidatedContext, error) {
	if !investigationSourceWorkWithinLimit(c) || len(c.ToolResultArtifacts) != 0 || len(e.ToolResultArtifactIdentities) != 0 {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	head := c.HeadSnapshotArtifact
	if !investigationArtifactMetadata(head, e, e.HeadSnapshotArtifactIdentity, "source_snapshot", artifact.OriginRepository, at, head, investigationSourceWorkLimit) {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	snapshot, err := source.ParseSnapshotArtifact(head)
	if err != nil || snapshot.Identity() != e.HeadSnapshotIdentity || snapshot.ManifestIdentity() != e.HeadManifestIdentity {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	if !investigationArtifactMetadata(c.ContextArtifact, e, e.ContextArtifactIdentity, "context_packet", artifact.OriginHost, at, head, 8<<20) || c.ContextArtifact.Validate() != nil {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	request, err := c.Context.ProviderRequest()
	if err != nil {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	payload := c.ContextArtifact.Payload()
	if !bytes.Equal(payload, request.Payload()) {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	var wire investigationContextReadback
	if json.Unmarshal(payload, &wire) != nil {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	state := wire.Investigation
	if wire.Scope != e.Scope.Identity() || wire.Snapshot != c.Context.Snapshot().Identity() || state.Session != e.SessionIdentity || state.Policy != e.PolicyIdentity || state.HeadArtifact != e.HeadSnapshotArtifactIdentity || state.HeadSnapshot != e.HeadSnapshotIdentity || state.Manifest != e.HeadManifestIdentity || state.Turn != 1 || state.Calls != 0 || state.Returned != 0 || state.PreviousRequest != "" || state.PreviousOutcome != "" || len(state.NewResults) != 0 || len(state.Results) != 0 || !validDigest(state.InitialContext) || !validDigest(state.Pin) {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	for _, id := range []string{e.HeadSnapshotArtifactIdentity, e.SessionIdentity, e.PolicyIdentity} {
		if !hasProvenance(c.ContextArtifact.Provenance(), id) {
			return investigationValidatedContext{}, ErrInvestigationArtifacts
		}
	}
	items := c.Context.EvidenceItems()
	if len(items) == 0 || len(items) > investigationArtifactSources || len(wire.Sources) != len(items) {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	paths := map[string]bool{}
	byID := map[string]evidence.EvidenceItem{}
	for _, item := range items {
		paths[item.SourceRange().Path()] = true
		byID[item.ID()] = item
	}
	if len(paths) != len(c.SourceFileArtifacts) {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	refs := map[string]source.FileReference{}
	for _, ref := range snapshot.Files() {
		if paths[ref.Path()] {
			refs[ref.Path()] = ref
		}
	}
	if len(refs) != len(paths) {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	provided := map[string]artifact.Artifact{}
	for _, file := range c.SourceFileArtifacts {
		if _, exists := provided[file.Identity()]; exists {
			return investigationValidatedContext{}, ErrInvestigationArtifacts
		}
		provided[file.Identity()] = file
	}
	fileIdentities := map[string]string{}
	for path, ref := range refs {
		value, ok := provided[ref.ArtifactIdentity()]
		if !ok || ref.SizeBytes() < 0 || ref.SizeBytes() > value.PayloadSizeBytes() || !investigationArtifactMetadata(value, e, ref.ArtifactIdentity(), "source_file", artifact.OriginRepository, at, head, investigationSourceWorkLimit) {
			return investigationValidatedContext{}, ErrInvestigationArtifacts
		}
		file, err := source.ParseFileArtifact(value, snapshot, ref)
		if err != nil {
			return investigationValidatedContext{}, ErrInvestigationArtifacts
		}
		content := file.Content()
		err = bindInvestigationArtifactFile(path, content, wire, byID, fileIdentities)
		clear(content)
		if err != nil {
			return investigationValidatedContext{}, err
		}
	}
	ranges := c.Context.Snapshot().Ranges()
	type rangeWire struct {
		Path  string `json:"path"`
		Start int    `json:"start"`
		End   int    `json:"end"`
		File  string `json:"file"`
	}
	rw := make([]rangeWire, len(ranges))
	for n, r := range ranges {
		if fileIdentities[r.Path()] == "" {
			return investigationValidatedContext{}, ErrInvestigationArtifacts
		}
		rw[n] = rangeWire{r.Path(), r.StartLine(), r.EndLine(), fileIdentities[r.Path()]}
	}
	encoded, _ := json.Marshal(struct {
		Contract string      `json:"contract"`
		Version  int         `json:"version"`
		Manifest string      `json:"manifest"`
		Ranges   []rangeWire `json:"ranges"`
	}{"open-trestle/acquired-review-range-set", 1, e.HeadManifestIdentity, rw})
	if artifactPayloadHash(encoded) != c.Context.Snapshot().Revision() {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	var memoryWire struct {
		MemoryScope string `json:"memory_scope_identity"`
		Memory      struct {
			ID string `json:"retrieval_identity"`
		} `json:"memory"`
		Additional []struct {
			ID string `json:"retrieval_identity"`
		} `json:"additional_memory"`
	}
	if json.Unmarshal(payload, &memoryWire) != nil {
		return investigationValidatedContext{}, ErrInvestigationArtifacts
	}
	memoryIDs := []string{memoryWire.Memory.ID}
	for _, m := range memoryWire.Additional {
		memoryIDs = append(memoryIDs, m.ID)
	}
	memoryIdentity := reviewContextMemoryIdentity(memoryWire.MemoryScope, memoryIDs)
	return investigationValidatedContext{wire: wire, requestIdentity: request.Identity(), payload: payload, memoryIdentity: memoryIdentity}, nil
}
func bindInvestigationArtifactFile(path string, content []byte, wire investigationContextReadback, items map[string]evidence.EvidenceItem, identities map[string]string) error {
	file, err := evidence.NewRepositoryFile(path, content)
	if err != nil {
		return ErrInvestigationArtifacts
	}
	identities[path] = file.Identity()
	for _, entry := range wire.Sources {
		if entry.Path != path {
			continue
		}
		item, ok := items[entry.ID]
		if !ok || item.SourceRange().Path() != path || item.SourceRange().StartLine() != entry.Start || item.SourceRange().EndLine() != entry.End || item.Digest() != entry.Digest {
			return ErrInvestigationArtifacts
		}
		binding, err := evidence.BindSourceSlice(file, content, item.SourceRange(), []byte(entry.Content))
		if err != nil || binding.SliceDigest() != item.Digest() {
			return ErrInvestigationArtifacts
		}
	}
	return nil
}

func NewInvestigationGenerationInputArtifact(c InvestigationArtifactContext, authorization gateway.RouteAttemptAuthorization, e InvestigationArtifactExpectations, at time.Time) (artifact.Artifact, error) {
	if !investigationSourceWorkWithinLimit(c) || !investigationExpected(e, "input", true) {
		return artifact.Artifact{}, ErrInvestigationArtifacts
	}
	checked, err := validateInvestigationArtifactContext(c, e, at)
	if err != nil {
		return artifact.Artifact{}, err
	}
	if authorization.Validate() != nil || authorization.RequestIdentity() != checked.requestIdentity || authorization.ReviewScopeIdentity() != e.Scope.Identity() || authorization.RouteRecordIdentity() != checked.wire.Investigation.Pin || authorization.Kind() != gateway.RouteAttemptInitial {
		return artifact.Artifact{}, ErrInvestigationArtifacts
	}
	input := InvestigationGenerationInput{scope: e.Scope.Identity(), contextArtifact: e.ContextArtifactIdentity, contextIdentity: c.Context.Identity(), memoryScope: checked.wire.MemoryScope, memoryIdentity: checked.memoryIdentity, schemaIdentity: artifactPayloadHash(review.InvestigationOutputSchema()), session: e.SessionIdentity, policy: e.PolicyIdentity, owner: e.OwnerIdentity, headArtifact: e.HeadSnapshotArtifactIdentity, headSnapshot: e.HeadSnapshotIdentity, headManifest: e.HeadManifestIdentity, initialContext: checked.wire.Investigation.InitialContext, snapshot: c.Context.Snapshot(), evidence: c.Context.EvidenceItems(), authorization: authorization}
	values, err := input.values()
	if err != nil {
		return artifact.Artifact{}, err
	}
	delete(values, "identity")
	encoded, err := json.Marshal(values)
	if err != nil {
		return artifact.Artifact{}, ErrInvestigationArtifacts
	}
	input.identity = artifactPayloadHash(encoded)
	payload, err := EncodeInvestigationGenerationInput(input)
	if err != nil {
		return artifact.Artifact{}, err
	}
	provenance := []string{e.ContextArtifactIdentity, e.HeadSnapshotArtifactIdentity, e.SessionIdentity, e.PolicyIdentity, e.OwnerIdentity, authorization.Identity()}
	sort.Strings(provenance)
	return artifact.New(e.Scope, artifact.KindTaskInput, "application/json", c.ContextArtifact.Classification(), artifact.OriginHost, c.ContextArtifact.Protection(), provenance, payload, at, investigationContextExpiry(c))
}
func ParseInvestigationGenerationInputArtifact(value artifact.Artifact, c InvestigationArtifactContext, e InvestigationArtifactExpectations, at time.Time) (InvestigationGenerationInput, error) {
	if !investigationSourceWorkWithinLimit(c) || !investigationExpected(e, "input", false) {
		return InvestigationGenerationInput{}, ErrInvestigationArtifacts
	}
	checked, err := validateInvestigationArtifactContext(c, e, at)
	if err != nil {
		return InvestigationGenerationInput{}, err
	}
	return parseInvestigationInputBound(value, c, e, checked, at)
}
func parseInvestigationInputBound(value artifact.Artifact, c InvestigationArtifactContext, e InvestigationArtifactExpectations, checked investigationValidatedContext, at time.Time) (InvestigationGenerationInput, error) {
	if !investigationArtifactMetadata(value, e, e.InputArtifactIdentity, "task_input", artifact.OriginHost, at, c.ContextArtifact, maximumGenerationInputBytes) || value.ExpiresAt().After(investigationContextExpiry(c)) || value.Validate() != nil {
		return InvestigationGenerationInput{}, ErrInvestigationArtifacts
	}
	input, err := ParseInvestigationGenerationInput(value.Payload())
	if err != nil {
		return InvestigationGenerationInput{}, err
	}
	if input.scope != e.Scope.Identity() || input.contextArtifact != e.ContextArtifactIdentity || input.contextIdentity != c.Context.Identity() || input.session != e.SessionIdentity || input.policy != e.PolicyIdentity || input.owner != e.OwnerIdentity || input.headArtifact != e.HeadSnapshotArtifactIdentity || input.headSnapshot != e.HeadSnapshotIdentity || input.headManifest != e.HeadManifestIdentity || input.initialContext != checked.wire.Investigation.InitialContext || input.memoryScope != checked.wire.MemoryScope || input.memoryIdentity != checked.memoryIdentity || input.snapshot.Identity() != c.Context.Snapshot().Identity() || input.authorization.RequestIdentity() != checked.requestIdentity || input.authorization.RouteRecordIdentity() != checked.wire.Investigation.Pin {
		return InvestigationGenerationInput{}, ErrInvestigationArtifacts
	}
	items := c.Context.EvidenceItems()
	if len(input.evidence) != len(items) {
		return InvestigationGenerationInput{}, ErrInvestigationArtifacts
	}
	for n, item := range items {
		if input.evidence[n].ID() != item.ID() || input.evidence[n].Kind() != item.Kind() || input.evidence[n].Digest() != item.Digest() || input.evidence[n].SourceRange() != item.SourceRange() {
			return InvestigationGenerationInput{}, ErrInvestigationArtifacts
		}
	}
	for _, id := range []string{e.ContextArtifactIdentity, e.HeadSnapshotArtifactIdentity, e.SessionIdentity, e.PolicyIdentity, e.OwnerIdentity, input.authorization.Identity()} {
		if !hasProvenance(value.Provenance(), id) {
			return InvestigationGenerationInput{}, ErrInvestigationArtifacts
		}
	}
	return input, nil
}

type InvestigationGenerationResult struct {
	identity, inputArtifact, turnArtifact, previous string
	input                                           InvestigationGenerationInput
	turn                                            gateway.InvestigationTurnRecord
	candidates                                      review.CandidateBatch
	execution                                       gateway.RouteExecutionRecord
}

func (r InvestigationGenerationResult) Identity() string                  { return r.identity }
func (r InvestigationGenerationResult) ContextIdentity() string           { return r.input.contextIdentity }
func (r InvestigationGenerationResult) Candidates() review.CandidateBatch { return r.candidates }
func (r InvestigationGenerationResult) RouteExecution() gateway.RouteExecutionRecord {
	return r.execution
}
func (r InvestigationGenerationResult) Turn() gateway.InvestigationTurnRecord { return r.turn }
func (r InvestigationGenerationResult) values() (map[string]any, error) {
	candidates, err := review.EncodeCandidateBatch(r.candidates)
	if err != nil {
		return nil, ErrInvestigationArtifacts
	}
	execution, err := gateway.EncodeRouteExecutionRecord(r.execution)
	if err != nil {
		return nil, ErrInvestigationArtifacts
	}
	i := r.input
	return map[string]any{"contract": "open-trestle/model-generation-result", "schema_version": 2, "identity": r.identity, "input_artifact_identity": r.inputArtifact, "context_artifact_identity": i.contextArtifact, "context_identity": i.contextIdentity, "candidate_batch_identity": r.candidates.Identity(), "route_execution_identity": r.execution.Identity(), "candidate_batch": json.RawMessage(candidates), "route_execution": json.RawMessage(execution), "investigation_session_identity": i.session, "investigation_policy_identity": i.policy, "owner_identity": i.owner, "head_snapshot_artifact_identity": i.headArtifact, "head_snapshot_identity": i.headSnapshot, "head_manifest_identity": i.headManifest, "initial_context_identity": i.initialContext, "tool_result_artifact_identities": []string{}, "generation_turn_artifact_identity": r.turnArtifact, "generation_turn_identity": r.turn.Identity(), "previous_turn_identity": r.previous}, nil
}
func (r InvestigationGenerationResult) Validate() error {
	if !validDigest(r.identity) || !validDigest(r.inputArtifact) || !validDigest(r.turnArtifact) || r.input.Validate() != nil || r.turn.Validate() != nil || r.candidates.Validate() != nil || r.execution.Validate() != nil || r.previous != "" || r.turn.PreviousTurnIdentity() != r.previous || r.turn.Authorization().Identity() != r.input.authorization.Identity() || r.execution.Authorization().Identity() != r.turn.Authorization().Identity() || r.execution.Outcome().Identity() != r.turn.Outcome().Identity() || r.execution.Reconciliation().Identity() != r.turn.Reconciliation().Identity() || r.candidates.SnapshotIdentity() != r.input.snapshot.Identity() || r.candidates.ResponseIdentity() != r.turn.Dispatch().Response().Identity() || r.execution.Output().Kind() != gateway.RouteOutputCandidateBatch || r.execution.Output().ContextIdentity() != r.input.contextIdentity || r.execution.Output().ArtifactIdentity() != r.candidates.Identity() {
		return ErrInvestigationArtifacts
	}
	values, err := r.values()
	if err != nil {
		return err
	}
	delete(values, "identity")
	encoded, err := json.Marshal(values)
	if err != nil || len(encoded) > maximumGenerationResultBytes || artifactPayloadHash(encoded) != r.identity {
		return ErrInvestigationArtifacts
	}
	return nil
}
func EncodeInvestigationGenerationResult(r InvestigationGenerationResult) ([]byte, error) {
	if r.Validate() != nil {
		return nil, ErrInvestigationArtifacts
	}
	values, err := r.values()
	if err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(values)
	if err != nil || len(encoded) > maximumGenerationResultBytes {
		return nil, ErrInvestigationArtifacts
	}
	return encoded, nil
}
func buildInvestigationResult(inputArtifact artifact.Artifact, c InvestigationArtifactContext, turnArtifact artifact.Artifact, e InvestigationArtifactExpectations, at time.Time) (InvestigationGenerationResult, error) {
	checked, err := validateInvestigationArtifactContext(c, e, at)
	if err != nil {
		return InvestigationGenerationResult{}, err
	}
	input, err := parseInvestigationInputBound(inputArtifact, c, e, checked, at)
	if err != nil {
		return InvestigationGenerationResult{}, err
	}
	if !investigationArtifactMetadata(turnArtifact, e, e.TurnArtifactIdentity, "investigation_turn", artifact.OriginHost, at, c.ContextArtifact, 16<<20) || turnArtifact.Validate() != nil {
		return InvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	payload := turnArtifact.Payload()
	turn, err := gateway.ParseInvestigationTurnRecord(payload)
	if err != nil {
		return InvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	canonical, err := gateway.EncodeInvestigationTurnRecord(turn)
	if err != nil || !bytes.Equal(canonical, payload) {
		return InvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	var metadata struct {
		Owner    string `json:"owner_identity"`
		Session  string `json:"session_identity"`
		Policy   string `json:"policy_identity"`
		Scope    string `json:"scope_identity"`
		Previous string `json:"previous_turn_identity"`
		Role     string `json:"role"`
		Ordinal  uint8  `json:"ordinal"`
		Request  struct {
			Identity  string `json:"identity"`
			MediaType string `json:"media_type"`
			Payload   string `json:"payload_b64"`
		} `json:"request"`
	}
	if json.Unmarshal(payload, &metadata) != nil || metadata.Owner != e.OwnerIdentity || metadata.Session != e.SessionIdentity || metadata.Policy != e.PolicyIdentity || metadata.Scope != e.Scope.Identity() || metadata.Previous != e.PreviousTurnIdentity || metadata.Previous != "" || metadata.Role != "generation" || metadata.Ordinal != 1 || metadata.Request.Identity != checked.requestIdentity || metadata.Request.MediaType != "application/json" || metadata.Request.Payload != base64.StdEncoding.EncodeToString(checked.payload) || turn.RequestIdentity() != checked.requestIdentity || turn.Authorization().Identity() != input.authorization.Identity() {
		return InvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	for _, id := range []string{e.ContextArtifactIdentity, e.InputArtifactIdentity, e.HeadSnapshotArtifactIdentity, e.OwnerIdentity, turn.Identity(), turn.Authorization().Identity(), turn.Outcome().Identity(), turn.Reconciliation().Identity()} {
		if !hasProvenance(turnArtifact.Provenance(), id) {
			return InvestigationGenerationResult{}, ErrInvestigationArtifacts
		}
	}
	candidates, err := review.ParseCandidateBatch(turn.Dispatch().Response(), input.snapshot, input.evidence)
	if err != nil {
		return InvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	request, err := c.Context.ProviderRequest()
	if err != nil {
		return InvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	output, err := gateway.NewSuccessfulRouteOutputReceipt(gateway.RouteOutputCandidateBatch, input.contextIdentity, candidates.Identity(), request, turn.Authorization(), turn.Outcome())
	if err != nil {
		return InvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	execution, err := gateway.NewRouteExecutionRecord(turn.Authorization(), turn.Outcome(), turn.Reconciliation(), output)
	if err != nil {
		return InvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	result := InvestigationGenerationResult{inputArtifact: e.InputArtifactIdentity, turnArtifact: e.TurnArtifactIdentity, previous: e.PreviousTurnIdentity, input: input, turn: turn, candidates: candidates, execution: execution}
	values, err := result.values()
	if err != nil {
		return InvestigationGenerationResult{}, err
	}
	delete(values, "identity")
	encoded, err := json.Marshal(values)
	if err != nil {
		return InvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	result.identity = artifactPayloadHash(encoded)
	return result, nil
}
func investigationResultProvenance(r InvestigationGenerationResult) []string {
	ids := []string{r.inputArtifact, r.input.contextArtifact, r.input.headArtifact, r.input.session, r.input.policy, r.input.owner, r.turnArtifact, r.turn.Identity(), r.candidates.Identity(), r.execution.Identity(), r.turn.Authorization().Identity(), r.turn.Outcome().Identity(), r.turn.Reconciliation().Identity(), r.execution.Output().Identity()}
	sort.Strings(ids)
	return ids
}
func NewInvestigationGenerationResultArtifact(input artifact.Artifact, c InvestigationArtifactContext, turn artifact.Artifact, e InvestigationArtifactExpectations, at time.Time) (artifact.Artifact, error) {
	if !investigationSourceWorkWithinLimit(c) || !investigationExpected(e, "result", true) {
		return artifact.Artifact{}, ErrInvestigationArtifacts
	}
	result, err := buildInvestigationResult(input, c, turn, e, at)
	if err != nil {
		return artifact.Artifact{}, err
	}
	payload, err := EncodeInvestigationGenerationResult(result)
	if err != nil {
		return artifact.Artifact{}, err
	}
	return artifact.New(e.Scope, artifact.KindCandidateBatch, "application/json", c.ContextArtifact.Classification(), artifact.OriginModel, c.ContextArtifact.Protection(), investigationResultProvenance(result), payload, at, minimumInvestigationExpiry(input, c.ContextArtifact, turn))
}
func ParseInvestigationGenerationResultArtifact(value, input artifact.Artifact, c InvestigationArtifactContext, turn artifact.Artifact, e InvestigationArtifactExpectations, at time.Time) (InvestigationGenerationResult, error) {
	if !investigationSourceWorkWithinLimit(c) || !investigationExpected(e, "result", false) || !investigationArtifactMetadata(value, e, e.ResultArtifactIdentity, "candidate_batch", artifact.OriginModel, at, c.ContextArtifact, maximumGenerationResultBytes) || value.ExpiresAt().After(minimumInvestigationExpiry(input, c.ContextArtifact, turn)) || value.Validate() != nil {
		return InvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	result, err := buildInvestigationResult(input, c, turn, e, at)
	if err != nil {
		return InvestigationGenerationResult{}, err
	}
	encoded, err := EncodeInvestigationGenerationResult(result)
	if err != nil || !bytes.Equal(encoded, value.Payload()) {
		return InvestigationGenerationResult{}, ErrInvestigationArtifacts
	}
	for _, id := range investigationResultProvenance(result) {
		if !hasProvenance(value.Provenance(), id) {
			return InvestigationGenerationResult{}, ErrInvestigationArtifacts
		}
	}
	return result, nil
}
func minimumInvestigationExpiry(values ...artifact.Artifact) time.Time {
	at := values[0].ExpiresAt()
	for _, value := range values[1:] {
		if value.ExpiresAt().Before(at) {
			at = value.ExpiresAt()
		}
	}
	return at
}
func decodeInvestigationJSON(encoded []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(encoded))
	d.DisallowUnknownFields()
	if d.Decode(target) != nil {
		return ErrInvestigationArtifacts
	}
	if err := d.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvestigationArtifacts
	}
	return nil
}
func (i InvestigationGenerationInput) String() string { return "investigation input claims" }
func (i InvestigationGenerationInput) GoString() string {
	return "model.InvestigationGenerationInput{<redacted>}"
}
func (i InvestigationGenerationInput) Format(s fmt.State, verb rune) {
	writeModelRedacted(s, verb, "investigation input claims", "model.InvestigationGenerationInput{<redacted>}")
}
func (r InvestigationGenerationResult) String() string { return "witness-bound investigation result" }
func (r InvestigationGenerationResult) GoString() string {
	return "model.InvestigationGenerationResult{<redacted>}"
}
func (r InvestigationGenerationResult) Format(s fmt.State, verb rune) {
	writeModelRedacted(s, verb, "witness-bound investigation result", "model.InvestigationGenerationResult{<redacted>}")
}

func artifactPayloadHash(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
func reviewContextMemoryIdentity(scope string, ids []string) string {
	encoded, _ := json.Marshal(struct {
		Contract   string   `json:"contract"`
		Version    int      `json:"version"`
		Scope      string   `json:"scope"`
		Retrievals []string `json:"retrievals"`
	}{"open-trestle/context-memory-set", 1, scope, ids})
	return artifactPayloadHash(encoded)
}
func investigationContextExpiry(c InvestigationArtifactContext) time.Time {
	at := minimumInvestigationExpiry(c.ContextArtifact, c.HeadSnapshotArtifact)
	for _, file := range c.SourceFileArtifacts {
		if file.ExpiresAt().Before(at) {
			at = file.ExpiresAt()
		}
	}
	return at
}
