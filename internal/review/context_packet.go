package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
)

const (
	maxContextSourceBytes    = 256 << 10
	maxContextAggregateBytes = 2 << 20
	maxContextMemoryItems    = 50
	// ModelCandidateBatchSchemaIdentity is the SHA-256 identity of canonical model-candidate-batch-v1 JSON Schema.
	ModelCandidateBatchSchemaIdentity = "b79f43bd52cb67e18896dd053ab85c21efd11c4ba5a97234f3f4ce867109dc0e"
)

var (
	// ErrInvalidContextStage identifies an unknown staged retrieval role.
	ErrInvalidContextStage = errors.New("invalid review context stage")
	// ErrInvalidContextTask identifies an unknown model task.
	ErrInvalidContextTask = errors.New("invalid review context task")
	// ErrInvalidContextSource identifies malformed, empty, excessive, or non-UTF-8 source content.
	ErrInvalidContextSource = errors.New("invalid review context source")
	// ErrContextSourceDigestMismatch identifies content inconsistent with its evidence digest.
	ErrContextSourceDigestMismatch = errors.New("review context source digest mismatch")
	// ErrContextSourceSliceMismatch identifies source content inconsistent with its exact file-slice binding.
	ErrContextSourceSliceMismatch = errors.New("review context source slice mismatch")
	// ErrContextSourceRangeMismatch identifies content whose physical line count differs from its evidence span.
	ErrContextSourceRangeMismatch = errors.New("review context source range mismatch")
	// ErrDuplicateContextSource identifies a repeated source or evidence reference.
	ErrDuplicateContextSource = errors.New("duplicate review context source")
	// ErrInvalidContextLimits identifies an excessive or unusable context budget.
	ErrInvalidContextLimits = errors.New("invalid review context limits")
	// ErrContextScopeMismatch identifies review and memory scopes from different tenant or repository partitions.
	ErrContextScopeMismatch = errors.New("review context scope mismatch")
	// ErrContextRetrievalMismatch identifies memory results from another authorization scope.
	ErrContextRetrievalMismatch = errors.New("review context retrieval mismatch")
	// ErrContextSourceBudgetExceeded identifies source content beyond the declared packet budget.
	ErrContextSourceBudgetExceeded = errors.New("review context source budget exceeded")
	// ErrContextMemoryBudgetExceeded identifies advisory results beyond the declared packet budget.
	ErrContextMemoryBudgetExceeded = errors.New("review context memory budget exceeded")
	// ErrInvalidContextPacketIdentity identifies packet content inconsistent with its identity.
	ErrInvalidContextPacketIdentity = errors.New("invalid review context packet identity")
	// ErrInvalidContextPacketRequest identifies malformed or cross-wired durable provider input.
	ErrInvalidContextPacketRequest = errors.New("invalid review context packet request")
)

// ContextStage identifies the bounded retrieval expansion that produced source evidence.
type ContextStage uint8

const (
	ContextStageChangedHunk ContextStage = iota + 1
	ContextStageEnclosingSymbol
	ContextStageDirectReference
	ContextStageRepositoryContext
)

func (s ContextStage) String() string {
	switch s {
	case ContextStageChangedHunk:
		return "changed_hunk"
	case ContextStageEnclosingSymbol:
		return "enclosing_symbol"
	case ContextStageDirectReference:
		return "direct_reference"
	case ContextStageRepositoryContext:
		return "repository_context"
	default:
		return ""
	}
}

func (s ContextStage) Validate() error {
	if s.String() == "" {
		return ErrInvalidContextStage
	}
	return nil
}

// ContextRisk identifies a non-authoritative ingest warning on untrusted source text.
type ContextRisk uint8

const (
	ContextRiskHiddenUnicode ContextRisk = 1 << iota
	ContextRiskInstructionLikeText
)

// ContextSource is immutable evidence content labeled as data rather than instructions.
type ContextSource struct {
	identity        string
	stage           ContextStage
	taint           memory.TaintClass
	evidenceItem    evidence.EvidenceItem
	content         string
	risks           ContextRisk
	hasSliceBinding bool
	sliceBinding    evidence.SourceSliceBinding
}

// NewContextSource verifies exact content against one host-issued evidence item.
func NewContextSource(stage ContextStage, taint memory.TaintClass, item evidence.EvidenceItem, content []byte) (ContextSource, error) {
	source := ContextSource{stage: stage, taint: taint, evidenceItem: item, content: string(content), risks: detectContextRisks(string(content))}
	if err := source.validateFields(); err != nil {
		return ContextSource{}, err
	}
	source.identity = deriveContextSourceIdentity(source)
	return source, nil
}

// NewBoundContextSource additionally proves the source is an exact slice of an acquired file.
func NewBoundContextSource(stage ContextStage, taint memory.TaintClass, item evidence.EvidenceItem, content []byte, binding evidence.SourceSliceBinding) (ContextSource, error) {
	source, err := NewContextSource(stage, taint, item, content)
	if err != nil {
		return ContextSource{}, err
	}
	if err := binding.Validate(); err != nil {
		return ContextSource{}, ErrContextSourceSliceMismatch
	}
	matchingRange := binding.SourceRange() == item.SourceRange()
	matchingDigest := binding.SliceDigest() == item.Digest()
	matchingSize := binding.SliceBytes() == len(content)
	if !matchingRange || !matchingDigest || !matchingSize {
		return ContextSource{}, ErrContextSourceSliceMismatch
	}
	source.hasSliceBinding = true
	source.sliceBinding = binding
	source.identity = deriveContextSourceIdentity(source)
	if err := source.Validate(); err != nil {
		return ContextSource{}, err
	}
	return source, nil
}

func (s ContextSource) Identity() string                          { return s.identity }
func (s ContextSource) Stage() ContextStage                       { return s.stage }
func (s ContextSource) Taint() memory.TaintClass                  { return s.taint }
func (s ContextSource) ReferenceID() string                       { return s.evidenceItem.ID() }
func (s ContextSource) EvidenceItem() evidence.EvidenceItem       { return s.evidenceItem }
func (s ContextSource) Content() []byte                           { return []byte(s.content) }
func (s ContextSource) SizeBytes() int                            { return len(s.content) }
func (s ContextSource) HasRisk(risk ContextRisk) bool             { return s.risks&risk != 0 }
func (s ContextSource) HasSliceBinding() bool                     { return s.hasSliceBinding }
func (s ContextSource) SliceBinding() evidence.SourceSliceBinding { return s.sliceBinding }
func (s ContextSource) SliceBindingIdentity() string              { return s.sliceBinding.Identity() }
func (s ContextSource) String() string                            { return "review context source" }
func (s ContextSource) GoString() string                          { return "review.ContextSource{<redacted>}" }
func (s ContextSource) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "review context source", "review.ContextSource{<redacted>}")
}

// Validate verifies evidence, digest, taint, risks, bounds, and content identity.
func (s ContextSource) Validate() error {
	if err := s.validateFields(); err != nil {
		return err
	}
	if s.identity != deriveContextSourceIdentity(s) {
		return ErrInvalidContextPacketIdentity
	}
	return nil
}

func (s ContextSource) validateFields() error {
	if err := s.stage.Validate(); err != nil {
		return err
	}
	if err := s.taint.Validate(); err != nil {
		return err
	}
	if !validCandidateReference(s.evidenceItem.ID()) || !validCandidateDigest(s.evidenceItem.Digest()) {
		return ErrInvalidContextSource
	}
	if _, err := evidence.NewEvidenceItem(s.evidenceItem.ID(), s.evidenceItem.Kind(), s.evidenceItem.Digest(), s.evidenceItem.SourceRange()); err != nil {
		return ErrInvalidContextSource
	}
	if len(s.content) == 0 || len(s.content) > maxContextSourceBytes || !utf8.ValidString(s.content) || strings.IndexRune(s.content, 0) >= 0 {
		return ErrInvalidContextSource
	}
	digest := sha256.Sum256([]byte(s.content))
	if hex.EncodeToString(digest[:]) != s.evidenceItem.Digest() {
		return ErrContextSourceDigestMismatch
	}
	if contextSourceLineCount(s.content) != s.evidenceItem.SourceRange().EndLine()-s.evidenceItem.SourceRange().StartLine()+1 {
		return ErrContextSourceRangeMismatch
	}
	if s.hasSliceBinding {
		if err := s.sliceBinding.Validate(); err != nil || s.sliceBinding.SourceRange() != s.evidenceItem.SourceRange() || s.sliceBinding.SliceDigest() != s.evidenceItem.Digest() || s.sliceBinding.SliceBytes() != len(s.content) {
			return ErrContextSourceSliceMismatch
		}
	} else if s.sliceBinding.Identity() != "" {
		return ErrContextSourceSliceMismatch
	}
	if s.risks != detectContextRisks(s.content) {
		return ErrInvalidContextSource
	}
	return nil
}

func contextSourceLineCount(content string) int {
	count := strings.Count(content, "\n")
	if !strings.HasSuffix(content, "\n") {
		count++
	}
	return count
}

func detectContextRisks(content string) ContextRisk {
	var risks ContextRisk
	for _, character := range content {
		if unicode.In(character, unicode.Cf) {
			risks |= ContextRiskHiddenUnicode
			break
		}
	}
	lower := strings.ToLower(content)
	for _, marker := range []string{"ignore previous", "system prompt", "developer message", "tool_call", "call a tool"} {
		if strings.Contains(lower, marker) {
			risks |= ContextRiskInstructionLikeText
			break
		}
	}
	return risks
}

func deriveContextSourceIdentity(source ContextSource) string {
	contentDigest := sha256.Sum256([]byte(source.content))
	rangeValue := source.evidenceItem.SourceRange()
	preimage := struct {
		Contract       string `json:"contract"`
		Version        int    `json:"version"`
		Stage          string `json:"stage"`
		Taint          string `json:"taint"`
		Reference      string `json:"reference"`
		EvidenceDigest string `json:"evidence_digest"`
		Path           string `json:"path"`
		Start          int    `json:"start"`
		End            int    `json:"end"`
		ContentDigest  string `json:"content_digest"`
		ContentBytes   int    `json:"content_bytes"`
		Risks          uint8  `json:"risks"`
		SliceBound     bool   `json:"slice_bound"`
		SliceBinding   string `json:"slice_binding"`
	}{
		Contract: "open-trestle/review-context-source", Version: 1,
		Stage: source.stage.String(), Taint: source.taint.String(), Reference: source.evidenceItem.ID(),
		EvidenceDigest: source.evidenceItem.Digest(), Path: rangeValue.Path(),
		Start: rangeValue.StartLine(), End: rangeValue.EndLine(),
		ContentDigest: hex.EncodeToString(contentDigest[:]), ContentBytes: len(source.content), Risks: uint8(source.risks),
		SliceBound: source.hasSliceBinding, SliceBinding: source.sliceBinding.Identity(),
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// ContextTask identifies the fixed host-controlled purpose of one model packet.
type ContextTask uint8

const (
	ContextTaskCandidateGeneration ContextTask = iota + 1
)

func (t ContextTask) String() string {
	if t == ContextTaskCandidateGeneration {
		return "candidate_generation"
	}
	return ""
}

func (t ContextTask) Validate() error {
	if t.String() == "" {
		return ErrInvalidContextTask
	}
	return nil
}

// ContextLimits bounds copied source bytes and advisory memory records.
type ContextLimits struct {
	maxSourceBytes uint32
	maxMemoryItems uint8
}

// NewContextLimits creates a bounded packet budget.
func NewContextLimits(maxSourceBytes uint32, maxMemoryItems uint8) (ContextLimits, error) {
	limits := ContextLimits{maxSourceBytes: maxSourceBytes, maxMemoryItems: maxMemoryItems}
	if err := limits.Validate(); err != nil {
		return ContextLimits{}, err
	}
	return limits, nil
}

func (l ContextLimits) MaxSourceBytes() uint32 { return l.maxSourceBytes }
func (l ContextLimits) MaxMemoryItems() uint8  { return l.maxMemoryItems }
func (l ContextLimits) Validate() error {
	if l.maxSourceBytes == 0 || l.maxSourceBytes > maxContextAggregateBytes || l.maxMemoryItems > maxContextMemoryItems {
		return ErrInvalidContextLimits
	}
	return nil
}

// ContextSourceOmission records validated evidence that cannot enter source selection.
type ContextSourceOmission struct {
	path               string
	startLine, endLine int
	reason             string
	count              uint32
}

func NewContextSourceOmission(path string, startLine, endLine int, reason string) (ContextSourceOmission, error) {
	return NewCountedContextSourceOmission(path, startLine, endLine, reason, 1)
}
func NewCountedContextSourceOmission(path string, startLine, endLine int, reason string, count uint32) (ContextSourceOmission, error) {
	value := ContextSourceOmission{path: path, startLine: startLine, endLine: endLine, reason: reason, count: count}
	if value.Validate() != nil {
		return ContextSourceOmission{}, ErrInvalidContextSourceSelection
	}
	return value, nil
}
func (o ContextSourceOmission) Path() string   { return o.path }
func (o ContextSourceOmission) StartLine() int { return o.startLine }
func (o ContextSourceOmission) EndLine() int   { return o.endLine }
func (o ContextSourceOmission) Reason() string { return o.reason }
func (o ContextSourceOmission) Count() uint32  { return o.count }
func (o ContextSourceOmission) Validate() error {
	if o.path == "" || len(o.path) > 1024 || o.startLine < 0 || o.endLine < 0 || (o.startLine == 0) != (o.endLine == 0) || o.startLine > 0 && o.endLine < o.startLine || !validContextSourceOmissionReason(o.reason) || o.count == 0 || o.count > 32768 {
		return ErrInvalidContextSourceSelection
	}
	return nil
}
func validContextSourceOmissionReason(value string) bool {
	_, err := contextSourceOmissionCategory(value)
	return err == nil
}
func contextSourceOmissionLess(a, b ContextSourceOmission) bool {
	if a.path != b.path {
		return a.path < b.path
	}
	if a.startLine != b.startLine {
		return a.startLine < b.startLine
	}
	if a.endLine != b.endLine {
		return a.endLine < b.endLine
	}
	return a.reason < b.reason
}

// ContextPacket separates exact source evidence from advisory scoped memory.
type ContextPacket struct {
	identity             string
	reviewScopeIdentity  string
	memoryScopeIdentity  string
	snapshotIdentity     string
	task                 ContextTask
	outputSchemaIdentity string
	sourceSelection      ContextSourceSelection
	sources              []ContextSource
	retrieval            memory.LexicalRetrieval
	additionalRetrievals []memory.LexicalRetrieval
	sourceOmissions      []ContextSourceOmission
	limits               ContextLimits
}

// NewContextPacket assembles a deterministic provider-neutral packet after hard scope filtering.
func NewContextPacket(reviewScope audit.ReviewScope, memoryScope memory.Scope, snapshot ReviewSnapshot, task ContextTask, sources []ContextSource, retrieval memory.LexicalRetrieval, limits ContextLimits) (ContextPacket, error) {
	return NewContextPacketWithRetrievals(reviewScope, memoryScope, snapshot, task, sources, []memory.LexicalRetrieval{retrieval}, limits)
}

// NewContextPacketWithRetrievals assembles a packet from a canonical bounded set of scoped retrievals.
func NewContextPacketWithRetrievals(reviewScope audit.ReviewScope, memoryScope memory.Scope, snapshot ReviewSnapshot, task ContextTask, sources []ContextSource, retrievals []memory.LexicalRetrieval, limits ContextLimits) (ContextPacket, error) {
	return NewContextPacketWithAccounting(reviewScope, memoryScope, snapshot, task, sources, retrievals, nil, limits)
}

// NewContextPacketWithAccounting retains every validated pre-selection source omission.
func NewContextPacketWithAccounting(reviewScope audit.ReviewScope, memoryScope memory.Scope, snapshot ReviewSnapshot, task ContextTask, sources []ContextSource, retrievals []memory.LexicalRetrieval, omissions []ContextSourceOmission, limits ContextLimits) (ContextPacket, error) {
	if err := reviewScope.Validate(); err != nil {
		return ContextPacket{}, err
	}
	if err := memoryScope.Validate(); err != nil {
		return ContextPacket{}, err
	}
	if reviewScope.TenantID() != memoryScope.TenantID() || reviewScope.RepositoryID() != memoryScope.RepositoryID() {
		return ContextPacket{}, ErrContextScopeMismatch
	}
	if err := snapshot.Validate(); err != nil {
		return ContextPacket{}, err
	}
	if err := task.Validate(); err != nil {
		return ContextPacket{}, err
	}
	if err := limits.Validate(); err != nil {
		return ContextPacket{}, err
	}
	if len(retrievals) == 0 || len(retrievals) > 64 {
		return ContextPacket{}, ErrContextRetrievalMismatch
	}
	canonicalRetrievals := append([]memory.LexicalRetrieval(nil), retrievals...)
	sort.Slice(canonicalRetrievals, func(i, j int) bool { return canonicalRetrievals[i].Identity() < canonicalRetrievals[j].Identity() })
	for index, retrieval := range canonicalRetrievals {
		if retrieval.Validate() != nil || retrieval.ScopeIdentity() != memoryScope.Identity() || index > 0 && retrieval.Identity() == canonicalRetrievals[index-1].Identity() {
			return ContextPacket{}, ErrContextRetrievalMismatch
		}
	}
	if len(sources) == 0 || len(sources) > maxContextSourceCandidates {
		return ContextPacket{}, ErrInvalidContextSource
	}
	for _, source := range sources {
		if err := source.Validate(); err != nil {
			return ContextPacket{}, err
		}
		if !memoryScope.AllowsPath(source.EvidenceItem().SourceRange().Path()) {
			return ContextPacket{}, ErrContextScopeMismatch
		}
	}
	selection, err := SelectContextSources(sources, limits)
	if err != nil {
		return ContextPacket{}, err
	}
	canonicalOmissions := append([]ContextSourceOmission(nil), omissions...)
	sort.Slice(canonicalOmissions, func(i, j int) bool { return contextSourceOmissionLess(canonicalOmissions[i], canonicalOmissions[j]) })
	for index, value := range canonicalOmissions {
		if value.Validate() != nil || index > 0 && !contextSourceOmissionLess(canonicalOmissions[index-1], value) {
			return ContextPacket{}, ErrInvalidContextSourceSelection
		}
	}
	selectedSources := selection.SelectedSources()
	if len(selectedSources) == 0 {
		return ContextPacket{}, ErrContextSourceBudgetExceeded
	}
	packet := ContextPacket{reviewScopeIdentity: reviewScope.Identity(), memoryScopeIdentity: memoryScope.Identity(), snapshotIdentity: snapshot.Identity(), task: task, outputSchemaIdentity: ModelCandidateBatchSchemaIdentity, sourceSelection: selection, sources: selectedSources, retrieval: canonicalRetrievals[0], additionalRetrievals: append([]memory.LexicalRetrieval(nil), canonicalRetrievals[1:]...), sourceOmissions: canonicalOmissions, limits: limits}
	if err := packet.validateFields(); err != nil {
		return ContextPacket{}, err
	}
	packet.identity = deriveContextPacketIdentity(packet)
	return packet, nil
}

func (p ContextPacket) Identity() string                        { return p.identity }
func (p ContextPacket) ReviewScopeIdentity() string             { return p.reviewScopeIdentity }
func (p ContextPacket) MemoryScopeIdentity() string             { return p.memoryScopeIdentity }
func (p ContextPacket) SnapshotIdentity() string                { return p.snapshotIdentity }
func (p ContextPacket) Task() ContextTask                       { return p.task }
func (p ContextPacket) OutputSchemaIdentity() string            { return p.outputSchemaIdentity }
func (p ContextPacket) SourceCount() int                        { return len(p.sources) }
func (p ContextPacket) SourceSelection() ContextSourceSelection { return p.sourceSelection }
func (p ContextPacket) MemoryItemCount() int {
	total := len(p.retrieval.Items())
	for _, retrieval := range p.additionalRetrievals {
		total += len(retrieval.Items())
	}
	return total
}
func (p ContextPacket) Retrieval() memory.LexicalRetrieval { return p.retrieval }
func (p ContextPacket) Retrievals() []memory.LexicalRetrieval {
	values := make([]memory.LexicalRetrieval, 0, 1+len(p.additionalRetrievals))
	values = append(values, p.retrieval)
	values = append(values, p.additionalRetrievals...)
	return values
}
func (p ContextPacket) SourceOmissions() []ContextSourceOmission {
	return append([]ContextSourceOmission(nil), p.sourceOmissions...)
}
func (p ContextPacket) MemoryIdentity() string {
	identities := make([]string, len(p.Retrievals()))
	for index, retrieval := range p.Retrievals() {
		identities[index] = retrieval.Identity()
	}
	return deriveContextMemoryIdentity(p.memoryScopeIdentity, identities)
}
func (p ContextPacket) Sources() []ContextSource {
	return append([]ContextSource(nil), p.sources...)
}
func (p ContextPacket) SourceIdentities() []string {
	identities := make([]string, len(p.sources))
	for index, source := range p.sources {
		identities[index] = source.Identity()
	}
	return identities
}
func (p ContextPacket) EvidenceItems() []evidence.EvidenceItem {
	items := make([]evidence.EvidenceItem, len(p.sources))
	for index, source := range p.sources {
		items[index] = source.EvidenceItem()
	}
	return items
}
func (p ContextPacket) String() string   { return "review context packet" }
func (p ContextPacket) GoString() string { return "review.ContextPacket{<redacted>}" }
func (p ContextPacket) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "review context packet", "review.ContextPacket{<redacted>}")
}

// ProviderRequest returns the immutable normalized request payload.
func (p ContextPacket) ProviderRequest() (provider.Request, error) {
	if err := p.Validate(); err != nil {
		return provider.Request{}, err
	}
	encoded, err := encodeContextPacket(p)
	if err != nil {
		return provider.Request{}, err
	}
	return provider.NewRequest(provider.CapabilityReviewV1, "application/json", encoded)
}

// Validate verifies scope, source, memory, budget, canonical order, and identity.
func (p ContextPacket) Validate() error {
	if err := p.validateFields(); err != nil {
		return err
	}
	if p.identity != deriveContextPacketIdentity(p) {
		return ErrInvalidContextPacketIdentity
	}
	return nil
}

func (p ContextPacket) validateFields() error {
	if !validCandidateDigest(p.reviewScopeIdentity) || !validCandidateDigest(p.memoryScopeIdentity) || !validCandidateDigest(p.snapshotIdentity) || p.outputSchemaIdentity != ModelCandidateBatchSchemaIdentity {
		return ErrInvalidContextPacketIdentity
	}
	if err := p.task.Validate(); err != nil {
		return err
	}
	if err := p.limits.Validate(); err != nil {
		return err
	}
	if err := p.sourceSelection.Validate(); err != nil {
		return err
	}
	if len(p.sources) == 0 || len(p.sources) > maxSelectedContextSources {
		return ErrInvalidContextSource
	}
	selected := p.sourceSelection.SelectedSources()
	if len(selected) != len(p.sources) || p.sourceSelection.limits != p.limits {
		return ErrInvalidContextSourceSelection
	}
	totalBytes := 0
	previousStage := ContextStage(0)
	previousReference := ""
	seen := make(map[string]struct{}, len(p.sources))
	for index, source := range p.sources {
		if err := source.Validate(); err != nil {
			return err
		}
		if source.Identity() != selected[index].Identity() {
			return ErrInvalidContextSourceSelection
		}
		if _, exists := seen[source.ReferenceID()]; exists {
			return ErrDuplicateContextSource
		}
		seen[source.ReferenceID()] = struct{}{}
		if source.Stage() < previousStage || source.Stage() == previousStage && previousReference != "" && source.ReferenceID() <= previousReference {
			return ErrDuplicateContextSource
		}
		previousStage, previousReference = source.Stage(), source.ReferenceID()
		totalBytes += source.SizeBytes()
	}
	if totalBytes > int(p.limits.MaxSourceBytes()) {
		return ErrContextSourceBudgetExceeded
	}
	previousOmission := ContextSourceOmission{}
	for index, omission := range p.sourceOmissions {
		if omission.Validate() != nil || index > 0 && !contextSourceOmissionLess(previousOmission, omission) {
			return ErrInvalidContextSourceSelection
		}
		previousOmission = omission
	}
	omittedCount := 0
	for _, omission := range p.sourceOmissions {
		omittedCount += int(omission.count)
		if omittedCount > 65536 {
			return ErrInvalidContextSourceSelection
		}
	}
	if len(p.sourceOmissions) > 16384 {
		return ErrInvalidContextSourceSelection
	}
	retrievals := p.Retrievals()
	if len(retrievals) == 0 || len(retrievals) > 64 {
		return ErrContextRetrievalMismatch
	}
	memoryItems := 0
	previousRetrieval := ""
	for _, retrieval := range retrievals {
		if retrieval.Validate() != nil || retrieval.ScopeIdentity() != p.memoryScopeIdentity || previousRetrieval != "" && retrieval.Identity() <= previousRetrieval {
			return ErrContextRetrievalMismatch
		}
		previousRetrieval = retrieval.Identity()
		memoryItems += len(retrieval.Items())
	}
	if memoryItems > int(p.limits.MaxMemoryItems()) {
		return ErrContextMemoryBudgetExceeded
	}
	return nil
}

type contextPacketWire struct {
	Contract                string                      `json:"contract"`
	SchemaVersion           int                         `json:"schema_version"`
	ReviewScopeIdentity     string                      `json:"review_scope_identity"`
	MemoryScopeIdentity     string                      `json:"memory_scope_identity"`
	SnapshotIdentity        string                      `json:"snapshot_identity"`
	Task                    string                      `json:"task"`
	OutputSchemaIdentity    string                      `json:"output_schema_identity"`
	Instructions            string                      `json:"instructions,omitempty"`
	OutputSchema            json.RawMessage             `json:"output_schema,omitempty"`
	SourceSelectionIdentity string                      `json:"source_selection_identity"`
	SourceCoverage          contextSourceCoverageWire   `json:"source_coverage"`
	SourceAuthority         string                      `json:"source_authority"`
	MemoryAuthority         string                      `json:"memory_authority"`
	ToolCalls               string                      `json:"tool_calls"`
	Limits                  contextLimitsWire           `json:"limits"`
	Sources                 []contextSourceWire         `json:"sources"`
	SourceOmissions         []contextSourceOmissionWire `json:"source_omissions,omitempty"`
	Memory                  contextMemoryWire           `json:"memory"`
	AdditionalMemory        []contextMemoryWire         `json:"additional_memory,omitempty"`
}

type contextSourceCoverageWire struct {
	Analyzed            int    `json:"analyzed,omitempty"`
	PreselectionOmitted int    `json:"preselection_omitted,omitempty"`
	Available           int    `json:"available"`
	Selected            int    `json:"selected"`
	Omitted             int    `json:"omitted"`
	SelectedBytes       uint32 `json:"selected_bytes"`
}

type contextLimitsWire struct {
	MaxSourceBytes uint32 `json:"max_source_bytes"`
	MaxMemoryItems uint8  `json:"max_memory_items"`
}

type contextSourceWire struct {
	SourceID       string   `json:"source_id"`
	Stage          string   `json:"stage"`
	Taint          string   `json:"taint"`
	EvidenceDigest string   `json:"evidence_digest"`
	Path           string   `json:"path"`
	StartLine      int      `json:"start_line"`
	EndLine        int      `json:"end_line"`
	RiskFlags      []string `json:"risk_flags"`
	Content        string   `json:"content"`
}

type contextSourceOmissionWire struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Reason    string `json:"reason"`
	Count     uint32 `json:"count"`
}

type contextMemoryWire struct {
	RetrievalIdentity string                  `json:"retrieval_identity"`
	QueryIdentity     string                  `json:"query_identity"`
	IndexRevision     uint64                  `json:"index_revision"`
	Items             []contextMemoryItemWire `json:"items"`
}

type contextMemoryItemWire struct {
	MemoryID           string   `json:"memory_id"`
	Kind               string   `json:"kind"`
	Taint              string   `json:"taint"`
	Path               string   `json:"path"`
	Symbols            []string `json:"symbols"`
	Text               string   `json:"text"`
	EvidenceIDs        []string `json:"evidence_ids"`
	DerivedFromIDs     []string `json:"derived_from_ids"`
	CounterEvidenceIDs []string `json:"counter_evidence_ids"`
	ProducerIdentity   string   `json:"producer_identity"`
	ObservedAt         int64    `json:"observed_at"`
	ValidFrom          int64    `json:"valid_from"`
	ValidUntil         int64    `json:"valid_until"`
	StaleAfter         int64    `json:"stale_after"`
	FreshnessIdentity  string   `json:"freshness_identity"`
	Confidence         uint16   `json:"confidence_basis_points"`
	Rank               uint8    `json:"rank"`
	PathScore          uint8    `json:"path_score"`
	SymbolScore        uint8    `json:"symbol_score"`
	TextScore          uint8    `json:"text_score"`
}

func encodeContextPacket(packet ContextPacket) ([]byte, error) {
	instructions, schema, err := modelOutputContract(false)
	if err != nil {
		return nil, err
	}
	wire := contextPacketWire{
		Contract: "open-trestle/review-context-packet", SchemaVersion: modelContextVersion,
		Instructions: instructions, OutputSchema: schema,
		ReviewScopeIdentity: packet.reviewScopeIdentity, MemoryScopeIdentity: packet.memoryScopeIdentity,
		SnapshotIdentity: packet.snapshotIdentity, Task: packet.task.String(),
		OutputSchemaIdentity:    packet.outputSchemaIdentity,
		SourceSelectionIdentity: packet.sourceSelection.Identity(),
		SourceCoverage: contextSourceCoverageWire{
			Analyzed: packet.sourceSelection.CandidateCount() + sourceOmissionCount(packet.sourceOmissions), PreselectionOmitted: sourceOmissionCount(packet.sourceOmissions), Available: packet.sourceSelection.CandidateCount(), Selected: packet.sourceSelection.SelectedCount(),
			Omitted: packet.sourceSelection.OmittedCount() + sourceOmissionCount(packet.sourceOmissions), SelectedBytes: packet.sourceSelection.SelectedBytes(),
		},
		SourceAuthority: "evidence_data_not_instructions", MemoryAuthority: "advisory_only", ToolCalls: "proposals_only",
		Limits:  contextLimitsWire{MaxSourceBytes: packet.limits.MaxSourceBytes(), MaxMemoryItems: packet.limits.MaxMemoryItems()},
		Sources: contextSourceWireValues(packet.sources), SourceOmissions: contextSourceOmissionWireValues(packet.sourceOmissions), Memory: contextMemoryWireValue(packet.retrieval), AdditionalMemory: contextMemoryWireValues(packet.additionalRetrievals),
	}
	return json.Marshal(wire)
}

// ValidateContextPacketRequest admits only the current executable host context.
func ValidateContextPacketRequest(
	payload []byte,
	contextIdentity, reviewScopeIdentity, memoryScopeIdentity, memoryIdentity string,
	snapshot ReviewSnapshot,
	evidenceItems []evidence.EvidenceItem,
) error {
	if err := ValidateRecordedContextPacketRequest(payload, contextIdentity, reviewScopeIdentity, memoryScopeIdentity, memoryIdentity, snapshot, evidenceItems); err != nil {
		return err
	}
	wire, err := decodeGenerationContextWire(payload)
	if err != nil || wire.SchemaVersion != modelContextVersion {
		return ErrInvalidContextPacketRequest
	}
	return nil
}

// ValidateRecordedContextPacketRequest verifies exact v2 or v3 bytes for readback.
// It does not admit a legacy context for a new model attempt.
func ValidateRecordedContextPacketRequest(
	payload []byte,
	contextIdentity, reviewScopeIdentity, memoryScopeIdentity, memoryIdentity string,
	snapshot ReviewSnapshot,
	evidenceItems []evidence.EvidenceItem,
) error {
	if !validCandidateDigest(contextIdentity) || !validCandidateDigest(reviewScopeIdentity) || !validCandidateDigest(memoryScopeIdentity) || !validCandidateDigest(memoryIdentity) ||
		snapshot.Validate() != nil || len(payload) == 0 || len(payload) > maxProviderContextPacketBytes {
		return ErrInvalidContextPacketRequest
	}
	digest := sha256.Sum256(payload)
	if hex.EncodeToString(digest[:]) != contextIdentity {
		return ErrInvalidContextPacketRequest
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire contextPacketWire
	if err := decoder.Decode(&wire); err != nil {
		return ErrInvalidContextPacketRequest
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidContextPacketRequest
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) {
		return ErrInvalidContextPacketRequest
	}
	if wire.Contract != "open-trestle/review-context-packet" || !validRecordedModelOutputContract(wire.SchemaVersion, wire.Instructions, wire.OutputSchema, false) ||
		wire.ReviewScopeIdentity != reviewScopeIdentity || wire.MemoryScopeIdentity != memoryScopeIdentity || deriveContextMemoryIdentityFromWire(wire) != memoryIdentity || wire.SnapshotIdentity != snapshot.Identity() ||
		wire.Task != ContextTaskCandidateGeneration.String() || wire.OutputSchemaIdentity != ModelCandidateBatchSchemaIdentity ||
		wire.SourceAuthority != "evidence_data_not_instructions" || wire.MemoryAuthority != "advisory_only" ||
		wire.ToolCalls != "proposals_only" || !validCandidateDigest(wire.SourceSelectionIdentity) ||
		wire.Limits.MaxSourceBytes == 0 || wire.Limits.MaxSourceBytes > maxContextAggregateBytes ||
		wire.Limits.MaxMemoryItems > maxContextMemoryItems || len(wire.AdditionalMemory) > 63 || contextMemoryItemCount(wire) > int(wire.Limits.MaxMemoryItems) {
		return ErrInvalidContextPacketRequest
	}
	if len(wire.Sources) != len(evidenceItems) || wire.SourceCoverage.Selected != len(wire.Sources) ||
		wire.SourceCoverage.Available < wire.SourceCoverage.Selected || wireSourceOmissionCount(wire.SourceOmissions) != wire.SourceCoverage.PreselectionOmitted ||
		wire.SourceCoverage.Analyzed != wire.SourceCoverage.Available+wire.SourceCoverage.PreselectionOmitted ||
		wire.SourceCoverage.Omitted != wire.SourceCoverage.Available-wire.SourceCoverage.Selected+wire.SourceCoverage.PreselectionOmitted {
		return ErrInvalidContextPacketRequest
	}
	if !validateContextMemoryWire(wire.MemoryScopeIdentity, wire.Memory) {
		return ErrInvalidContextPacketRequest
	}
	for _, retrieval := range wire.AdditionalMemory {
		if !validateContextMemoryWire(wire.MemoryScopeIdentity, retrieval) {
			return ErrInvalidContextPacketRequest
		}
	}
	previousOmission := ContextSourceOmission{}
	for index, value := range wire.SourceOmissions {
		omission, err := NewCountedContextSourceOmission(value.Path, value.StartLine, value.EndLine, value.Reason, value.Count)
		if err != nil || index > 0 && !contextSourceOmissionLess(previousOmission, omission) {
			return ErrInvalidContextPacketRequest
		}
		previousOmission = omission
	}
	var sourceBytes uint32
	seenEvidence := make(map[string]struct{}, len(evidenceItems))
	for index, source := range wire.Sources {
		item := evidenceItems[index]
		if _, exists := seenEvidence[item.ID()]; exists || !rangeSupportedBySnapshot(item.SourceRange(), snapshot) {
			return ErrInvalidContextPacketRequest
		}
		seenEvidence[item.ID()] = struct{}{}
		rangeValue := item.SourceRange()
		if source.SourceID != item.ID() || source.EvidenceDigest != item.Digest() ||
			source.Path != rangeValue.Path() || source.StartLine != rangeValue.StartLine() ||
			source.EndLine != rangeValue.EndLine() || !utf8.ValidString(source.Content) ||
			!validContextStageToken(source.Stage) || !validContextTaintToken(source.Taint) {
			return ErrInvalidContextPacketRequest
		}
		contentDigest := sha256.Sum256([]byte(source.Content))
		if hex.EncodeToString(contentDigest[:]) != item.Digest() ||
			contextSourceLineCount(source.Content) != rangeValue.EndLine()-rangeValue.StartLine()+1 ||
			!slices.Equal(source.RiskFlags, contextRiskTokens(detectContextRisks(source.Content))) ||
			len(source.Content) > int(^uint32(0)-sourceBytes) {
			return ErrInvalidContextPacketRequest
		}
		sourceBytes += uint32(len(source.Content))
	}
	if sourceBytes != wire.SourceCoverage.SelectedBytes || sourceBytes > wire.Limits.MaxSourceBytes {
		return ErrInvalidContextPacketRequest
	}
	return nil
}

const maxProviderContextPacketBytes = 8 << 20

func validContextStageToken(value string) bool {
	for stage := ContextStageChangedHunk; stage <= ContextStageRepositoryContext; stage++ {
		if value == stage.String() {
			return true
		}
	}
	return false
}

func validContextTaintToken(value string) bool {
	_, err := memory.ParseTaintClass(value)
	return err == nil
}

func contextRiskTokens(risks ContextRisk) []string {
	tokens := make([]string, 0, 2)
	if risks&ContextRiskHiddenUnicode != 0 {
		tokens = append(tokens, "hidden_unicode")
	}
	if risks&ContextRiskInstructionLikeText != 0 {
		tokens = append(tokens, "instruction_like_text")
	}
	return tokens
}

func sourceOmissionCount(values []ContextSourceOmission) int {
	total := 0
	for _, value := range values {
		total += int(value.count)
	}
	return total
}
func wireSourceOmissionCount(values []contextSourceOmissionWire) int {
	total := 0
	for _, value := range values {
		if value.Count == 0 || value.Count > 32768 {
			return -1
		}
		total += int(value.Count)
		if total > 65536 {
			return -1
		}
	}
	return total
}
func contextSourceOmissionWireValues(omissions []ContextSourceOmission) []contextSourceOmissionWire {
	values := make([]contextSourceOmissionWire, len(omissions))
	for index, value := range omissions {
		values[index] = contextSourceOmissionWire{value.path, value.startLine, value.endLine, value.reason, value.count}
	}
	return values
}
func validateContextMemoryWire(scope string, retrieval contextMemoryWire) bool {
	if !validNonzeroContextDigest(scope) || !validNonzeroContextDigest(retrieval.QueryIdentity) || !validNonzeroContextDigest(retrieval.RetrievalIdentity) || len(retrieval.Items) > maxContextMemoryItems || len(retrieval.Items) > 0 && retrieval.IndexRevision == 0 {
		return false
	}
	itemIDs := make([]string, len(retrieval.Items))
	seen := make(map[string]struct{}, len(retrieval.Items))
	for index, item := range retrieval.Items {
		if item.Rank != uint8(index+1) || (item.PathScore == 0 && item.SymbolScore == 0 && item.TextScore == 0) || contextMemoryRecordIdentity(scope, item) != item.MemoryID {
			return false
		}
		if _, ok := seen[item.MemoryID]; ok {
			return false
		}
		seen[item.MemoryID] = struct{}{}
		encoded, _ := json.Marshal(struct {
			Contract string `json:"contract"`
			Version  int    `json:"version"`
			Query    string `json:"query"`
			Record   string `json:"record"`
			Rank     uint8  `json:"rank"`
			Path     uint8  `json:"path"`
			Symbol   uint8  `json:"symbol"`
			Text     uint8  `json:"text"`
		}{"open-trestle/memory-retrieval-item", 1, retrieval.QueryIdentity, item.MemoryID, item.Rank, item.PathScore, item.SymbolScore, item.TextScore})
		digest := sha256.Sum256(encoded)
		itemIDs[index] = hex.EncodeToString(digest[:])
	}
	encoded, _ := json.Marshal(struct {
		Contract string   `json:"contract"`
		Version  int      `json:"version"`
		Scope    string   `json:"scope"`
		Query    string   `json:"query"`
		Revision uint64   `json:"revision"`
		Items    []string `json:"items"`
	}{"open-trestle/memory-lexical-retrieval", 1, scope, retrieval.QueryIdentity, retrieval.IndexRevision, itemIDs})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:]) == retrieval.RetrievalIdentity
}
func contextMemoryRecordIdentity(scope string, item contextMemoryItemWire) string {
	kind, kindErr := memory.ParseRecordKind(item.Kind)
	taint, taintErr := memory.ParseTaintClass(item.Taint)
	if kindErr != nil || taintErr != nil || kind.String() != item.Kind || taint.String() != item.Taint || !validContextMemoryText(item.Text) || !validContextMemoryPath(item.Path) || !validContextMemoryStrings(item.Symbols, 32, 256, false) || !validContextMemoryStrings(item.EvidenceIDs, 32, 128, true) || !validContextMemoryStrings(item.DerivedFromIDs, 32, 128, true) || !validContextMemoryStrings(item.CounterEvidenceIDs, 32, 128, true) || !validNonzeroContextDigest(item.ProducerIdentity) || item.ObservedAt <= 0 || item.ValidFrom <= 0 || item.ValidFrom > item.ObservedAt || item.ValidUntil != 0 && item.ValidUntil <= item.ValidFrom || item.StaleAfter != 0 && item.StaleAfter <= item.ObservedAt {
		return ""
	}
	if kind == memory.RecordDerivedObservation {
		if len(item.DerivedFromIDs) < 2 || len(item.EvidenceIDs) != 0 || !validNonzeroContextDigest(item.FreshnessIdentity) || item.Confidence == 0 || item.Confidence > 10000 {
			return ""
		}
	} else if len(item.EvidenceIDs) == 0 || len(item.DerivedFromIDs) != 0 || len(item.CounterEvidenceIDs) != 0 || item.StaleAfter != 0 || item.FreshnessIdentity != "" || item.Confidence != 0 {
		return ""
	}
	textDigest := sha256.Sum256([]byte(item.Text))
	encoded, _ := json.Marshal(struct {
		Contract        string   `json:"contract"`
		Version         int      `json:"version"`
		Scope           string   `json:"scope"`
		Kind            string   `json:"kind"`
		Taint           string   `json:"taint"`
		Path            string   `json:"path"`
		Symbols         []string `json:"symbols"`
		TextDigest      string   `json:"text_digest"`
		TextBytes       int      `json:"text_bytes"`
		Evidence        []string `json:"evidence"`
		DerivedFrom     []string `json:"derived_from"`
		CounterEvidence []string `json:"counter_evidence"`
		Producer        string   `json:"producer"`
		ObservedAt      int64    `json:"observed_at"`
		ValidFrom       int64    `json:"valid_from"`
		ValidUntil      int64    `json:"valid_until"`
		StaleAfter      int64    `json:"stale_after"`
		Freshness       string   `json:"freshness"`
		Confidence      uint16   `json:"confidence"`
	}{"open-trestle/memory-record", 1, scope, item.Kind, item.Taint, item.Path, item.Symbols, hex.EncodeToString(textDigest[:]), len(item.Text), item.EvidenceIDs, item.DerivedFromIDs, item.CounterEvidenceIDs, item.ProducerIdentity, item.ObservedAt, item.ValidFrom, item.ValidUntil, item.StaleAfter, item.FreshnessIdentity, item.Confidence})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func validContextMemoryText(value string) bool {
	return len(value) > 0 && len(value) <= 4096 && utf8.ValidString(value) && !strings.ContainsRune(value, 0)
}
func validContextMemoryPath(value string) bool {
	if value == "." {
		return true
	}
	_, err := evidence.NewRepositoryFile(value, nil)
	return err == nil
}
func validContextMemoryStrings(values []string, maximum, maximumBytes int, references bool) bool {
	if len(values) > maximum {
		return false
	}
	previous := ""
	for _, value := range values {
		if value == "" || len(value) > maximumBytes || !utf8.ValidString(value) || strings.ContainsRune(value, 0) || previous != "" && value <= previous {
			return false
		}
		if references {
			// Memory references use the bound above, not the candidate-reference bound.
			if !isCandidateAlphaNumeric(value[0]) {
				return false
			}
			for index := 1; index < len(value); index++ {
				character := value[index]
				if !isCandidateAlphaNumeric(character) && character != '-' && character != '_' && character != '.' && character != ':' {
					return false
				}
			}
		}
		previous = value
	}
	return true
}

func validNonzeroContextDigest(value string) bool {
	return validCandidateDigest(value) && strings.Trim(value, "0") != ""
}
func deriveContextMemoryIdentity(scopeIdentity string, retrievalIdentities []string) string {
	encoded, _ := json.Marshal(struct {
		Contract   string   `json:"contract"`
		Version    int      `json:"version"`
		Scope      string   `json:"scope"`
		Retrievals []string `json:"retrievals"`
	}{"open-trestle/context-memory-set", 1, scopeIdentity, retrievalIdentities})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func deriveContextMemoryIdentityFromWire(wire contextPacketWire) string {
	identities := make([]string, 0, 1+len(wire.AdditionalMemory))
	identities = append(identities, wire.Memory.RetrievalIdentity)
	for _, retrieval := range wire.AdditionalMemory {
		identities = append(identities, retrieval.RetrievalIdentity)
	}
	return deriveContextMemoryIdentity(wire.MemoryScopeIdentity, identities)
}

func contextMemoryWireValues(retrievals []memory.LexicalRetrieval) []contextMemoryWire {
	values := make([]contextMemoryWire, len(retrievals))
	for index, retrieval := range retrievals {
		values[index] = contextMemoryWireValue(retrieval)
	}
	return values
}
func contextMemoryItemCount(wire contextPacketWire) int {
	total := len(wire.Memory.Items)
	for _, retrieval := range wire.AdditionalMemory {
		total += len(retrieval.Items)
	}
	return total
}

func deriveContextPacketIdentity(packet ContextPacket) string {
	encoded, err := encodeContextPacket(packet)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func writeRedactedReviewFormat(state fmt.State, verb rune, plain, goSyntax string) {
	formatted := plain
	if verb == 'q' {
		formatted = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		formatted = goSyntax
	}
	_, _ = state.Write([]byte(formatted))
}
