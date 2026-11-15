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
	// ModelCandidateBatchSchemaIdentity is the SHA-256 identity of the canonical
	// candidate batch JSON Schema that new generation contexts request:
	// model-candidate-batch-v2, used from context schema version 7.
	ModelCandidateBatchSchemaIdentity = "63a1bd4a1f2bea9faf93e17e0722aa0b50ba87d2a8ba80088422b8d5190f91bb"
	// ModelCandidateBatchV1SchemaIdentity is the SHA-256 identity of canonical
	// model-candidate-batch-v1 JSON Schema, requested by generation contexts
	// before version 7. It is accepted only for recorded readback.
	ModelCandidateBatchV1SchemaIdentity = "b79f43bd52cb67e18896dd053ab85c21efd11c4ba5a97234f3f4ce867109dc0e"
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

// Stage values order source selection and packet sources. Only their names
// are recorded, so a new stage may take any position in the order.
const (
	ContextStageChangedHunk ContextStage = iota + 1
	// ContextStageRemovedLines carries the base lines a deletion-only change
	// removed at one deletion point, bound to the exact base file and labelled
	// with base line numbers. It is evidence of what was removed, never an
	// anchor: findings anchor on head lines. It is valid from generation
	// context version 8, verification version 7 and investigation version 6,
	// and is selected right after the changed hunks it belongs to.
	ContextStageRemovedLines
	ContextStageEnclosingSymbol
	ContextStageDirectReference
	ContextStageRepositoryContext
)

func (s ContextStage) String() string {
	switch s {
	case ContextStageChangedHunk:
		return "changed_hunk"
	case ContextStageRemovedLines:
		return "removed_lines"
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
// Risks are attention markers for the model and for people; they never suppress
// review, select sources, or grant authority.
type ContextRisk uint8

const (
	ContextRiskHiddenUnicode ContextRisk = 1 << iota
	ContextRiskInstructionLikeText
	// ContextRiskAgentConfiguration marks a source whose path names repository AI
	// material: agent instruction files, agent skills, prompts, or agent tool
	// configuration (see agentConfigurationPath). Such files are reviewed as code.
	ContextRiskAgentConfiguration
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
	// headLine is set only on the removed_lines source of a deletion point:
	// the head line beside which its base lines were removed.
	headLine int
}

// NewContextSource verifies exact content against one host-issued evidence item.
func NewContextSource(stage ContextStage, taint memory.TaintClass, item evidence.EvidenceItem, content []byte) (ContextSource, error) {
	source := ContextSource{stage: stage, taint: taint, evidenceItem: item, content: string(content), risks: detectSourceRisks(item.SourceRange().Path(), string(content))}
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

// HeadLine returns, for the removed_lines source of a deletion point, the head
// line beside which its base lines were removed; 0 otherwise.
func (s ContextSource) HeadLine() int { return s.headLine }

// NewRemovedLinesContextSource binds removed base lines as a removed_lines
// source. headLine is the head line beside which they were removed, as the
// analysis record names it, or 0 when no head line remains beside them.
func NewRemovedLinesContextSource(item evidence.EvidenceItem, content []byte, binding evidence.SourceSliceBinding, headLine int) (ContextSource, error) {
	source, err := NewBoundContextSource(ContextStageRemovedLines, memory.TaintRepositoryControlled, item, content, binding)
	if err != nil {
		return ContextSource{}, err
	}
	source.headLine = headLine
	source.identity = deriveContextSourceIdentity(source)
	if err := source.Validate(); err != nil {
		return ContextSource{}, err
	}
	return source, nil
}
func (s ContextSource) String() string   { return "review context source" }
func (s ContextSource) GoString() string { return "review.ContextSource{<redacted>}" }
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
	if s.stage == ContextStageRemovedLines && s.taint != memory.TaintRepositoryControlled {
		return ErrInvalidContextSource
	}
	if s.headLine < 0 || s.headLine > maxCandidateSourceLine || s.headLine != 0 && s.stage != ContextStageRemovedLines {
		return ErrInvalidContextSource
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
	if s.risks != detectSourceRisks(s.evidenceItem.SourceRange().Path(), s.content) {
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

// legacyInstructionMarkers are the content markers recorded by generation
// contexts before version 7, verification contexts before version 6, and
// publication content scans. They must not change: recorded readback
// re-derives risk_flags from content with exactly this list.
var legacyInstructionMarkers = []string{"ignore previous", "system prompt", "developer message", "tool_call", "call a tool"}

// extendedInstructionMarkers are additional high-signal literal markers used
// from generation context version 7 and verification context version 6: chat
// template role and turn tokens, fake system tags, override phrases, and the
// JSON authority label older Open Trestle payloads used. Matching is a literal
// substring search over lowercased text, so it has no backtracking cost.
var extendedInstructionMarkers = []string{
	"<|im_start|>", "<|im_end|>", "<|system|>", "<|start_header_id|>", "<start_of_turn>", "[inst]",
	"<system>", "</system>", "ignore all previous", "ignore prior", "ignore all prior",
	"instruction_authority", "you are now",
}

// detectContextRisks applies the legacy content rules. Recorded readback of
// earlier context versions and publication content scans use it unchanged.
func detectContextRisks(content string) ContextRisk {
	var risks ContextRisk
	for _, character := range content {
		if unicode.In(character, unicode.Cf) {
			risks |= ContextRiskHiddenUnicode
			break
		}
	}
	if containsAnyMarker(strings.ToLower(content), legacyInstructionMarkers) {
		risks |= ContextRiskInstructionLikeText
	}
	return risks
}

// detectSourceRisks applies the current rules: legacy content rules, the
// extended instruction markers, and the agent_configuration path rule.
func detectSourceRisks(path, content string) ContextRisk {
	risks := detectContextRisks(content)
	if risks&ContextRiskInstructionLikeText == 0 && containsAnyMarker(strings.ToLower(content), extendedInstructionMarkers) {
		risks |= ContextRiskInstructionLikeText
	}
	if agentConfigurationPath(path) {
		risks |= ContextRiskAgentConfiguration
	}
	return risks
}

// recordedSourceRisks returns the rules a recorded context version used.
func recordedSourceRisks(current bool, path, content string) ContextRisk {
	if current {
		return detectSourceRisks(path, content)
	}
	return detectContextRisks(content)
}

func containsAnyMarker(lower string, markers []string) bool {
	for _, marker := range markers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// agentConfigurationPath reports whether a repository-relative path names AI
// material by convention. The list is documented in
// docs/prompt-injection-boundary.md: AGENTS.md, CLAUDE.md, GEMINI.md,
// .cursorrules and SKILL.md at any depth (file names compared
// case-insensitively); any file under a .cursor, .claude, .codex, .trestle or
// prompts directory; .github/copilot-instructions.md; Markdown files under a
// skills directory; and *.prompt, *.prompt.md and *.prompty files.
func agentConfigurationPath(path string) bool {
	segments := strings.Split(path, "/")
	base := strings.ToLower(segments[len(segments)-1])
	switch base {
	case "agents.md", "claude.md", "gemini.md", ".cursorrules", "skill.md":
		return true
	}
	if strings.HasSuffix(base, ".prompt") || strings.HasSuffix(base, ".prompt.md") || strings.HasSuffix(base, ".prompty") {
		return true
	}
	directories := segments[:len(segments)-1]
	for index, directory := range directories {
		switch strings.ToLower(directory) {
		case ".cursor", ".claude", ".codex", ".trestle", "prompts":
			return true
		case "skills":
			if strings.HasSuffix(base, ".md") {
				return true
			}
		case ".github":
			if index == len(directories)-1 && base == "copilot-instructions.md" {
				return true
			}
		}
	}
	return false
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
		// HeadLine is present only on a deletion point's removed_lines source.
		HeadLine int `json:"head_line,omitempty"`
	}{
		Contract: "open-trestle/review-context-source", Version: 1,
		Stage: source.stage.String(), Taint: source.taint.String(), Reference: source.evidenceItem.ID(),
		EvidenceDigest: source.evidenceItem.Digest(), Path: rangeValue.Path(),
		Start: rangeValue.StartLine(), End: rangeValue.EndLine(),
		ContentDigest: hex.EncodeToString(contentDigest[:]), ContentBytes: len(source.content), Risks: uint8(source.risks),
		SliceBound: source.hasSliceBinding, SliceBinding: source.sliceBinding.Identity(),
		HeadLine: source.headLine,
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
	if RepositoryInstructionOmissionReason(value) {
		return true
	}
	_, err := contextSourceOmissionCategory(value)
	return err == nil
}

// repositoryInstructionPaths is the fixed, root-only list of repository review
// instruction files, in supply order. Subdirectory copies are never read.
var repositoryInstructionPaths = []string{"AGENTS.md", "CLAUDE.md", ".github/copilot-instructions.md", ".trestle/review-instructions.md"}

// RepositoryInstructionPaths returns the fixed, root-only repository review
// instruction file paths that context assembly may supply from the base tree
// as repository_context, in supply order.
func RepositoryInstructionPaths() []string { return slices.Clone(repositoryInstructionPaths) }

// RepositoryInstructionPath reports whether path is one of the fixed
// repository review instruction file paths.
func RepositoryInstructionPath(path string) bool {
	return slices.Contains(repositoryInstructionPaths, path)
}

// RepositoryInstructionOmissionReason reports whether reason records a
// repository instruction file that was not supplied as repository_context.
// Instruction files are advisory context, not changed source: these omissions
// are reported separately and never count against changed-source coverage.
func RepositoryInstructionOmissionReason(reason string) bool {
	switch reason {
	case "repository_instruction_truncated", "repository_instruction_size_limit", "repository_instruction_unsupported_content",
		"repository_instruction_path_not_authorized", "repository_instruction_candidate_limit", "repository_instruction_packet_budget",
		"repository_instruction_changed":
		return true
	}
	return false
}

// changedSourceCoverage removes repository instruction omissions from recorded
// packet coverage. The packet wire keeps complete accounting; derived coverage,
// diagnostics, and completeness see only changed-source omissions.
func changedSourceCoverage(coverage contextSourceCoverageWire, records []contextSourceOmissionWire) (analyzed, omitted int, instruction uint32) {
	for _, record := range records {
		if RepositoryInstructionOmissionReason(record.Reason) {
			instruction += record.Count
		}
	}
	return coverage.Analyzed - int(instruction), coverage.Omitted - int(instruction), instruction
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
	specialist           ContextSpecialist
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

// Specialist returns the bound packaged specialist; the zero value means none.
func (p ContextPacket) Specialist() ContextSpecialist { return p.specialist }

// WithSpecialist returns a copy that binds one packaged specialist profile. The
// copy encodes the optional specialist block of context schema version 8; the
// receiver is unchanged.
func (p ContextPacket) WithSpecialist(specialist ContextSpecialist) (ContextPacket, error) {
	if err := p.Validate(); err != nil {
		return ContextPacket{}, err
	}
	if !p.specialist.IsZero() || specialist.IsZero() || specialist.Validate() != nil {
		return ContextPacket{}, ErrInvalidContextSpecialist
	}
	value := p
	value.sources = append([]ContextSource(nil), p.sources...)
	value.additionalRetrievals = append([]memory.LexicalRetrieval(nil), p.additionalRetrievals...)
	value.sourceOmissions = append([]ContextSourceOmission(nil), p.sourceOmissions...)
	value.specialist = specialist
	value.identity = deriveContextPacketIdentity(value)
	if err := value.Validate(); err != nil {
		return ContextPacket{}, err
	}
	return value, nil
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
	if !p.specialist.IsZero() && p.specialist.Validate() != nil {
		return ErrInvalidContextSpecialist
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
	InstructionsIdentity    string                      `json:"instructions_identity,omitempty"`
	OutputSchema            json.RawMessage             `json:"output_schema,omitempty"`
	Specialist              *contextSpecialistWire      `json:"specialist,omitempty"`
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
	SourceID       string `json:"source_id"`
	Stage          string `json:"stage"`
	Taint          string `json:"taint"`
	EvidenceDigest string `json:"evidence_digest"`
	Path           string `json:"path"`
	StartLine      int    `json:"start_line"`
	EndLine        int    `json:"end_line"`
	// HeadLine appears only on the removed_lines source of a deletion point:
	// the head line beside which its base lines were removed.
	HeadLine  int      `json:"head_line,omitempty"`
	RiskFlags []string `json:"risk_flags"`
	Content   string   `json:"content"`
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
	// Every new generation context is version 8. The specialist block is present
	// only when a packaged profile is bound. Instruction prose never enters the
	// payload: the model receives it only through the trusted system channel,
	// and the payload binds it by instructions_identity.
	version := modelGenerationContextVersion
	var specialist *contextSpecialistWire
	if !packet.specialist.IsZero() {
		specialist = packet.specialist.wire()
	}
	instructions, schema, err := modelOutputContractForVersion(version, false)
	if err != nil {
		return nil, err
	}
	wire := contextPacketWire{
		Contract: "open-trestle/review-context-packet", SchemaVersion: version,
		InstructionsIdentity: modelInstructionsIdentity(instructions), OutputSchema: schema, Specialist: specialist,
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
	if err != nil || !executableGenerationContextVersion(wire.SchemaVersion) {
		return ErrInvalidContextPacketRequest
	}
	return nil
}

// ValidateRecordedContextPacketRequest verifies exact v2, v3, v5, v7 or v8 bytes for readback.
// A v7 or v8 specialist block must re-derive exactly from the embedded profile catalog.
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
	if wire.Contract != "open-trestle/review-context-packet" || !validRecordedModelOutputContract(wire.SchemaVersion, wire.Instructions, wire.InstructionsIdentity, wire.OutputSchema, false) || !validGenerationContextSpecialist(wire) ||
		wire.ReviewScopeIdentity != reviewScopeIdentity || wire.MemoryScopeIdentity != memoryScopeIdentity || deriveContextMemoryIdentityFromWire(wire) != memoryIdentity || wire.SnapshotIdentity != snapshot.Identity() ||
		wire.Task != ContextTaskCandidateGeneration.String() || wire.OutputSchemaIdentity != candidateSchemaIdentityForContextVersion(wire.SchemaVersion) ||
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
	if !validSourceHeadLines(wire.Sources) {
		return ErrInvalidContextPacketRequest
	}
	var sourceBytes uint32
	seenEvidence := make(map[string]struct{}, len(evidenceItems))
	for index, source := range wire.Sources {
		item := evidenceItems[index]
		// Removed base lines are not head ranges and are never in the snapshot.
		removed := source.Stage == ContextStageRemovedLines.String()
		if _, exists := seenEvidence[item.ID()]; exists || !removed && !rangeSupportedBySnapshot(item.SourceRange(), snapshot) {
			return ErrInvalidContextPacketRequest
		}
		seenEvidence[item.ID()] = struct{}{}
		rangeValue := item.SourceRange()
		if source.SourceID != item.ID() || source.EvidenceDigest != item.Digest() ||
			source.Path != rangeValue.Path() || source.StartLine != rangeValue.StartLine() ||
			source.EndLine != rangeValue.EndLine() || !utf8.ValidString(source.Content) ||
			!validContextStageToken(source.Stage, wire.SchemaVersion == modelGenerationContextVersion) || !validContextTaintToken(source.Taint) ||
			removed && source.Taint != memory.TaintRepositoryControlled.String() {
			return ErrInvalidContextPacketRequest
		}
		contentDigest := sha256.Sum256([]byte(source.Content))
		if hex.EncodeToString(contentDigest[:]) != item.Digest() ||
			contextSourceLineCount(source.Content) != rangeValue.EndLine()-rangeValue.StartLine()+1 ||
			!slices.Equal(source.RiskFlags, contextRiskTokens(recordedSourceRisks(systemChannelGenerationVersion(wire.SchemaVersion), source.Path, source.Content))) ||
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

// validSourceHeadLines checks the head lines recorded on removed_lines
// sources: only a removed_lines source carries one, and it lies inside a
// changed_hunk source of the same file, the deletion-point context around it.
func validSourceHeadLines(sources []contextSourceWire) bool {
	for _, source := range sources {
		if source.HeadLine == 0 {
			continue
		}
		if source.Stage != ContextStageRemovedLines.String() || source.HeadLine < 0 || source.HeadLine > maxCandidateSourceLine {
			return false
		}
		placed := false
		for _, head := range sources {
			if head.Stage == ContextStageChangedHunk.String() && head.Path == source.Path && head.StartLine <= source.HeadLine && source.HeadLine <= head.EndLine {
				placed = true
				break
			}
		}
		if !placed {
			return false
		}
	}
	return true
}

// validContextStageToken admits removed_lines only for the contract versions
// that define it; every earlier version keeps its original stage set.
func validContextStageToken(value string, removedLines bool) bool {
	if value == ContextStageRemovedLines.String() {
		return removedLines
	}
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

const (
	contextRiskTokenHiddenUnicode      = "hidden_unicode"
	contextRiskTokenInstructionLike    = "instruction_like_text"
	contextRiskTokenAgentConfiguration = "agent_configuration"
)

func contextRiskTokens(risks ContextRisk) []string {
	tokens := make([]string, 0, 3)
	if risks&ContextRiskHiddenUnicode != 0 {
		tokens = append(tokens, contextRiskTokenHiddenUnicode)
	}
	if risks&ContextRiskInstructionLikeText != 0 {
		tokens = append(tokens, contextRiskTokenInstructionLike)
	}
	if risks&ContextRiskAgentConfiguration != 0 {
		tokens = append(tokens, contextRiskTokenAgentConfiguration)
	}
	return tokens
}

// ContextRiskSourceCounts reports how many sources in exact recorded
// generation-context bytes carry the agent_configuration and
// instruction_like_text risk flags. The counts are content-free attention
// signals for people; flags never suppress review or change selection.
func ContextRiskSourceCounts(payload []byte) (agentConfiguration, instructionLike int, err error) {
	if len(payload) == 0 || len(payload) > maxProviderContextPacketBytes {
		return 0, 0, ErrInvalidContextPacketRequest
	}
	wire, err := decodeGenerationContextWire(payload)
	if err != nil || wire.Contract != "open-trestle/review-context-packet" {
		return 0, 0, ErrInvalidContextPacketRequest
	}
	for _, source := range wire.Sources {
		if slices.Contains(source.RiskFlags, contextRiskTokenAgentConfiguration) {
			agentConfiguration++
		}
		if slices.Contains(source.RiskFlags, contextRiskTokenInstructionLike) {
			instructionLike++
		}
	}
	return agentConfiguration, instructionLike, nil
}

// ContextChangeEvidence reads a recorded generation context and returns the
// IDs of its sources that are evidence of the change itself: changed hunks
// (including the unchanged head lines bound around a deletion point) and
// removed base lines. Direct references and repository context are unchanged
// code. It never returns source content.
func ContextChangeEvidence(payload []byte) (map[string]bool, error) {
	if len(payload) == 0 || len(payload) > maxProviderContextPacketBytes {
		return nil, ErrInvalidContextPacketRequest
	}
	wire, err := decodeGenerationContextWire(payload)
	if err != nil || wire.Contract != "open-trestle/review-context-packet" {
		return nil, ErrInvalidContextPacketRequest
	}
	ids := map[string]bool{}
	for _, source := range wire.Sources {
		if source.Stage == ContextStageChangedHunk.String() || source.Stage == ContextStageRemovedLines.String() {
			ids[source.SourceID] = true
		}
	}
	return ids, nil
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
