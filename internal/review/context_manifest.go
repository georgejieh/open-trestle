package review

import (
	"context"
	"errors"
	"slices"
	"time"
)

// ErrInvalidContextManifest identifies malformed context accounting.
var ErrInvalidContextManifest = errors.New("invalid review context manifest")

const (
	contextManifestAuthority = "host_accounting"
	maxManifestDefinitions   = 256
	maxManifestCount         = 1 << 24
)

// Budget bases recorded in a context manifest.
const (
	ContextBudgetDefault     = "default"
	ContextBudgetRouteWindow = "route_window"
)

const (
	minimumRouteSourceBytes = 8 << 10
	maximumRouteSourceBytes = 1 << 20
	// defaultContextSourceBytes is the source byte bound of a packet whose
	// routes declare no context window.
	defaultContextSourceBytes = 128 << 10
)

// ContextBudget is the source byte budget of a packet and how it was chosen.
// Every packet keeps at most 32 sources.
type ContextBudget struct {
	Basis              string
	RouteContextTokens uint32
	OutputTokens       uint32
	MaxSourceBytes     uint32
}

// DefaultContextBudget is the budget of a packet whose routes declare no
// context window: 128 KiB.
func DefaultContextBudget() ContextBudget {
	return ContextBudget{Basis: ContextBudgetDefault, MaxSourceBytes: defaultContextSourceBytes}
}

// RouteContextBudget derives a budget from the smallest context window of
// the routes that may receive the packet and the output tokens reserved for
// the answer. A request reserves one token per payload byte, so half of the
// window left after the answer goes to source text; the other half covers
// the JSON framing, the instructions, memory and, for the verifier, the
// candidates. The result stays between 8 KiB and 1 MiB, within what the
// secret scanner reads in one request. A window of zero is unknown and gives
// the default.
func RouteContextBudget(windowTokens, outputTokens uint32) ContextBudget {
	if windowTokens == 0 {
		return DefaultContextBudget()
	}
	available := uint32(0)
	if windowTokens > outputTokens {
		available = windowTokens - outputTokens
	}
	bytes := min(max(available/2, minimumRouteSourceBytes), maximumRouteSourceBytes)
	return ContextBudget{Basis: ContextBudgetRouteWindow, RouteContextTokens: windowTokens, OutputTokens: outputTokens, MaxSourceBytes: bytes}
}

// Limits returns the packet limits of the budget.
func (b ContextBudget) Limits(maxMemoryItems uint8) (ContextLimits, error) {
	return NewContextLimits(b.MaxSourceBytes, maxMemoryItems)
}

func (l ContextLimits) wire() contextLimitsWire {
	return contextLimitsWire{MaxSourceBytes: l.maxSourceBytes, MaxMemoryItems: l.maxMemoryItems}
}

// Index states recorded in a context manifest.
const (
	ContextIndexUsed = "used"
	// ContextIndexSnapshot is context planned from the review's own
	// snapshots, analysed in process, when no repository index was used.
	ContextIndexSnapshot    = "snapshot"
	ContextIndexUnavailable = "unavailable"
	ContextIndexOverBudget  = "over_budget"
	ContextIndexFailed      = "failed"
)

// Omission reasons of index context recorded in a context manifest.
const (
	ContextOmittedPacketBudget = "packet_budget"
	ContextOmittedSourceLimit  = "source_limit"
	ContextOmittedStageLimit   = "stage_limit"
	ContextOmittedSizeLimit    = "size_limit"
	ContextOmittedDuplicate    = "duplicate"
	ContextOmittedPath         = "path_not_authorized"
	ContextOmittedContent      = "unsupported_content"
	ContextOmittedRange        = "invalid_range"
)

var contextManifestOmissionReasons = []string{ContextOmittedDuplicate, ContextOmittedRange, ContextOmittedPacketBudget, ContextOmittedPath, ContextOmittedSizeLimit, ContextOmittedSourceLimit, ContextOmittedStageLimit, ContextOmittedContent}

// ModelCheckClasses are the classes a review tells its models to spend no
// effort on when the repository's CI enforces them; every other enforced
// class is information only and never a reason to reduce scrutiny.
var ModelCheckClasses = []string{"formatting", "lint", "type_check"}

// RepositoryCheckClasses are the classes of issue a repository's own checks
// can be recorded as enforcing.
var RepositoryCheckClasses = []string{"coverage_gate", "dependency_review", "formatting", "fuzzing", "lint", "race_detection", "secret_scan", "static_analysis", "type_check", "unit_tests", "vulnerability_scan"}

// ContextIndexCoverage counts what the index behind a plan covered.
type ContextIndexCoverage struct {
	Files, Indexed, LeftOut, AnalysisGaps, ChangeGaps, ClosureCut int
}

// ContextPlanItem is one range of unchanged head code a repository index
// proposes as context: its stage, its rank within the stage (1 first) and,
// for a use or a test, its reference depth from the changed definitions.
type ContextPlanItem struct {
	Stage              ContextStage
	Path               string
	StartLine, EndLine int
	Rank, Depth        int
}

// ContextPlanDefinition is a changed head definition with the counts of its
// direct dependents and of the tests among them.
type ContextPlanDefinition struct {
	Path               string
	StartLine, EndLine int
	Dependents, Tests  int
}

// ContextPlan is what a repository index proposes as context for a change.
// Items come in priority order: by stage, then by rank. StageOmitted counts,
// per stage, the items the planner's own per-stage bounds left out.
type ContextPlan struct {
	State    string
	Complete bool
	// RankingComplete is false when a bound cut the repository map's
	// ranking; it does not make the index incomplete.
	RankingComplete bool
	// ValueUses is true when the analysis of every changed definition's
	// language records value uses (reads, function values, field reads), so
	// that zero dependents can show that nothing uses the change.
	ValueUses    bool
	Coverage     ContextIndexCoverage
	Items        []ContextPlanItem
	StageOmitted map[ContextStage]int
	Changed      []ContextPlanDefinition
	// Dependents counts the direct dependents of every changed definition,
	// in the head and the base.
	Dependents int
	// Checks are the repository check classes read from the base tree.
	Checks []string
}

// UnavailableContextPlan is the plan of a review without an index.
func UnavailableContextPlan(state string) ContextPlan {
	return ContextPlan{State: state}
}

// WithContextPlanDeadline bounds work that only adds context to a review,
// such as building, loading or planning from an index, to a quarter of the
// time left before ctx's deadline, so that the model calls keep the rest.
// Without a deadline, ctx bounds the work alone.
func WithContextPlanDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline, ok := ctx.Deadline()
	if !ok {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, time.Until(deadline)/4)
}

// ContextPlanAbandoned reports that bounded, a context from
// WithContextPlanDeadline, ran out of its own time while ctx still has time.
func ContextPlanAbandoned(ctx, bounded context.Context) bool {
	return bounded.Err() != nil && ctx.Err() == nil
}

// ContextManifestSource is an index source included in a packet.
type ContextManifestSource struct {
	SourceID    string
	Stage       ContextStage
	Rank, Depth int
}

// ContextManifestOmission counts index context of one stage left out for
// one reason.
type ContextManifestOmission struct {
	Stage  ContextStage
	Reason string
	Count  int
}

// ContextManifestDefinition places a changed definition on the packet
// source that holds its first line.
type ContextManifestDefinition struct {
	SourceID          string
	Line              int
	Dependents, Tests int
}

// ContextManifestSpec is the content of a context manifest.
type ContextManifestSpec struct {
	Budget           ContextBudget
	Plan             ContextPlan
	Included         []ContextManifestSource
	Omitted          []ContextManifestOmission
	Changed          []ContextManifestDefinition
	ChangedNotListed int
}

// ContextManifest records how a packet's source budget was chosen, what the
// repository index proposed and which of it the packet includes or leaves
// out, and the repository's own checks. It holds host-issued source IDs,
// closed tokens and numbers, never repository text.
type ContextManifest struct {
	manifest *contextManifestWire
	checks   []string
}

type contextManifestWire struct {
	Authority        string                          `json:"authority"`
	Budget           contextBudgetWire               `json:"budget"`
	Index            contextIndexWire                `json:"index"`
	Included         []contextManifestSourceWire     `json:"included"`
	Omitted          []contextManifestOmissionWire   `json:"omitted"`
	Changed          []contextManifestDefinitionWire `json:"changed_definitions"`
	ChangedNotListed int                             `json:"changed_definitions_not_listed"`
	Dependents       int                             `json:"dependents"`
	// Checks are the classes the repository's CI enforces, as information.
	Checks []string `json:"checks"`
}

type contextBudgetWire struct {
	Basis              string `json:"basis"`
	RouteContextTokens uint32 `json:"route_context_tokens,omitempty"`
	OutputTokens       uint32 `json:"output_tokens,omitempty"`
}

type contextIndexWire struct {
	State    string `json:"state"`
	Complete bool   `json:"complete"`
	// ValueUses says the analysis of every changed definition records
	// value uses, so that zero dependents shows nothing uses the change.
	ValueUses       bool `json:"value_uses"`
	RankingComplete bool `json:"ranking_complete"`
	Files           int  `json:"files"`
	Indexed         int  `json:"indexed"`
	LeftOut         int  `json:"left_out"`
	AnalysisGaps    int  `json:"analysis_gaps"`
	ChangeGaps      int  `json:"change_gaps"`
	ClosureCut      int  `json:"closure_cut"`
}

type contextManifestSourceWire struct {
	SourceID string `json:"source_id"`
	Stage    string `json:"stage"`
	Rank     int    `json:"rank"`
	Depth    int    `json:"depth,omitempty"`
}

type contextManifestOmissionWire struct {
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

type contextManifestDefinitionWire struct {
	SourceID   string `json:"source_id"`
	Line       int    `json:"line"`
	Dependents int    `json:"dependents"`
	Tests      int    `json:"tests"`
}

func (m ContextManifest) IsZero() bool { return m.manifest == nil }

func (m ContextManifest) manifestWire() *contextManifestWire { return m.manifest }
func (m ContextManifest) checksWire() []string               { return m.checks }

// indexContextStage reports the stages a repository index supplies.
func indexContextStage(stage string) bool {
	switch stage {
	case ContextStageEnclosingSymbol.String(), ContextStageDirectReference.String(), ContextStageRelatedTest.String(), ContextStageRepositoryMap.String():
		return true
	}
	return false
}

// WithContextManifest returns a copy that carries the context manifest and
// the repository checks of version 10. Every index-stage source of the packet
// must be listed as included, in source order.
func (p ContextPacket) WithContextManifest(spec ContextManifestSpec) (ContextPacket, error) {
	if err := p.Validate(); err != nil {
		return ContextPacket{}, err
	}
	if !p.manifest.IsZero() {
		return ContextPacket{}, ErrInvalidContextManifest
	}
	plan := spec.Plan
	wire := &contextManifestWire{
		Authority: contextManifestAuthority,
		Budget:    contextBudgetWire{Basis: spec.Budget.Basis, RouteContextTokens: spec.Budget.RouteContextTokens, OutputTokens: spec.Budget.OutputTokens},
		Index: contextIndexWire{State: plan.State, Complete: plan.Complete, ValueUses: plan.ValueUses, RankingComplete: plan.RankingComplete, Files: plan.Coverage.Files, Indexed: plan.Coverage.Indexed, LeftOut: plan.Coverage.LeftOut,
			AnalysisGaps: plan.Coverage.AnalysisGaps, ChangeGaps: plan.Coverage.ChangeGaps, ClosureCut: plan.Coverage.ClosureCut},
		Included: []contextManifestSourceWire{}, Omitted: []contextManifestOmissionWire{}, Changed: []contextManifestDefinitionWire{},
		ChangedNotListed: spec.ChangedNotListed, Dependents: plan.Dependents,
	}
	stageOf := map[string]ContextStage{}
	for _, source := range p.sources {
		stageOf[source.ReferenceID()] = source.Stage()
	}
	included := slices.Clone(spec.Included)
	order := map[string]int{}
	for index, source := range p.sources {
		order[source.ReferenceID()] = index
	}
	slices.SortFunc(included, func(a, b ContextManifestSource) int { return order[a.SourceID] - order[b.SourceID] })
	for _, value := range included {
		wire.Included = append(wire.Included, contextManifestSourceWire{SourceID: value.SourceID, Stage: value.Stage.String(), Rank: value.Rank, Depth: value.Depth})
	}
	counts := map[[2]string]int{}
	for _, value := range spec.Omitted {
		if value.Count > 0 {
			counts[[2]string{value.Stage.String(), value.Reason}] += value.Count
		}
	}
	for key, count := range counts {
		wire.Omitted = append(wire.Omitted, contextManifestOmissionWire{Stage: key[0], Reason: key[1], Count: count})
	}
	slices.SortFunc(wire.Omitted, func(a, b contextManifestOmissionWire) int {
		if a.Stage != b.Stage {
			return int(stageByName(a.Stage)) - int(stageByName(b.Stage))
		}
		return compareStrings(a.Reason, b.Reason)
	})
	for _, value := range spec.Changed {
		wire.Changed = append(wire.Changed, contextManifestDefinitionWire{SourceID: value.SourceID, Line: value.Line, Dependents: value.Dependents, Tests: value.Tests})
	}
	slices.SortFunc(wire.Changed, func(a, b contextManifestDefinitionWire) int {
		if a.SourceID != b.SourceID {
			return order[a.SourceID] - order[b.SourceID]
		}
		return a.Line - b.Line
	})
	wire.Checks = slices.Clone(plan.Checks)
	slices.Sort(wire.Checks)
	wire.Checks = slices.Compact(wire.Checks)
	if wire.Checks == nil {
		wire.Checks = []string{}
	}
	var checks []string
	for _, check := range wire.Checks {
		if slices.Contains(ModelCheckClasses, check) {
			checks = append(checks, check)
		}
	}
	value := p
	value.manifest = ContextManifest{manifest: wire, checks: checks}
	value.identity = deriveContextPacketIdentity(value)
	if err := value.Validate(); err != nil {
		return ContextPacket{}, err
	}
	return value, nil
}

func stageByName(name string) ContextStage {
	for stage := ContextStageChangedHunk; stage <= ContextStageRepositoryContext; stage++ {
		if stage.String() == name {
			return stage
		}
	}
	return 0
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// validContextManifestWire checks a manifest, when there is one, against the
// packet's sources: closed tokens, bounded counts, every index-stage source
// listed once in source order with its own stage, and every changed
// definition placed on a line of a changed_hunk or enclosing_symbol source.
func validContextManifestWire(wire *contextManifestWire, sources []contextSourceWire) bool {
	if wire == nil {
		return true
	}
	if wire.Authority != contextManifestAuthority || wire.Included == nil || wire.Omitted == nil || wire.Changed == nil {
		return false
	}
	switch wire.Budget.Basis {
	case ContextBudgetDefault:
		if wire.Budget.RouteContextTokens != 0 || wire.Budget.OutputTokens != 0 {
			return false
		}
	case ContextBudgetRouteWindow:
		if wire.Budget.RouteContextTokens == 0 {
			return false
		}
	default:
		return false
	}
	index := wire.Index
	switch index.State {
	case ContextIndexUsed, ContextIndexSnapshot:
	case ContextIndexUnavailable, ContextIndexOverBudget, ContextIndexFailed:
		if index.Complete || index.ValueUses || index.Files != 0 || index.Indexed != 0 || len(wire.Included) != 0 || len(wire.Changed) != 0 || wire.Dependents != 0 {
			return false
		}
	default:
		return false
	}
	for _, value := range []int{index.Files, index.Indexed, index.LeftOut, index.AnalysisGaps, index.ChangeGaps, index.ClosureCut, wire.ChangedNotListed, wire.Dependents} {
		if value < 0 || value > maxManifestCount {
			return false
		}
	}
	if wire.Checks == nil || !slices.IsSorted(wire.Checks) || slices.ContainsFunc(wire.Checks, func(c string) bool { return !slices.Contains(RepositoryCheckClasses, c) }) || len(slices.Compact(slices.Clone(wire.Checks))) != len(wire.Checks) {
		return false
	}
	if index.Indexed > index.Files || len(wire.Changed) > maxManifestDefinitions || len(wire.Omitted) > len(contextManifestOmissionReasons)*4 {
		return false
	}
	position := map[string]int{}
	for i, source := range sources {
		position[source.SourceID] = i
	}
	listed := 0
	previous := -1
	for _, value := range wire.Included {
		at, ok := position[value.SourceID]
		if !ok || at <= previous || sources[at].Stage != value.Stage || !indexContextStage(value.Stage) || value.Rank < 1 || value.Rank > maxManifestCount || value.Depth < 0 || value.Depth > 64 {
			return false
		}
		previous = at
		listed++
	}
	indexSources := 0
	for _, source := range sources {
		if indexContextStage(source.Stage) {
			indexSources++
		}
	}
	if listed != indexSources {
		return false
	}
	for i, value := range wire.Omitted {
		if !indexContextStage(value.Stage) || !slices.Contains(contextManifestOmissionReasons, value.Reason) || value.Count < 1 || value.Count > maxManifestCount {
			return false
		}
		if i > 0 {
			last := wire.Omitted[i-1]
			if stage, lastStage := stageByName(value.Stage), stageByName(last.Stage); stage < lastStage || stage == lastStage && value.Reason <= last.Reason {
				return false
			}
		}
	}
	previous, previousLine := -1, 0
	for _, value := range wire.Changed {
		at, ok := position[value.SourceID]
		if !ok || at < previous || at == previous && value.Line < previousLine {
			return false
		}
		source := sources[at]
		if source.Stage != ContextStageChangedHunk.String() && source.Stage != ContextStageEnclosingSymbol.String() || value.Line < source.StartLine || value.Line > source.EndLine ||
			value.Dependents < 0 || value.Dependents > maxManifestCount || value.Tests < 0 || value.Tests > value.Dependents {
			return false
		}
		previous, previousLine = at, value.Line
	}
	return true
}

func validRepositoryChecks(checks []string) bool {
	if checks == nil {
		return true
	}
	if len(checks) == 0 || !slices.IsSorted(checks) {
		return false
	}
	for i, check := range checks {
		if !slices.Contains(ModelCheckClasses, check) || i > 0 && checks[i-1] == check {
			return false
		}
	}
	return true
}

// ContextManifestSummary is the manifest of a recorded context, with each
// listed source's path and lines resolved from the packet.
type ContextManifestSummary struct {
	Present          bool
	Budget           ContextBudget
	State            string
	Complete         bool
	Coverage         ContextIndexCoverage
	Included         []ContextManifestSummarySource
	Omitted          []ContextManifestOmission
	Changed          []ContextManifestSummaryDefinition
	ChangedNotListed int
	Dependents       int
	// Checks are the classes the repository's CI enforces, as information.
	Checks                     []string
	ValueUses, RankingComplete bool
}

// ContextManifestSummarySource is an included index source.
type ContextManifestSummarySource struct {
	SourceID, Path     string
	Stage              ContextStage
	StartLine, EndLine int
	Rank, Depth        int
}

// ContextManifestSummaryDefinition is a changed definition placed on a
// packet source.
type ContextManifestSummaryDefinition struct {
	Path              string
	Line              int
	Dependents, Tests int
}

// ContextManifestOf reads the context manifest of exact recorded generation
// context bytes. A context before version 10 has none.
func ContextManifestOf(payload []byte) (ContextManifestSummary, error) {
	if len(payload) == 0 || len(payload) > maxProviderContextPacketBytes {
		return ContextManifestSummary{}, ErrInvalidContextPacketRequest
	}
	wire, err := decodeGenerationContextWire(payload)
	if err != nil || wire.Contract != "open-trestle/review-context-packet" || !validContextManifestWire(wire.ContextManifest, wire.Sources) || !validRepositoryChecks(wire.RepositoryChecks) {
		return ContextManifestSummary{}, ErrInvalidContextPacketRequest
	}
	manifest := wire.ContextManifest
	if manifest == nil {
		return ContextManifestSummary{}, nil
	}
	summary := ContextManifestSummary{Present: true, State: manifest.Index.State, Complete: manifest.Index.Complete, ChangedNotListed: manifest.ChangedNotListed, Dependents: manifest.Dependents, Checks: slices.Clone(manifest.Checks), ValueUses: manifest.Index.ValueUses, RankingComplete: manifest.Index.RankingComplete,
		Budget:   ContextBudget{Basis: manifest.Budget.Basis, RouteContextTokens: manifest.Budget.RouteContextTokens, OutputTokens: manifest.Budget.OutputTokens, MaxSourceBytes: wire.Limits.MaxSourceBytes},
		Coverage: ContextIndexCoverage{Files: manifest.Index.Files, Indexed: manifest.Index.Indexed, LeftOut: manifest.Index.LeftOut, AnalysisGaps: manifest.Index.AnalysisGaps, ChangeGaps: manifest.Index.ChangeGaps, ClosureCut: manifest.Index.ClosureCut}}
	byID := map[string]contextSourceWire{}
	for _, source := range wire.Sources {
		byID[source.SourceID] = source
	}
	for _, value := range manifest.Included {
		source := byID[value.SourceID]
		summary.Included = append(summary.Included, ContextManifestSummarySource{SourceID: value.SourceID, Path: source.Path, Stage: stageByName(value.Stage), StartLine: source.StartLine, EndLine: source.EndLine, Rank: value.Rank, Depth: value.Depth})
	}
	for _, value := range manifest.Omitted {
		summary.Omitted = append(summary.Omitted, ContextManifestOmission{Stage: stageByName(value.Stage), Reason: value.Reason, Count: value.Count})
	}
	for _, value := range manifest.Changed {
		summary.Changed = append(summary.Changed, ContextManifestSummaryDefinition{Path: byID[value.SourceID].Path, Line: value.Line, Dependents: value.Dependents, Tests: value.Tests})
	}
	return summary, nil
}
