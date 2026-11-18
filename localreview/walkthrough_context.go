package localreview

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/review"
)

// WalkthroughContext is the context a run's generation context carried
// beside the changed code, from its context manifest.
type WalkthroughContext struct {
	// Index is the repository index state: used, unavailable, over_budget
	// or failed, or snapshot for context from the review's own snapshots.
	// Complete is false when the analysis did not cover every file.
	Index    string `json:"index"`
	Complete bool   `json:"complete"`
	// Budget is how the source budget was chosen: route_window or default.
	Budget             string `json:"budget"`
	MaxSourceBytes     uint32 `json:"max_source_bytes"`
	RouteContextTokens uint32 `json:"route_context_tokens,omitempty"`
	// Definitions, Callers, Tests and MapEntries count the included sources
	// of each index stage.
	Definitions int                         `json:"definitions"`
	Callers     int                         `json:"callers"`
	Tests       int                         `json:"tests"`
	MapEntries  int                         `json:"map_entries"`
	Included    []WalkthroughContextSource  `json:"included"`
	Omitted     []WalkthroughContextOmitted `json:"omitted"`
	// Checks are the classes of issue the repository's own checks enforce.
	Checks []string `json:"checks"`
}

// WalkthroughContextSource is one included index source.
type WalkthroughContextSource struct {
	Stage     string `json:"stage"`
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
	Rank      int    `json:"rank"`
	Depth     int    `json:"depth,omitempty"`
}

// WalkthroughContextOmitted counts index context of one stage left out for
// one reason.
type WalkthroughContextOmitted struct {
	Stage  string `json:"stage"`
	Reason string `json:"reason"`
	Count  int    `json:"count"`
}

func contextWalkthrough(m review.ContextManifestSummary) *WalkthroughContext {
	if !m.Present {
		return nil
	}
	w := &WalkthroughContext{Index: m.State, Complete: m.Complete, Budget: m.Budget.Basis, MaxSourceBytes: m.Budget.MaxSourceBytes, RouteContextTokens: m.Budget.RouteContextTokens,
		Included: []WalkthroughContextSource{}, Omitted: []WalkthroughContextOmitted{}, Checks: append([]string{}, m.Checks...)}
	for _, source := range m.Included {
		switch source.Stage {
		case review.ContextStageEnclosingSymbol:
			w.Definitions++
		case review.ContextStageDirectReference:
			w.Callers++
		case review.ContextStageRelatedTest:
			w.Tests++
		case review.ContextStageRepositoryMap:
			w.MapEntries++
		}
		w.Included = append(w.Included, WalkthroughContextSource{Stage: source.Stage.String(), Path: source.Path, StartLine: source.StartLine, EndLine: source.EndLine, Rank: source.Rank, Depth: source.Depth})
	}
	for _, omitted := range m.Omitted {
		w.Omitted = append(w.Omitted, WalkthroughContextOmitted{Stage: omitted.Stage.String(), Reason: omitted.Reason, Count: omitted.Count})
	}
	return w
}

func (w *WalkthroughContext) clone() *WalkthroughContext {
	if w == nil {
		return nil
	}
	value := *w
	value.Included = slices.Clone(w.Included)
	value.Omitted = slices.Clone(w.Omitted)
	value.Checks = slices.Clone(w.Checks)
	return &value
}

func (w *WalkthroughContext) valid() bool {
	if w == nil {
		return true
	}
	if w.Included == nil || w.Omitted == nil || w.Checks == nil || len(w.Included) > 64 || len(w.Omitted) > 64 || len(w.Checks) > len(review.RepositoryCheckClasses) {
		return false
	}
	switch w.Index {
	case review.ContextIndexUsed, review.ContextIndexSnapshot, review.ContextIndexUnavailable, review.ContextIndexOverBudget, review.ContextIndexFailed:
	default:
		return false
	}
	if w.Budget != review.ContextBudgetDefault && w.Budget != review.ContextBudgetRouteWindow {
		return false
	}
	stages := map[string]int{}
	for _, source := range w.Included {
		stages[source.Stage]++
		if source.Path == "" || len(source.Path) > maxWalkthroughPathBytes || !utf8.ValidString(source.Path) || source.StartLine < 1 || source.EndLine < source.StartLine || source.Rank < 1 {
			return false
		}
	}
	if stages["enclosing_symbol"] != w.Definitions || stages["direct_reference"] != w.Callers || stages["related_test"] != w.Tests || stages["repository_map"] != w.MapEntries || w.Definitions+w.Callers+w.Tests+w.MapEntries != len(w.Included) {
		return false
	}
	for _, omitted := range w.Omitted {
		if omitted.Count < 1 || omitted.Stage == "" || omitted.Reason == "" {
			return false
		}
	}
	for _, check := range w.Checks {
		if !slices.Contains(review.RepositoryCheckClasses, check) {
			return false
		}
	}
	return true
}

var contextStageNames = map[string]string{"enclosing_symbol": "definition", "direct_reference": "caller", "related_test": "test", "repository_map": "map entr"}

// contextText words the context the review saw beside the changed code.
func contextText(w *WalkthroughContext) []string {
	if w == nil {
		return nil
	}
	var line string
	switch w.Index {
	case review.ContextIndexUsed, review.ContextIndexSnapshot:
		line = fmt.Sprintf("context used: %d enclosing definition%s, %d caller%s, %d test%s, %d map entr%s", w.Definitions, plural(w.Definitions), w.Callers, plural(w.Callers), w.Tests, plural(w.Tests), w.MapEntries, map[bool]string{true: "y", false: "ies"}[w.MapEntries == 1])
		if w.Index == review.ContextIndexSnapshot {
			line += " (from the review's own snapshots, Go only; the repository index was not used)"
		}
		if !w.Complete {
			line += " (the analysis does not cover every file)"
		}
	case review.ContextIndexOverBudget:
		line = "context used: changed code only (the repository index was not ready within its time budget)"
	case review.ContextIndexFailed:
		line = "context used: changed code only (the repository index could not be read)"
	default:
		line = "context used: changed code only (no repository index)"
	}
	if len(w.Omitted) > 0 {
		parts := []string{}
		for _, omitted := range w.Omitted {
			noun := contextStageNames[omitted.Stage]
			if noun == "map entr" {
				noun += map[bool]string{true: "y", false: "ies"}[omitted.Count == 1]
			} else {
				noun += plural(omitted.Count)
			}
			parts = append(parts, fmt.Sprintf("%d %s (%s)", omitted.Count, noun, strings.ReplaceAll(omitted.Reason, "_", " ")))
		}
		line += "; left out: " + strings.Join(parts, ", ")
	}
	lines := []string{line + fmt.Sprintf("; budget %d KiB (%s)", w.MaxSourceBytes>>10, strings.ReplaceAll(w.Budget, "_", " "))}
	if len(w.Checks) > 0 {
		lines = append(lines, "checks the repository's CI enforces: "+strings.Join(w.Checks, ", "))
	}
	return lines
}
