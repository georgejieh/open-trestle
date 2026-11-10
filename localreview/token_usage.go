package localreview

import (
	"fmt"
	"slices"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// tokenUsageResultVersion is the result schema version that reports
// token_usage. It keeps every field of versions 1 to 5.
const tokenUsageResultVersion = 6

// TokenCount is provider-reported token use summed over route attempts.
// Known means every summed attempt reported usage; only then are the counts
// present, so an unknown count is never reported as zero. InputTokens includes
// CachedInputTokens, as providers report them. Counts carry no content.
type TokenCount struct {
	Known             bool    `json:"known"`
	RouteAttempts     uint32  `json:"route_attempts"`
	InputTokens       *uint64 `json:"input_tokens,omitempty"`
	OutputTokens      *uint64 `json:"output_tokens,omitempty"`
	CachedInputTokens *uint64 `json:"cached_input_tokens,omitempty"`
}

// TokenUsage is the token_usage of a schema version 6 result: the total over
// every route attempt the run claimed, and the generation and verification
// shares of it. A stage is unknown when an attempt of no known stage exists,
// because that attempt may belong to it.
type TokenUsage struct {
	TokenCount
	Generation   TokenCount `json:"generation"`
	Verification TokenCount `json:"verification"`
}

func (c TokenCount) clone() TokenCount {
	copied := TokenCount{Known: c.Known, RouteAttempts: c.RouteAttempts}
	for _, field := range []struct{ from, to **uint64 }{{&c.InputTokens, &copied.InputTokens}, {&c.OutputTokens, &copied.OutputTokens}, {&c.CachedInputTokens, &copied.CachedInputTokens}} {
		if *field.from != nil {
			value := **field.from
			*field.to = &value
		}
	}
	return copied
}

func (u TokenUsage) clone() TokenUsage {
	return TokenUsage{TokenCount: u.TokenCount.clone(), Generation: u.Generation.clone(), Verification: u.Verification.clone()}
}

// validate checks that one count has its numbers exactly when known.
func (c TokenCount) validate() bool {
	present := c.InputTokens != nil && c.OutputTokens != nil && c.CachedInputTokens != nil
	absent := c.InputTokens == nil && c.OutputTokens == nil && c.CachedInputTokens == nil
	return c.Known && present || !c.Known && absent
}

// line is the text form of the total.
func (c TokenCount) line() string {
	attempts := fmt.Sprintf("%d route attempts", c.RouteAttempts)
	if c.RouteAttempts == 1 {
		attempts = "1 route attempt"
	}
	if !c.Known {
		return fmt.Sprintf("tokens: unknown over %s (not every attempt reported usage)\n", attempts)
	}
	return fmt.Sprintf("tokens: input=%d output=%d cached_input=%d over %s\n", *c.InputTokens, *c.OutputTokens, *c.CachedInputTokens, attempts)
}

type tokenStage uint8

const (
	tokenStageUnattributed tokenStage = iota
	tokenStageGeneration
	tokenStageVerification
)

// recordedTokenUsage is the usage of a route attempt whose execution the run
// recorded, with the stage it served.
type recordedTokenUsage struct {
	usage provider.RouteTokenUsage
	stage tokenStage
}

type tokenTally struct {
	attempts              uint32
	unknown               bool
	input, output, cached uint64
}

func (t *tokenTally) add(usage provider.RouteTokenUsage, reported bool) {
	t.attempts++
	if !reported || !usage.IsKnown() {
		t.unknown = true
		return
	}
	t.input += uint64(usage.InputTokens())
	t.output += uint64(usage.OutputTokens())
	t.cached += uint64(usage.CachedInputTokens())
}

func (t tokenTally) count() TokenCount {
	count := TokenCount{Known: !t.unknown, RouteAttempts: t.attempts}
	if count.Known {
		input, output, cached := t.input, t.output, t.cached
		count.InputTokens, count.OutputTokens, count.CachedInputTokens = &input, &output, &cached
	}
	return count
}

// accountTokenUsage sums provider-reported usage over the route attempts a run
// claimed, each counted once. An attempt the run recorded uses its recorded
// outcome; any other claimed attempt uses the adapter result observed for it,
// or is unknown when none was observed, and serves the stage stageOf names. A
// recorded attempt without a claim is still counted. Callers bound claims, so
// the sums cannot overflow.
func accountTokenUsage(claims []string, recorded map[string]recordedTokenUsage, stageOf func(string) tokenStage, observed func(string) (provider.RouteTokenUsage, bool)) TokenUsage {
	var total, generation, verification tokenTally
	unattributed := false
	add := func(stage tokenStage, usage provider.RouteTokenUsage, reported bool) {
		total.add(usage, reported)
		switch stage {
		case tokenStageGeneration:
			generation.add(usage, reported)
		case tokenStageVerification:
			verification.add(usage, reported)
		default:
			unattributed = true
		}
	}
	seen := make(map[string]bool, len(claims)+len(recorded))
	for _, authorization := range claims {
		if seen[authorization] {
			continue
		}
		seen[authorization] = true
		if record, ok := recorded[authorization]; ok {
			add(record.stage, record.usage, true)
			continue
		}
		usage, ok := observed(authorization)
		add(stageOf(authorization), usage, ok)
	}
	unclaimed := make([]string, 0, len(recorded))
	for authorization := range recorded {
		if !seen[authorization] {
			unclaimed = append(unclaimed, authorization)
		}
	}
	slices.Sort(unclaimed)
	for _, authorization := range unclaimed {
		add(recorded[authorization].stage, recorded[authorization].usage, true)
	}
	if unattributed {
		generation.unknown, verification.unknown = true, true
	}
	return TokenUsage{TokenCount: total.count(), Generation: generation.count(), Verification: verification.count()}
}

// validCompletedTokenUsage checks the token usage of a completed direct
// review: one generation and one verification attempt, each a usage report a
// provider adapter could return, whose counts sum to the total, known exactly
// when the result's cost usage is known.
func validCompletedTokenUsage(usage TokenUsage, usageKnown bool) bool {
	if usage.RouteAttempts != 2 || usage.Known != usageKnown || !usage.TokenCount.validate() {
		return false
	}
	known := true
	var input, output, cached uint64
	for _, stage := range []TokenCount{usage.Generation, usage.Verification} {
		if stage.RouteAttempts != 1 || !stage.validate() {
			return false
		}
		known = known && stage.Known
		if stage.Known {
			if _, err := provider.NewRouteTokenUsage(*stage.InputTokens, *stage.OutputTokens, *stage.CachedInputTokens); err != nil {
				return false
			}
			input, output, cached = input+*stage.InputTokens, output+*stage.OutputTokens, cached+*stage.CachedInputTokens
		}
	}
	return usage.Known == known && (!known || *usage.InputTokens == input && *usage.OutputTokens == output && *usage.CachedInputTokens == cached)
}
