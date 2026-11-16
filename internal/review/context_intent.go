package review

import (
	"errors"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/patternhygiene"
)

// Stated intent and pattern hygiene are two optional objects of a version 9
// generation context. Both are data, never instructions: the stated intent is
// the change author's own commit text, and pattern hygiene is deterministic
// host evidence that names packet sources by ID and carries no repository
// text.

const (
	maxStatedIntentCommits     = 16
	maxStatedIntentCommitBytes = 2 << 10
	maxStatedIntentTotalBytes  = 16 << 10
	maxStatedIntentMessage     = 64 << 20
	maxStatedIntentOmitted     = 1 << 16

	statedIntentSourceCommits = "commit_messages"
	statedIntentAuthority     = "author_stated_unverified"

	maxPatternHygieneItems   = 16
	maxPatternHygieneCount   = 1 << 20
	patternHygieneAuthority  = "deterministic_host_observation"
	maxStatedIntentSubjectBy = 200
)

// ErrInvalidStatedIntent identifies malformed commit intent input.
var ErrInvalidStatedIntent = errors.New("invalid stated intent")

// IntentCommit is one commit of the reviewed range as the host read it: its
// full object ID, a prefix of its exact message bytes, and the message size.
type IntentCommit struct {
	CommitID     string
	Message      []byte
	MessageBytes int
}

type statedIntentCommit struct {
	commitID     string
	text         string
	messageBytes int
	unsupported  bool
	risks        ContextRisk
}

// StatedIntent is the bounded, author-stated intent of one change: its commit
// messages, oldest first. Each message keeps at most 2 KiB and the total at
// most 16 KiB; at most 16 commits are listed. Nothing is dropped silently: a
// cut message is marked truncated with its full size, commits past a bound are
// counted, and a range the host could not read completely is marked.
type StatedIntent struct {
	commits    []statedIntentCommit
	omitted    int
	incomplete bool
}

// NewStatedIntent bounds commit messages, oldest first, into a stated intent.
// A message that is not UTF-8 text keeps no text and is marked unsupported.
func NewStatedIntent(commits []IntentCommit, rangeIncomplete bool) (StatedIntent, error) {
	value := StatedIntent{incomplete: rangeIncomplete}
	total := 0
	for _, commit := range commits {
		if !validIntentCommitID(commit.CommitID) || commit.MessageBytes < len(commit.Message) || commit.MessageBytes > maxStatedIntentMessage {
			return StatedIntent{}, ErrInvalidStatedIntent
		}
		if len(value.commits) >= maxStatedIntentCommits || total >= maxStatedIntentTotalBytes {
			value.omitted++
			continue
		}
		text, ok := intentText(commit.Message, min(maxStatedIntentCommitBytes, maxStatedIntentTotalBytes-total))
		entry := statedIntentCommit{commitID: commit.CommitID, messageBytes: commit.MessageBytes, unsupported: !ok}
		if ok {
			entry.text = text
			entry.risks = detectSourceRisks("", text)
			total += len(text)
		}
		value.commits = append(value.commits, entry)
	}
	if value.omitted > maxStatedIntentOmitted {
		return StatedIntent{}, ErrInvalidStatedIntent
	}
	return value, nil
}

// intentText returns the longest valid UTF-8 prefix of message within limit
// bytes, or false when the message is not text (invalid UTF-8 before the cut,
// or a NUL byte).
func intentText(message []byte, limit int) (string, bool) {
	cut := message[:min(len(message), limit)]
	for trimmed := 0; trimmed < utf8.UTFMax && len(cut) > 0 && !utf8.Valid(cut); trimmed++ {
		cut = cut[:len(cut)-1]
	}
	if !utf8.Valid(cut) || strings.IndexByte(string(cut), 0) >= 0 {
		return "", false
	}
	return string(cut), true
}

func validIntentCommitID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if !(value[index] >= '0' && value[index] <= '9' || value[index] >= 'a' && value[index] <= 'f') {
			return false
		}
	}
	return true
}

// IsZero reports an intent with nothing to carry.
func (s StatedIntent) IsZero() bool { return len(s.commits) == 0 && s.omitted == 0 }

// TextBytes is the commit text the intent carries; it counts toward the
// packet's source byte budget.
func (s StatedIntent) TextBytes() int {
	total := 0
	for _, commit := range s.commits {
		total += len(commit.text)
	}
	return total
}

// Fit returns a copy whose text fits within limit bytes: commits are kept in
// order while they fit, the first that does not is cut and marked truncated,
// and the rest are counted as omitted.
func (s StatedIntent) Fit(limit int) StatedIntent {
	value := StatedIntent{omitted: s.omitted, incomplete: s.incomplete}
	remaining := max(limit, 0)
	for index, commit := range s.commits {
		if len(commit.text) > remaining {
			if remaining == 0 {
				value.omitted += len(s.commits) - index
				break
			}
			commit.text, _ = intentText([]byte(commit.text), remaining)
			commit.risks = detectSourceRisks("", commit.text)
		}
		remaining -= len(commit.text)
		value.commits = append(value.commits, commit)
	}
	return value
}

func (s StatedIntent) wire() *statedIntentWire {
	if s.IsZero() {
		return nil
	}
	wire := &statedIntentWire{Source: statedIntentSourceCommits, Authority: statedIntentAuthority, Commits: make([]statedIntentCommitWire, len(s.commits)), CommitsOmitted: s.omitted, RangeIncomplete: s.incomplete}
	for index, commit := range s.commits {
		wire.Commits[index] = statedIntentCommitWire{
			CommitID: commit.commitID, Text: commit.text, MessageBytes: commit.messageBytes,
			Truncated: !commit.unsupported && len(commit.text) < commit.messageBytes, UnsupportedContent: commit.unsupported,
			RiskFlags: contextRiskTokens(commit.risks),
		}
	}
	return wire
}

type statedIntentWire struct {
	Source          string                   `json:"source"`
	Authority       string                   `json:"authority"`
	Commits         []statedIntentCommitWire `json:"commits"`
	CommitsOmitted  int                      `json:"commits_omitted,omitempty"`
	RangeIncomplete bool                     `json:"range_incomplete,omitempty"`
}

type statedIntentCommitWire struct {
	CommitID           string   `json:"commit_id"`
	Text               string   `json:"text"`
	MessageBytes       int      `json:"message_bytes"`
	Truncated          bool     `json:"truncated,omitempty"`
	UnsupportedContent bool     `json:"unsupported_content,omitempty"`
	RiskFlags          []string `json:"risk_flags"`
}

// validStatedIntentWire checks a recorded stated intent: its constants,
// bounds, truncation markers and risk flags re-derived from the text.
func validStatedIntentWire(wire *statedIntentWire) bool {
	if wire == nil {
		return true
	}
	if wire.Source != statedIntentSourceCommits || wire.Authority != statedIntentAuthority || len(wire.Commits) > maxStatedIntentCommits ||
		wire.CommitsOmitted < 0 || wire.CommitsOmitted > maxStatedIntentOmitted || len(wire.Commits) == 0 && wire.CommitsOmitted == 0 {
		return false
	}
	total := 0
	for _, commit := range wire.Commits {
		if !validIntentCommitID(commit.CommitID) || len(commit.Text) > maxStatedIntentCommitBytes || !utf8.ValidString(commit.Text) || strings.IndexByte(commit.Text, 0) >= 0 ||
			commit.MessageBytes < len(commit.Text) || commit.MessageBytes > maxStatedIntentMessage ||
			commit.UnsupportedContent && (commit.Text != "" || commit.Truncated) ||
			!commit.UnsupportedContent && commit.Truncated != (len(commit.Text) < commit.MessageBytes) ||
			!slices.Equal(commit.RiskFlags, contextRiskTokens(detectSourceRisks("", commit.Text))) {
			return false
		}
		total += len(commit.Text)
	}
	return total <= maxStatedIntentTotalBytes
}

func statedIntentWireBytes(wire *statedIntentWire) int {
	if wire == nil {
		return 0
	}
	total := 0
	for _, commit := range wire.Commits {
		total += len(commit.Text)
	}
	return total
}

// ContextPatternHygiene is the pattern-hygiene evidence of a generation
// context: complete counts, and up to 16 items placed on the packet's
// changed_hunk sources by source ID and head line. An item whose line is not
// in a selected changed source is counted in ItemsNotListed instead.
type ContextPatternHygiene struct {
	counts         patternhygiene.Counts
	unread         int
	items          []patternHygieneItemWire
	itemsNotListed int
	present        bool
}

// NewContextPatternHygiene places a report on packet sources. Root-cause notes
// come first, then anti-pattern increases, then the other observations.
func NewContextPatternHygiene(report patternhygiene.Report, sources []ContextSource) ContextPatternHygiene {
	value := ContextPatternHygiene{counts: report.Counts, unread: report.UnreadDirectories, present: true}
	place := func(item patternHygieneItemWire, path string) {
		for _, source := range sources {
			rangeValue := source.EvidenceItem().SourceRange()
			if source.Stage() != ContextStageChangedHunk || rangeValue.Path() != path || item.Line < rangeValue.StartLine() || item.Line > rangeValue.EndLine() {
				continue
			}
			if len(value.items) >= maxPatternHygieneItems {
				break
			}
			item.SourceID = source.ReferenceID()
			value.items = append(value.items, item)
			return
		}
		value.itemsNotListed++
	}
	for _, note := range report.Notes {
		place(patternHygieneItemWire{Kind: string(note.Kind), Line: note.Line}, note.Path)
	}
	for _, increase := range report.Increases {
		if len(increase.Added) == 0 {
			value.itemsNotListed++
			continue
		}
		place(patternHygieneItemWire{Kind: string(patternhygiene.KindAntiPattern), Rule: increase.Rule, Line: increase.Added[0].Line, BaseCount: increase.Base, HeadCount: increase.Head}, increase.Added[0].Path)
	}
	for _, observation := range report.Observations {
		place(patternHygieneItemWire{Kind: string(observation.Kind), Rule: observation.Rule, Line: observation.Line}, observation.Path)
	}
	// Anything the bounded report lists past its own bounds is counted too.
	listed := len(report.Notes) + len(report.Increases) + len(report.Observations)
	value.itemsNotListed += max(0, report.Counts.RootCauseNotes+report.Counts.IncreasedAntiPatterns+report.Counts.Suppressions+report.Counts.WorkaroundComments+report.Counts.UnreferencedTODOs+report.Counts.AbsoluteDirectives-listed)
	return value
}

// IsZero reports that no pattern-hygiene stage ran for the packet.
func (h ContextPatternHygiene) IsZero() bool { return !h.present }

func (h ContextPatternHygiene) wire() *patternHygieneWire {
	if !h.present {
		return nil
	}
	// A clean change still records that the stage ran, with an empty list.
	items := make([]patternHygieneItemWire, len(h.items))
	copy(items, h.items)
	return &patternHygieneWire{
		Authority: patternHygieneAuthority,
		Counts: patternHygieneCountsWire{
			AntiPatternsIncreased: h.counts.IncreasedAntiPatterns, AntiPatternsSpreading: h.counts.SpreadingAntiPatterns,
			Suppressions: h.counts.Suppressions, WorkaroundComments: h.counts.WorkaroundComments, UnreferencedTODOs: h.counts.UnreferencedTODOs,
			AbsoluteDirectives: h.counts.AbsoluteDirectives, RootCauseNotes: h.counts.RootCauseNotes, UnreadDirectories: h.unread,
		},
		Items: items, ItemsNotListed: h.itemsNotListed,
	}
}

type patternHygieneWire struct {
	Authority      string                   `json:"authority"`
	Counts         patternHygieneCountsWire `json:"counts"`
	Items          []patternHygieneItemWire `json:"items"`
	ItemsNotListed int                      `json:"items_not_listed,omitempty"`
}

type patternHygieneCountsWire struct {
	AntiPatternsIncreased int `json:"anti_patterns_increased"`
	AntiPatternsSpreading int `json:"anti_patterns_spreading"`
	Suppressions          int `json:"suppressions"`
	WorkaroundComments    int `json:"workaround_comments"`
	UnreferencedTODOs     int `json:"unreferenced_todos"`
	AbsoluteDirectives    int `json:"absolute_directives"`
	RootCauseNotes        int `json:"root_cause_notes"`
	UnreadDirectories     int `json:"unread_directories"`
}

// patternHygieneItemWire carries no repository text: a kind, a curated rule
// ID, a host-issued source ID, a line number and, for an anti-pattern, the
// base and head counts in the file's directory.
type patternHygieneItemWire struct {
	Kind      string `json:"kind"`
	Rule      string `json:"rule,omitempty"`
	SourceID  string `json:"source_id"`
	Line      int    `json:"line"`
	BaseCount int    `json:"base_count,omitempty"`
	HeadCount int    `json:"head_count,omitempty"`
}

// validPatternHygieneWire checks a recorded pattern-hygiene object against the
// packet's sources: closed kinds and rule IDs, counts that cover the listed
// items, and every item on a line of a changed_hunk source.
func validPatternHygieneWire(wire *patternHygieneWire, sources []contextSourceWire) bool {
	if wire == nil {
		return true
	}
	counts := wire.Counts
	for _, value := range []int{counts.AntiPatternsIncreased, counts.AntiPatternsSpreading, counts.Suppressions, counts.WorkaroundComments, counts.UnreferencedTODOs, counts.AbsoluteDirectives, counts.RootCauseNotes, counts.UnreadDirectories, wire.ItemsNotListed} {
		if value < 0 || value > maxPatternHygieneCount {
			return false
		}
	}
	if wire.Authority != patternHygieneAuthority || wire.Items == nil || len(wire.Items) > maxPatternHygieneItems || counts.AntiPatternsSpreading > counts.AntiPatternsIncreased || counts.RootCauseNotes > counts.Suppressions {
		return false
	}
	listed := map[string]int{}
	for _, item := range wire.Items {
		placed := false
		for _, source := range sources {
			if source.SourceID == item.SourceID && source.Stage == ContextStageChangedHunk.String() && item.Line >= source.StartLine && item.Line <= source.EndLine {
				placed = true
				break
			}
		}
		if !placed {
			return false
		}
		switch patternhygiene.Kind(item.Kind) {
		case patternhygiene.KindAntiPattern:
			if _, ok := patternhygiene.RuleByID(item.Rule); !ok || item.BaseCount < 0 || item.HeadCount <= item.BaseCount || item.HeadCount > maxPatternHygieneCount {
				return false
			}
		case patternhygiene.KindSuppression:
			if !slices.Contains(patternhygiene.SuppressionRules, item.Rule) || item.BaseCount != 0 || item.HeadCount != 0 {
				return false
			}
		case patternhygiene.KindWorkaroundComment, patternhygiene.KindUnreferencedTODO, patternhygiene.KindAbsoluteDirective, patternhygiene.KindRootCauseNotFixed:
			if item.Rule != "" || item.BaseCount != 0 || item.HeadCount != 0 {
				return false
			}
		default:
			return false
		}
		listed[item.Kind]++
	}
	return listed[string(patternhygiene.KindAntiPattern)] <= counts.AntiPatternsIncreased && listed[string(patternhygiene.KindSuppression)] <= counts.Suppressions &&
		listed[string(patternhygiene.KindWorkaroundComment)] <= counts.WorkaroundComments && listed[string(patternhygiene.KindUnreferencedTODO)] <= counts.UnreferencedTODOs &&
		listed[string(patternhygiene.KindAbsoluteDirective)] <= counts.AbsoluteDirectives && listed[string(patternhygiene.KindRootCauseNotFixed)] <= counts.RootCauseNotes
}

// StatedIntentSummary is what a result shows of a recorded stated intent:
// commit subjects (first lines, at most 200 bytes each), never bodies.
type StatedIntentSummary struct {
	Present         bool
	Subjects        []string
	Commits         int
	CommitsOmitted  int
	Truncated       int
	Unsupported     int
	InstructionLike int
	RangeIncomplete bool
}

// ContextStatedIntent reads the stated intent of exact recorded generation
// context bytes. A context before version 9, or one without commits, has none.
func ContextStatedIntent(payload []byte) (StatedIntentSummary, error) {
	if len(payload) == 0 || len(payload) > maxProviderContextPacketBytes {
		return StatedIntentSummary{}, ErrInvalidContextPacketRequest
	}
	wire, err := decodeGenerationContextWire(payload)
	if err != nil || wire.Contract != "open-trestle/review-context-packet" || !validStatedIntentWire(wire.StatedIntent) {
		return StatedIntentSummary{}, ErrInvalidContextPacketRequest
	}
	if wire.StatedIntent == nil {
		return StatedIntentSummary{}, nil
	}
	summary := StatedIntentSummary{Present: true, Commits: len(wire.StatedIntent.Commits), CommitsOmitted: wire.StatedIntent.CommitsOmitted, RangeIncomplete: wire.StatedIntent.RangeIncomplete}
	for _, commit := range wire.StatedIntent.Commits {
		if commit.Truncated {
			summary.Truncated++
		}
		if commit.UnsupportedContent {
			summary.Unsupported++
			continue
		}
		if slices.Contains(commit.RiskFlags, contextRiskTokenInstructionLike) {
			summary.InstructionLike++
		}
		subject, _, _ := strings.Cut(commit.Text, "\n")
		subject = strings.TrimSpace(subject)
		if len(subject) > maxStatedIntentSubjectBy {
			subject, _ = intentText([]byte(subject), maxStatedIntentSubjectBy)
		}
		summary.Subjects = append(summary.Subjects, subject)
	}
	return summary, nil
}

// PatternHygieneItem is one listed pattern-hygiene item with its source path.
type PatternHygieneItem struct {
	Kind      string
	Rule      string
	Path      string
	Line      int
	BaseCount int
	HeadCount int
}

// PatternHygieneSummary is the pattern-hygiene evidence of a recorded context.
type PatternHygieneSummary struct {
	Present        bool
	Counts         patternhygiene.Counts
	Unread         int
	Items          []PatternHygieneItem
	ItemsNotListed int
}

// ContextPatternHygieneSummary reads the pattern-hygiene object of exact
// recorded generation context bytes. A context before version 9 has none.
func ContextPatternHygieneSummary(payload []byte) (PatternHygieneSummary, error) {
	if len(payload) == 0 || len(payload) > maxProviderContextPacketBytes {
		return PatternHygieneSummary{}, ErrInvalidContextPacketRequest
	}
	wire, err := decodeGenerationContextWire(payload)
	if err != nil || wire.Contract != "open-trestle/review-context-packet" || !validPatternHygieneWire(wire.PatternHygiene, wire.Sources) {
		return PatternHygieneSummary{}, ErrInvalidContextPacketRequest
	}
	if wire.PatternHygiene == nil {
		return PatternHygieneSummary{}, nil
	}
	counts := wire.PatternHygiene.Counts
	summary := PatternHygieneSummary{Present: true, Unread: counts.UnreadDirectories, ItemsNotListed: wire.PatternHygiene.ItemsNotListed, Counts: patternhygiene.Counts{
		IncreasedAntiPatterns: counts.AntiPatternsIncreased, SpreadingAntiPatterns: counts.AntiPatternsSpreading, Suppressions: counts.Suppressions,
		WorkaroundComments: counts.WorkaroundComments, UnreferencedTODOs: counts.UnreferencedTODOs, AbsoluteDirectives: counts.AbsoluteDirectives, RootCauseNotes: counts.RootCauseNotes,
	}}
	paths := map[string]string{}
	for _, source := range wire.Sources {
		paths[source.SourceID] = source.Path
	}
	for _, item := range wire.PatternHygiene.Items {
		summary.Items = append(summary.Items, PatternHygieneItem{Kind: item.Kind, Rule: item.Rule, Path: paths[item.SourceID], Line: item.Line, BaseCount: item.BaseCount, HeadCount: item.HeadCount})
	}
	return summary, nil
}
