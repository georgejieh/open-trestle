package localreview

import (
	"sort"
	"strings"
	"unicode"

	"github.com/georgejieh/open-trestle/diagnostics"
)

// Finding deduplication and ranking: the deterministic judgement that runs
// after independent verification. No model decides which findings survive.
//
// DeduplicateFindings is the one merge rule for every place several verified
// findings can describe the same defect: the findings of one review run
// (including an investigation run), the members of a specialist review set,
// and repeated runs of the same change. RankFindings orders the result.

// FindingOrigin is one source of verified findings to merge: a review set
// member, one run of a repeated review, or a single review's own run.
type FindingOrigin struct {
	// Label names the origin in contributor lists, such as "general" or a
	// specialist profile ID.
	Label string
	// Independence is the origin's recorded verification independence level
	// (distinct_route, distinct_model or distinct_provider), or empty.
	Independence string
	Findings     []ReportFinding
}

// FindingContributor is one verified finding that a merged finding represents.
type FindingContributor struct {
	Origin      string
	Identity    string
	Severity    diagnostics.Severity
	StartLine   uint32
	EndLine     uint32
	Side        diagnostics.LineSide
	PreExisting bool
}

// MergedFinding is one distinct defect after deduplication.
type MergedFinding struct {
	// Finding is the representative: the contributor with the strongest
	// verified evidence (see strongerFinding). Its own title, claim, severity
	// and location are reported.
	Finding ReportFinding
	// Contributors lists every merged verified finding, the representative
	// included, in origin order and then in finding order.
	Contributors []FindingContributor
	// Origins counts the distinct origins whose verifier confirmed the defect.
	Origins int
	// Independence is the strongest verification independence among them.
	Independence string
	// Rank is the 1-based position RankFindings assigned; 0 before ranking.
	Rank int

	origin int
	tokens defectStatement
	labels map[string]bool
}

// MergedIdentities returns the identities of the findings merged into the
// representative, in contributor order.
func (m MergedFinding) MergedIdentities() []string {
	out := []string{}
	for _, contributor := range m.Contributors {
		if contributor.Identity != m.Finding.Identity {
			out = append(out, contributor.Identity)
		}
	}
	return out
}

// OriginLabels returns each contributing origin once, in contributor order.
func (m MergedFinding) OriginLabels() []string {
	out := []string{}
	seen := map[string]bool{}
	for _, contributor := range m.Contributors {
		if !seen[contributor.Origin] {
			seen[contributor.Origin] = true
			out = append(out, contributor.Origin)
		}
	}
	return out
}

// PreExisting reports a defect every contributor located only on unchanged
// lines that the change did not touch. One contributor on a changed line makes
// the defect part of the change.
func (m MergedFinding) PreExisting() bool {
	for _, contributor := range m.Contributors {
		if !contributor.PreExisting {
			return false
		}
	}
	return len(m.Contributors) > 0
}

// ShownByDefault reports a confirmed high, critical or medium finding: text
// and Markdown output list these and count the rest unless --all is given.
func (m MergedFinding) ShownByDefault() bool {
	return severityRank(m.Finding.Severity) >= severityRank(diagnostics.SeverityWarning)
}

// MergedDuplicates counts the findings merged into another finding.
func MergedDuplicates(findings []MergedFinding) int {
	duplicates := 0
	for _, finding := range findings {
		duplicates += len(finding.Contributors) - 1
	}
	return duplicates
}

// DeduplicateFindings merges verified findings that describe the same defect.
// Two findings are duplicates when all of these hold:
//
//   - they have the same path and side (base and head line numbers are
//     different coordinates and never merge);
//   - the finding's line range overlaps the group representative's range;
//   - their categories are the same or compatible (see compatibleCategories);
//   - their defect statements (title and claim) are near-identical once
//     normalized: at least four fifths of their combined distinctive words are
//     shared (see defectStatementTokens).
//
// Only the representative's own range and statement decide a match, so a
// finding never joins a group through a finding the group already absorbed.
// The representative is the strongest verified finding of the group; when a
// stronger finding joins, it becomes the representative and the comparison
// basis. Findings of one origin can merge too: one run may report a defect
// twice, and two distinct defects in one hunk are not near-identical.
//
// Matching is deterministic: origins in the given order, each origin's
// findings sorted by path, side, range and identity, each finding joining the
// first matching group. Groups are returned in creation order; RankFindings
// orders them.
func DeduplicateFindings(origins []FindingOrigin) []MergedFinding {
	var groups []*MergedFinding
	for index, origin := range origins {
		ordered := append([]ReportFinding(nil), origin.Findings...)
		sort.SliceStable(ordered, func(i, j int) bool { return locationLess(ordered[i], ordered[j]) })
		for _, finding := range ordered {
			tokens := defectStatementTokens(finding.Title, finding.Claim)
			contributor := FindingContributor{Origin: origin.Label, Identity: finding.Identity, Severity: finding.Severity, StartLine: finding.StartLine, EndLine: finding.EndLine, Side: finding.Side, PreExisting: finding.PreExisting}
			var group *MergedFinding
			for _, candidate := range groups {
				representative := candidate.Finding
				if representative.Path == finding.Path && representative.Side == finding.Side &&
					finding.StartLine <= representative.EndLine && representative.StartLine <= finding.EndLine &&
					compatibleCategories(representative.Category, finding.Category) && nearIdentical(candidate.tokens, tokens) {
					group = candidate
					break
				}
			}
			if group == nil {
				groups = append(groups, &MergedFinding{Finding: finding, Contributors: []FindingContributor{contributor}, Origins: 1, Independence: origin.Independence, origin: index, tokens: tokens, labels: map[string]bool{origin.Label: true}})
				continue
			}
			group.Contributors = append(group.Contributors, contributor)
			if !group.labels[origin.Label] {
				group.labels[origin.Label] = true
				group.Origins++
			}
			if independenceRank(origin.Independence) > independenceRank(group.Independence) {
				group.Independence = origin.Independence
			}
			if strongerFinding(finding, index, group.Finding, group.origin) {
				group.Finding, group.origin, group.tokens = finding, index, tokens
			}
		}
	}
	out := make([]MergedFinding, 0, len(groups))
	for _, group := range groups {
		out = append(out, *group)
	}
	return out
}

// RankFindings orders merged findings and numbers them from 1:
//
//  1. final severity (the representative's verified severity);
//  2. verification confidence: the number of distinct origins whose verifier
//     confirmed the defect, then the strongest verification independence;
//  3. evidence strength: the representative's distinct evidence items, then a
//     narrower range;
//  4. location (path, head before base, lines), category and identity, so
//     equal findings keep one order.
func RankFindings(findings []MergedFinding) []MergedFinding {
	out := append([]MergedFinding(nil), findings...)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if x, y := severityRank(a.Finding.Severity), severityRank(b.Finding.Severity); x != y {
			return x > y
		}
		if a.Origins != b.Origins {
			return a.Origins > b.Origins
		}
		if x, y := independenceRank(a.Independence), independenceRank(b.Independence); x != y {
			return x > y
		}
		if x, y := distinctEvidence(a.Finding), distinctEvidence(b.Finding); x != y {
			return x > y
		}
		if x, y := lineSpan(a.Finding), lineSpan(b.Finding); x != y {
			return x < y
		}
		if locationLess(a.Finding, b.Finding) || locationLess(b.Finding, a.Finding) {
			return locationLess(a.Finding, b.Finding)
		}
		if a.Finding.Category != b.Finding.Category {
			return a.Finding.Category < b.Finding.Category
		}
		return a.Finding.Identity < b.Finding.Identity
	})
	for index := range out {
		out[index].Rank = index + 1
	}
	return out
}

// strongerFinding reports whether a (from origin ai) has stronger verified
// evidence than b (from origin bi): the more severe verified finding; then the
// one citing more distinct evidence; then one located on changed lines over a
// pre-existing one; then the narrower range; then the earlier origin and
// location. Equal findings keep the earlier one.
func strongerFinding(a ReportFinding, ai int, b ReportFinding, bi int) bool {
	if x, y := severityRank(a.Severity), severityRank(b.Severity); x != y {
		return x > y
	}
	if x, y := distinctEvidence(a), distinctEvidence(b); x != y {
		return x > y
	}
	if a.PreExisting != b.PreExisting {
		return !a.PreExisting
	}
	if x, y := lineSpan(a), lineSpan(b); x != y {
		return x < y
	}
	if ai != bi {
		return ai < bi
	}
	return locationLess(a, b)
}

func locationLess(a, b ReportFinding) bool {
	switch {
	case a.Path != b.Path:
		return a.Path < b.Path
	case a.Side != b.Side:
		return a.Side < b.Side
	case a.StartLine != b.StartLine:
		return a.StartLine < b.StartLine
	case a.EndLine != b.EndLine:
		return a.EndLine < b.EndLine
	}
	return a.Identity < b.Identity
}

func lineSpan(finding ReportFinding) uint32 {
	if finding.EndLine < finding.StartLine {
		return 0
	}
	return finding.EndLine - finding.StartLine
}

func distinctEvidence(finding ReportFinding) int {
	seen := map[string]bool{}
	for _, id := range finding.EvidenceIDs {
		seen[id] = true
	}
	return len(seen)
}

// severityRank orders diagnostic severities; higher is more severe. Verified
// high and critical findings are both diagnostics.SeverityError.
func severityRank(severity diagnostics.Severity) int {
	switch severity {
	case diagnostics.SeverityError:
		return 4
	case diagnostics.SeverityWarning:
		return 3
	case diagnostics.SeverityInformation:
		return 2
	case diagnostics.SeverityHint:
		return 1
	}
	return 0
}

// independenceRank orders verification independence levels.
func independenceRank(level string) int {
	switch level {
	case "distinct_provider":
		return 3
	case "distinct_model":
		return 2
	case "distinct_route":
		return 1
	}
	return 0
}

// categoryFamilies groups the closed advisory categories: behaviour defects,
// security, and code-health issues. Categories in one family are compatible.
// Security is a family of its own, so a security label is never absorbed into
// a finding of another category.
var categoryFamilies = map[string]int{
	"correctness": 1, "concurrency": 1, "performance": 1, "reliability": 1,
	"security":        2,
	"maintainability": 3, "style": 3, "documentation": 3, "testing": 3,
}

// compatibleCategories reports equal categories, categories of one family, or
// an uncategorized finding (a result without finding guidance), which is
// compatible with any category.
func compatibleCategories(a, b string) bool {
	if a == b || a == "" || b == "" {
		return true
	}
	family := categoryFamilies[a]
	return family != 0 && family == categoryFamilies[b]
}

// Near-identical statements share at least nearIdenticalNumerator /
// nearIdenticalDenominator (four fifths) of their combined distinctive words
// (Jaccard similarity). Integer arithmetic keeps the comparison exact.
const (
	nearIdenticalNumerator   = 4
	nearIdenticalDenominator = 5
)

// defectStatement is a finding's normalized title and claim: its distinctive
// words, and those of them that look like code symbols.
type defectStatement struct {
	words   map[string]bool
	symbols map[string]bool
}

// nearIdentical reports two statements that share at least four fifths of
// their combined distinctive words and differ in no symbol: a word that only
// one of them uses must not be an identifier or number, so "a / b" and
// "a / c", or "limit 10" and "limit 100", describe different defects.
func nearIdentical(a, b defectStatement) bool {
	shared := 0
	for word := range a.words {
		if b.words[word] {
			shared++
		} else if a.symbols[word] {
			return false
		}
	}
	for word := range b.words {
		if !a.words[word] && b.symbols[word] {
			return false
		}
	}
	union := len(a.words) + len(b.words) - shared
	return union > 0 && shared*nearIdenticalDenominator >= union*nearIdenticalNumerator
}

// statementStopwords are function words that carry no defect identity.
// Negations ("not", "no") are kept: they change what a statement claims.
var statementStopwords = map[string]bool{}

func init() {
	for _, word := range strings.Fields(`a an the and or nor but if so as of to in on at by for with without from into onto
	upon about over under after before again once here there then than when while which who whom whose what where why how
	is are was were be been being am it its this that these those they them their
	may can could will would should must shall might any all some more most other also does do did done
	has have had having only very just same each per via such both few own too because due`) {
		statementStopwords[word] = true
	}
}

// defectStatementTokens normalizes a finding's title and claim: runs of
// letters, digits and underscores, lowercased, without function words, with a
// plural "s" or "ies" reduced to its singular. A word is a symbol when it is
// at most two characters long, holds a digit or an underscore, or has a
// capital letter after its first character (camelCase or an all-caps name).
func defectStatementTokens(title, claim string) defectStatement {
	statement := defectStatement{words: map[string]bool{}, symbols: map[string]bool{}}
	var word []rune
	flush := func() {
		if len(word) == 0 {
			return
		}
		symbol := len(word) <= 2
		for index, character := range word {
			symbol = symbol || unicode.IsDigit(character) || character == '_' || index > 0 && unicode.IsUpper(character)
		}
		value := strings.ToLower(string(word))
		word = word[:0]
		if statementStopwords[value] {
			return
		}
		value = singular(value)
		statement.words[value] = true
		if symbol {
			statement.symbols[value] = true
		}
	}
	for _, character := range title + " " + claim {
		if unicode.IsLetter(character) || unicode.IsDigit(character) || character == '_' {
			word = append(word, character)
			continue
		}
		flush()
	}
	flush()
	return statement
}

// singular reduces a regular English plural: "entries" to "entry", "checks"
// to "check". Words ending in "ss", "us" or "is", and short words, are kept.
func singular(word string) string {
	switch {
	case len(word) > 4 && strings.HasSuffix(word, "ies"):
		return word[:len(word)-3] + "y"
	case len(word) > 3 && strings.HasSuffix(word, "s") && !strings.HasSuffix(word, "ss") && !strings.HasSuffix(word, "us") && !strings.HasSuffix(word, "is"):
		return word[:len(word)-1]
	}
	return word
}
