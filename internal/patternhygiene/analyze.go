package patternhygiene

import (
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

// Kind names one class of pattern-hygiene evidence.
type Kind string

const (
	// KindAntiPattern is a curated anti-pattern whose count the change raised
	// in a directory.
	KindAntiPattern Kind = "anti_pattern"
	// KindSuppression is a lint or type suppression on an added line.
	KindSuppression Kind = "suppression"
	// KindWorkaroundComment is an added comment that justifies a workaround.
	KindWorkaroundComment Kind = "workaround_comment"
	// KindUnreferencedTODO is an added TODO, FIXME or XXX with no issue reference.
	KindUnreferencedTODO Kind = "unreferenced_todo"
	// KindAbsoluteDirective is an added NEVER, ALWAYS or MUST NOT rule (in
	// capitals or bold) in an agent instruction or skill file.
	KindAbsoluteDirective Kind = "absolute_directive"
	// KindRootCauseNotFixed is a suppression added beside a workaround
	// comment: the change silences a check and explains why instead of
	// fixing the cause. It is a deterministic low-severity note.
	KindRootCauseNotFixed Kind = "root_cause_not_fixed"
)

// Bounds keep a report small enough to travel in a model request.
const (
	MaxIncreases     = 32
	MaxObservations  = 64
	MaxNotes         = 16
	maxAddedPerRule  = 4
	maxAnalyzedBytes = 1 << 20
)

// File is one repository file's exact bytes.
type File struct {
	Path    string
	Content []byte
}

// LineRange is an inclusive range of head line numbers.
type LineRange struct{ Start, End int }

// Change is one changed file: its head path and the head line ranges the
// change added or modified. A removed file has no ranges.
type Change struct {
	Path  string
	Added []LineRange
}

// Input is what Analyze compares. Base and Head hold every file of a
// supported language in the changed files' directories (one level, not
// recursive), and Head also holds each changed rule file. A directory the
// caller could not read completely is listed in Unread; its counts are not
// compared, because a partial count could invent an increase.
type Input struct {
	Changes    []Change
	Base, Head []File
	Unread     []string
}

// Location is one line of one head file.
type Location struct {
	Path string
	Line int
}

// Increase is one anti-pattern whose count in a directory is higher in the
// head than in the base. Spreading means the base already had it: the change
// copies an established pattern rather than introducing a new one.
type Increase struct {
	Rule      string
	Directory string
	Base      int
	Head      int
	Spreading bool
	// Added locates up to four matches on the change's added lines; it may be
	// empty when the count rose without a match on a changed line (a file
	// moved into the directory, for example).
	Added []Location
}

// Observation is one piece of added-line evidence.
type Observation struct {
	Kind Kind
	Rule string
	Location
}

// Report is the deterministic pattern-hygiene evidence of one change. Lists
// are bounded and sorted; the counts are complete.
type Report struct {
	Increases    []Increase
	Observations []Observation
	Notes        []Observation
	Counts       Counts
	// UnreadDirectories counts changed directories whose files were not all
	// read, so no anti-pattern count was compared for them.
	UnreadDirectories int
}

// Counts are the complete totals behind the bounded lists.
type Counts struct {
	IncreasedAntiPatterns int
	SpreadingAntiPatterns int
	Suppressions          int
	WorkaroundComments    int
	UnreferencedTODOs     int
	AbsoluteDirectives    int
	RootCauseNotes        int
}

// Analyze builds the report. It is deterministic: the same input always gives
// the same report, and file order does not matter.
func Analyze(input Input) Report {
	unread := map[string]bool{}
	for _, directory := range input.Unread {
		unread[directory] = true
	}
	heads := map[string][]byte{}
	for _, file := range input.Head {
		heads[file.Path] = file.Content
	}
	var report Report
	directories := map[string]bool{}
	for _, change := range input.Changes {
		if _, ok := LanguageOf(change.Path); ok {
			directories[path.Dir(change.Path)] = true
		}
	}
	for directory := range directories {
		if unread[directory] {
			report.UnreadDirectories++
		}
	}
	baseCounts := countRules(input.Base, directories, unread)
	headCounts := countRules(input.Head, directories, unread)

	// Matches on added lines, per rule and directory, anchor the increases.
	addedMatches := map[[2]string][]Location{}
	changes := append([]Change(nil), input.Changes...)
	sort.Slice(changes, func(i, j int) bool { return changes[i].Path < changes[j].Path })
	for _, change := range changes {
		content, ok := heads[change.Path]
		if !ok || len(change.Added) == 0 || !analyzable(content) {
			continue
		}
		if RuleFile(change.Path) {
			for number, line := range strings.Split(string(content), "\n") {
				if inRanges(number+1, change.Added) && absoluteDirective(line) {
					report.Counts.AbsoluteDirectives++
					report.Observations = appendBounded(report.Observations, Observation{KindAbsoluteDirective, "", Location{change.Path, number + 1}}, MaxObservations)
				}
			}
		}
		language, ok := LanguageOf(change.Path)
		if !ok {
			continue
		}
		var suppressions, workarounds []int
		for index, line := range contextLines(change.Path, language, content) {
			number := index + 1
			if !inRanges(number, change.Added) {
				continue
			}
			for _, rule := range Rules {
				if ruleApplies(rule, language) && rule.match(line) {
					key := [2]string{rule.ID, path.Dir(change.Path)}
					addedMatches[key] = append(addedMatches[key], Location{change.Path, number})
				}
			}
			if line.comment == "" {
				continue
			}
			if rule := suppressionRule(line); rule != "" {
				report.Counts.Suppressions++
				suppressions = append(suppressions, number)
				report.Observations = appendBounded(report.Observations, Observation{KindSuppression, rule, Location{change.Path, number}}, MaxObservations)
			}
			if workaroundComment(line.comment) {
				report.Counts.WorkaroundComments++
				workarounds = append(workarounds, number)
				report.Observations = appendBounded(report.Observations, Observation{KindWorkaroundComment, "", Location{change.Path, number}}, MaxObservations)
			}
			if unreferencedTODO(line.comment) {
				report.Counts.UnreferencedTODOs++
				report.Observations = appendBounded(report.Observations, Observation{KindUnreferencedTODO, "", Location{change.Path, number}}, MaxObservations)
			}
		}
		// A suppression on, or right beside, a workaround comment silences a
		// check and explains why, instead of fixing the cause.
		for _, line := range suppressions {
			for _, other := range workarounds {
				if other >= line-1 && other <= line+1 {
					report.Counts.RootCauseNotes++
					report.Notes = appendBounded(report.Notes, Observation{KindRootCauseNotFixed, "", Location{change.Path, line}}, MaxNotes)
					break
				}
			}
		}
	}

	keys := make([][2]string, 0, len(headCounts))
	for key := range headCounts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i][1] != keys[j][1] {
			return keys[i][1] < keys[j][1]
		}
		return ruleOrder(keys[i][0]) < ruleOrder(keys[j][0])
	})
	for _, key := range keys {
		base, head := baseCounts[key], headCounts[key]
		if head <= base {
			continue
		}
		report.Counts.IncreasedAntiPatterns++
		if base > 0 {
			report.Counts.SpreadingAntiPatterns++
		}
		added := addedMatches[key]
		if len(added) > maxAddedPerRule {
			added = added[:maxAddedPerRule]
		}
		report.Increases = appendBounded(report.Increases, Increase{Rule: key[0], Directory: key[1], Base: base, Head: head, Spreading: base > 0, Added: append([]Location(nil), added...)}, MaxIncreases)
	}
	sortObservations(report.Observations)
	sortObservations(report.Notes)
	return report
}

func countRules(files []File, directories, unread map[string]bool) map[[2]string]int {
	counts := map[[2]string]int{}
	for _, file := range files {
		directory := path.Dir(file.Path)
		language, ok := LanguageOf(file.Path)
		if !ok || !directories[directory] || unread[directory] || !analyzable(file.Content) {
			continue
		}
		for _, line := range contextLines(file.Path, language, file.Content) {
			for _, rule := range Rules {
				if ruleApplies(rule, language) && rule.match(line) {
					counts[[2]string{rule.ID, directory}]++
				}
			}
		}
	}
	return counts
}

// contextLines lexes a file and attaches the facts the rules need.
func contextLines(filePath string, language Language, content []byte) []lineContext {
	lexed := lexLines(language, string(content))
	test := testFile(filePath, language)
	goPackage := ""
	if language == LanguageGo {
		for _, line := range lexed {
			fields := strings.Fields(line.code)
			if len(fields) >= 2 && fields[0] == "package" {
				goPackage = fields[1]
				break
			}
		}
	}
	out := make([]lineContext, len(lexed))
	for index, line := range lexed {
		out[index] = lineContext{path: filePath, language: language, test: test, goPackage: goPackage, code: line.code, comment: line.comment}
	}
	return out
}

// analyzable is UTF-8 text without NUL bytes, within the per-file bound.
func analyzable(content []byte) bool {
	return len(content) <= maxAnalyzedBytes && utf8.Valid(content) && !strings.ContainsRune(string(content), 0)
}

func ruleApplies(rule Rule, language Language) bool {
	for _, candidate := range rule.Language {
		if candidate == language {
			return true
		}
	}
	return false
}

func ruleOrder(id string) int {
	for index, rule := range Rules {
		if rule.ID == id {
			return index
		}
	}
	return len(Rules)
}

func inRanges(line int, ranges []LineRange) bool {
	for _, value := range ranges {
		if line >= value.Start && line <= value.End {
			return true
		}
	}
	return false
}

func appendBounded[T any](values []T, value T, bound int) []T {
	if len(values) >= bound {
		return values
	}
	return append(values, value)
}

func sortObservations(values []Observation) {
	sort.SliceStable(values, func(i, j int) bool {
		if values[i].Path != values[j].Path {
			return values[i].Path < values[j].Path
		}
		if values[i].Line != values[j].Line {
			return values[i].Line < values[j].Line
		}
		return values[i].Kind < values[j].Kind
	})
}

// RuleByID returns the table entry for a rule ID.
func RuleByID(id string) (Rule, bool) {
	for _, rule := range Rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return Rule{}, false
}
