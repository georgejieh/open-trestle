// Package patternhygiene finds, deterministically, changes that add or spread
// a small curated set of anti-patterns, escape-hatch comments and absolute
// rules in agent instruction files. It is review evidence, not a linter: the
// list is short, every rule is lexical, and each one prefers a missed match to
// a false one. Nothing here reads a model or the network.
package patternhygiene

import (
	"regexp"
	"strings"
)

// Rule is one curated anti-pattern. Its occurrences are counted in the base
// and head trees of the changed files' directories; a change that raises the
// count adds or spreads the pattern.
type Rule struct {
	// ID is stable and recorded; never reuse one for a different pattern.
	ID       string
	Language []Language
	// Pattern says what is matched; Why says why a reviewer should look.
	Pattern string
	Why     string
	match   func(line lineContext) bool
}

// lineContext is one lexed line with the file facts the rules need.
type lineContext struct {
	path     string
	language Language
	test     bool
	// goPackage is the file's package clause name, or "" when none was found
	// (a rule that depends on it then does not match).
	goPackage string
	code      string
	comment   string
}

var (
	goTimeSleep       = regexp.MustCompile(`\btime\.Sleep\s*\(`)
	goPanic           = regexp.MustCompile(`(^|[^.\w])panic\s*\(`)
	goLibraryPrint    = regexp.MustCompile(`\bfmt\.(Print|Println|Printf)\s*\(`)
	jsUseEffect       = regexp.MustCompile(`\buseEffect\s*\(`)
	jsSetTimeout      = regexp.MustCompile(`(^|[^.\w]|\bwindow\.|\bglobalThis\.)setTimeout\s*\(`)
	jsAnimationFrame  = regexp.MustCompile(`(^|[^.\w]|\bwindow\.|\bglobalThis\.)requestAnimationFrame\s*\(`)
	pyMutableDefault  = regexp.MustCompile(`^\s*(async\s+)?def\s+\w+\s*\(.*=\s*(\[\s*\]|\{\s*\}|list\(\s*\)|dict\(\s*\)|set\(\s*\))\s*[,)]`)
	pyBareExcept      = regexp.MustCompile(`^\s*except\s*:`)
	pyTypeIgnore      = regexp.MustCompile(`(^|#)\s*type:\s*ignore\b`)
	pyNoqa            = regexp.MustCompile(`(?i)(^|#)\s*noqa\b`)
	goNolintDirective = regexp.MustCompile(`^nolint\b`)
)

// Rules is the curated anti-pattern table, in a stable order. It is
// documented in docs/local-model-review.md#pattern-hygiene.
var Rules = []Rule{
	{ID: "go.time_sleep", Language: []Language{LanguageGo}, Pattern: "time.Sleep( in non-test Go code",
		Why:   "a fixed sleep usually stands in for missing synchronization or retry logic",
		match: func(l lineContext) bool { return !l.test && goTimeSleep.MatchString(l.code) }},
	{ID: "go.library_panic", Language: []Language{LanguageGo}, Pattern: "panic( in a non-main, non-test Go package",
		Why:   "library code should return an error and let the caller decide",
		match: func(l lineContext) bool { return libraryGo(l) && goPanic.MatchString(l.code) }},
	{ID: "go.library_print", Language: []Language{LanguageGo}, Pattern: "fmt.Print, fmt.Println or fmt.Printf in a non-main, non-test Go package",
		Why:   "standard output from a library is usually leftover debugging that bypasses the caller's logging",
		match: func(l lineContext) bool { return libraryGo(l) && goLibraryPrint.MatchString(l.code) }},
	{ID: "go.nolint_without_reason", Language: []Language{LanguageGo}, Pattern: "//nolint without a trailing // reason",
		Why:   "an unexplained suppression cannot be reviewed or removed later",
		match: func(l lineContext) bool { return goNolint(l.comment) && !goNolintHasReason(l.comment) }},
	{ID: "js.use_effect", Language: []Language{LanguageJavaScript, LanguageTypeScript}, Pattern: "useEffect( in a .jsx or .tsx component file",
		Why:   "effects invite stale closures, missing dependencies and render loops; many are better as derived state or event handlers",
		match: func(l lineContext) bool { return componentFile(l.path) && jsUseEffect.MatchString(l.code) }},
	{ID: "js.set_timeout", Language: []Language{LanguageJavaScript, LanguageTypeScript}, Pattern: "setTimeout( outside test files",
		Why:   "a timer often papers over an ordering problem instead of fixing it",
		match: func(l lineContext) bool { return !l.test && jsSetTimeout.MatchString(l.code) }},
	{ID: "js.request_animation_frame", Language: []Language{LanguageJavaScript, LanguageTypeScript}, Pattern: "requestAnimationFrame( outside test files",
		Why:   "deferring work to the next frame often hides a layout or ordering problem",
		match: func(l lineContext) bool { return !l.test && jsAnimationFrame.MatchString(l.code) }},
	{ID: "js.eslint_disable", Language: []Language{LanguageJavaScript, LanguageTypeScript}, Pattern: "an eslint-disable comment",
		Why:   "it silences the check instead of fixing what it found",
		match: func(l lineContext) bool { return eslintDisable(l.comment) }},
	{ID: "js.ts_ignore", Language: []Language{LanguageJavaScript, LanguageTypeScript}, Pattern: "a @ts-ignore comment",
		Why:   "it hides every type error on the next line, including future ones",
		match: func(l lineContext) bool { return tsIgnore(l.comment) }},
	{ID: "py.mutable_default", Language: []Language{LanguagePython}, Pattern: "a mutable default argument ([], {}, list(), dict(), set()) in a one-line def",
		Why:   "the default object is created once and shared by every call",
		match: func(l lineContext) bool { return pyMutableDefault.MatchString(l.code) }},
	{ID: "py.bare_except", Language: []Language{LanguagePython}, Pattern: "a bare except: clause",
		Why:   "it also catches KeyboardInterrupt and SystemExit and hides the real failure",
		match: func(l lineContext) bool { return pyBareExcept.MatchString(l.code) }},
	{ID: "py.type_ignore", Language: []Language{LanguagePython}, Pattern: "a # type: ignore comment",
		Why:   "it silences the type checker for the whole line",
		match: func(l lineContext) bool { return pyTypeIgnore.MatchString(l.comment) }},
	{ID: "py.noqa_without_code", Language: []Language{LanguagePython}, Pattern: "# noqa without an error code",
		Why:   "a bare noqa silences every check on the line, not only the one intended",
		match: func(l lineContext) bool { return noqa(l.comment) && !noqaHasCode(l.comment) }},
}

// SuppressionRules are the rule IDs a suppression observation may name.
var SuppressionRules = []string{"go.nolint", "js.eslint_disable", "js.ts_ignore", "py.type_ignore", "py.noqa"}

// suppressionRule names the lint or type suppression in a line's comment, or
// returns "" when it has none. Suppressions are reported whether or not they
// give a reason.
func suppressionRule(l lineContext) string {
	switch l.language {
	case LanguageGo:
		if goNolint(l.comment) {
			return "go.nolint"
		}
	case LanguageJavaScript, LanguageTypeScript:
		if eslintDisable(l.comment) {
			return "js.eslint_disable"
		}
		if tsIgnore(l.comment) {
			return "js.ts_ignore"
		}
	case LanguagePython:
		if pyTypeIgnore.MatchString(l.comment) {
			return "py.type_ignore"
		}
		if noqa(l.comment) {
			return "py.noqa"
		}
	}
	return ""
}

func libraryGo(l lineContext) bool { return !l.test && l.goPackage != "" && l.goPackage != "main" }

// goNolint matches a //nolint directive: the comment starts with nolint and no
// space follows the slashes, as golangci-lint requires.
func goNolint(comment string) bool { return goNolintDirective.MatchString(comment) }

// goNolintHasReason reports a nolint directive followed by "// reason".
func goNolintHasReason(comment string) bool {
	_, reason, found := strings.Cut(comment, "//")
	return found && strings.TrimSpace(reason) != ""
}

func eslintDisable(comment string) bool {
	return strings.HasPrefix(strings.TrimSpace(comment), "eslint-disable")
}

func tsIgnore(comment string) bool {
	return strings.HasPrefix(strings.TrimLeft(strings.TrimSpace(comment), "*/ "), "@ts-ignore")
}

func noqa(comment string) bool { return pyNoqa.MatchString(comment) }

// noqaHasCode reports "noqa: CODE", which names the check it silences.
func noqaHasCode(comment string) bool {
	location := pyNoqa.FindStringIndex(comment)
	if location == nil {
		return false
	}
	rest := strings.TrimLeft(comment[location[1]:], " ")
	return strings.HasPrefix(rest, ":") && strings.TrimSpace(rest[1:]) != ""
}

// componentFile is a .jsx or .tsx file, where useEffect is a component hook.
func componentFile(path string) bool {
	return strings.HasSuffix(path, ".jsx") || strings.HasSuffix(path, ".tsx")
}

// testFile reports a test file by the language's naming convention.
func testFile(path string, language Language) bool {
	base := path[strings.LastIndex(path, "/")+1:]
	switch language {
	case LanguageGo:
		return strings.HasSuffix(base, "_test.go")
	case LanguageJavaScript, LanguageTypeScript:
		return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") || strings.Contains("/"+path, "/__tests__/")
	case LanguagePython:
		return strings.HasPrefix(base, "test_") || strings.HasSuffix(base, "_test.py")
	}
	return false
}

// Justification and escape-hatch comments. Matching is on the lowercased
// comment text and deliberately narrow: "temporary" alone is not enough
// ("a temporary file"), it must name a fix, workaround, hack or patch.
var workaroundPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bworkaround\b|\bwork around\b`),
	regexp.MustCompile(`\bhack\b|\bhacky\b`),
	regexp.MustCompile(`\btemporary (fix|workaround|hack|solution|patch)\b`),
	regexp.MustCompile(`\btemporarily (disable|disabled|disabling|skip|skipped|skipping|bypass|ignore|ignored|hardcode|hard-code)\b`),
	regexp.MustCompile(`\bfor now\b`),
	regexp.MustCompile(`\bbecause\b.*\b(doesn't|does not|don't|do not|can't|cannot|won't|isn't|is not)\b`),
	regexp.MustCompile(`\bto avoid\b.*\bwe\b`),
}

func workaroundComment(comment string) bool {
	lower := strings.ToLower(comment)
	for _, pattern := range workaroundPatterns {
		if pattern.MatchString(lower) {
			return true
		}
	}
	return false
}

// A TODO, FIXME or XXX marker must be uppercase, start a word and be followed
// by a colon, a parenthesis, whitespace or the end, so "XXX-XXX" placeholders
// and words such as "todos" never match.
var todoMarker = regexp.MustCompile(`(^|\s)(TODO|FIXME|XXX)([:(\s]|$)`)

// An issue reference: #123, ABC-123, gh-123, issue 123, or a URL.
var issueReference = regexp.MustCompile(`#\d+|\b[A-Z][A-Z0-9]+-\d+\b|\bgh-\d+\b|(?i:\bissue\s*#?\d+)|https?://\S+`)

func unreferencedTODO(comment string) bool {
	return todoMarker.MatchString(comment) && !issueReference.MatchString(comment)
}

// Absolute directives added to agent instruction files: NEVER, ALWAYS and MUST
// NOT in capitals, or never, always and must not inside bold. Lowercase prose
// is not flagged.
var (
	capitalDirective = regexp.MustCompile(`\b(NEVER|ALWAYS|MUST NOT)\b`)
	boldSpan         = regexp.MustCompile(`\*\*([^*]+)\*\*|__([^_]+)__`)
	directiveWord    = regexp.MustCompile(`(?i)\b(never|always|must not)\b`)
)

func absoluteDirective(line string) bool {
	if capitalDirective.MatchString(line) {
		return true
	}
	for _, span := range boldSpan.FindAllStringSubmatch(line, -1) {
		if directiveWord.MatchString(span[1] + span[2]) {
			return true
		}
	}
	return false
}

// RuleFile reports a repository file whose added rules this package checks
// for absolute directives: AGENTS.md, CLAUDE.md, GEMINI.md and SKILL.md at any
// depth, files under .cursor/rules, .github/copilot-instructions.md,
// .trestle/review-instructions.md, and Markdown files under a skills
// directory. These are already treated as instruction-like repository content
// and are reviewed as code, never followed.
func RuleFile(path string) bool {
	segments := strings.Split(path, "/")
	base := strings.ToLower(segments[len(segments)-1])
	switch base {
	case "agents.md", "claude.md", "gemini.md", "skill.md", ".cursorrules":
		return true
	}
	if path == ".github/copilot-instructions.md" || path == ".trestle/review-instructions.md" {
		return true
	}
	for index, segment := range segments[:len(segments)-1] {
		if segment == ".cursor" && index+1 < len(segments)-1 && segments[index+1] == "rules" {
			return true
		}
		if strings.EqualFold(segment, "skills") && strings.HasSuffix(base, ".md") {
			return true
		}
	}
	return false
}
