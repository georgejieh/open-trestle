package agentprofile

import (
	"fmt"
	"path"
	"sort"
	"strings"
	"unicode/utf8"
)

// StyleIntent identifies a repository-declared style contract.
type StyleIntent string

// Declared style intents detected from repository configuration files.
const (
	StyleClangFormat  StyleIntent = "clang_format"
	StyleEditorConfig StyleIntent = "editorconfig"
	StyleESLint       StyleIntent = "eslint"
	StyleGofmt        StyleIntent = "gofmt_effective_go"
	StyleGoogleCPP    StyleIntent = "google_cpp"
	StyleGooglePython StyleIntent = "google_python"
	StylePEP8         StyleIntent = "pep8"
	StylePrettier     StyleIntent = "prettier"
	StyleRubocop      StyleIntent = "rubocop"
	StyleRustfmt      StyleIntent = "rustfmt"
	StyleBlack        StyleIntent = "black"
)

// styleIntentLanguages declares which changed languages each intent governs.
// An empty slice means the intent governs every changed text file.
var styleIntentLanguages = map[StyleIntent][]Language{
	StyleBlack:        {LanguagePython},
	StyleClangFormat:  {LanguageC, LanguageCPP},
	StyleEditorConfig: nil,
	StyleESLint:       {LanguageJavaScript, LanguageTypeScript, LanguageVue, LanguageSvelte},
	StyleGofmt:        {LanguageGo},
	StyleGoogleCPP:    {LanguageC, LanguageCPP},
	StyleGooglePython: {LanguagePython},
	StylePEP8:         {LanguagePython},
	StylePrettier: {
		LanguageJavaScript, LanguageTypeScript, LanguageCSS, LanguageHTML, LanguageVue, LanguageSvelte,
		LanguageJSON, LanguageYAML, LanguageMarkdown,
	},
	StyleRubocop: {LanguageRuby},
	StyleRustfmt: {LanguageRust},
}

// styleConfigRule declares one kind of style configuration file: the lowercase
// base names and name prefixes it matches, every intent such a file can declare,
// and, when its content selects among them, the function that does so. A rule
// without declares declares all of its intents by the file's presence.
type styleConfigRule struct {
	names, prefixes []string
	intents         []StyleIntent
	declares        func(content string) []StyleIntent
}

// styleConfigRules is the single table that recognition, detection and the
// intents a file name can declare all derive from. Intents are sorted.
var styleConfigRules = []styleConfigRule{
	{names: []string{"go.mod"}, intents: []StyleIntent{StyleGofmt}},
	{names: []string{".editorconfig"}, intents: []StyleIntent{StyleEditorConfig}},
	{names: []string{".prettierrc"}, prefixes: []string{".prettierrc.", "prettier.config."}, intents: []StyleIntent{StylePrettier}},
	{names: []string{"package.json"}, intents: []StyleIntent{StylePrettier}, declares: func(content string) []StyleIntent {
		return markedIntents(content, StylePrettier, `"prettier"`)
	}},
	{names: []string{".eslintrc"}, prefixes: []string{".eslintrc.", "eslint.config."}, intents: []StyleIntent{StyleESLint}},
	{names: []string{".flake8", ".pycodestyle", "ruff.toml", ".ruff.toml"}, intents: []StyleIntent{StylePEP8}},
	{names: []string{"setup.cfg", "tox.ini"}, intents: []StyleIntent{StyleGooglePython, StylePEP8}, declares: func(content string) []StyleIntent {
		return append(markedIntents(content, StyleGooglePython, "based_on_style = google", "based_on_style=google"),
			markedIntents(content, StylePEP8, "[flake8]", "[pycodestyle]")...)
	}},
	{names: []string{"pyproject.toml"}, intents: []StyleIntent{StyleBlack, StyleGooglePython, StylePEP8}, declares: func(content string) []StyleIntent {
		intents := append(markedIntents(content, StyleBlack, "[tool.black"), markedIntents(content, StylePEP8, "[tool.ruff", "[tool.flake8", "[tool.pycodestyle")...)
		if strings.Contains(content, "[tool.yapf") && strings.Contains(content, "google") {
			intents = append(intents, StyleGooglePython)
		}
		return intents
	}},
	{names: []string{".style.yapf"}, intents: []StyleIntent{StyleGooglePython, StylePEP8}, declares: func(content string) []StyleIntent {
		if strings.Contains(content, "google") {
			return []StyleIntent{StyleGooglePython}
		}
		return []StyleIntent{StylePEP8}
	}},
	{names: []string{".clang-format", "_clang-format"}, intents: []StyleIntent{StyleClangFormat, StyleGoogleCPP}, declares: func(content string) []StyleIntent {
		return append([]StyleIntent{StyleClangFormat}, markedIntents(content, StyleGoogleCPP, "basedonstyle: google")...)
	}},
	{names: []string{"rustfmt.toml", ".rustfmt.toml"}, intents: []StyleIntent{StyleRustfmt}},
	{names: []string{".rubocop.yml"}, intents: []StyleIntent{StyleRubocop}},
}

// markedIntents returns intent when lowercase content holds any marker.
func markedIntents(content string, intent StyleIntent, markers ...string) []StyleIntent {
	for _, marker := range markers {
		if strings.Contains(content, marker) {
			return []StyleIntent{intent}
		}
	}
	return nil
}

// styleConfigRuleFor returns the rule matching a path's base name, ignoring case.
func styleConfigRuleFor(filePath string) (styleConfigRule, bool) {
	base := strings.ToLower(path.Base(filePath))
	for _, rule := range styleConfigRules {
		for _, name := range rule.names {
			if base == name {
				return rule, true
			}
		}
		for _, prefix := range rule.prefixes {
			if strings.HasPrefix(base, prefix) {
				return rule, true
			}
		}
	}
	return styleConfigRule{}, false
}

// IsStyleConfigFile reports whether declared-style detection reads a file with
// this path's base name. Matching is exact and case-insensitive, as in
// detection. A recognized file declares a style only when detection finds its
// documented marker.
func IsStyleConfigFile(filePath string) bool {
	_, ok := styleConfigRuleFor(filePath)
	return ok
}

// styleConfigIntents returns every intent a file with this name can declare,
// whatever its content, or nil for a name detection does not recognize.
func styleConfigIntents(filePath string) []StyleIntent {
	rule, ok := styleConfigRuleFor(filePath)
	if !ok {
		return nil
	}
	return append([]StyleIntent(nil), rule.intents...)
}

// detectStyleIntents derives declared style intents from configuration file
// paths and, where supplied, their bounded contents. Detection is exact and
// case-insensitive; it never infers a style from source code.
func detectStyleIntents(configFiles []ConfigFile) []StyleIntent {
	set := map[StyleIntent]struct{}{}
	for _, file := range configFiles {
		rule, ok := styleConfigRuleFor(file.Path)
		if !ok {
			continue
		}
		intents := rule.intents
		if rule.declares != nil {
			intents = rule.declares(strings.ToLower(file.Content))
		}
		for _, intent := range intents {
			set[intent] = struct{}{}
		}
	}
	if len(set) == 0 {
		return nil
	}
	intents := make([]StyleIntent, 0, len(set))
	for intent := range set {
		intents = append(intents, intent)
	}
	sort.Slice(intents, func(i, j int) bool { return intents[i] < intents[j] })
	return intents
}

// styleGoverns reports whether an intent governs a changed language.
func styleGoverns(intent StyleIntent, language Language) bool {
	languages, ok := styleIntentLanguages[intent]
	if !ok {
		return false
	}
	if len(languages) == 0 {
		return true
	}
	for _, governed := range languages {
		if governed == language {
			return true
		}
	}
	return false
}

// recommendedStyle is the fixed standard suggested for a changed language.
type recommendedStyle struct{ name, standard string }

// recommendedStyles holds exactly the languages that a declared intent other
// than editorconfig can govern. A language without a detector has no entry,
// because Open Trestle cannot tell whether such a repository declares a style.
var recommendedStyles = map[Language]recommendedStyle{
	LanguageGo:         {"Go", "gofmt and Effective Go"},
	LanguagePython:     {"Python", "PEP 8, enforced with Ruff or Black"},
	LanguageJavaScript: {"JavaScript", "Prettier with ESLint"},
	LanguageTypeScript: {"TypeScript", "Prettier with ESLint"},
	LanguageVue:        {"Vue", "Prettier with ESLint"},
	LanguageSvelte:     {"Svelte", "Prettier with ESLint"},
	LanguageCSS:        {"CSS", "Prettier"},
	LanguageHTML:       {"HTML", "Prettier"},
	LanguageJSON:       {"JSON", "Prettier"},
	LanguageYAML:       {"YAML", "Prettier"},
	LanguageMarkdown:   {"Markdown", "Prettier"},
	LanguageC:          {"C", "Google C++ Style through clang-format (BasedOnStyle: Google)"},
	LanguageCPP:        {"C++", "Google C++ Style through clang-format (BasedOnStyle: Google)"},
	LanguageRust:       {"Rust", "rustfmt"},
	LanguageRuby:       {"Ruby", "RuboCop and the community Ruby Style Guide"},
}

// RecommendedStyle returns the display name of a language and the standard
// style suggested for it when the repository declares none. ok is false for a
// language without a style detector.
func RecommendedStyle(language Language) (name, standard string, ok bool) {
	value, ok := recommendedStyles[language]
	return value.name, value.standard, ok
}

// StyleRecommendation suggests the standard style for one changed language
// that has a style detector but no declared intent governing it. It comes from
// a fixed table, never from a model, and is advice only.
type StyleRecommendation struct {
	Language     Language
	ChangedFiles int
}

// StyleAdvice is the outcome of RecommendStyles, each list in language order.
// Withheld lists the changed languages left without a recommendation because a
// configuration file that could declare their style was not read, so their
// declared style is unknown.
type StyleAdvice struct {
	Recommendations []StyleRecommendation
	Withheld        []StyleRecommendation
}

// RecommendStyles returns one recommendation for each language of changedPaths
// that has a style detector and that no intent declared by configFiles governs.
// An editorconfig intent alone does not count, because EditorConfig covers only
// whitespace basics. Vendor and generated files are not counted, as in routing,
// and neither are generated dependency lock files such as package-lock.json.
//
// unreadConfigPaths names recognized configuration files that could not be
// read. A language that one of them could govern, by any intent its name can
// declare, is withheld instead of recommended; every other language is still
// recommended.
func RecommendStyles(changedPaths []string, configFiles []ConfigFile, unreadConfigPaths []string) (StyleAdvice, error) {
	if len(changedPaths) > maxFeatureFiles || len(configFiles) > MaxConfigFiles {
		return StyleAdvice{}, fmt.Errorf("%w: too many paths or config files", ErrInvalidChangeFeatures)
	}
	for _, config := range configFiles {
		if !validRepositoryPath(config.Path) || len(config.Content) > MaxConfigFileBytes || !utf8.ValidString(config.Content) {
			return StyleAdvice{}, fmt.Errorf("%w: invalid config file", ErrInvalidChangeFeatures)
		}
	}
	var unknown []StyleIntent
	for _, unread := range unreadConfigPaths {
		if !validRepositoryPath(unread) || !IsStyleConfigFile(unread) {
			return StyleAdvice{}, fmt.Errorf("%w: unread config path is not a recognized configuration file", ErrInvalidChangeFeatures)
		}
		unknown = append(unknown, styleConfigIntents(unread)...)
	}
	declared := detectStyleIntents(configFiles)
	counts := map[Language]int{}
	for _, changedPath := range changedPaths {
		if !validRepositoryPath(changedPath) {
			return StyleAdvice{}, fmt.Errorf("%w: changed path is not a clean relative repository path", ErrInvalidChangeFeatures)
		}
		language, hasLanguage := languageForPath(changedPath)
		if class := classifyPath(changedPath, language, hasLanguage); !hasLanguage || class == FileClassVendor || class == FileClassGenerated || isDependencyLockFile(changedPath) {
			continue
		}
		if _, ok := recommendedStyles[language]; ok {
			counts[language]++
		}
	}
	var advice StyleAdvice
	for language, count := range counts {
		value := StyleRecommendation{Language: language, ChangedFiles: count}
		switch {
		case governsLanguage(declared, language):
		case governsLanguage(unknown, language):
			advice.Withheld = append(advice.Withheld, value)
		default:
			advice.Recommendations = append(advice.Recommendations, value)
		}
	}
	for _, list := range [][]StyleRecommendation{advice.Recommendations, advice.Withheld} {
		sort.Slice(list, func(i, j int) bool { return list[i].Language < list[j].Language })
	}
	return advice, nil
}

// governsLanguage reports whether an intent other than editorconfig governs language.
func governsLanguage(intents []StyleIntent, language Language) bool {
	for _, intent := range intents {
		if intent != StyleEditorConfig && styleGoverns(intent, language) {
			return true
		}
	}
	return false
}
