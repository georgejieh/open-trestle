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

// IsStyleConfigFile reports whether declared-style detection reads a file with
// this path's base name. Matching is exact and case-insensitive, as in
// detection. A recognized file declares a style only when detection finds its
// documented marker.
func IsStyleConfigFile(filePath string) bool {
	base := strings.ToLower(path.Base(filePath))
	switch base {
	case "go.mod", ".editorconfig", ".prettierrc", "package.json", ".eslintrc",
		".flake8", ".pycodestyle", "ruff.toml", ".ruff.toml", "setup.cfg", "tox.ini", "pyproject.toml", ".style.yapf",
		".clang-format", "_clang-format", "rustfmt.toml", ".rustfmt.toml", ".rubocop.yml":
		return true
	}
	for _, prefix := range []string{".prettierrc.", "prettier.config.", ".eslintrc.", "eslint.config."} {
		if strings.HasPrefix(base, prefix) {
			return true
		}
	}
	return false
}

// detectStyleIntents derives declared style intents from configuration file
// paths and, where supplied, their bounded contents. Detection is exact and
// case-insensitive; it never infers a style from source code.
func detectStyleIntents(configFiles []ConfigFile) []StyleIntent {
	set := map[StyleIntent]struct{}{}
	for _, file := range configFiles {
		base := strings.ToLower(path.Base(file.Path))
		content := strings.ToLower(file.Content)
		switch {
		case base == "go.mod":
			set[StyleGofmt] = struct{}{}
		case base == ".editorconfig":
			set[StyleEditorConfig] = struct{}{}
		case base == ".prettierrc" || strings.HasPrefix(base, ".prettierrc.") || strings.HasPrefix(base, "prettier.config."):
			set[StylePrettier] = struct{}{}
		case base == "package.json" && strings.Contains(content, `"prettier"`):
			set[StylePrettier] = struct{}{}
		case base == ".eslintrc" || strings.HasPrefix(base, ".eslintrc.") || strings.HasPrefix(base, "eslint.config."):
			set[StyleESLint] = struct{}{}
		case base == ".flake8" || base == ".pycodestyle" || base == "ruff.toml" || base == ".ruff.toml":
			set[StylePEP8] = struct{}{}
		case base == "setup.cfg" || base == "tox.ini":
			if strings.Contains(content, "[flake8]") || strings.Contains(content, "[pycodestyle]") {
				set[StylePEP8] = struct{}{}
			}
			if strings.Contains(content, "based_on_style = google") || strings.Contains(content, "based_on_style=google") {
				set[StyleGooglePython] = struct{}{}
			}
		case base == "pyproject.toml":
			if strings.Contains(content, "[tool.ruff") || strings.Contains(content, "[tool.flake8") || strings.Contains(content, "[tool.pycodestyle") {
				set[StylePEP8] = struct{}{}
			}
			if strings.Contains(content, "[tool.black") {
				set[StyleBlack] = struct{}{}
			}
			if strings.Contains(content, "[tool.yapf") && strings.Contains(content, "google") {
				set[StyleGooglePython] = struct{}{}
			}
		case base == ".style.yapf":
			if strings.Contains(content, "google") {
				set[StyleGooglePython] = struct{}{}
			} else {
				set[StylePEP8] = struct{}{}
			}
		case base == ".clang-format" || base == "_clang-format":
			set[StyleClangFormat] = struct{}{}
			if strings.Contains(content, "basedonstyle: google") {
				set[StyleGoogleCPP] = struct{}{}
			}
		case base == "rustfmt.toml" || base == ".rustfmt.toml":
			set[StyleRustfmt] = struct{}{}
		case base == ".rubocop.yml":
			set[StyleRubocop] = struct{}{}
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

// RecommendStyles returns one recommendation, in language order, for each
// language of changedPaths that has a style detector and that no intent
// declared by configFiles governs. An editorconfig intent alone does not count,
// because EditorConfig covers only whitespace basics. Vendor and generated
// files are not counted, as in routing.
func RecommendStyles(changedPaths []string, configFiles []ConfigFile) ([]StyleRecommendation, error) {
	if len(changedPaths) > maxFeatureFiles || len(configFiles) > MaxConfigFiles {
		return nil, fmt.Errorf("%w: too many paths or config files", ErrInvalidChangeFeatures)
	}
	for _, config := range configFiles {
		if !validRepositoryPath(config.Path) || len(config.Content) > MaxConfigFileBytes || !utf8.ValidString(config.Content) {
			return nil, fmt.Errorf("%w: invalid config file", ErrInvalidChangeFeatures)
		}
	}
	intents := detectStyleIntents(configFiles)
	counts := map[Language]int{}
	for _, changedPath := range changedPaths {
		if !validRepositoryPath(changedPath) {
			return nil, fmt.Errorf("%w: changed path is not a clean relative repository path", ErrInvalidChangeFeatures)
		}
		language, hasLanguage := languageForPath(changedPath)
		if class := classifyPath(changedPath, language, hasLanguage); !hasLanguage || class == FileClassVendor || class == FileClassGenerated {
			continue
		}
		if _, ok := recommendedStyles[language]; ok {
			counts[language]++
		}
	}
	var recommendations []StyleRecommendation
	for language, count := range counts {
		governed := false
		for _, intent := range intents {
			if intent != StyleEditorConfig && styleGoverns(intent, language) {
				governed = true
			}
		}
		if !governed {
			recommendations = append(recommendations, StyleRecommendation{Language: language, ChangedFiles: count})
		}
	}
	sort.Slice(recommendations, func(i, j int) bool { return recommendations[i].Language < recommendations[j].Language })
	return recommendations, nil
}
