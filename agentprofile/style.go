package agentprofile

import (
	"path"
	"sort"
	"strings"
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
