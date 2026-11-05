package agentprofile

import (
	"errors"
	"path"
	"sort"
	"strings"
)

const maxPathBytes = 4096

var (
	// ErrInvalidPath identifies a path that is not a clean, relative, slash-separated repository path.
	ErrInvalidPath = errors.New("invalid repository path")
	// ErrInvalidGlob identifies a malformed activation path glob.
	ErrInvalidGlob = errors.New("invalid path glob")
)

func validRepositoryPath(value string) bool {
	if value == "" || len(value) > maxPathBytes || strings.HasPrefix(value, "/") || strings.ContainsAny(value, "\\\x00") {
		return false
	}
	if path.Clean(value) != value || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return false
	}
	return true
}

// languageForPath derives a language from the final extension only.
func languageForPath(filePath string) (Language, bool) {
	base := strings.ToLower(path.Base(filePath))
	switch base {
	case "dockerfile", "makefile", "jenkinsfile":
		return "", false
	}
	switch strings.ToLower(path.Ext(base)) {
	case ".go":
		return LanguageGo, true
	case ".py", ".pyi":
		return LanguagePython, true
	case ".js", ".mjs", ".cjs", ".jsx":
		return LanguageJavaScript, true
	case ".ts", ".mts", ".cts", ".tsx":
		return LanguageTypeScript, true
	case ".java":
		return LanguageJava, true
	case ".kt", ".kts":
		return LanguageKotlin, true
	case ".rs":
		return LanguageRust, true
	case ".rb":
		return LanguageRuby, true
	case ".php":
		return LanguagePHP, true
	case ".cs":
		return LanguageCSharp, true
	case ".c", ".h":
		return LanguageC, true
	case ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx":
		return LanguageCPP, true
	case ".swift":
		return LanguageSwift, true
	case ".scala":
		return LanguageScala, true
	case ".sh", ".bash", ".zsh":
		return LanguageShell, true
	case ".sql":
		return LanguageSQL, true
	case ".html", ".htm":
		return LanguageHTML, true
	case ".css", ".scss", ".sass", ".less":
		return LanguageCSS, true
	case ".vue":
		return LanguageVue, true
	case ".svelte":
		return LanguageSvelte, true
	case ".md", ".mdx", ".rst", ".adoc":
		return LanguageMarkdown, true
	case ".yaml", ".yml":
		return LanguageYAML, true
	case ".json":
		return LanguageJSON, true
	case ".toml":
		return LanguageTOML, true
	default:
		return "", false
	}
}

var dependencyManifestNames = map[string]struct{}{
	"go.mod": {}, "go.sum": {}, "package.json": {}, "package-lock.json": {}, "npm-shrinkwrap.json": {},
	"yarn.lock": {}, "pnpm-lock.yaml": {}, "requirements.txt": {}, "pipfile": {}, "pipfile.lock": {},
	"poetry.lock": {}, "pyproject.toml": {}, "uv.lock": {}, "cargo.toml": {}, "cargo.lock": {},
	"gemfile": {}, "gemfile.lock": {}, "pom.xml": {}, "build.gradle": {}, "build.gradle.kts": {},
	"composer.json": {}, "composer.lock": {},
}

// classifyPath derives one file class from exact path rules, first match wins.
func classifyPath(filePath string, language Language, hasLanguage bool) FileClass {
	lower := strings.ToLower(filePath)
	segments := strings.Split(lower, "/")
	base := segments[len(segments)-1]
	directories := segments[:len(segments)-1]
	for _, segment := range directories {
		if segment == "vendor" || segment == "node_modules" || segment == "third_party" {
			return FileClassVendor
		}
	}
	for _, suffix := range []string{".pb.go", "_generated.go", ".gen.go", ".min.js", ".min.css", ".generated.ts", ".g.dart"} {
		if strings.HasSuffix(base, suffix) {
			return FileClassGenerated
		}
	}
	if strings.HasPrefix(base, "zz_generated") {
		return FileClassGenerated
	}
	if _, ok := dependencyManifestNames[base]; ok || strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
		return FileClassDependencyManifest
	}
	if isCIBuildPath(lower, base) {
		return FileClassCIBuild
	}
	if hasLanguage && isTestPath(base, directories) {
		return FileClassTest
	}
	if hasLanguage && language == LanguageMarkdown || base == "license" || base == "notice" {
		return FileClassDocs
	}
	if hasLanguage {
		if _, ok := programmingLanguages[language]; ok {
			return FileClassSource
		}
		return FileClassConfig
	}
	if strings.HasPrefix(base, ".") || strings.HasSuffix(base, ".ini") || strings.HasSuffix(base, ".cfg") || strings.HasSuffix(base, ".conf") {
		return FileClassConfig
	}
	return FileClassOther
}

func isCIBuildPath(lower, base string) bool {
	if strings.HasPrefix(lower, ".github/workflows/") || strings.HasPrefix(lower, ".circleci/") || strings.HasPrefix(lower, ".buildkite/") {
		return true
	}
	switch base {
	case ".gitlab-ci.yml", "jenkinsfile", "makefile", "azure-pipelines.yml", ".travis.yml", "docker-compose.yml", "docker-compose.yaml", "compose.yaml", "compose.yml":
		return true
	}
	return base == "dockerfile" || strings.HasPrefix(base, "dockerfile.") || strings.HasSuffix(base, ".dockerfile")
}

func isTestPath(base string, directories []string) bool {
	if strings.HasSuffix(base, "_test.go") || strings.HasSuffix(base, "_test.py") || strings.HasPrefix(base, "test_") && strings.HasSuffix(base, ".py") {
		return true
	}
	for _, marker := range []string{".test.", ".spec."} {
		if strings.Contains(base, marker) {
			return true
		}
	}
	if strings.HasSuffix(base, "test.java") || strings.HasSuffix(base, "tests.cs") || strings.HasSuffix(base, "test.kt") || strings.HasSuffix(base, "_spec.rb") {
		return true
	}
	for _, segment := range directories {
		if segment == "__tests__" || segment == "tests" || segment == "test" || segment == "testdata" || segment == "spec" {
			return true
		}
	}
	return false
}

// pathSecurityTokens maps exact lowercase path words to security signals.
var pathSecurityTokens = map[string]Signal{
	"auth": SignalAuth, "authn": SignalAuth, "authz": SignalAuth, "oauth": SignalAuth, "login": SignalAuth,
	"session": SignalAuth, "sessions": SignalAuth, "jwt": SignalAuth, "permission": SignalAuth,
	"permissions": SignalAuth, "acl": SignalAuth, "rbac": SignalAuth, "password": SignalAuth,
	"crypto": SignalCrypto, "cipher": SignalCrypto, "tls": SignalCrypto, "x509": SignalCrypto, "kms": SignalCrypto,
	"envelope": SignalCrypto, "signature": SignalCrypto, "signing": SignalCrypto, "encryption": SignalCrypto,
	"http": SignalHTTP, "https": SignalHTTP, "server": SignalHTTP, "handler": SignalHTTP, "handlers": SignalHTTP,
	"router": SignalHTTP, "middleware": SignalHTTP, "api": SignalHTTP, "cors": SignalHTTP, "csrf": SignalHTTP,
	"exec": SignalExec, "command": SignalExec, "commands": SignalExec, "shell": SignalExec, "subprocess": SignalExec,
	"sandbox": SignalExec, "spawn": SignalExec,
	"sql": SignalSQL, "query": SignalSQL, "queries": SignalSQL, "migration": SignalSQL, "migrations": SignalSQL,
	"postgres": SignalSQL, "postgresql": SignalSQL, "sqlite": SignalSQL, "mysql": SignalSQL,
	"webhook": SignalWebhook, "webhooks": SignalWebhook,
	"secret": SignalSecrets, "secrets": SignalSecrets, "credential": SignalSecrets, "credentials": SignalSecrets,
	"token": SignalSecrets, "tokens": SignalSecrets, "keyring": SignalSecrets,
	"deserialize": SignalDeserialization, "unmarshal": SignalDeserialization, "decode": SignalDeserialization,
	"pickle": SignalDeserialization,
}

// pathSignals derives signals from exact path words and file class.
func pathSignals(filePath string, class FileClass) []Signal {
	set := map[Signal]struct{}{}
	words := strings.FieldsFunc(strings.ToLower(filePath), func(r rune) bool {
		return r == '/' || r == '.' || r == '_' || r == '-'
	})
	for _, word := range words {
		if signal, ok := pathSecurityTokens[word]; ok {
			set[signal] = struct{}{}
		}
	}
	switch class {
	case FileClassCIBuild:
		set[SignalCIConfig] = struct{}{}
	case FileClassDependencyManifest:
		set[SignalDependencyManifest] = struct{}{}
	}
	if path.Ext(strings.ToLower(filePath)) == ".sql" {
		set[SignalSQL] = struct{}{}
	}
	return sortedSignals(set)
}

func sortedSignals(set map[Signal]struct{}) []Signal {
	if len(set) == 0 {
		return nil
	}
	signals := make([]Signal, 0, len(set))
	for signal := range set {
		signals = append(signals, signal)
	}
	sort.Slice(signals, func(i, j int) bool { return signals[i] < signals[j] })
	return signals
}

// validateGlob checks a slash-separated glob whose segments use path.Match syntax and at most one "**".
func validateGlob(pattern string) error {
	if pattern == "" || len(pattern) > 256 || strings.HasPrefix(pattern, "/") || strings.Contains(pattern, "\\") {
		return ErrInvalidGlob
	}
	recursiveSegments := 0
	for _, segment := range strings.Split(pattern, "/") {
		if segment == "" {
			return ErrInvalidGlob
		}
		if segment == "**" {
			recursiveSegments++
			if recursiveSegments > 1 {
				return ErrInvalidGlob
			}
			continue
		}
		if strings.Contains(segment, "**") {
			return ErrInvalidGlob
		}
		if _, err := path.Match(segment, ""); err != nil {
			return ErrInvalidGlob
		}
	}
	return nil
}

// matchGlob matches a validated glob against a repository path. "**" matches zero or more segments.
func matchGlob(pattern, filePath string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(filePath, "/"))
}

func matchSegments(pattern, segments []string) bool {
	for len(pattern) > 0 {
		if pattern[0] == "**" {
			rest := pattern[1:]
			for index := 0; index <= len(segments); index++ {
				if matchSegments(rest, segments[index:]) {
					return true
				}
			}
			return false
		}
		if len(segments) == 0 {
			return false
		}
		matched, err := path.Match(pattern[0], segments[0])
		if err != nil || !matched {
			return false
		}
		pattern, segments = pattern[1:], segments[1:]
	}
	return len(segments) == 0
}
