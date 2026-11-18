package repoindex

import (
	"bytes"
	"path"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// Role says what a file is for. Roles come from fixed rules on the path
// and, for generated code, on the first bytes of the content.
type Role string

const (
	RoleSource    Role = "source"
	RoleTest      Role = "test"
	RoleConfig    Role = "config"
	RoleDocs      Role = "docs"
	RoleGenerated Role = "generated"
	RoleVendored  Role = "vendored"
	RoleOther     Role = "other"
)

var (
	vendoredDirectories = map[string]bool{"vendor": true, "third_party": true, "third-party": true, "thirdparty": true, "node_modules": true, "bower_components": true, "Pods": true, "Carthage": true}
	testDirectories     = map[string]bool{"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true, "testdata": true, "fixtures": true, "__fixtures__": true, "__mocks__": true}
	docsDirectories     = map[string]bool{"doc": true, "docs": true, "documentation": true}

	generatedNames = map[string]bool{
		"package-lock.json": true, "yarn.lock": true, "pnpm-lock.yaml": true, "npm-shrinkwrap.json": true,
		"Cargo.lock": true, "go.sum": true, "poetry.lock": true, "Pipfile.lock": true, "composer.lock": true,
		"Gemfile.lock": true, "Podfile.lock": true, "Package.resolved": true, "uv.lock": true,
	}
	generatedSuffixes = []string{
		".pb.go", ".pb.gw.go", "_pb2.py", "_pb2_grpc.py", "_pb2.pyi", ".pb.h", ".pb.cc", ".pb.c",
		"_grpc.pb.go", ".min.js", ".min.css", ".designer.cs", ".g.cs", ".g.i.cs", ".g.dart",
		".freezed.dart", "_generated.go", ".generated.ts", ".generated.js", ".gen.go",
	}
	generatedPrefixes = []string{"zz_generated."}

	docsExtensions   = map[string]bool{".md": true, ".markdown": true, ".rst": true, ".adoc": true, ".asciidoc": true, ".txt": true, ".rtf": true}
	docsNames        = []string{"README", "CHANGELOG", "CHANGES", "LICENSE", "LICENCE", "NOTICE", "AUTHORS", "CONTRIBUTING", "CODE_OF_CONDUCT", "SECURITY", "SUPPORT", "GOVERNANCE", "HISTORY"}
	configExtensions = map[string]bool{
		".json": true, ".jsonc": true, ".json5": true, ".yaml": true, ".yml": true, ".toml": true, ".ini": true,
		".cfg": true, ".conf": true, ".properties": true, ".xml": true, ".plist": true, ".gradle": true,
		".cmake": true, ".mk": true, ".bazel": true, ".bzl": true, ".csproj": true, ".fsproj": true,
		".vbproj": true, ".sln": true, ".props": true, ".targets": true, ".gemspec": true, ".editorconfig": true,
		".env": true, ".mod": true, ".work": true,
	}
	configNames = map[string]bool{
		"Makefile": true, "makefile": true, "GNUmakefile": true, "Dockerfile": true, "Containerfile": true,
		"CMakeLists.txt": true, "BUILD": true, "WORKSPACE": true, "Gemfile": true, "Rakefile": true,
		"Podfile": true, "Package.swift": true, "Pipfile": true, "requirements.txt": true, "Jenkinsfile": true,
		"Procfile": true, "Vagrantfile": true, "Justfile": true, "justfile": true, "Taskfile": true,
		".gitignore": true, ".gitattributes": true, ".gitmodules": true, ".dockerignore": true,
		".npmrc": true, ".nvmrc": true, ".prettierrc": true, ".eslintrc": true, ".babelrc": true,
		"CODEOWNERS": true, "setup.py": true,
	}
	configDirectories = map[string]bool{".github": true, ".circleci": true, ".gitlab": true, ".buildkite": true, ".devcontainer": true}
)

// ClassifyPath returns the role a path implies, checked in this order:
// vendored (a vendor, third_party, node_modules or similar directory),
// generated (lock files and the names code generators give their output),
// test (a test directory or a test file name of the file's language), docs
// (documentation names and extensions, and files under a top-level docs
// directory that are not code, HTML included), config, source (a language
// with an analyzer) and other. ClassifyContent
// can still mark a source or test file generated.
func ClassifyPath(filePath string) Role {
	directories := strings.Split(path.Dir(filePath), "/")
	base := path.Base(filePath)
	extension := strings.ToLower(path.Ext(base))
	for _, d := range directories {
		if vendoredDirectories[d] {
			return RoleVendored
		}
	}
	if generatedNames[base] || extension == ".lock" || hasAnySuffix(base, generatedSuffixes) || hasAnyPrefix(base, generatedPrefixes) {
		return RoleGenerated
	}
	language, analysable := syntaxanalysis.LanguageForPath(base)
	if analysable && isTestFile(base, language) {
		return RoleTest
	}
	for _, d := range directories {
		if testDirectories[d] {
			return RoleTest
		}
	}
	if docsExtensions[extension] && !configNames[base] || isDocsName(base) {
		return RoleDocs
	}
	if configNames[base] || configExtensions[extension] || strings.HasPrefix(base, "tsconfig") && extension == ".json" {
		return RoleConfig
	}
	for _, d := range directories {
		if configDirectories[d] {
			return RoleConfig
		}
	}
	inDocs := docsDirectories[directories[0]]
	switch {
	case analysable && !(inDocs && language == syntaxanalysis.LanguageHTML):
		return RoleSource
	case inDocs:
		return RoleDocs
	}
	return RoleOther
}

// isTestFile applies each language's test file naming convention.
func isTestFile(base string, language syntaxanalysis.Language) bool {
	stem := strings.TrimSuffix(base, path.Ext(base))
	switch language {
	case syntaxanalysis.LanguageGo:
		return strings.HasSuffix(base, "_test.go")
	case syntaxanalysis.LanguagePython:
		return strings.HasPrefix(stem, "test_") || strings.HasSuffix(stem, "_test") || base == "conftest.py"
	case syntaxanalysis.LanguageJavaScript, syntaxanalysis.LanguageTypeScript, syntaxanalysis.LanguageTSX:
		return strings.Contains(base, ".test.") || strings.Contains(base, ".spec.")
	case syntaxanalysis.LanguageJava, syntaxanalysis.LanguageCSharp, syntaxanalysis.LanguageSwift, syntaxanalysis.LanguagePHP:
		return strings.HasSuffix(stem, "Test") || strings.HasSuffix(stem, "Tests") || strings.HasSuffix(stem, "IT") || strings.HasSuffix(stem, "Spec")
	case syntaxanalysis.LanguageRuby:
		return strings.HasSuffix(stem, "_spec") || strings.HasSuffix(stem, "_test") || strings.HasPrefix(stem, "test_")
	case syntaxanalysis.LanguageRust, syntaxanalysis.LanguageC, syntaxanalysis.LanguageCPP:
		return strings.HasSuffix(stem, "_test") || strings.HasSuffix(stem, "_tests") || strings.HasSuffix(stem, "_unittest") || strings.HasPrefix(stem, "test_")
	}
	return false
}

func isDocsName(base string) bool {
	upper := strings.ToUpper(strings.TrimSuffix(base, path.Ext(base)))
	for _, name := range docsNames {
		if upper == name {
			return true
		}
	}
	return false
}

func hasAnySuffix(s string, suffixes []string) bool {
	for _, suffix := range suffixes {
		if strings.HasSuffix(s, suffix) {
			return true
		}
	}
	return false
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}
	return false
}

// generatedMarkerBytes is how far into a file a generator's marker counts.
const generatedMarkerBytes = 2048

// isGeneratedContent reports a generator's marker near the top of a file:
// the Go convention "Code generated ... DO NOT EDIT." or "@generated".
func isGeneratedContent(content []byte) bool {
	head := content[:min(len(content), generatedMarkerBytes)]
	for _, line := range bytes.Split(head, []byte{'\n'}) {
		if bytes.Contains(line, []byte("@generated")) || bytes.Contains(line, []byte("Code generated")) && bytes.Contains(line, []byte("DO NOT EDIT")) {
			return true
		}
	}
	return false
}

// binarySniffBytes is how much of a file is checked for a NUL byte, the
// rule Git uses to call a file binary.
const binarySniffBytes = 8000

func isBinaryContent(content []byte) bool {
	return bytes.IndexByte(content[:min(len(content), binarySniffBytes)], 0) >= 0
}
