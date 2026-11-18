package repoprofile

import (
	"path"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/repoindex"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// Test layouts.
const (
	LayoutColocated     = "colocated"
	LayoutTestDirectory = "test_directory"
)

// Tests describes how a repository tests itself.
type Tests struct {
	Frameworks []string `json:"frameworks"` // closed tokens, sorted
	Layouts    []string `json:"layouts"`    // closed tokens, sorted
	Files      int      `json:"files"`      // analysed test files
}

type frameworkRule struct {
	languages []syntaxanalysis.Language
	source    string
	framework string
}

var (
	scriptLanguages = []syntaxanalysis.Language{syntaxanalysis.LanguageJavaScript, syntaxanalysis.LanguageTypeScript, syntaxanalysis.LanguageTSX}

	// frameworkRules name a test framework from an import source: the source
	// equals the rule's or continues it after a slash or a dot.
	frameworkRules = []frameworkRule{
		{[]syntaxanalysis.Language{syntaxanalysis.LanguageGo}, "testing", "go_testing"},
		{[]syntaxanalysis.Language{syntaxanalysis.LanguageGo}, "github.com/stretchr/testify", "testify"},
		{[]syntaxanalysis.Language{syntaxanalysis.LanguagePython}, "pytest", "pytest"},
		{[]syntaxanalysis.Language{syntaxanalysis.LanguagePython}, "unittest", "unittest"},
		{scriptLanguages, "vitest", "vitest"},
		{scriptLanguages, "jest", "jest"},
		{scriptLanguages, "@jest/globals", "jest"},
		{scriptLanguages, "mocha", "mocha"},
		{scriptLanguages, "@playwright/test", "playwright"},
		{[]syntaxanalysis.Language{syntaxanalysis.LanguageJava}, "org.junit", "junit"},
		{[]syntaxanalysis.Language{syntaxanalysis.LanguageRuby}, "rspec", "rspec"},
		{[]syntaxanalysis.Language{syntaxanalysis.LanguageRuby}, "minitest", "minitest"},
	}

	testDirectories = map[string]bool{"test": true, "tests": true, "__tests__": true, "spec": true, "specs": true}
)

func (r frameworkRule) matches(language syntaxanalysis.Language, source string) bool {
	return slices.Contains(r.languages, language) &&
		(source == r.source || strings.HasPrefix(source, r.source+"/") || strings.HasPrefix(source, r.source+"."))
}

func detectTests(files []repoindex.FileEntry, imports func(path string) []string) Tests {
	tests := Tests{Frameworks: []string{}, Layouts: []string{}}
	sourceDirectories := map[string]bool{}
	for _, f := range files {
		if f.Role == repoindex.RoleSource && f.Status == repoindex.StatusIndexed && f.Language != "" {
			sourceDirectories[path.Dir(f.Path)+"\x00"+string(f.Language)] = true
		}
	}
	frameworks, layouts := map[string]bool{}, map[string]bool{}
	for _, f := range files {
		if !isAnalysedTest(f) {
			continue
		}
		tests.Files++
		dir := path.Dir(f.Path)
		if sourceDirectories[dir+"\x00"+string(f.Language)] {
			layouts[LayoutColocated] = true
		}
		for _, element := range strings.Split(dir, "/") {
			if testDirectories[element] {
				layouts[LayoutTestDirectory] = true
			}
		}
		if imports == nil {
			continue
		}
		for _, source := range imports(f.Path) {
			for _, rule := range frameworkRules {
				if rule.matches(f.Language, source) {
					frameworks[rule.framework] = true
				}
			}
		}
	}
	for name := range frameworks {
		tests.Frameworks = append(tests.Frameworks, name)
	}
	for name := range layouts {
		tests.Layouts = append(tests.Layouts, name)
	}
	slices.Sort(tests.Frameworks)
	slices.Sort(tests.Layouts)
	return tests
}
