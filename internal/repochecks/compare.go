package repochecks

import (
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// compare drops tests whose two runs on one side disagree and classifies
// the rest by their base and head outcomes. A test that passed on base and
// of whose group (its package, class or file, or the test itself when it
// has none) head reported nothing stopped running, unless a failure on head
// covers it, which is then the regression, or deleted says the change
// removed its test file.
func compare(result *Result, sides [2][2]map[string]Outcome, deleted func(string) bool) {
	base, baseFlaky := stable(sides[0])
	head, headFlaky := stable(sides[1])
	dropped := baseFlaky
	for id := range headFlaky {
		dropped[id] = true
	}
	result.Flaky = len(dropped)
	var failures []string
	for id, outcome := range head {
		if dropped[id] {
			continue
		}
		result.Tests++
		before, ok := base[id]
		switch {
		case outcome == Pass && ok && before == Fail:
			result.Fixed++
		case outcome != Fail:
		case ok && before == Fail:
			result.StillFailing++
		case ok && before == Pass, !ok && passedWithin(base, id):
			result.Regressions = append(result.Regressions, id)
		case !ok:
			result.NewFailures = append(result.NewFailures, id)
		}
		if outcome == Fail {
			failures = append(failures, id)
		}
	}
	reported := map[string]bool{}
	for _, run := range sides[1] {
		for id := range run {
			// A result for a whole package or file names its group too.
			reported[id], reported[testGroup(id)] = true, true
		}
	}
	for id, outcome := range base {
		if outcome != Pass || dropped[id] || reported[testGroup(id)] || strings.HasSuffix(id, exitStatusSuffix) || deleted(id) ||
			slices.ContainsFunc(failures, func(failure string) bool { return within(id, failure) }) {
			continue
		}
		result.StoppedRunning = append(result.StoppedRunning, id)
	}
	slices.Sort(result.Regressions)
	slices.Sort(result.NewFailures)
	slices.Sort(result.StoppedRunning)
}

// stable keeps the tests whose two runs agree and returns the others as
// flaky.
func stable(runs [2]map[string]Outcome) (map[string]Outcome, map[string]bool) {
	kept, flaky := map[string]Outcome{}, map[string]bool{}
	for id, first := range runs[0] {
		if second, ok := runs[1][id]; ok && second == first {
			kept[id] = first
		} else {
			flaky[id] = true
		}
	}
	for id := range runs[1] {
		if _, ok := runs[0][id]; !ok {
			flaky[id] = true
		}
	}
	return kept, flaky
}

// testGroup is the package, class, module or file a test ID names, or the
// ID itself when it names none.
func testGroup(id string) string {
	if group, _, ok := strings.Cut(id, "::"); ok {
		return group
	}
	if group, _, ok := strings.Cut(id, " > "); ok {
		return group
	}
	if index := strings.LastIndex(id, "."); index > 0 {
		return id[:index]
	}
	return id
}

// within reports whether test is inside the package, module, class or file
// that the result id names, as a test of a Go package that failed to build
// is, or a test of a Python module that could not be imported.
func within(test, id string) bool {
	scope := strings.TrimPrefix(id, unittestImportFailure)
	for _, separator := range []string{".", "::", " > "} {
		if strings.HasPrefix(test, scope+separator) {
			return true
		}
	}
	return false
}

// passedWithin reports whether base has a passing test inside id.
func passedWithin(base map[string]Outcome, id string) bool {
	for other, outcome := range base {
		if outcome == Pass && within(other, id) {
			return true
		}
	}
	return false
}

// deletedTests reports the test IDs that belong to a test file the change
// deletes or renames, for the stacks whose IDs name a test's package,
// module or file: Go packages, Python modules and Rust integration test
// binaries. Other stacks' tests of a deleted file are listed as stopped.
func deletedTests(check Check, scope Scope, trees trees) func(string) bool {
	var prefixes []string
	for _, file := range scope.Changed {
		if !isTestFile(file) || !isFile(filepath.Join(trees.base, filepath.FromSlash(file))) || isFile(filepath.Join(trees.head, filepath.FromSlash(file))) {
			continue
		}
		switch {
		case check.Stack == "go" && strings.HasSuffix(file, "_test.go"):
			if module := goModulePath(trees.base, check.Dir); module != "" {
				if relative, ok := insideFolder(check.Dir, path.Dir(file)); ok {
					prefixes = append(prefixes, path.Join(module, relative)+".")
				}
			}
		case check.Stack == "python" && strings.HasSuffix(file, ".py"):
			module := strings.ReplaceAll(strings.TrimSuffix(file, ".py"), "/", ".")
			prefixes = append(prefixes, module+".", module+"::")
		case check.Stack == "rust" && strings.HasSuffix(file, ".rs") && path.Base(path.Dir(file)) == "tests":
			binary := strings.TrimSuffix(path.Base(file), ".rs")
			prefixes = append(prefixes, binary+"::", binary+"#")
		}
	}
	return func(id string) bool {
		return slices.ContainsFunc(prefixes, func(prefix string) bool { return strings.HasPrefix(id, prefix) })
	}
}

// insideFolder returns folder relative to root when it is inside it.
func insideFolder(root, folder string) (string, bool) {
	if root == "." {
		return folder, true
	}
	if folder == root {
		return ".", true
	}
	relative, ok := strings.CutPrefix(folder, root+"/")
	return relative, ok
}

func isTestFile(file string) bool {
	base := path.Base(file)
	for _, marker := range []string{"_test.go", ".test.", ".spec.", "_test.rs"} {
		if strings.Contains(base, marker) {
			return true
		}
	}
	return isPythonTest(file) || strings.Contains("/"+file, "/tests/") || strings.Contains("/"+file, "/test/")
}
