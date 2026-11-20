// Package repochecks detects a repository's own tests and linters, runs
// them in the check sandbox on the base and head trees of a change, twice
// each, and reports regressions: tests that pass on base and fail on head.
// Results come only from the exit status and the structured output the
// harness asks each runner for.
package repochecks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/internal/checksandbox"
)

// Runner runs one command in the sandbox; checksandbox.Run in production.
type Runner func(context.Context, checksandbox.Spec) (checksandbox.Result, error)

// Input is one change to check.
type Input struct {
	// BaseTree and HeadTree are host folders holding the two commits' trees.
	// They are only read.
	BaseTree, HeadTree string
	Scope              Scope
	// ExtraFiles are added, by slash-separated relative path, to both trees
	// in every run's scratch, for checks written for this change.
	ExtraFiles map[string][]byte
	// Limits bound each run; Budget bounds the whole review's checks.
	Limits checksandbox.Limits
	Budget time.Duration
	Runner Runner
}

// Result is one check's outcome across the four runs.
type Result struct {
	Name  string
	Stack string
	// Ran is false when the check could not run; Reason then says why.
	Ran    bool
	Reason string
	// Tests counts the tests with a stable result on head.
	Tests int
	// Regressions are tests that passed on base and failed on head, in
	// both runs of each side.
	Regressions []string
	// NewFailures are tests absent from base that failed in both head runs.
	NewFailures []string
	// Flaky counts tests dropped because two runs of one side disagreed.
	Flaky int
}

// Report is the outcome of every detected check.
type Report struct {
	Results []Result
}

// DefaultBudget bounds all checks of one review.
const DefaultBudget = 10 * time.Minute

// Run detects the checks for the change and runs each on base and head.
func Run(ctx context.Context, input Input) (Report, error) {
	return runWith(ctx, input, realHost())
}

func runWith(ctx context.Context, input Input, machine host) (Report, error) {
	checks, err := Detect(input.HeadTree, input.Scope)
	if err != nil {
		return Report{}, fmt.Errorf("the head tree cannot be read: %w", err)
	}
	if input.Runner == nil {
		input.Runner = checksandbox.Run
	}
	if input.Budget <= 0 {
		input.Budget = DefaultBudget
	}
	ctx, cancel := context.WithTimeout(ctx, input.Budget)
	defer cancel()
	base, head, cleanup, err := prepareTrees(input)
	if err != nil {
		return Report{}, err
	}
	defer cleanup()
	report := Report{}
	seeds := &goSeeds{homes: map[string]string{}}
	defer seeds.close()
	for _, check := range checks {
		report.Results = append(report.Results, runCheck(ctx, machine, input, check, base, head, seeds))
	}
	return report, nil
}

// prepareTrees returns the trees to run, with the extra files added to
// copies when there are any.
func prepareTrees(input Input) (string, string, func(), error) {
	if len(input.ExtraFiles) == 0 {
		return input.BaseTree, input.HeadTree, func() {}, nil
	}
	scratch, err := os.MkdirTemp("", "open-trestle-checks-")
	if err != nil {
		return "", "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(scratch) }
	var trees []string
	for _, side := range []struct{ name, tree string }{{"base", input.BaseTree}, {"head", input.HeadTree}} {
		target := filepath.Join(scratch, side.name)
		if err := copyFolder(side.tree, target); err != nil {
			cleanup()
			return "", "", nil, err
		}
		if err := writeFiles(target, input.ExtraFiles); err != nil {
			cleanup()
			return "", "", nil, err
		}
		trees = append(trees, target)
	}
	return trees[0], trees[1], cleanup, nil
}

func runCheck(ctx context.Context, machine host, input Input, check Check, base, head string, seeds *goSeeds) Result {
	result := Result{Name: check.Name, Stack: check.Stack}
	if check.Missing != "" {
		result.Reason = check.Missing
		return result
	}
	program, chain, err := machine.resolve(check)
	if err != nil {
		result.Reason = check.Tool + " is not installed on this machine"
		return result
	}
	spec := checksandbox.Spec{
		Dir: filepath.FromSlash(check.Dir), Args: append(append([]string{program}, platformArgs(check)...), check.Args...),
		Path: chain.path, ReadOnly: chain.readOnly, Env: chain.env, Report: check.Report, Limits: input.Limits,
	}
	if check.Stack == "go" {
		spec.HomeSeed = seeds.home(ctx, program, chain, []string{base, head})
	}
	trees := []string{base, head}
	var sides [2][2]map[string]Outcome
	for index, tree := range trees {
		if index == 0 && !isDir(filepath.Join(tree, filepath.FromSlash(check.Dir))) {
			// The check is new on head; nothing of it exists on base.
			sides[0] = [2]map[string]Outcome{{}, {}}
			continue
		}
		for attempt := range 2 {
			spec.Tree = tree
			tests, reason := runOnce(ctx, input.Runner, spec, check, trees)
			if reason != "" {
				result.Reason = reason
				return result
			}
			sides[index][attempt] = tests
		}
	}
	result.Ran = true
	compare(&result, sides, !removesTests(input.Scope, head))
	return result
}

// removesTests reports whether the change deletes or renames a test file,
// or whether that cannot be known.
func removesTests(scope Scope, head string) bool {
	if scope.whole() {
		return true
	}
	for _, file := range scope.Changed {
		if isTestFile(file) && !isFile(filepath.Join(head, filepath.FromSlash(file))) {
			return true
		}
	}
	return false
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

func isFile(name string) bool {
	info, err := os.Stat(name)
	return err == nil && info.Mode().IsRegular()
}

// platformArgs are flags a toolchain needs inside this system's sandbox.
// The go command cannot run there on Windows, where the NUL device grants
// nothing to sandboxed processes; its checks report that.
// Inside a Windows AppContainer, Node cannot resolve real paths through
// the drive root and its per-file test processes do not start, so tests run
// in one process without path resolution.
func platformArgs(check Check) []string {
	if runtime.GOOS == "windows" && check.Tool == "node" && check.Format == FormatTAP {
		return []string{"--preserve-symlinks", "--preserve-symlinks-main", "--test-isolation=none"}
	}
	return nil
}

// runOnce runs the check once and returns its results, or the reason it
// could not run.
func runOnce(ctx context.Context, runner Runner, spec checksandbox.Spec, check Check, trees []string) (map[string]Outcome, string) {
	if ctx.Err() != nil {
		return nil, "the review's time for checks ran out"
	}
	outcome, err := runner(ctx, spec)
	switch {
	case err != nil:
		var unavailable *checksandbox.Unavailable
		if errors.As(err, &unavailable) {
			return nil, unavailable.Reason
		}
		return nil, "the sandbox failed"
	case outcome.TimedOut:
		return nil, fmt.Sprintf("it ran past its %v time limit", spec.Limits.Time)
	case outcome.OutputExceeded:
		return nil, "its output passed the limit"
	case outcome.DiskExceeded:
		return nil, "it filled its scratch space"
	}
	parsed := parseRun(check.Format, check.Name, outcome.ExitCode, outcome.Stdout, outcome.Stderr, outcome.Report)
	// A module the repository itself provides is not a missing dependency:
	// a change that renamed or removed it broke the tests that use it.
	parsed.missing = slices.DeleteFunc(parsed.missing, func(name string) bool { return repositoryProvides(name, trees) })
	if len(parsed.missing) > 0 {
		sort.Strings(parsed.missing)
		return nil, "missing dependency: " + strings.Join(parsed.missing, ", ")
	}
	if len(parsed.tests) == 0 {
		if outcome.ExitCode == 0 {
			return map[string]Outcome{}, ""
		}
		return nil, fmt.Sprintf("the runner exited with status %d and reported no results", outcome.ExitCode)
	}
	if check.Format != FormatExit {
		recordExitStatus(parsed, check.Name, outcome.ExitCode)
	}
	return parsed.tests, ""
}

// exitStatusSuffix marks the result recordExitStatus adds.
const exitStatusSuffix = " (exit status)"

// recordExitStatus adds the command's own result: a pass on exit status
// zero, and a failure when it exited otherwise although no reported test
// failed. Output that claims every test passed therefore cannot hide a
// failing run.
func recordExitStatus(parsed parsed, name string, exitCode int) {
	id := name + exitStatusSuffix
	if exitCode == 0 {
		parsed.record(id, Pass)
		return
	}
	for _, outcome := range parsed.tests {
		if outcome == Fail {
			return
		}
	}
	parsed.record(id, Fail)
}

// repositoryProvides reports whether name is part of the repository: a path
// (a test runner names a file it could not load), a Python package or
// module at the top of either tree, or a package of a Go module declared in
// either tree.
func repositoryProvides(name string, trees []string) bool {
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return true
	}
	if strings.HasPrefix(name, ".") {
		return filepath.IsLocal(filepath.Clean(name))
	}
	top := strings.SplitN(name, ".", 2)[0]
	for _, tree := range trees {
		if isDir(filepath.Join(tree, top)) || isFile(filepath.Join(tree, top+".py")) || isDir(filepath.Join(tree, "src", top)) {
			return true
		}
		for _, module := range goModules(tree) {
			if name == module || strings.HasPrefix(name, module+"/") {
				return true
			}
		}
	}
	return false
}

var moduleLine = regexp.MustCompile(`(?m)^module\s+"?([^\s"]+)"?\s*$`)

// goModules are the module paths of the go.mod files in tree.
func goModules(tree string) []string {
	files, err := listFiles(tree)
	if err != nil {
		return nil
	}
	var modules []string
	for _, file := range files {
		if path.Base(file) != "go.mod" {
			continue
		}
		if data, err := os.ReadFile(filepath.Join(tree, filepath.FromSlash(file))); err == nil {
			if match := moduleLine.FindSubmatch(data); match != nil {
				modules = append(modules, string(match[1]))
			}
		}
	}
	return modules
}

// compare drops tests whose two runs on one side disagree and classifies
// the rest. With vanished set, a test that passed on base and of whose
// group (its package, class or file) head reported nothing at all is a
// regression too: something on head stopped the tests from running.
func compare(result *Result, sides [2][2]map[string]Outcome, vanished bool) {
	stable := func(runs [2]map[string]Outcome) (map[string]Outcome, map[string]bool) {
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
	base, baseFlaky := stable(sides[0])
	head, headFlaky := stable(sides[1])
	dropped := map[string]bool{}
	for id := range baseFlaky {
		dropped[id] = true
	}
	for id := range headFlaky {
		dropped[id] = true
	}
	result.Flaky = len(dropped)
	for id, outcome := range head {
		if dropped[id] {
			continue
		}
		result.Tests++
		if outcome != Fail {
			continue
		}
		switch before, ok := base[id]; {
		case ok && before == Pass, !ok && passedWithin(base, id):
			result.Regressions = append(result.Regressions, id)
		case !ok:
			result.NewFailures = append(result.NewFailures, id)
		}
	}
	if vanished {
		reported := map[string]bool{}
		for _, run := range sides[1] {
			for id := range run {
				// A result for a whole package or file names its group too.
				reported[id], reported[testGroup(id)] = true, true
			}
		}
		for id, outcome := range base {
			if outcome == Pass && !dropped[id] && !reported[testGroup(id)] && !strings.HasSuffix(id, exitStatusSuffix) {
				result.Regressions = append(result.Regressions, id+" (did not run on head)")
			}
		}
	}
	slices.Sort(result.Regressions)
	slices.Sort(result.NewFailures)
}

// testGroup is the package, class, module or file a test ID names.
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
	return ""
}

// passedWithin reports whether base has a passing test inside id, as when
// a Go package that passed its tests on base fails to build on head.
func passedWithin(base map[string]Outcome, id string) bool {
	for other, outcome := range base {
		if outcome == Pass && strings.HasPrefix(other, id+".") {
			return true
		}
	}
	return false
}
