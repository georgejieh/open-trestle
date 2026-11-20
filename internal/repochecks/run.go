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
	"path/filepath"
	"runtime"
	"slices"
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
	// Tests counts the results with a stable outcome on head.
	Tests int
	// Regressions passed on base and failed on head, in both runs of each
	// side: tests, and packages, modules or files that failed as a whole on
	// head while tests in them passed on base. A run that passed its time,
	// output or disk limit on head, or exited with a failure without results
	// there, after base ran within them, is one too.
	Regressions []string
	// NewFailures are tests absent from base that failed in both head runs.
	NewFailures []string
	// StoppedRunning passed on base and have no result on head, and no
	// failure on head covers them: the change renamed or removed them, or
	// something stopped them from running.
	StoppedRunning []string
	// Fixed failed on base and pass on head; StillFailing fail on both.
	Fixed, StillFailing int
	// Flaky counts tests dropped because two runs of one side disagreed.
	Flaky int
}

// Report is the outcome of every detected check.
type Report struct {
	Results []Result
	// Leftovers are the scratch folders that runs could not remove. They
	// are host paths, for the person running the review, not the models.
	Leftovers []string
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
	trees := newTrees(input.BaseTree, input.HeadTree)
	report := Report{}
	run := input.Runner
	input.Runner = func(ctx context.Context, spec checksandbox.Spec) (checksandbox.Result, error) {
		result, err := run(ctx, spec)
		if result.Leftover != "" {
			report.Leftovers = append(report.Leftovers, result.Leftover)
		}
		return result, err
	}
	seeds := &goSeeds{homes: map[string]string{}}
	defer seeds.close()
	for _, check := range checks {
		report.Results = append(report.Results, runCheck(ctx, machine, input, check, trees, seeds))
	}
	return report, nil
}

func runCheck(ctx context.Context, machine host, input Input, check Check, trees trees, seeds *goSeeds) Result {
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
		Dir: filepath.FromSlash(check.Dir), Args: append([]string{program}, platformArgs(check)...),
		Path: chain.path, ReadOnly: chain.readOnly, Env: chain.env, Report: check.Report, Limits: input.Limits,
	}
	if check.Stack == "go" {
		spec.HomeSeed = seeds.home(ctx, program, chain, []string{trees.base, trees.head})
	}
	base, problem := runSide(ctx, input.Runner, spec, check, trees, trees.base)
	if problem != nil {
		result.Reason = problem.reason("base")
		return result
	}
	head, problem := runSide(ctx, input.Runner, spec, check, trees, trees.head)
	switch {
	case problem != nil && problem.headFailure != "":
		// Base ran within its limits; head did not.
		result.Ran, result.Tests = true, 1
		result.Regressions = []string{check.Name + " (" + problem.headFailure + " on head)"}
		return result
	case problem != nil:
		result.Reason = problem.reason("head")
		return result
	}
	result.Ran = true
	compare(&result, [2][2]map[string]Outcome{base, head}, deletedTests(check, input.Scope, trees))
	return result
}

// runSide runs the check twice on tree and returns both runs' results, or
// the problem that stopped it. A tree without the check's folder or any of
// its Go packages has no results: the check is new there.
func runSide(ctx context.Context, runner Runner, spec checksandbox.Spec, check Check, trees trees, tree string) ([2]map[string]Outcome, *problem) {
	runs := [2]map[string]Outcome{{}, {}}
	args, present := sideArgs(check, tree)
	if !present {
		return runs, nil
	}
	spec.Tree, spec.Args = tree, append(slices.Clip(spec.Args), args...)
	for attempt := range runs {
		tests, problem := runOnce(ctx, runner, spec, check, trees)
		if problem != nil {
			return runs, problem
		}
		runs[attempt] = tests
	}
	return runs, nil
}

// sideArgs are the check's arguments on tree, and false when the check has
// nothing to run there.
func sideArgs(check Check, tree string) ([]string, bool) {
	dir := filepath.Join(tree, filepath.FromSlash(check.Dir))
	if !isDir(dir) {
		return nil, false
	}
	if len(check.Packages) == 0 {
		return check.Args, true
	}
	args := slices.Clone(check.Args)
	for _, pattern := range check.Packages {
		if pattern == "./..." || hasGoFiles(filepath.Join(dir, filepath.FromSlash(pattern))) {
			args = append(args, pattern)
		}
	}
	return args, len(args) > len(check.Args)
}

func hasGoFiles(dir string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(entries, func(entry os.DirEntry) bool {
		return entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".go")
	})
}

// problem is why one run gave no results to compare. headFailure, when
// set, is the short name of a failure that the code under test can cause
// (passing a limit, or failing without results); when base ran without
// it, it is a regression on head.
type problem struct {
	text        string
	sided       bool
	headFailure string
}

// reason is the problem's text, naming the side it happened on when it is
// about that side's code.
func (p problem) reason(side string) string {
	if !p.sided {
		return p.text
	}
	return p.text + " on " + side
}

var errBudget = &problem{text: "the review's time for checks ran out"}

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

// runOnce runs the check once and returns its results, or the problem that
// left it without any.
func runOnce(ctx context.Context, runner Runner, spec checksandbox.Spec, check Check, trees trees) (map[string]Outcome, *problem) {
	if ctx.Err() != nil {
		return nil, errBudget
	}
	outcome, err := runner(ctx, spec)
	switch {
	case ctx.Err() != nil:
		// The review's budget, not the run's own limit, stopped it.
		return nil, errBudget
	case err != nil:
		var unavailable *checksandbox.Unavailable
		if errors.As(err, &unavailable) {
			return nil, &problem{text: unavailable.Reason}
		}
		return nil, &problem{text: "the sandbox failed"}
	case outcome.TimedOut:
		return nil, &problem{text: fmt.Sprintf("it ran past its %v time limit", spec.Limits.Time), sided: true, headFailure: "timed out"}
	case outcome.OutputExceeded:
		return nil, &problem{text: "its output passed the limit", sided: true, headFailure: "output past the limit"}
	case outcome.DiskExceeded:
		return nil, &problem{text: "it filled its scratch space", sided: true, headFailure: "scratch space filled"}
	}
	parsed := parseRun(check.Format, check.Name, outcome.ExitCode, outcome.Stdout, outcome.Stderr, outcome.Report, trees.provides)
	switch {
	case parsed.overflow:
		return nil, &problem{text: fmt.Sprintf("it reported more than %d results", maxRunResults), sided: true}
	case len(parsed.tests) > 0:
		if check.Format != FormatExit {
			recordExitStatus(parsed, check.Name, outcome.ExitCode)
		}
		return parsed.tests, nil
	case len(parsed.missing) > 0:
		slices.Sort(parsed.missing)
		return nil, &problem{text: "missing dependency: " + strings.Join(slices.Compact(parsed.missing), ", "), sided: true}
	case outcome.ExitCode == 0:
		return map[string]Outcome{}, nil
	}
	return nil, &problem{text: fmt.Sprintf("the runner exited with status %d and reported no results", outcome.ExitCode), sided: true,
		headFailure: fmt.Sprintf("exit status %d without results", outcome.ExitCode)}
}

// exitStatusSuffix marks the result recordExitStatus adds.
const exitStatusSuffix = " (exit status)"

// recordExitStatus adds the command's own result: a pass on exit status
// zero, and a failure when it exited otherwise although no reported test
// failed. Output that claims every test passed therefore cannot hide a
// failing run.
func recordExitStatus(parsed *parsed, name string, exitCode int) {
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
