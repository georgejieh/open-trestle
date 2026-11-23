package repochecks

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/checksandbox"
)

func TestMain(m *testing.M) {
	checksandbox.RunChildIfRequested()
	// Sandbox grants are recorded below the state folder; keep the tests'
	// records out of the user's.
	state, err := os.MkdirTemp("", "open-trestle-test-state-")
	if err != nil {
		panic(err)
	}
	os.Setenv("XDG_STATE_HOME", state)
	code := m.Run()
	_ = checksandbox.RemoveToolchainGrants()
	os.RemoveAll(state)
	os.Exit(code)
}

// fakeRunner answers each run from a script keyed by tree side and attempt.
type fakeRunner struct {
	mu      sync.Mutex
	base    string
	calls   map[string]int
	answers func(side string, attempt int, spec checksandbox.Spec) (checksandbox.Result, error)
}

func (f *fakeRunner) run(_ context.Context, spec checksandbox.Spec) (checksandbox.Result, error) {
	f.mu.Lock()
	side := "head"
	if spec.Tree == f.base {
		side = "base"
	}
	key := side + strings.Join(spec.Args, " ")
	attempt := f.calls[key]
	f.calls[key]++
	f.mu.Unlock()
	return f.answers(side, attempt, spec)
}

func goEvents(results map[string]string) []byte {
	var lines []string
	for test, action := range results {
		lines = append(lines, `{"Action":"`+action+`","Package":"m/a","Test":"`+test+`"}`)
	}
	slices.Sort(lines)
	return []byte(strings.Join(lines, "\n"))
}

func fakeHost(t *testing.T) host {
	program := filepath.Join(t.TempDir(), "bin", "go")
	if err := os.MkdirAll(filepath.Dir(program), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(program, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	return host{lookPath: func(string) (string, error) { return program, nil }, getenv: func(string) string { return "" }, home: t.TempDir()}
}

func goTrees(t *testing.T) (string, string) {
	files := map[string]string{"go.mod": "module m\n", "a/a.go": "package a"}
	return writeTree(t, files), writeTree(t, files)
}

func runFake(t *testing.T, answers func(side string, attempt int, spec checksandbox.Spec) (checksandbox.Result, error)) Report {
	t.Helper()
	base, head := goTrees(t)
	fake := &fakeRunner{base: base, calls: map[string]int{}, answers: answers}
	report, err := runWith(context.Background(), Input{
		BaseTree: base, HeadTree: head, Scope: Scope{Changed: []string{"a/a.go"}},
		Limits: checksandbox.DefaultLimits(), Runner: fake.run,
	}, fakeHost(t))
	if err != nil {
		t.Fatal(err)
	}
	return report
}

func TestRunFindsRegressionsAndDropsFlakyTests(t *testing.T) {
	report := runFake(t, func(side string, attempt int, spec checksandbox.Spec) (checksandbox.Result, error) {
		if spec.Args[1] == "vet" {
			return checksandbox.Result{}, nil
		}
		results := map[string]string{"TestStable": "pass", "TestBroken": "pass", "TestFlaky": "pass", "TestAlwaysFails": "fail"}
		if side == "head" {
			results["TestBroken"] = "fail"
			results["TestNew"] = "fail"
		}
		if attempt == 1 {
			results["TestFlaky"] = "fail"
		}
		return checksandbox.Result{ExitCode: 1, Stdout: goEvents(results)}, nil
	})
	if len(report.Results) != 2 {
		t.Fatalf("results %+v", report.Results)
	}
	test := report.Results[0]
	if !test.Ran || !slices.Equal(test.Regressions, []string{"m/a.TestBroken"}) || !slices.Equal(test.NewFailures, []string{"m/a.TestNew"}) || test.Flaky != 1 || test.Tests != 4 {
		t.Fatalf("go test result %+v", test)
	}
	if vet := report.Results[1]; !vet.Ran || len(vet.Regressions) != 0 || vet.Tests != 0 {
		t.Fatalf("go vet result %+v", vet)
	}
}

func TestRunTreatsAFailingExitAsARegressionWhenEveryTestClaimsToPass(t *testing.T) {
	report := runFake(t, func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		result := checksandbox.Result{Stdout: goEvents(map[string]string{"TestA": "pass"})}
		if side == "head" && spec.Args[1] == "test" {
			result.ExitCode = 1
		}
		return result, nil
	})
	if got := report.Results[0].Regressions; !slices.Equal(got, []string{"go test ./a (exit status)"}) {
		t.Fatalf("regressions %v", got)
	}
}

// A test that passed on base and has no result on head stopped running; it
// is listed apart from the regressions, since a rename does the same.
func TestRunListsTestsThatStopRunningOnHead(t *testing.T) {
	report := runFake(t, func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		if side == "head" && spec.Args[1] == "test" {
			// TestMain exited before any test ran.
			return checksandbox.Result{}, nil
		}
		return checksandbox.Result{Stdout: goEvents(map[string]string{"TestA": "pass"})}, nil
	})
	if got := report.Results[0]; !got.Ran || len(got.Regressions) != 0 || !slices.Equal(got.StoppedRunning, []string{"m/a.TestA"}) {
		t.Fatalf("result %+v", got)
	}
}

// Tests of a Python module that head cannot import are covered by that
// module's failure, which is the regression.
func TestCompareCoversTestsOfAModuleThatFailsAsAWhole(t *testing.T) {
	base := map[string]Outcome{"tests.test_price.Total.test_sum": Pass, "tests.test_other.O.test_ok": Pass}
	head := map[string]Outcome{"unittest.loader._FailedTest.tests.test_price": Fail, "tests.test_other.O.test_ok": Pass}
	var result Result
	compare(&result, [2][2]map[string]Outcome{{base, base}, {head, head}}, func(string) bool { return false })
	if !slices.Equal(result.Regressions, []string{"unittest.loader._FailedTest.tests.test_price"}) || len(result.StoppedRunning) != 0 || result.Tests != 2 {
		t.Fatalf("result %+v", result)
	}
}

func TestCompareCountsFixedAndStillFailingTests(t *testing.T) {
	base := map[string]Outcome{"p.TestFixed": Fail, "p.TestStill": Fail, "p.TestOK": Pass}
	head := map[string]Outcome{"p.TestFixed": Pass, "p.TestStill": Fail, "p.TestOK": Pass}
	var result Result
	compare(&result, [2][2]map[string]Outcome{{base, base}, {head, head}}, func(string) bool { return false })
	if result.Fixed != 1 || result.StillFailing != 1 || len(result.Regressions) != 0 || result.Tests != 3 {
		t.Fatalf("result %+v", result)
	}
}

// Deleting one test file hides only its own package's tests from the
// stopped list, not those of another package that stopped running.
func TestRunScopesDeletedTestFilesToTheirPackage(t *testing.T) {
	files := map[string]string{"go.mod": "module m\n", "a/a.go": "package a", "a/x_test.go": "package a", "b/b.go": "package b"}
	base := writeTree(t, files)
	delete(files, "a/x_test.go")
	head := writeTree(t, files)
	fake := &fakeRunner{base: base, calls: map[string]int{}, answers: func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		if side == "head" || spec.Args[1] == "vet" {
			return checksandbox.Result{}, nil
		}
		return checksandbox.Result{Stdout: []byte(`{"Action":"pass","Package":"m/a","Test":"TestX"}` + "\n" + `{"Action":"pass","Package":"m/b","Test":"TestB"}`)}, nil
	}}
	report, err := runWith(context.Background(), Input{BaseTree: base, HeadTree: head, Scope: Scope{Changed: []string{"a/x_test.go", "b/b.go"}}, Limits: checksandbox.DefaultLimits(), Runner: fake.run}, fakeHost(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := report.Results[0]; !slices.Equal(got.StoppedRunning, []string{"m/b.TestB"}) {
		t.Fatalf("result %+v", got)
	}
}

// Base runs only the Go packages it has; a package added on head is new.
func TestRunGivesEachTreeOnlyItsOwnPackages(t *testing.T) {
	base := writeTree(t, map[string]string{"go.mod": "module m\n", "a/a.go": "package a"})
	head := writeTree(t, map[string]string{"go.mod": "module m\n", "a/a.go": "package a", "b/b.go": "package b"})
	var mu sync.Mutex
	args := map[string][]string{}
	fake := &fakeRunner{base: base, calls: map[string]int{}, answers: func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		mu.Lock()
		args[side+" "+spec.Args[1]] = spec.Args[1:]
		mu.Unlock()
		return checksandbox.Result{Stdout: goEvents(map[string]string{"TestA": "pass"})}, nil
	}}
	_, err := runWith(context.Background(), Input{BaseTree: base, HeadTree: head, Scope: Scope{Changed: []string{"a/a.go", "b/b.go"}}, Limits: checksandbox.DefaultLimits(), Runner: fake.run}, fakeHost(t))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(args["base vet"], []string{"vet", "./a"}) || !slices.Equal(args["head vet"], []string{"vet", "./a", "./b"}) || !slices.Equal(args["base test"], []string{"test", "-json", "-count=1", "./a"}) {
		t.Fatalf("args %v", args)
	}
	only := writeTree(t, map[string]string{"go.mod": "module m\n"})
	calls := 0
	fake = &fakeRunner{base: only, calls: map[string]int{}, answers: func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		if side == "base" {
			calls++
		}
		return checksandbox.Result{Stdout: goEvents(map[string]string{"TestA": "fail"})}, nil
	}}
	report, _ := runWith(context.Background(), Input{BaseTree: only, HeadTree: head, Scope: Scope{Changed: []string{"b/b.go"}}, Limits: checksandbox.DefaultLimits(), Runner: fake.run}, fakeHost(t))
	if calls != 0 || !slices.Equal(report.Results[0].NewFailures, []string{"m/a.TestA"}) {
		t.Fatalf("base ran %d times; result %+v", calls, report.Results[0])
	}
}

// A test that prints the words of a missing module is still a result.
func TestRunKeepsResultsWhoseOutputMentionsAMissingModule(t *testing.T) {
	report := runFake(t, func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		outcome := "pass"
		if side == "head" {
			outcome = "fail"
		}
		stdout := `{"Action":"output","Package":"m/a","Test":"TestA","Output":"ModuleNotFoundError: No module named 'requests'\n"}` + "\n" + `{"Action":"` + outcome + `","Package":"m/a","Test":"TestA"}`
		return checksandbox.Result{ExitCode: 1, Stdout: []byte(stdout)}, nil
	})
	if got := report.Results[0]; !got.Ran || !slices.Equal(got.Regressions, []string{"m/a.TestA"}) {
		t.Fatalf("result %+v", got)
	}
}

// A run that passes a limit on head after base ran within it is a head
// failure; on base it means the check could not run, and says so.
func TestRunTreatsAHeadLimitAfterACleanBaseAsARegression(t *testing.T) {
	for _, test := range []struct {
		name   string
		result checksandbox.Result
		want   string
	}{
		{"timeout", checksandbox.Result{TimedOut: true}, "go test ./a (timed out on head)"},
		{"output", checksandbox.Result{OutputExceeded: true}, "go test ./a (output past the limit on head)"},
		{"disk", checksandbox.Result{DiskExceeded: true}, "go test ./a (scratch space filled on head)"},
		{"no results", checksandbox.Result{ExitCode: 2}, "go test ./a (exit status 2 without results on head)"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := runFake(t, func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
				if side == "head" && spec.Args[1] == "test" {
					return test.result, nil
				}
				return checksandbox.Result{Stdout: goEvents(map[string]string{"TestA": "pass"})}, nil
			})
			if got := report.Results[0]; !got.Ran || got.Tests != 1 || !slices.Equal(got.Regressions, []string{test.want}) {
				t.Fatalf("result %+v", got)
			}
		})
	}
	report := runFake(t, func(side string, _ int, _ checksandbox.Spec) (checksandbox.Result, error) {
		if side == "base" {
			return checksandbox.Result{TimedOut: true}, nil
		}
		return checksandbox.Result{}, nil
	})
	if got := report.Results[0]; got.Ran || got.Reason != "it ran past its 3m0s time limit on base" {
		t.Fatalf("result %+v", got)
	}
}

func TestRunTreatsAHeadBuildFailureAsARegression(t *testing.T) {
	report := runFake(t, func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		if side == "base" || spec.Args[1] == "vet" {
			return checksandbox.Result{Stdout: goEvents(map[string]string{"TestA": "pass"})}, nil
		}
		return checksandbox.Result{ExitCode: 1, Stdout: []byte(`{"Action":"fail","Package":"m/a"}`)}, nil
	})
	if got := report.Results[0].Regressions; !slices.Equal(got, []string{"m/a"}) {
		t.Fatalf("regressions %v", got)
	}
}

func TestRunReportsWhyACheckCouldNotRun(t *testing.T) {
	for _, test := range []struct {
		name   string
		result checksandbox.Result
		err    error
		want   string
	}{
		{"sandbox unavailable", checksandbox.Result{}, &checksandbox.Unavailable{Reason: "unprivileged user namespaces are turned off"}, "unprivileged user namespaces are turned off"},
		{"missing module", checksandbox.Result{ExitCode: 1, Stderr: []byte("a.go:3:8: no required module provides package github.com/acme/lib; to add it:")}, nil, "missing dependency: github.com/acme/lib"},
		{"timeout", checksandbox.Result{TimedOut: true}, nil, "time limit"},
		{"output", checksandbox.Result{OutputExceeded: true}, nil, "output passed the limit"},
		{"disk", checksandbox.Result{DiskExceeded: true}, nil, "filled its scratch"},
		{"no results", checksandbox.Result{ExitCode: 2}, nil, "reported no results"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := runFake(t, func(string, int, checksandbox.Spec) (checksandbox.Result, error) { return test.result, test.err })
			got := report.Results[0]
			if got.Ran || !strings.Contains(got.Reason, test.want) {
				t.Fatalf("got %+v, want could not run: %s", got, test.want)
			}
		})
	}
}

func TestRunStopsAtTheBudget(t *testing.T) {
	base, head := goTrees(t)
	fake := &fakeRunner{base: base, calls: map[string]int{}, answers: func(string, int, checksandbox.Spec) (checksandbox.Result, error) {
		time.Sleep(30 * time.Millisecond)
		return checksandbox.Result{Stdout: goEvents(map[string]string{"TestA": "pass"})}, nil
	}}
	report, err := runWith(context.Background(), Input{BaseTree: base, HeadTree: head, Scope: Scope{Changed: []string{"a/a.go"}}, Limits: checksandbox.DefaultLimits(), Budget: 50 * time.Millisecond, Runner: fake.run}, fakeHost(t))
	if err != nil {
		t.Fatal(err)
	}
	if last := report.Results[len(report.Results)-1]; last.Ran || !strings.Contains(last.Reason, "time for checks ran out") {
		t.Fatalf("last result %+v", last)
	}
}

func TestRunCollectsScratchFoldersThatCouldNotBeRemoved(t *testing.T) {
	report := runFake(t, func(side string, _ int, _ checksandbox.Spec) (checksandbox.Result, error) {
		result := checksandbox.Result{Stdout: goEvents(map[string]string{"TestA": "pass"})}
		if side == "head" {
			result.Leftover = "/tmp/open-trestle-check-1"
		}
		return result, nil
	})
	// Two go test runs and one go vet run on head.
	if len(report.Leftovers) != 3 || report.Leftovers[0] != "/tmp/open-trestle-check-1" {
		t.Fatalf("leftovers %v", report.Leftovers)
	}
}

// A diagnostic that only head has is new and shown with its head line; one
// that moved down is still failing; one that only base has is gone. Each
// side runs a diagnostics check once.
func TestRunReportsNewDiagnosticsWithTheirHeadLine(t *testing.T) {
	base, head := goTrees(t)
	fake := &fakeRunner{base: base, calls: map[string]int{}, answers: func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		if spec.Args[1] != "vet" {
			return checksandbox.Result{Stdout: goEvents(map[string]string{"TestA": "pass"})}, nil
		}
		stderr := "a/a.go:3:2: self-assignment of x\na/a.go:8:2: unreachable code\n"
		if side == "head" {
			stderr = "# m/a\na/a.go:9:2: self-assignment of x\na/a.go:5:2: self-assignment of x\n/work/a/a.go:7:1: result of fmt.Sprint call not used\n"
		}
		return checksandbox.Result{ExitCode: 1, Stderr: []byte(stderr), Work: "/work"}, nil
	}}
	report, err := runWith(context.Background(), Input{BaseTree: base, HeadTree: head, Scope: Scope{Changed: []string{"a/a.go"}}, Limits: checksandbox.DefaultLimits(), Runner: fake.run}, fakeHost(t))
	if err != nil {
		t.Fatal(err)
	}
	vet := report.Results[1]
	want := []string{"a/a.go:7: result of fmt.Sprint call not used", "a/a.go:9: self-assignment of x"}
	if !vet.Ran || !slices.Equal(vet.NewFailures, want) || vet.StillFailing != 1 || len(vet.Regressions) != 0 || len(vet.StoppedRunning) != 0 || vet.Tests != 3 || vet.Flaky != 0 {
		t.Fatalf("go vet result %+v", vet)
	}
	if fake.calls["basego vet ./a"] != 1 || fake.calls["headgo vet ./a"] != 1 || fake.calls["basego test -json -count=1 ./a"] != 2 {
		t.Fatalf("calls %v", fake.calls)
	}
}

// A linter that exits with a failure and prints no diagnostic it can read
// fails as a run, as before.
func TestRunTreatsALinterFailureWithoutDiagnosticsAsARegression(t *testing.T) {
	report := runFake(t, func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		if side == "head" && spec.Args[1] == "vet" {
			return checksandbox.Result{ExitCode: 1, Stderr: []byte("go: internal error\n")}, nil
		}
		return checksandbox.Result{Stdout: goEvents(map[string]string{"TestA": "pass"})}, nil
	})
	if got := report.Results[1]; !got.Ran || !slices.Equal(got.Regressions, []string{"go vet ./a (exit status 1 without results on head)"}) {
		t.Fatalf("result %+v", got)
	}
}

func TestSummary(t *testing.T) {
	report := Report{Results: []Result{
		{Name: "go test ./a", Ran: true, Tests: 9, Regressions: []string{"m/a.TestX"}, StoppedRunning: []string{"m/a.TestY"}, Fixed: 2, StillFailing: 1, Flaky: 2},
		{Name: "go vet ./a", Ran: true, Tests: 1},
		{Name: "npm test", Reason: "missing dependency: jest on base"},
	}}
	want := "ran 2 of 3 checks in the sandbox: 1 regression, 1 stopped running, 2 fixed, 1 still failing, 2 flaky dropped, 1 could not run (npm test: missing dependency: jest on base)"
	if got := report.Summary(); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if got := (Report{}).Summary(); got != "no checks apply to this change" {
		t.Fatalf("got %q", got)
	}
}
