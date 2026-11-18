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
	os.Exit(m.Run())
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
	if vet := report.Results[1]; !vet.Ran || len(vet.Regressions) != 0 || vet.Tests != 1 {
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

func TestRunTreatsTestsThatStopRunningOnHeadAsRegressions(t *testing.T) {
	report := runFake(t, func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		if side == "head" && spec.Args[1] == "test" {
			// TestMain exited before any test ran.
			return checksandbox.Result{}, nil
		}
		return checksandbox.Result{Stdout: goEvents(map[string]string{"TestA": "pass"})}, nil
	})
	if got := report.Results[0].Regressions; !slices.Equal(got, []string{"m/a.TestA (did not run on head)"}) {
		t.Fatalf("regressions %v", got)
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

func TestRunAddsExtraFilesToBothSides(t *testing.T) {
	base, head := goTrees(t)
	seen := map[string]bool{}
	var mu sync.Mutex
	fake := &fakeRunner{base: "", calls: map[string]int{}, answers: func(_ string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		data, err := os.ReadFile(filepath.Join(spec.Tree, "a", "extra_test.go"))
		mu.Lock()
		seen[spec.Tree] = err == nil && string(data) == "package a"
		mu.Unlock()
		return checksandbox.Result{}, nil
	}}
	_, err := runWith(context.Background(), Input{
		BaseTree: base, HeadTree: head, Scope: Scope{Changed: []string{"a/a.go"}}, Limits: checksandbox.DefaultLimits(), Runner: fake.run,
		ExtraFiles: map[string][]byte{"a/extra_test.go": []byte("package a")},
	}, fakeHost(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(seen) != 2 {
		t.Fatalf("runs saw %v, want two copied trees", seen)
	}
	for tree, ok := range seen {
		if !ok || tree == base || tree == head {
			t.Fatalf("tree %s: extra file present %v", tree, ok)
		}
	}
	if _, err := os.Stat(filepath.Join(head, "a", "extra_test.go")); err == nil {
		t.Fatal("the extra file was written into the input tree")
	}
}

func TestSummary(t *testing.T) {
	report := Report{Results: []Result{
		{Name: "go test ./a", Ran: true, Tests: 9, Regressions: []string{"m/a.TestX"}, Flaky: 2},
		{Name: "go vet ./a", Ran: true, Tests: 1},
		{Name: "npm test", Reason: "missing dependency: jest"},
	}}
	want := "ran 2 of 3 checks in the sandbox: 1 regression, 2 flaky dropped, 1 could not run (npm test: missing dependency: jest)"
	if got := report.Summary(); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
	if got := (Report{}).Summary(); got != "no checks apply to this change" {
		t.Fatalf("got %q", got)
	}
}
