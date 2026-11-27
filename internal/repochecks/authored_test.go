package repochecks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/checksandbox"
)

const goCheck = "package calc\n\nimport \"testing\"\n\nfunc TestTrestleAdd(t *testing.T) {\n\tif Add(2, 3) != 5 {\n\t\tt.Fatal(Add(2, 3))\n\t}\n}\n"

func TestValidateGoCheckRefusesWhatCouldFakeARegression(t *testing.T) {
	tests, err := validateGoCheck(goCheck, "calc")
	if err != nil || !slices.Equal(tests, []string{"TestTrestleAdd"}) {
		t.Fatalf("valid check: %v, %v", tests, err)
	}
	if _, err := validateGoCheck(strings.Replace(goCheck, "package calc", "package calc_test", 1), "calc"); err != nil {
		t.Fatalf("external test package refused: %v", err)
	}
	withImport := func(path string) string {
		return strings.Replace(goCheck, `import "testing"`, "import (\n\t\"testing\"\n\t_ \""+path+"\"\n)", 1)
	}
	for name, content := range map[string]string{
		"other package":  strings.Replace(goCheck, "package calc", "package other", 1),
		"build tag":      "//go:build linux\n\n" + goCheck,
		"old build tag":  "// +build linux\n\n" + goCheck,
		"embed":          goCheck + "\n//go:embed calc.go\nvar source string\n",
		"linkname":       goCheck + "\n//go:linkname now runtime.nanotime\nfunc now() int64\n",
		"init":           goCheck + "\nfunc init() {}\n",
		"TestMain":       goCheck + "\nfunc TestMain(m *testing.M) {}\n",
		"no test":        "package calc\n\nfunc helper() {}\n",
		"lowercase test": "package calc\n\nimport \"testing\"\n\nfunc Testadd(t *testing.T) {}\n",
		"syntax":         "package calc\n\nfunc {",
		"os":             withImport("os"),
		"os/exec":        withImport("os/exec"),
		"io/ioutil":      withImport("io/ioutil"),
		"io/fs":          withImport("io/fs"),
		"path/filepath":  withImport("path/filepath"),
		"text/template":  withImport("text/template"),
		"debug tree":     withImport("debug/elf"),
		"embed import":   withImport("embed"),
		"go/parser":      withImport("go/parser"),
		"runtime":        withImport("runtime"),
		"runtime/debug":  withImport("runtime/debug"),
		"unsafe":         withImport("unsafe"),
		"syscall":        withImport("syscall"),
		"plugin":         withImport("plugin"),
		"net":            withImport("net"),
		"net/http":       withImport("net/http"),
		"cgo":            withImport("C"),
	} {
		if _, err := validateGoCheck(content, "calc"); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
	if _, err := validateGoCheck(withImport("strings"), "calc"); err != nil {
		t.Fatalf("a standard import was refused: %v", err)
	}
}

func TestAuthoredCheckRefusesPythonEscapesAndBadInput(t *testing.T) {
	head := writeTree(t, map[string]string{"go.mod": "module m\n", "calc/calc.go": "package calc\n"})
	valid := "from shop.price import total\n\n\ndef test_total():\n    assert total([1]) == 1\n"
	if _, name, err := authoredCheck(head, 1, Authored{Framework: "pytest", Dir: "shop", Content: valid}); err != nil || name != "shop/test_trestle_check_1.py" {
		t.Fatalf("valid Python check: %q, %v", name, err)
	}
	for _, word := range []string{"open('x')", "__file__", "import inspect", "import subprocess", "os.environ", "import socket", "import importlib", "pytest_plugins = []", "import conftest"} {
		if _, _, err := authoredCheck(head, 1, Authored{Framework: "pytest", Dir: "shop", Content: valid + word + "\n"}); err == nil {
			t.Errorf("%s: admitted", word)
		}
	}
	for name, authored := range map[string]Authored{
		"too large":     {Framework: "pytest", Dir: "shop", Content: strings.Repeat("#", maxAuthoredBytes+1)},
		"NUL":           {Framework: "pytest", Dir: "shop", Content: "x\x00"},
		"not UTF-8":     {Framework: "pytest", Dir: "shop", Content: "\xff"},
		"outside":       {Framework: "pytest", Dir: "../up", Content: valid},
		"framework":     {Framework: "jest", Dir: "shop", Content: valid},
		"no Go module":  {Framework: "go_test", Dir: "calc", Content: goCheck},
		"no Go package": {Framework: "go_test", Dir: ".", Content: goCheck},
	} {
		tree := head
		if name == "no Go module" {
			tree = writeTree(t, map[string]string{"calc/calc.go": "package calc\n"})
		}
		if _, _, err := authoredCheck(tree, 1, authored); err == nil {
			t.Errorf("%s: admitted", name)
		}
	}
	check, name, err := authoredCheck(head, 2, Authored{Framework: "go_test", Dir: "calc", Content: goCheck})
	if err != nil || name != "calc/trestle_check_2_test.go" || check.Dir != "." || !slices.Equal(check.Packages, []string{"./calc"}) || !slices.Contains(check.Args, "^(TestTrestleAdd)$") {
		t.Fatalf("Go check %+v %q %v", check, name, err)
	}
}

func TestClassifyAuthored(t *testing.T) {
	runs := func(first, second map[string]Outcome) [2]map[string]Outcome {
		return [2]map[string]Outcome{first, second}
	}
	pass := map[string]Outcome{"m/a.TestX": Pass}
	fail := map[string]Outcome{"m/a.TestX": Fail}
	build := map[string]Outcome{"m/a": Fail}
	for _, test := range []struct {
		name                     string
		base, head               [2]map[string]Outcome
		baseProblem, headProblem *problem
		want                     string
	}{
		{"regression", runs(pass, pass), runs(fail, fail), nil, nil, AuthoredRegression},
		{"base does not build", runs(build, build), runs(fail, fail), nil, nil, AuthoredFailsOnHead},
		{"base exits without results", runs(nil, nil), runs(fail, fail), &problem{noResults: true}, nil, AuthoredFailsOnHead},
		{"flaky on head", runs(pass, pass), runs(fail, pass), nil, nil, ""},
		{"flaky on base", runs(pass, fail), runs(fail, fail), nil, nil, ""},
		{"head does not build", runs(pass, pass), runs(nil, nil), nil, &problem{noResults: true}, ""},
		{"both fail", runs(fail, fail), runs(fail, fail), nil, nil, ""},
		{"both pass", runs(pass, pass), runs(pass, pass), nil, nil, ""},
		{"base timed out", runs(nil, nil), runs(fail, fail), &problem{headFailure: "timed out"}, nil, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, tests := classifyAuthored(test.base, test.head, test.baseProblem, test.headProblem)
			if got != test.want || got != "" && !slices.Equal(tests, []string{"m/a.TestX"}) {
				t.Fatalf("got %q %v, want %q", got, tests, test.want)
			}
		})
	}
}

func TestRunAuthoredWritesTheFileAndRunsOnlyItsTests(t *testing.T) {
	files := map[string]string{"go.mod": "module m\n", "a/a.go": "package a\n"}
	base, head := writeTree(t, files), writeTree(t, files)
	fake := &fakeRunner{base: base, calls: map[string]int{}, answers: func(side string, _ int, spec checksandbox.Spec) (checksandbox.Result, error) {
		if !slices.Contains(spec.Args, "^(TestTrestle)$") || !slices.Contains(spec.Args, "./a") {
			t.Errorf("args %v", spec.Args)
		}
		if side == "head" {
			return checksandbox.Result{ExitCode: 1, Stdout: goEvents(map[string]string{"TestTrestle": "fail"})}, nil
		}
		return checksandbox.Result{Stdout: goEvents(map[string]string{"TestTrestle": "pass"})}, nil
	}}
	content := "package a\n\nimport \"testing\"\n\nfunc TestTrestle(t *testing.T) {}\n"
	report := runAuthoredWith(context.Background(), AuthoredInput{
		BaseTree: base, HeadTree: head, Limits: checksandbox.DefaultLimits(), Runner: fake.run,
		Checks: []Authored{{Framework: "go_test", Dir: "a", Content: content}, {Framework: "go_test", Dir: "a", Content: "package a\n\nimport \"os\"\n"}},
	}, fakeHost(t))
	if len(report.Results) != 2 {
		t.Fatalf("results %+v", report.Results)
	}
	if kept := report.Results[0]; kept.Status != AuthoredRegression || kept.Path != "a/trestle_check_1_test.go" || !slices.Equal(kept.Tests, []string{"m/a.TestTrestle"}) {
		t.Fatalf("kept %+v", kept)
	}
	if refused := report.Results[1]; refused.Status != "" || refused.Reason == "" {
		t.Fatalf("refused %+v", refused)
	}
	for _, tree := range []string{base, head} {
		if data, err := os.ReadFile(filepath.Join(tree, "a", "trestle_check_1_test.go")); err != nil || string(data) != content {
			t.Fatalf("written file %q %v", data, err)
		}
	}
	if fake.calls["base"+strings.Join(append([]string{"go"}, "test", "-json", "-count=1", "-run", "^(TestTrestle)$", "./a"), " ")] != 2 {
		t.Fatalf("calls %v", fake.calls)
	}
	// The host never overwrites a file: a second run of the same check finds
	// it there and discards it.
	again := runAuthoredWith(context.Background(), AuthoredInput{BaseTree: base, HeadTree: head, Runner: fake.run, Checks: []Authored{{Framework: "go_test", Dir: "a", Content: content}}}, fakeHost(t))
	if again.Results[0].Status != "" {
		t.Fatalf("an existing file was replaced: %+v", again.Results[0])
	}
}

// The checker's Go test, run in the real sandbox: it passes on base and
// fails on head, so it is kept as a regression.
func TestEndToEndModelWrittenGoCheck(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the model-written check end to end test runs on Linux")
	}
	if err := checksandbox.Available(); err != nil {
		t.Skipf("the sandbox is not available here: %v", err)
	}
	files := map[string]string{"go.mod": "module example.com/calc\n\ngo 1.22\n", "calc/calc.go": "package calc\n\nfunc Add(a, b int) int { return a + b }\n"}
	head := map[string]string{"go.mod": files["go.mod"], "calc/calc.go": "package calc\n\nfunc Add(a, b int) int { return a - b }\n"}
	limits := checksandbox.DefaultLimits()
	limits.Time = 5 * time.Minute
	report := RunAuthored(context.Background(), AuthoredInput{
		BaseTree: writeTree(t, files), HeadTree: writeTree(t, head), Limits: limits, Budget: 10 * time.Minute,
		Checks: []Authored{{Framework: "go_test", Dir: "calc", Content: goCheck}},
	})
	result := report.Results[0]
	if cannotRunHere(result.Reason) {
		t.Skipf("the check could not run here: %s", result.Reason)
	}
	if result.Status != AuthoredRegression || !slices.Equal(result.Tests, []string{"example.com/calc/calc.TestTrestleAdd"}) {
		t.Fatalf("result %+v", result)
	}
}
