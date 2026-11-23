package repochecks

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func requireTests(t *testing.T, got *parsed, want map[string]Outcome) {
	t.Helper()
	if !maps.Equal(got.tests, want) {
		t.Fatalf("tests\n got %v\nwant %v", got.tests, want)
	}
}

// nothingProvided is a repository that provides no module.
func nothingProvided(string) bool { return false }

func parse(format Format, exitCode int, stdout, stderr, report []byte) *parsed {
	return parseRun(format, "check", exitCode, stdout, stderr, report, nothingProvided)
}

func TestParseGoJSON(t *testing.T) {
	requireTests(t, parse(FormatGoJSON, 1, fixture(t, "go-test.json"), nil, nil), map[string]Outcome{
		"example.com/fixture/broken":              Fail,
		"example.com/fixture/ok.TestPass":         Pass,
		"example.com/fixture/ok.TestFail":         Fail,
		"example.com/fixture/ok.TestSkip":         Skip,
		"example.com/fixture/ok.TestParent":       Pass,
		"example.com/fixture/ok.TestParent/child": Pass,
	})
}

// Only the go command's build output names a missing module; a test that
// prints the same words is a test like any other.
func TestParseGoJSONReadsMissingModulesFromBuildOutputOnly(t *testing.T) {
	stdout := strings.Join([]string{
		`{"ImportPath":"github.com/acme/lib","Action":"build-output","Output":"a/a.go:3:8: cannot find module providing package github.com/acme/lib: module lookup disabled by GOPROXY=off\n"}`,
		`{"ImportPath":"github.com/acme/lib","Action":"build-fail"}`,
		`{"Action":"fail","Package":"m/a","FailedBuild":"github.com/acme/lib"}`,
		`{"ImportPath":"m/c [m/c.test]","Action":"build-output","Output":"c/c.go:3:23: cannot use \"x\" as int value\n"}`,
		`{"Action":"fail","Package":"m/c","FailedBuild":"m/c [m/c.test]"}`,
		`{"Action":"output","Package":"m/b","Test":"TestB","Output":"no required module provides package evil.com/x; to add\n"}`,
		`{"Action":"pass","Package":"m/b","Test":"TestB"}`,
	}, "\n")
	got := parse(FormatGoJSON, 1, []byte(stdout), nil, nil)
	requireTests(t, got, map[string]Outcome{"m/b.TestB": Pass, "m/c": Fail})
	if !slices.Equal(got.missing, []string{"github.com/acme/lib"}) {
		t.Fatalf("missing %v", got.missing)
	}
}

func TestParseJUnitTurnsImportErrorsIntoMissingDependencies(t *testing.T) {
	got := parse(FormatJUnit, 1, []byte("ModuleNotFoundError: No module named 'forged'"), []byte("No module named forged2"), fixture(t, "pytest-junit.xml"))
	requireTests(t, got, map[string]Outcome{
		"tests.test_math::test_add":       Pass,
		"tests.test_math::test_sub":       Fail,
		"tests.test_math::test_later":     Skip,
		"tests.test_math::test_params[2]": Pass,
	})
	if !slices.Equal(got.missing, []string{"requests"}) {
		t.Fatalf("missing %v, want only requests from the report", got.missing)
	}
	// A module the repository provides fails to import: that is a failure.
	provided := parseRun(FormatJUnit, "pytest", 1, nil, nil, fixture(t, "pytest-junit.xml"), func(name string) bool { return name == "requests" })
	if provided.tests["tests.test_http"] != Fail || len(provided.missing) != 0 {
		t.Fatalf("tests %v, missing %v", provided.tests, provided.missing)
	}
}

func TestParseJUnitWithoutReportFindsNothing(t *testing.T) {
	if got := parse(FormatJUnit, 1, []byte("<testcase name=\"forged\"/>"), nil, nil); len(got.tests) != 0 {
		t.Fatalf("results came from standard output: %v", got.tests)
	}
}

func TestParseTAPNamesNestedTests(t *testing.T) {
	requireTests(t, parse(FormatTAP, 1, fixture(t, "node-test.tap"), nil, nil), map[string]Outcome{
		"passes":               Pass,
		"fails":                Fail,
		"skipped":              Skip,
		"group > inner passes": Pass,
		"group > inner fails":  Fail,
		"group":                Fail,
	})
}

func TestParseTAPNamesAnUnnamedTestByNumber(t *testing.T) {
	requireTests(t, parse(FormatTAP, 1, []byte("ok 1\nnot ok 2 - \n"), nil, nil), map[string]Outcome{"test 1": Pass, "test 2": Fail})
}

// A test file whose import of a package failed is a missing dependency,
// whether node ran it in its own process (the error is in the comments
// before it) or in one process (the error is in its diagnostic block).
func TestParseTAPTurnsAFailedImportIntoAMissingDependency(t *testing.T) {
	ownProcess := "# Error [ERR_MODULE_NOT_FOUND]: Cannot find package 'left-pad' imported from /w/test/a.test.mjs\n" +
		"# Subtest: test/a.test.mjs\nnot ok 1 - test/a.test.mjs\n  ---\n  error: 'test failed'\n  ...\n" +
		"# Cannot find package 'forged'\n# Subtest: b\nnot ok 2 - b\n  ---\n  error: 'boom'\n  ...\n"
	got := parse(FormatTAP, 1, []byte(ownProcess), nil, nil)
	requireTests(t, got, map[string]Outcome{"b": Fail})
	if !slices.Equal(got.missing, []string{"left-pad"}) {
		t.Fatalf("missing %v", got.missing)
	}
	oneProcess := "# Subtest: test/a.test.mjs\nnot ok 1 - test/a.test.mjs\n  ---\n  error: \"Cannot find package 'left-pad' imported from /w/test/a.test.mjs\"\n  code: 'ERR_MODULE_NOT_FOUND'\n  ...\nok 2 - c\n"
	got = parse(FormatTAP, 1, []byte(oneProcess), nil, nil)
	requireTests(t, got, map[string]Outcome{"c": Pass})
	if !slices.Equal(got.missing, []string{"left-pad"}) {
		t.Fatalf("missing %v", got.missing)
	}
}

func TestParseUnittestReadsOnlyStandardError(t *testing.T) {
	requireTests(t, parse(FormatUnittest, 1, []byte("test_fake (x.Y.test_fake) ... ok\n"), fixture(t, "unittest.txt"), nil), map[string]Outcome{
		"test_sample.Sample.test_error": Fail,
		"test_sample.Sample.test_fail":  Fail,
		"test_sample.Sample.test_pass":  Pass,
		"test_sample.Sample.test_skip":  Skip,
	})
}

func TestParseLibtestIgnoresCapturedOutput(t *testing.T) {
	requireTests(t, parse(FormatLibtest, 101, fixture(t, "cargo-test.txt"), nil, nil), map[string]Outcome{
		"tests::adds":      Pass,
		"tests::subtracts": Fail,
		"tests::later":     Skip,
	})
}

// Each Rust test is named by the binary cargo ran it in, so the same test
// path in two crates is two tests.
func TestParseLibtestNamesTestsByTheirBinary(t *testing.T) {
	stdout := "running 1 test\ntest tests::smoke ... ok\n\ntest result: ok.\n\nrunning 1 test\ntest tests::smoke ... FAILED\n\ntest result: FAILED.\n\nrunning 1 test\ntest it_works ... ok\n\nrunning 1 test\ntest src/lib.rs - add (line 3) ... ok\n"
	stderr := "   Compiling calc v0.1.0\n     Running unittests src/lib.rs (target/debug/deps/calc-0123456789abcdef)\n" +
		"     Running unittests src/lib.rs (/tmp/target/debug/deps/other-fedcba9876543210)\n" +
		"     Running tests/smoke.rs (target\\debug\\deps\\smoke-0123456789abcdef.exe)\n   Doc-tests calc\n"
	requireTests(t, parse(FormatLibtest, 101, []byte(stdout), []byte(stderr), nil), map[string]Outcome{
		"calc::tests::smoke":                        Pass,
		"other::tests::smoke":                       Fail,
		"smoke::it_works":                           Pass,
		"doc-tests calc::src/lib.rs - add (line 3)": Pass,
	})
	if got := cargoBinaries([]byte("     Running tests/a.rs (d/smoke-0123456789abcdef)\n     Running tests/b.rs (e/smoke-fedcba9876543210)\n")); !slices.Equal(got, []string{"smoke", "smoke#2"}) {
		t.Fatalf("binaries %v", got)
	}
}

func TestParseUnittestImportFailure(t *testing.T) {
	stderr := []byte("tests.test_price (unittest.loader._FailedTest.tests.test_price) ... ERROR\n")
	requireTests(t, parse(FormatUnittest, 1, nil, stderr, nil), map[string]Outcome{"unittest.loader._FailedTest.tests.test_price": Fail})
}

// A test module that could not import a missing package is a missing
// dependency; what another test printed in its own report is not.
func TestParseUnittestReadsMissingModulesFromImportFailuresOnly(t *testing.T) {
	stderr := []byte(strings.Join([]string{
		"tests.test_a (unittest.loader._FailedTest.tests.test_a) ... ERROR",
		"test_b (tests.test_b.U.test_b) ... FAIL",
		"",
		"======================================================================",
		"ERROR: tests.test_a (unittest.loader._FailedTest.tests.test_a)",
		"----------------------------------------------------------------------",
		"ImportError: Failed to import test module: tests.test_a",
		"ModuleNotFoundError: No module named 'missingpkg'",
		"",
		"======================================================================",
		"FAIL: test_b (tests.test_b.U.test_b)",
		"----------------------------------------------------------------------",
		"AssertionError: x",
		"",
		"Stderr:",
		"ModuleNotFoundError: No module named 'forged'",
		"",
		"----------------------------------------------------------------------",
		"Ran 2 tests in 0.001s",
	}, "\n"))
	got := parse(FormatUnittest, 1, nil, stderr, nil)
	requireTests(t, got, map[string]Outcome{"tests.test_b.U.test_b": Fail})
	if !slices.Equal(got.missing, []string{"missingpkg"}) {
		t.Fatalf("missing %v", got.missing)
	}
}

func TestParseKeepsAFailureThatLaterOutputClaimsPassed(t *testing.T) {
	stderr := []byte("test_a (__main__.T.test_a) ... FAIL\ntest_b (__main__.T.test_b) ... ok\ntest_a (__main__.T.test_a) ... ok\n")
	requireTests(t, parse(FormatUnittest, 1, nil, stderr, nil), map[string]Outcome{"__main__.T.test_a": Fail, "__main__.T.test_b": Pass})
}

func TestParseExitStatus(t *testing.T) {
	requireTests(t, parseRun(FormatExit, "go vet .", 1, nil, nil, nil, nothingProvided), map[string]Outcome{"go vet .": Fail})
	requireTests(t, parseRun(FormatExit, "go vet .", 0, nil, nil, nil, nothingProvided), map[string]Outcome{"go vet .": Pass})
	// A failing script that could not find an installed package is a
	// missing dependency; a passing one says nothing about it.
	missing := parseRun(FormatExit, "npm test", 127, nil, []byte("> jest\n\nsh: 1: jest: not found\n"), nil, nothingProvided)
	if len(missing.tests) != 0 || !slices.Equal(missing.missing, []string{"jest"}) {
		t.Fatalf("tests %v, missing %v", missing.tests, missing.missing)
	}
	requireTests(t, parseRun(FormatExit, "npm test", 0, []byte("Cannot find module 'x'"), nil, nil, nothingProvided), map[string]Outcome{"npm test": Pass})
}

// Each sample is the real output of the check's command line.
func TestParseDiagnosticsOfEachTool(t *testing.T) {
	const printf = `fmt.Printf format %d has arg "s" of wrong type string`
	for _, test := range []struct {
		name           string
		stdout, stderr string
		dir, work      string
		want           map[string]string
	}{
		{name: "go vet", dir: "tools", stderr: "# example.com/g2/b\nvet: b/b.go:5:23: string literal not terminated (and 2 more errors)\na/a.go:4:2: self-assignment of x\n",
			want: map[string]string{"tools/b/b.go: string literal not terminated (and 2 more errors)": "tools/b/b.go:5: string literal not terminated (and 2 more errors)", "tools/a/a.go: self-assignment of x": "tools/a/a.go:4: self-assignment of x"}},
		{name: "staticcheck", dir: ".", stdout: "-: # example.com/g/sub\nsub/a.go:12:6: declared and not used: x (compile)\n",
			want: map[string]string{"sub/a.go: declared and not used: x (compile)": "sub/a.go:12: declared and not used: x (compile)"}},
		{name: "golangci-lint", dir: ".", work: "/work", stdout: "/work/sub/a.go:12:9: Error return value of `os.Open` is not checked (errcheck)\n/work/sub/a.go:10:14: printf: " + printf + " (govet)\n/work/sub/a.go:11:14: printf: " + printf + " (govet)\n",
			want: map[string]string{
				"sub/a.go: Error return value of `os.Open` is not checked (errcheck)": "sub/a.go:12: Error return value of `os.Open` is not checked (errcheck)",
				"sub/a.go: printf: " + printf + " (govet)":                            "sub/a.go:10: printf: " + printf + " (govet)",
				"sub/a.go: printf: " + printf + " (govet) (2)":                        "sub/a.go:11: printf: " + printf + " (govet)",
			}},
		{name: "ruff", dir: ".", stdout: "pkg/a.py:1:1: I001 [*] Import block is un-sorted or un-formatted\npkg/a.py:2:8: F401 [*] `sys` imported but unused\n",
			want: map[string]string{"pkg/a.py: I001 [*] Import block is un-sorted or un-formatted": "pkg/a.py:1: I001 [*] Import block is un-sorted or un-formatted", "pkg/a.py: F401 [*] `sys` imported but unused": "pkg/a.py:2: F401 [*] `sys` imported but unused"}},
		{name: "flake8", dir: ".", stdout: "./pkg/a.py:2:1: F401 'sys' imported but unused\n",
			want: map[string]string{"pkg/a.py: F401 'sys' imported but unused": "pkg/a.py:2: F401 'sys' imported but unused"}},
		{name: "mypy", dir: ".", stdout: "a.py:2: note: By default the bodies of untyped functions are not checked, consider using --check-untyped-defs  [annotation-unchecked]\n" +
			"pkg/a.py:13: error: Incompatible return value type (got \"int\", expected \"str\")  [return-value]\n",
			want: map[string]string{"pkg/a.py: error: Incompatible return value type (got \"int\", expected \"str\")  [return-value]": "pkg/a.py:13: error: Incompatible return value type (got \"int\", expected \"str\")  [return-value]"}},
		{name: "cargo clippy", dir: ".", stderr: "    Checking calc v0.1.0 (/work)\nsrc/lib.rs:8:13: warning: writing `&Vec` instead of `&[_]` involves a new object where a slice will do\n" +
			"warning: `calc` (lib) generated 2 warnings (run `cargo clippy --fix --lib -p calc -- ` to apply 1 suggestion)\n    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.28s\n",
			want: map[string]string{"src/lib.rs: warning: writing `&Vec` instead of `&[_]` involves a new object where a slice will do": "src/lib.rs:8: warning: writing `&Vec` instead of `&[_]` involves a new object where a slice will do"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := parseDiagnostics([]byte(test.stdout), []byte(test.stderr), test.dir, test.work, 1, nothingProvided)
			if !maps.Equal(got.located, test.want) || len(got.tests) != len(test.want) || len(got.missing) != 0 {
				t.Fatalf("located %q\ntests %v, missing %v", got.located, got.tests, got.missing)
			}
			for id := range test.want {
				if got.tests[id] != Fail {
					t.Fatalf("%q is %q", id, got.tests[id])
				}
			}
		})
	}
}

func TestParseDiagnosticsNamesAMissingModule(t *testing.T) {
	stderr := "go: finding module for package github.com/acme/lib\nc/c.go:3:8: cannot find module providing package github.com/acme/lib: module lookup disabled by GOPROXY=off\n"
	got := parseDiagnostics(nil, []byte(stderr), ".", "", 1, nothingProvided)
	if len(got.tests) != 0 || !slices.Equal(got.missing, []string{"github.com/acme/lib"}) {
		t.Fatalf("tests %v, missing %v", got.tests, got.missing)
	}
}

func TestParseDiagnosticsBoundsWhatItHolds(t *testing.T) {
	long := strings.Repeat("é", 4<<10)
	got := parseDiagnostics([]byte(long+".go:1: "+long+"\n"+long+".go:2: "+long+"\n"), nil, ".", "", 1, nothingProvided)
	if len(got.tests) != 2 {
		t.Fatalf("tests %d", len(got.tests))
	}
	for id := range got.tests {
		if len(id) > maxTestIDBytes || got.located[id] == "" {
			t.Fatalf("ID of %d bytes, located %q", len(id), got.located[id])
		}
	}
	var many strings.Builder
	for index := range maxRunResults + 1 {
		fmt.Fprintf(&many, "a.go:%d: m\n", index+1)
	}
	if got := parseDiagnostics([]byte(many.String()), nil, ".", "", 1, nothingProvided); !got.overflow {
		t.Fatalf("overflow %v with %d results", got.overflow, len(got.tests))
	}
}

// One run's output cannot make the host hold unbounded names or results.
func TestParsersBoundNamesDepthAndResults(t *testing.T) {
	long := strings.Repeat("é", 4<<10)
	var tap strings.Builder
	for depth := range 40 {
		fmt.Fprintf(&tap, "%s# Subtest: %s%d\n", strings.Repeat("    ", depth), long, depth)
	}
	tap.WriteString(strings.Repeat("    ", 40) + "ok 1 - " + long + "\n")
	for id, outcome := range parse(FormatTAP, 0, []byte(tap.String()), nil, nil).tests {
		if len(id) > maxTestIDBytes || strings.Count(id, " > ") > maxTestDepth || outcome != Pass || !strings.HasSuffix(id, "é") {
			t.Fatalf("TAP ID of %d bytes and %d levels", len(id), strings.Count(id, " > "))
		}
	}
	goEvent := fmt.Sprintf(`{"Action":"pass","Package":"m/%s","Test":"T%s"}`, long, long)
	for id := range parse(FormatGoJSON, 0, []byte(goEvent), nil, nil).tests {
		if len(id) > maxTestIDBytes {
			t.Fatalf("Go ID of %d bytes", len(id))
		}
	}
	var many strings.Builder
	for index := range maxRunResults + 1 {
		fmt.Fprintf(&many, "ok %d - t%d\n", index, index)
	}
	if got := parse(FormatTAP, 0, []byte(many.String()), nil, nil); !got.overflow || len(got.tests) != maxRunResults {
		t.Fatalf("overflow %v with %d results", got.overflow, len(got.tests))
	}
}

func TestMissingDependencyNamesAreText(t *testing.T) {
	if got := missingDependencies([]byte("ModuleNotFoundError: No module named '\x1b]52;c;aGk=\x07'")); len(got) != 0 {
		t.Fatalf("a name with terminal controls was kept: %q", got)
	}
}

func TestMissingDependencies(t *testing.T) {
	for output, want := range map[string]string{
		"x.go:3:8: no required module provides package github.com/acme/lib; to add it:":                                                 "github.com/acme/lib",
		"go: github.com/acme/lib@v1.2.0: module lookup disabled by GOPROXY=off":                                                         "github.com/acme/lib",
		"a/a.go:3:8: cannot find module providing package github.com/acme/lib: module lookup disabled by GOPROXY=off":                   "github.com/acme/lib",
		"missing go.sum entry for module providing package golang.org/x/text (imported by m); to add:":                                  "golang.org/x/text",
		"ModuleNotFoundError: No module named 'yaml'":                                                                                   "yaml",
		"/usr/bin/python3: No module named pytest":                                                                                      "pytest",
		"Error: Cannot find module 'left-pad'":                                                                                          "left-pad",
		"sh: 1: jest: not found":                                                                                                        "jest",
		"'jest' is not recognized as an internal or external command,":                                                                  "jest",
		"error: no matching package named `serde` found":                                                                                "serde",
		"go: example.com/m@v0.0.0 (replaced by ../sibling): reading ../sibling/go.mod: replacement directory ../sibling does not exist": "../sibling",
	} {
		if got := missingDependencies([]byte(output)); !slices.Equal(got, []string{want}) {
			t.Errorf("%q: got %v, want %s", output, got, want)
		}
	}
}
