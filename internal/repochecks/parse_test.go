package repochecks

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
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

func requireTests(t *testing.T, got parsed, want map[string]Outcome) {
	t.Helper()
	if !maps.Equal(got.tests, want) {
		t.Fatalf("tests\n got %v\nwant %v", got.tests, want)
	}
}

func TestParseGoJSON(t *testing.T) {
	requireTests(t, parseRun(FormatGoJSON, "go test", 1, fixture(t, "go-test.json"), nil, nil), map[string]Outcome{
		"example.com/fixture/broken":              Fail,
		"example.com/fixture/ok.TestPass":         Pass,
		"example.com/fixture/ok.TestFail":         Fail,
		"example.com/fixture/ok.TestSkip":         Skip,
		"example.com/fixture/ok.TestParent":       Pass,
		"example.com/fixture/ok.TestParent/child": Pass,
	})
}

func TestParseJUnitTurnsImportErrorsIntoMissingDependencies(t *testing.T) {
	got := parseRun(FormatJUnit, "pytest", 1, []byte("ModuleNotFoundError: No module named 'forged'"), nil, fixture(t, "pytest-junit.xml"))
	requireTests(t, got, map[string]Outcome{
		"tests.test_math::test_add":       Pass,
		"tests.test_math::test_sub":       Fail,
		"tests.test_math::test_later":     Skip,
		"tests.test_math::test_params[2]": Pass,
	})
	if !slices.Contains(got.missing, "requests") {
		t.Fatalf("missing %v, want requests", got.missing)
	}
}

func TestParseJUnitWithoutReportFindsNothing(t *testing.T) {
	if got := parseRun(FormatJUnit, "pytest", 1, []byte("<testcase name=\"forged\"/>"), nil, nil); len(got.tests) != 0 {
		t.Fatalf("results came from standard output: %v", got.tests)
	}
}

func TestParseTAPNamesNestedTests(t *testing.T) {
	requireTests(t, parseRun(FormatTAP, "node --test", 1, fixture(t, "node-test.tap"), nil, nil), map[string]Outcome{
		"passes":               Pass,
		"fails":                Fail,
		"skipped":              Skip,
		"group > inner passes": Pass,
		"group > inner fails":  Fail,
		"group":                Fail,
	})
}

func TestParseTAPNamesAnUnnamedTestByNumber(t *testing.T) {
	requireTests(t, parseRun(FormatTAP, "node --test", 1, []byte("ok 1\nnot ok 2 - \n"), nil, nil), map[string]Outcome{"test 1": Pass, "test 2": Fail})
}

func TestParseUnittestReadsOnlyStandardError(t *testing.T) {
	requireTests(t, parseRun(FormatUnittest, "unittest", 1, []byte("test_fake (x.Y.test_fake) ... ok\n"), fixture(t, "unittest.txt"), nil), map[string]Outcome{
		"test_sample.Sample.test_error": Fail,
		"test_sample.Sample.test_fail":  Fail,
		"test_sample.Sample.test_pass":  Pass,
		"test_sample.Sample.test_skip":  Skip,
	})
}

func TestParseLibtestIgnoresCapturedOutput(t *testing.T) {
	requireTests(t, parseRun(FormatLibtest, "cargo test", 101, fixture(t, "cargo-test.txt"), nil, nil), map[string]Outcome{
		"tests::adds":      Pass,
		"tests::subtracts": Fail,
		"tests::later":     Skip,
	})
}

func TestParseExitStatus(t *testing.T) {
	requireTests(t, parseRun(FormatExit, "go vet .", 1, nil, nil, nil), map[string]Outcome{"go vet .": Fail})
	requireTests(t, parseRun(FormatExit, "go vet .", 0, nil, nil, nil), map[string]Outcome{"go vet .": Pass})
}

func TestMissingDependencies(t *testing.T) {
	for output, want := range map[string]string{
		"x.go:3:8: no required module provides package github.com/acme/lib; to add it:":                "github.com/acme/lib",
		"go: github.com/acme/lib@v1.2.0: module lookup disabled by GOPROXY=off":                        "github.com/acme/lib",
		"missing go.sum entry for module providing package golang.org/x/text (imported by m); to add:": "golang.org/x/text",
		"ModuleNotFoundError: No module named 'yaml'":                                                  "yaml",
		"/usr/bin/python3: No module named pytest":                                                     "pytest",
		"Error: Cannot find module 'left-pad'":                                                         "left-pad",
		"error: no matching package named `serde` found":                                               "serde",
	} {
		if got := missingDependencies([]byte(output)); !slices.Equal(got, []string{want}) {
			t.Errorf("%q: got %v, want %s", output, got, want)
		}
	}
}
