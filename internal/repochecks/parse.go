package repochecks

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"regexp"
	"strings"
)

// Outcome is one test's result in one run.
type Outcome string

const (
	Pass Outcome = "pass"
	Fail Outcome = "fail"
	Skip Outcome = "skip"
)

// Format names the structured output a check's runner was asked for.
type Format string

const (
	FormatGoJSON   Format = "go_test_json"
	FormatJUnit    Format = "junit_xml"
	FormatTAP      Format = "tap"
	FormatUnittest Format = "unittest_verbose"
	FormatLibtest  Format = "libtest"
	// FormatExit records one result for the whole command from its exit
	// status.
	FormatExit Format = "exit_status"
)

// parsed is what one run's output says.
type parsed struct {
	tests map[string]Outcome
	// missing names dependencies the run could not find.
	missing []string
}

func newParsed() parsed { return parsed{tests: map[string]Outcome{}} }

// parseRun reads the results of one run from the output the harness asked
// the runner for: standard output, or the report file for JUnit.
func parseRun(format Format, name string, exitCode int, stdout, stderr, report []byte) parsed {
	result := newParsed()
	switch format {
	case FormatGoJSON:
		result = parseGoJSON(stdout)
	case FormatJUnit:
		result = parseJUnit(report)
	case FormatTAP:
		result = parseTAP(stdout)
	case FormatUnittest:
		result = parseUnittest(stderr)
	case FormatLibtest:
		result = parseLibtest(stdout)
	case FormatExit:
		outcome := Pass
		if exitCode != 0 {
			outcome = Fail
		}
		result.tests[name] = outcome
	}
	result.missing = append(result.missing, missingDependencies(stdout, stderr)...)
	return result
}

type goTestEvent struct {
	Action  string
	Package string
	Test    string
}

// parseGoJSON reads test2json events. A package that fails without a
// failing test (a build failure) is recorded under the package's name.
func parseGoJSON(stdout []byte) parsed {
	result := newParsed()
	failedTests := map[string]bool{}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	for scanner.Scan() {
		var event goTestEvent
		if json.Unmarshal(scanner.Bytes(), &event) != nil || event.Package == "" {
			continue
		}
		var outcome Outcome
		switch event.Action {
		case "pass":
			outcome = Pass
		case "fail":
			outcome = Fail
		case "skip":
			outcome = Skip
		default:
			continue
		}
		if event.Test != "" {
			result.tests[event.Package+"."+event.Test] = outcome
			if outcome == Fail {
				failedTests[event.Package] = true
			}
			continue
		}
		if outcome == Fail && !failedTests[event.Package] {
			result.tests[event.Package] = Fail
		}
	}
	return result
}

type junitCase struct {
	Class   string    `xml:"classname,attr"`
	Name    string    `xml:"name,attr"`
	Failure *junitMsg `xml:"failure"`
	Error   *junitMsg `xml:"error"`
	Skipped *junitMsg `xml:"skipped"`
}

type junitMsg struct {
	Message string `xml:"message,attr"`
	Text    string `xml:",chardata"`
}

// parseJUnit reads every testcase element of a JUnit XML report. A case
// that errored because an import is missing becomes a missing dependency,
// not a failure.
func parseJUnit(report []byte) parsed {
	result := newParsed()
	decoder := xml.NewDecoder(bytes.NewReader(report))
	for {
		token, err := decoder.Token()
		if err != nil {
			return result
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "testcase" {
			continue
		}
		var testCase junitCase
		if decoder.DecodeElement(&testCase, &start) != nil {
			return result
		}
		id := testCase.Name
		if testCase.Class != "" {
			id = testCase.Class + "::" + testCase.Name
		}
		switch {
		case testCase.Error != nil:
			if missing := missingDependencies([]byte(testCase.Error.Message+"\n"+testCase.Error.Text), nil); len(missing) > 0 {
				result.missing = append(result.missing, missing...)
				continue
			}
			result.tests[id] = Fail
		case testCase.Failure != nil:
			result.tests[id] = Fail
		case testCase.Skipped != nil:
			result.tests[id] = Skip
		default:
			result.tests[id] = Pass
		}
	}
}

var tapLine = regexp.MustCompile(`^(\s*)(not ok|ok)\b\s*(\d*)\s*(?:-\s*)?(.*?)\s*$`)
var tapSubtest = regexp.MustCompile(`^(\s*)# Subtest: (.*)$`)

// parseTAP reads TAP results; a nested test is named by the subtests that
// enclose it.
func parseTAP(stdout []byte) parsed {
	result := newParsed()
	var stack []string
	depth := func(indent string) int { return len(indent) / 4 }
	for _, line := range strings.Split(string(stdout), "\n") {
		if match := tapSubtest.FindStringSubmatch(line); match != nil {
			level := depth(match[1])
			stack = append(stack[:min(level, len(stack))], match[2])
			continue
		}
		match := tapLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		level := depth(match[1])
		description, directive, _ := strings.Cut(match[4], " # ")
		if strings.TrimSpace(description) == "" {
			description = "test " + match[3]
		}
		name := strings.Join(append(append([]string{}, stack[:min(level, len(stack))]...), description), " > ")
		outcome := Pass
		if match[2] == "not ok" {
			outcome = Fail
		}
		if upper := strings.ToUpper(directive); strings.HasPrefix(upper, "SKIP") || strings.HasPrefix(upper, "TODO") {
			outcome = Skip
		}
		result.tests[name] = outcome
		stack = stack[:min(level, len(stack))]
	}
	return result
}

var unittestLine = regexp.MustCompile(`^(\w+) \(([\w.]+)\) \.\.\. (ok|FAIL|ERROR|skipped|expected failure|unexpected success)`)

// parseUnittest reads the verbose result lines that unittest writes to
// standard error.
func parseUnittest(stderr []byte) parsed {
	result := newParsed()
	for _, line := range strings.Split(string(stderr), "\n") {
		match := unittestLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		id := match[2]
		if !strings.HasSuffix(id, "."+match[1]) {
			id += "." + match[1]
		}
		switch match[3] {
		case "ok", "expected failure":
			result.tests[id] = Pass
		case "skipped":
			result.tests[id] = Skip
		default:
			result.tests[id] = Fail
		}
	}
	return result
}

var libtestLine = regexp.MustCompile(`^test (\S+) \.\.\. (ok|FAILED|ignored)`)

// parseLibtest reads the result lines of each test binary, which come
// between its "running" line and its failure report; the captured output of
// failing tests follows and is not read.
func parseLibtest(stdout []byte) parsed {
	result := newParsed()
	results := false
	for _, line := range strings.Split(string(stdout), "\n") {
		switch {
		case strings.HasPrefix(line, "running "):
			results = true
			continue
		case line == "failures:" || strings.HasPrefix(line, "test result:"):
			results = false
			continue
		}
		match := libtestLine.FindStringSubmatch(line)
		if !results || match == nil {
			continue
		}
		result.tests[match[1]] = map[string]Outcome{"ok": Pass, "FAILED": Fail, "ignored": Skip}[match[2]]
	}
	return result
}

// missingDependencyPatterns recognise the messages toolchains print when a
// dependency is absent from the offline caches.
var missingDependencyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`no required module provides package (\S+?);`),
	regexp.MustCompile(`missing go\.sum entry for module providing package (\S+?)[;\s]`),
	regexp.MustCompile(`(\S+?)@\S+: module lookup disabled by GOPROXY=off`),
	regexp.MustCompile(`ModuleNotFoundError: No module named '([^']+)'`),
	regexp.MustCompile(`No module named ([\w.]+)`),
	regexp.MustCompile(`Cannot find (?:module|package) '([^']+)'`),
	regexp.MustCompile(`no matching package named ` + "`" + `([^` + "`" + `]+)` + "`"),
}

func missingDependencies(outputs ...[]byte) []string {
	seen := map[string]bool{}
	var names []string
	for _, output := range outputs {
		for _, pattern := range missingDependencyPatterns {
			for _, match := range pattern.FindAllSubmatch(output, 8) {
				name := strings.Trim(string(match[1]), "'\"`")
				if name != "" && !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}
	return names
}
