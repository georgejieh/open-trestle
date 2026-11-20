package repochecks

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"path"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
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

// Bounds on what one run's output can make the host hold: a name part (a
// subtest's or a test binary's) and a whole test ID are cut, subtests past
// a depth are named by their enclosing ones, and a run with more results
// than maxRunResults is refused.
const (
	maxNameBytes   = 256
	maxTestIDBytes = 1024
	maxTestDepth   = 16
	maxRunResults  = 50_000
)

// parsed is what one run's output says.
type parsed struct {
	tests map[string]Outcome
	// missing names dependencies that runner-level records (a build that
	// failed, a module that could not be collected or imported) say are
	// absent. Those records are not results.
	missing []string
	// overflow is set when the run reported more than maxRunResults tests.
	overflow bool
}

func newParsed() *parsed { return &parsed{tests: map[string]Outcome{}} }

// record keeps the worst outcome a run reports for a test, so a line the
// test prints itself cannot turn a failure into a pass.
func (p *parsed) record(id string, outcome Outcome) {
	id = cut(id, maxTestIDBytes)
	previous, ok := p.tests[id]
	if !ok && len(p.tests) == maxRunResults {
		p.overflow = true
		return
	}
	if ok && (previous == Fail || previous == Pass && outcome == Skip) {
		return
	}
	p.tests[id] = outcome
}

// addMissing keeps the dependencies in text that the repository does not
// provide, and reports whether there were any.
func (p *parsed) addMissing(provided func(string) bool, text ...[]byte) bool {
	found := false
	for _, name := range missingDependencies(text...) {
		if !provided(name) {
			p.missing = append(p.missing, name)
			found = true
		}
	}
	return found
}

// cut shortens text to at most limit bytes on a character boundary.
func cut(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	end := limit
	for end > 0 && !utf8.RuneStart(text[end]) {
		end--
	}
	return text[:end]
}

// parseRun reads the results of one run from the output the harness asked
// the runner for: standard output, or the report file for JUnit. provided
// reports whether the repository itself provides a module a record names
// as missing; such a record is a failure, not a missing dependency. A run
// that failed without any result may still say on its output that a
// dependency is missing.
func parseRun(format Format, name string, exitCode int, stdout, stderr, report []byte, provided func(string) bool) *parsed {
	result := newParsed()
	switch format {
	case FormatGoJSON:
		result = parseGoJSON(stdout, stderr, provided)
	case FormatJUnit:
		result = parseJUnit(report, provided)
	case FormatTAP:
		result = parseTAP(stdout, provided)
	case FormatUnittest:
		result = parseUnittest(stderr, provided)
	case FormatLibtest:
		result = parseLibtest(stdout, stderr)
	case FormatExit:
		switch {
		case exitCode == 0:
			result.record(name, Pass)
		case !result.addMissing(provided, stdout, stderr):
			result.record(name, Fail)
		}
	}
	if len(result.tests) == 0 && exitCode != 0 && format != FormatExit {
		result.addMissing(provided, stdout, stderr)
	}
	return result
}

type goTestEvent struct {
	Action      string
	Package     string
	Test        string
	ImportPath  string
	Output      string
	FailedBuild string
}

// parseGoJSON reads test2json events. A package that fails without a
// failing test (a build failure) is recorded under the package's name,
// unless its build failed because a module is missing. Only the go
// command's own output names missing modules: build output events and
// standard error, where test output never goes.
func parseGoJSON(stdout, stderr []byte, provided func(string) bool) *parsed {
	result := newParsed()
	failedTests := map[string]bool{}
	buildOutput := map[string][]byte{}
	type packageFailure struct{ name, build string }
	var failures []packageFailure
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Buffer(make([]byte, 64<<10), 4<<20)
	for scanner.Scan() {
		var event goTestEvent
		if json.Unmarshal(scanner.Bytes(), &event) != nil {
			continue
		}
		if event.Action == "build-output" && event.ImportPath != "" && len(buildOutput[event.ImportPath]) < 64<<10 {
			buildOutput[event.ImportPath] = append(buildOutput[event.ImportPath], event.Output...)
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
		if event.Package == "" {
			continue
		}
		if event.Test != "" {
			result.record(event.Package+"."+event.Test, outcome)
			if outcome == Fail {
				failedTests[event.Package] = true
			}
			continue
		}
		if outcome == Fail && !failedTests[event.Package] {
			failures = append(failures, packageFailure{event.Package, event.FailedBuild})
		}
	}
	missingOnStderr := result.addMissing(provided, stderr)
	for _, failure := range failures {
		missing := missingOnStderr && failure.build == ""
		if output, ok := buildOutput[failure.build]; ok {
			missing = result.addMissing(provided, output)
		}
		if !missing {
			result.record(failure.name, Fail)
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
// that errored, as a module that could not be collected does, because an
// import is missing becomes a missing dependency, not a failure.
func parseJUnit(report []byte, provided func(string) bool) *parsed {
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
		id := cut(testCase.Name, maxNameBytes)
		if testCase.Class != "" {
			id = cut(testCase.Class, maxNameBytes) + "::" + id
		}
		switch {
		case testCase.Error != nil:
			if !result.addMissing(provided, []byte(testCase.Error.Message+"\n"+testCase.Error.Text)) {
				result.record(id, Fail)
			}
		case testCase.Failure != nil:
			result.record(id, Fail)
		case testCase.Skipped != nil:
			result.record(id, Skip)
		default:
			result.record(id, Pass)
		}
	}
}

var tapLine = regexp.MustCompile(`^(\s*)(not ok|ok)\b\s*(\d*)\s*(?:-\s*)?(.*?)\s*$`)
var tapSubtest = regexp.MustCompile(`^(\s*)# Subtest: (.*)$`)

// scriptFile matches a test name that is a script's path: node names a
// test file that failed as a whole, for example one whose import failed,
// by its path.
var scriptFile = regexp.MustCompile(`\.[cm]?[jt]sx?$`)

// tapResult is one TAP result line with the text that explains it: the
// comment lines before it, where node writes a test file's own error
// output, and its YAML diagnostic block.
type tapResult struct {
	name    string
	outcome Outcome
	text    []byte
}

// parseTAP reads TAP results; a nested test is named by the subtests that
// enclose it. A test file that failed because a package it imports is not
// installed is a missing dependency, not a failure.
func parseTAP(stdout []byte, provided func(string) bool) *parsed {
	result := newParsed()
	var stack []string
	var comments []byte
	var pending *tapResult
	finish := func() {
		if pending == nil {
			return
		}
		if pending.outcome != Fail || !scriptFile.MatchString(pending.name) || !result.addMissing(provided, pending.text) {
			result.record(pending.name, pending.outcome)
		}
		pending = nil
	}
	depth := func(indent string) int { return min(len(indent)/4, maxTestDepth) }
	inYAML, yamlSeen := false, false
	for _, line := range strings.Split(string(stdout), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case inYAML:
			if len(pending.text) < 64<<10 {
				pending.text = append(append(pending.text, line...), '\n')
			}
			inYAML = trimmed != "..."
			continue
		case pending != nil && !yamlSeen && trimmed == "---":
			inYAML, yamlSeen = true, true
			continue
		}
		if match := tapSubtest.FindStringSubmatch(line); match != nil {
			finish()
			level := depth(match[1])
			stack = append(stack[:min(level, len(stack))], cut(match[2], maxNameBytes))
			continue
		}
		match := tapLine.FindStringSubmatch(line)
		if match == nil {
			if strings.HasPrefix(trimmed, "#") && len(comments) < 64<<10 {
				comments = append(append(comments, line...), '\n')
			}
			continue
		}
		finish()
		yamlSeen = false
		level := depth(match[1])
		description, directive, _ := strings.Cut(match[4], " # ")
		if strings.TrimSpace(description) == "" {
			description = "test " + match[3]
		}
		name := strings.Join(append(append([]string{}, stack[:min(level, len(stack))]...), cut(description, maxNameBytes)), " > ")
		outcome := Pass
		if match[2] == "not ok" {
			outcome = Fail
		}
		if upper := strings.ToUpper(directive); strings.HasPrefix(upper, "SKIP") || strings.HasPrefix(upper, "TODO") {
			outcome = Skip
		}
		pending = &tapResult{name: name, outcome: outcome, text: comments}
		comments = nil
		stack = stack[:min(level, len(stack))]
	}
	finish()
	return result
}

var unittestLine = regexp.MustCompile(`^([\w.]+) \(([\w.]+)\) \.\.\. (ok|FAIL|ERROR|skipped|expected failure|unexpected success)`)

// unittestImportFailure prefixes the ID unittest gives a test module it
// could not import.
const unittestImportFailure = "unittest.loader._FailedTest."

var unittestFailureHeader = regexp.MustCompile(`^ERROR: ([\w.]+) \((unittest\.loader\._FailedTest[\w.]*)\)$`)

// unittestID names a test by its class, or module, and method.
func unittestID(method, class string) string {
	if strings.HasSuffix(class, "."+method) {
		return cut(class, maxTestIDBytes)
	}
	return cut(class, maxTestIDBytes) + "." + cut(method, maxNameBytes)
}

// parseUnittest reads the verbose result lines that unittest writes to
// standard error. A test module that could not be imported because a
// module is missing, as its failure report says, is a missing dependency.
func parseUnittest(stderr []byte, provided func(string) bool) *parsed {
	result := newParsed()
	lines := strings.Split(string(stderr), "\n")
	missing := unittestMissingModules(lines, provided, result)
	for _, line := range lines {
		match := unittestLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		id := unittestID(match[1], match[2])
		switch match[3] {
		case "ok", "expected failure":
			result.record(id, Pass)
		case "skipped":
			result.record(id, Skip)
		default:
			if !missing[id] {
				result.record(id, Fail)
			}
		}
	}
	return result
}

// unittestMissingModules reads unittest's failure reports for the test
// modules it could not import, adds the missing modules they name to
// result, and returns the IDs of those modules.
func unittestMissingModules(lines []string, provided func(string) bool, result *parsed) map[string]bool {
	modules := map[string]bool{}
	for index := 0; index < len(lines); index++ {
		header := unittestFailureHeader.FindStringSubmatch(lines[index])
		if header == nil {
			continue
		}
		var report []byte
		for index += 2; index < len(lines) && !separatorLine(lines[index]) && len(report) < 64<<10; index++ {
			report = append(append(report, lines[index]...), '\n')
		}
		index--
		if result.addMissing(provided, report) {
			modules[unittestID(header[1], header[2])] = true
		}
	}
	return modules
}

// separatorLine is a line of = or - that starts or ends a unittest report.
func separatorLine(line string) bool {
	return len(line) >= 20 && (strings.Trim(line, "=") == "" || strings.Trim(line, "-") == "")
}

var libtestLine = regexp.MustCompile(`^test (.+?) \.\.\. (ok|FAILED|ignored)`)
var libtestRunning = regexp.MustCompile(`^running \d+ tests?$`)

// cargoBinary matches the lines cargo writes to standard error before it
// runs each test binary.
var cargoBinary = regexp.MustCompile(`^\s+(?:Running (?:unittests )?\S+ \((.+)\)|Doc-tests (\S+))\s*$`)

var cargoHash = regexp.MustCompile(`-[0-9a-f]{16}$`)

// parseLibtest reads the result lines of each test binary, which come
// between its "running" line and its failure report; the captured output of
// failing tests follows and is not read. Each test is named by its binary,
// so tests::smoke of two crates stays two tests: cargo names the binaries,
// in the order it runs them, on standard error.
func parseLibtest(stdout, stderr []byte) *parsed {
	result := newParsed()
	binaries := cargoBinaries(stderr)
	block, results := -1, false
	prefix := ""
	for _, line := range strings.Split(string(stdout), "\n") {
		switch {
		case libtestRunning.MatchString(line):
			block++
			results, prefix = true, ""
			if block < len(binaries) {
				prefix = binaries[block] + "::"
			}
			continue
		case line == "failures:" || strings.HasPrefix(line, "test result:"):
			results = false
			continue
		}
		match := libtestLine.FindStringSubmatch(line)
		if !results || match == nil {
			continue
		}
		result.record(prefix+cut(match[1], maxNameBytes), map[string]Outcome{"ok": Pass, "FAILED": Fail, "ignored": Skip}[match[2]])
	}
	return result
}

// cargoBinaries names the test binaries cargo ran, in order: a binary's
// file name without its hash, or "doc-tests" and the crate, with "#2" and
// on for a name that repeats.
func cargoBinaries(stderr []byte) []string {
	var names []string
	seen := map[string]int{}
	for _, line := range strings.Split(string(stderr), "\n") {
		match := cargoBinary.FindStringSubmatch(line)
		if match == nil {
			continue
		}
		name := "doc-tests " + match[2]
		if match[1] != "" {
			name = cargoHash.ReplaceAllString(strings.TrimSuffix(path.Base(strings.ReplaceAll(match[1], `\`, "/")), ".exe"), "")
		}
		name = cut(name, maxNameBytes)
		if seen[name]++; seen[name] > 1 {
			name += fmt.Sprintf("#%d", seen[name])
		}
		names = append(names, name)
	}
	return names
}

// missingDependencyPatterns recognise the messages toolchains print when a
// dependency is absent from the offline caches.
var missingDependencyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`no required module provides package (\S+?);`),
	regexp.MustCompile(`cannot find module providing package (\S+?):`),
	regexp.MustCompile(`missing go\.sum entry for module providing package (\S+?)[;\s]`),
	regexp.MustCompile(`(\S+?)@\S+: module lookup disabled by GOPROXY=off`),
	regexp.MustCompile(`replacement directory (\S+) does not exist`),
	regexp.MustCompile(`ModuleNotFoundError: No module named '([^']+)'`),
	regexp.MustCompile(`No module named ([\w.]+)`),
	regexp.MustCompile(`Cannot find (?:module|package) '([^']+)'`),
	regexp.MustCompile(`(?m)^sh: \d+: ([\w@./-]+): not found$`),
	regexp.MustCompile(`'([\w@./-]+)' is not recognized as an internal or external command`),
	regexp.MustCompile(`no matching package named ` + "`" + `([^` + "`" + `]+)` + "`"),
}

// printable reports whether text has no control or format character.
func printable(text string) bool {
	for _, character := range text {
		if unicode.IsControl(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func missingDependencies(outputs ...[]byte) []string {
	seen := map[string]bool{}
	var names []string
	for _, output := range outputs {
		for _, pattern := range missingDependencyPatterns {
			for _, match := range pattern.FindAllSubmatch(output, 8) {
				name := strings.Trim(string(match[1]), "'\"`")
				if name != "" && len(name) <= 200 && printable(name) && !seen[name] {
					seen[name] = true
					names = append(names, name)
				}
			}
		}
	}
	return names
}
