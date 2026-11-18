package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// initHintedCommands returns the command lines the development-build note
// prints between its introduction and its closing line.
func initHintedCommands(t *testing.T) []string {
	t.Helper()
	var out bytes.Buffer
	(&initWizard{out: &out}).explainScannerBlock("development")
	text := out.String()
	start := strings.Index(text, "(docs/operations.md):\n")
	end := strings.Index(text, "  Then run this in the repository:")
	if start < 0 || end < start {
		t.Fatalf("the note lost its introduction or closing line:\n%s", text)
	}
	lines := []string{}
	for _, line := range strings.Split(strings.TrimRight(text[start+len("(docs/operations.md):\n"):end], "\n"), "\n") {
		command, ok := strings.CutPrefix(line, "    ")
		if !ok || strings.TrimSpace(command) == "" {
			t.Fatalf("hinted command line %q is not indented by four spaces", line)
		}
		lines = append(lines, command)
	}
	return lines
}

// initOperationsCommandLines returns every non-comment line of the shell blocks
// in docs/operations.md, in document order.
func initOperationsCommandLines(t *testing.T) []string {
	t.Helper()
	guide, err := os.ReadFile(filepath.Join("..", "..", "docs", "operations.md"))
	if err != nil {
		t.Fatal(err)
	}
	lines, inBlock := []string{}, false
	for _, line := range strings.Split(string(guide), "\n") {
		switch {
		case line == "```sh":
			inBlock = true
		case line == "```":
			inBlock = false
		case inBlock && strings.TrimSpace(line) != "" && !strings.HasPrefix(strings.TrimSpace(line), "#"):
			lines = append(lines, line)
		}
	}
	return lines
}

func TestInitPackagingHintListsEveryRequiredStepInOrder(t *testing.T) {
	hinted := initHintedCommands(t)
	text := strings.Join(hinted, "\n")
	// The candidate builder refuses a staging tree without
	// release/vulnerability-scan.json, which only the passive vulnerability
	// gate writes, so the gate must run between scanner staging and the build.
	at := -1
	for _, step := range []string{
		"python3 tools/package_secret_scanner.py --output .container",
		"python3 tools/package_secret_scanner.py --verify .container",
		"python3 tools/vulnerability_gate.py --staging .container",
		"python3 tools/linux_distribution.py",
		"sha256sum -c open-trestle-linux-amd64.pyz.sha256",
		"./open-trestle-linux-amd64.pyz verify-archive",
		"sudo ./open-trestle-linux-amd64.pyz install",
	} {
		next := strings.Index(text, step)
		if next <= at {
			t.Fatalf("the hint does not list %q after the steps before it:\n%s", step, text)
		}
		at = next
	}
	// Every hinted line is a line of docs/operations.md, and they appear there in
	// the same order, so the wizard and the guide cannot drift apart.
	guide := initOperationsCommandLines(t)
	position := 0
	for _, line := range hinted {
		found := false
		for ; position < len(guide); position++ {
			if guide[position] == line {
				found, position = true, position+1
				break
			}
		}
		if !found {
			t.Fatalf("hinted line %q is not in docs/operations.md after the lines before it", line)
		}
	}
	for _, line := range hinted {
		if len([]rune(line))+4 > 100 {
			t.Fatalf("hinted line wider than 100 columns: %q", line)
		}
	}
}
