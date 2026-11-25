package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestHelpPrintsGroupedUsageToStandardOutput(t *testing.T) {
	var usage bytes.Buffer
	writeUsage(&usage)
	for _, argument := range []string{"--help", "-h", "help"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{argument}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || stdout.String() != usage.String() {
			t.Fatalf("trestle %s: exit=%d stderr=%q", argument, code, stderr.String())
		}
	}
}

func TestUsageGroupsCommandsByAudience(t *testing.T) {
	var usage bytes.Buffer
	writeUsage(&usage)
	text := usage.String()
	groups := []struct {
		name     string
		commands []string
	}{
		{"Everyday", []string{"\n  review ", "\n  update ", "\n  usage "}},
		{"Setup and keys", []string{"\n  init ", "\n  keys "}},
		{"Integrations", []string{"\n  local-git ", "\n  runs ", "\n  mcp ", "\n  lsp "}},
		{"Operators", []string{"\n  setup ", "\n  config ", "\n  admin "}},
		{"Evaluation", []string{"\n  evaluate ", "\n  validate-fixture "}},
	}
	starts := make([]int, len(groups)+1)
	for i, group := range groups {
		starts[i] = strings.Index(text, "\n"+group.name+":\n")
		if starts[i] < 0 || i > 0 && starts[i] <= starts[i-1] {
			t.Fatalf("group %q is missing or out of order:\n%s", group.name, text)
		}
	}
	starts[len(groups)] = len(text)
	for i, group := range groups {
		section := text[starts[i]:starts[i+1]]
		for _, command := range group.commands {
			if !strings.Contains(section, command) {
				t.Fatalf("group %s lacks %q:\n%s", group.name, command, section)
			}
		}
	}
}

func TestUnknownCommandKeepsItsUsageError(t *testing.T) {
	var usage bytes.Buffer
	writeUsage(&usage)
	for _, args := range [][]string{{"help", "review"}, {"ci", "argument"}, {"validate-fixture"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != usage.String() {
			t.Fatalf("trestle %v: exit=%d stdout=%q", args, code, stdout.String())
		}
	}
}

func TestUnknownCommandIsShortWithASuggestion(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"reveiw"}, "trestle: \"reveiw\" is not a trestle command.\nDid you mean: review?\nRun trestle --help to see all commands.\n"},
		{[]string{"Keyz", "list"}, "trestle: \"Keyz\" is not a trestle command.\nDid you mean: keys?\nRun trestle --help to see all commands.\n"},
		{[]string{"nonsense", "argument"}, "trestle: \"nonsense\" is not a trestle command.\nRun trestle --help to see all commands.\n"},
		{[]string{"x"}, "trestle: \"x\" is not a trestle command.\nRun trestle --help to see all commands.\n"},
		{[]string{"--verbose"}, "trestle: \"--verbose\" is not a trestle command.\nRun trestle --help to see all commands.\n"},
	} {
		var stdout, stderr bytes.Buffer
		if code := run(test.args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != test.want {
			t.Fatalf("trestle %v: exit=%d\n%q\nwant\n%q", test.args, code, stderr.String(), test.want)
		}
	}
}

func TestHelpIsShortAndEveryCommandHasItsOwn(t *testing.T) {
	var usage bytes.Buffer
	writeUsage(&usage)
	text := usage.String()
	if lines := strings.Count(text, "\n"); lines > 45 || !strings.HasPrefix(text, "usage: trestle <command> [flags]\n") || !strings.HasSuffix(text, "\nRun trestle <command> --help for flags.\n") {
		t.Fatalf("%d lines:\n%s", lines, text)
	}
	initAssertWidth(t, strings.ReplaceAll(text, homeDocs, "docs/"))
	for _, group := range trestleCommandGroups {
		for _, command := range group.commands {
			var stdout, stderr bytes.Buffer
			if code := run([]string{command.name, "--help"}, &stdout, &stderr); code != 0 || !strings.HasPrefix(stdout.String(), "usage: trestle ") {
				t.Fatalf("trestle %s --help: exit=%d %q %q", command.name, code, stdout.String(), stderr.String())
			}
		}
	}
}

func TestVersionIsOneLine(t *testing.T) {
	for _, argument := range []string{"--version", "version"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{argument}, &stdout, &stderr); code != 0 || stderr.Len() != 0 || stdout.String() != "Open Trestle development build (no source revision recorded)\n" {
			t.Fatalf("trestle %s: exit=%d %q %q", argument, code, stdout.String(), stderr.String())
		}
	}
}
