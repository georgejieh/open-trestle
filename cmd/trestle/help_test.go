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
		{"Everyday", []string{"usage: trestle review [", "usage: trestle update [", "usage: trestle usage "}},
		{"Setup and keys", []string{"usage: trestle init ", "usage: trestle keys [list]"}},
		{"Integrations", []string{"usage: trestle local-git model-review ", "usage: trestle runs submit ", "usage: trestle mcp ", "usage: trestle lsp "}},
		{"Operators", []string{"usage: trestle setup bootstrap ", "usage: trestle config validate ", "usage: trestle admin runtime "}},
		{"Evaluation", []string{"usage: trestle evaluate adjudication ", "usage: trestle validate-fixture "}},
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
	for _, args := range [][]string{{"nonsense"}, {"nonsense", "argument"}, {"help", "review"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.String() != usage.String() {
			t.Fatalf("trestle %v: exit=%d stdout=%q", args, code, stdout.String())
		}
	}
}
