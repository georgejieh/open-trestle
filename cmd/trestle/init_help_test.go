package main

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
)

// After three unusable answers the wizard points to `trestle init --help` for
// the answer flags, so the help must name every flag the wizard accepts.
func TestInitHelpListsEveryAnswerFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runInitWithClock(context.Background(), []string{"--help"}, strings.NewReader(""), &stdout, &stderr, systemSetupClock{})
	if code != initExitDone || stderr.Len() != 0 {
		t.Fatalf("--help exit=%d stderr=%s", code, stderr.String())
	}
	help := stdout.String()
	for _, name := range append(append([]string{}, initStringFlags...), initBoolFlags...) {
		if !regexp.MustCompile(`(^|[\s\[])--` + regexp.QuoteMeta(name) + `([\s\]=]|$)`).MatchString(help) {
			t.Errorf("help does not list --%s:\n%s", name, help)
		}
	}
	for _, line := range strings.Split(help, "\n") {
		if len([]rune(line)) > 100 {
			t.Errorf("help line wider than 100 columns: %q", line)
		}
	}
	if !strings.Contains(help, "docs/getting-started.md") {
		t.Errorf("help lost its pointer to the guide:\n%s", help)
	}
}
