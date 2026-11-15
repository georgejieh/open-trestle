package main

import (
	"bytes"
	"os"
	"testing"
)

// The home screen needs a real terminal on both sides and no NO_COLOR or
// TERM=dumb; a pseudo-terminal stands in for one.
func TestHomeInteractiveNeedsATerminalWithoutNoColorOrDumbTerm(t *testing.T) {
	_, terminal := openTestPTY(t)
	t.Setenv("TERM", "xterm-256color")
	t.Setenv("NO_COLOR", "") // restored after the test
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	if !homeInteractive(terminal, terminal) {
		t.Fatal("a terminal on both sides was not interactive")
	}
	if homeInteractive(terminal, &bytes.Buffer{}) || homeInteractive(&bytes.Buffer{}, terminal) {
		t.Fatal("a pipe on one side was treated as interactive")
	}
	t.Setenv("NO_COLOR", "")
	if homeInteractive(terminal, terminal) {
		t.Fatal("NO_COLOR (even empty) did not keep the usage text")
	}
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TERM", "dumb")
	if homeInteractive(terminal, terminal) {
		t.Fatal("TERM=dumb did not keep the usage text")
	}
}
