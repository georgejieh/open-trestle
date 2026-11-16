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
	// /dev/null is a character device but not a terminal: a script that
	// runs `trestle </dev/null >/dev/null` keeps the usage text and exit 2.
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if homeInteractive(null, null) || homeInteractive(terminal, null) || homeInteractive(null, terminal) {
		t.Fatal("/dev/null was treated as a terminal")
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
