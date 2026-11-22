package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// initAsTerminal makes the wizard treat its output as an interactive terminal.
func initAsTerminal(t *testing.T) {
	t.Helper()
	previous := initTerminal
	initTerminal = func(io.Writer) bool { return true }
	t.Cleanup(func() { initTerminal = previous })
}

// initColorEnv clears the variables that select or suppress color.
func initColorEnv(t *testing.T, term, colorterm string) {
	t.Helper()
	t.Setenv("TERM", term)
	t.Setenv("COLORTERM", colorterm)
	t.Setenv("NO_COLOR", "")
	if err := os.Unsetenv("NO_COLOR"); err != nil {
		t.Fatal(err)
	}
}

// initAssertWidth fails when a shown line is wider than initWidth columns.
// Commands to copy keep their full length, and a documentation link or URL
// is never split, so one that alone exceeds a line sits on its own line.
func initAssertWidth(t *testing.T, text string) {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		for _, part := range initPromptEnd.Split(line, -1) {
			word := strings.TrimRight(strings.TrimSpace(part), ".,;:)")
			link := !strings.Contains(word, " ") && (strings.HasPrefix(word, "docs/") || strings.Contains(word, "://"))
			if initVisible(part) > initWidth && !initCommandLine(part) && !strings.Contains(part, "`") && !link {
				t.Fatalf("line wider than %d columns: %q", initWidth, part)
			}
		}
	}
}

func TestInitStyleColorsOnlyAnInteractiveTerminal(t *testing.T) {
	checkout := remoteBootstrapCheckout(t)
	args := []string{"--directory", filepath.Join(t.TempDir(), "setup"), "--base", "refs/heads/base", "--head", "refs/heads/review"}
	for _, test := range []struct {
		name, term, colorterm string
		terminal, noColor     bool
		want, unwanted        []string
	}{
		{"256 colors", "xterm-256color", "", true, false, []string{"\x1b[1;38;5;25mOpen Trestle · setup\x1b[0m", "\x1b[38;5;59m===|X|", "\x1b[1;38;5;25m●\x1b[0m\x1b[2m○○○○○\x1b[0m", "\x1b[38;5;25m  Choose (1-5):\x1b[0m "}, []string{"38;2;"}},
		{"24-bit colors", "xterm-256color", "truecolor", true, false, []string{"\x1b[1;38;2;28;93;168mOpen Trestle · setup", "\x1b[38;2;73;96;105m", "\x1b[38;2;28;93;168m"}, []string{"38;5;"}},
		{"NO_COLOR", "xterm-256color", "truecolor", true, true, []string{"Open Trestle · setup", "●○○○○○"}, []string{"\x1b["}},
		{"TERM=dumb", "dumb", "truecolor", true, false, []string{"#.....  Step 1 of 6", "Open Trestle · setup"}, []string{"\x1b[", "●"}},
		{"not a terminal", "xterm-256color", "truecolor", false, false, []string{"●○○○○○  Step 1 of 6"}, []string{"\x1b["}},
	} {
		t.Run(test.name, func(t *testing.T) {
			initColorEnv(t, test.term, test.colorterm)
			if test.noColor {
				t.Setenv("NO_COLOR", "")
			}
			if test.terminal {
				initAsTerminal(t)
			}
			result := runInitScript(t, checkout, args, "")
			for _, want := range test.want {
				if !strings.Contains(result.stdout, want) {
					t.Fatalf("output lacks %q:\n%q", want, result.stdout)
				}
			}
			for _, unwanted := range test.unwanted {
				if strings.Contains(result.stdout+result.stderr, unwanted) {
					t.Fatalf("output contains %q:\n%q", unwanted, result.stdout)
				}
			}
		})
	}
}

func TestInitStyleNoInputNeverColors(t *testing.T) {
	initColorEnv(t, "xterm-256color", "truecolor")
	initAsTerminal(t)
	result := runInitScript(t, remoteBootstrapCheckout(t), []string{"--no-input", "--directory", filepath.Join(t.TempDir(), "setup"), "--provider", "local"})
	if strings.Contains(result.stdout+result.stderr, "\x1b[") {
		t.Fatalf("--no-input printed color:\n%q", result.stdout)
	}
}

func TestInitStyleMarksKeepTheirGlyphsInColor(t *testing.T) {
	ok, wait, bad, optional := initStyle{palette: initColor256}.marks()
	for mark, want := range map[string]string{ok: "\x1b[38;5;65m✓", wait: "\x1b[38;5;94m…", bad: "\x1b[38;5;131m✗", optional: "\x1b[2m–"} {
		if !strings.HasPrefix(mark, want) || !strings.HasSuffix(mark, "\x1b[0m") {
			t.Fatalf("mark %q, want prefix %q", mark, want)
		}
	}
	if ok, wait, bad, optional := (initStyle{ascii: true}).marks(); ok != "[ok]" || wait != "[..]" || bad != "[x]" || optional != "[--]" {
		t.Fatal("TERM=dumb lost the ASCII marks")
	}
}

func TestInitFitWrapsAtSpacesAndKeepsHangsAndCommands(t *testing.T) {
	for _, test := range []struct {
		line string
		want []string
	}{
		{"    ✓ The saved configuration loads into the model dispatcher today", []string{"    ✓ The saved configuration loads into the model", "      dispatcher today"}},
		{"  Changes:    1 commit · 1 file changed, 1 insertion(+), 1 deletion(-)", []string{"  Changes:    1 commit · 1 file changed, 1 insertion(+), 1", "              deletion(-)"}},
		{"  then run `trestle init --directory /a/long/folder/name/for/this/setup` again", []string{"  then run", "  `trestle init --directory /a/long/folder/name/for/this/setup`", "  again"}},
		{"  \x1b[2mshort\x1b[0m", []string{"  \x1b[2mshort\x1b[0m"}},
	} {
		got := initFit(test.line, initWidth)
		if strings.Join(got, "\n") != strings.Join(test.want, "\n") {
			t.Fatalf("initFit(%q) =\n%q\nwant\n%q", test.line, got, test.want)
		}
	}
	colored := initStyle{palette: initColor256}.paint(initToneDim, strings.Repeat("word ", 20))
	for _, line := range initFit("  "+colored, initWidth) {
		if initVisible(line) > initWidth {
			t.Fatalf("colored line too wide: %q", line)
		}
	}
}

func TestInitPanelFramesRowsWithinTheWidth(t *testing.T) {
	rows := [][2]string{{"Finder", "vendor/" + strings.Repeat("long-model-name-", 5)}, {"Limits", "context 128000 · output 16000 tokens"}}
	for _, ascii := range []bool{false, true} {
		lines := initPanel("Setup summary", rows, ascii)
		top, bottom := "┌─ Setup summary ", "└"
		if ascii {
			top, bottom = "+- Setup summary ", "+"
		}
		if !strings.HasPrefix(lines[0], top) || !strings.HasPrefix(lines[len(lines)-1], bottom) || len(lines) < 5 {
			t.Fatalf("panel frame:\n%s", strings.Join(lines, "\n"))
		}
		for _, line := range lines {
			if initVisible(line) != initWidth {
				t.Fatalf("panel line is %d columns, want %d: %q", initVisible(line), initWidth, line)
			}
		}
		if !initHas(strings.Join(lines, "\n"), "Limits  context 128000 · output 16000 tokens") {
			t.Fatalf("panel lost a row:\n%s", strings.Join(lines, "\n"))
		}
	}
}

// The compact mark keeps the full mark's identity: two X-braced towers at the
// same columns on every line, a cable leaving each tower, and the deck.
func TestCompactBridgeMarkKeepsTheTowersAligned(t *testing.T) {
	width := len(bridgeCompactMark[0])
	towers := -1
	for index, line := range bridgeCompactMark {
		for _, r := range line {
			if r > 127 {
				t.Fatalf("line %d is not ASCII: %q", index+1, line)
			}
		}
		if len(line) != width || width > initWidth/2 {
			t.Fatalf("line %d width %d (want %d, at most %d): %q", index+1, len(line), width, initWidth/2, line)
		}
		first, last := strings.Index(line, "|X|"), strings.LastIndex(line, "|X|")
		if first < 0 || last == first || strings.Count(line, "|X|") != 2 {
			t.Fatalf("line %d lacks two towers: %q", index+1, line)
		}
		if towers < 0 {
			towers = first*100 + last
		} else if first*100+last != towers {
			t.Fatalf("line %d moves a tower: %q", index+1, line)
		}
	}
	if !strings.Contains(bridgeCompactMark[0], `|X|\`) || !strings.Contains(bridgeCompactMark[0], `/|X|`) || !strings.HasPrefix(bridgeCompactMark[2], "===") {
		t.Fatalf("the compact mark lost its cables or deck: %q", bridgeCompactMark)
	}
}
