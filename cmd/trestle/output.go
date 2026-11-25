package main

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/georgejieh/open-trestle/spending"
)

// outPrinter prints a command's result on standard output. On a terminal it
// uses the marks, tones and width of trestle init: a heading, rows of
// "  <mark> label  value" whose labels line up, and a dim "-> command" for
// the next step. Elsewhere the command prints its plain lines with plain,
// which scripts read, so they must not change.
type outPrinter struct {
	*initWizard
	terminal bool
}

func newOutPrinter(ctx context.Context, out io.Writer) outPrinter {
	return outPrinter{latestReviewPrinter(ctx, out, ""), initTerminal(out)}
}

// note prints one sentence: after a mark and wrapped on a terminal, as it
// is elsewhere.
func (p outPrinter) note(mark, text string) {
	if !p.terminal {
		fmt.Fprintln(p.out, text)
		return
	}
	p.say("%s", "  "+mark+" "+text)
}

// aside prints a sentence of background: dim on a terminal, as it is
// elsewhere.
func (p outPrinter) aside(text string) {
	if !p.terminal {
		fmt.Fprintln(p.out, text)
		return
	}
	p.hint("  " + text)
}

func (p outPrinter) heading(title string) {
	p.sayVerbatim(p.style.paint(initToneHeading, title))
}

// commandFail prints a refusal on standard error, "trestle <command>: <what
// happened>. <what did or did not change>.", then each command to run next on
// its own indented line, never wrapped. It returns code.
func commandFail(stderr io.Writer, code int, command, message string, next ...string) int {
	fmt.Fprintf(stderr, "trestle %s: %s\n", command, message)
	style := newInitStyle(stderr, false)
	for _, line := range next {
		fmt.Fprintln(stderr, style.paint(initToneDim, "  -> "+line))
	}
	return code
}

// outRow is one row; label may be empty, tone colors the value, and next are
// the commands that fix it, printed beneath it.
type outRow struct {
	mark, label, value string
	tone               initTone
	next               []string
}

// rows prints rows with their labels padded to the longest one. A value
// wraps under itself.
func (p outPrinter) rows(rows ...outRow) {
	width := 0
	for _, row := range rows {
		width = max(width, initVisible(row.label))
	}
	for _, row := range rows {
		prefix := "  " + row.mark + " "
		if width > 0 {
			prefix += row.label + strings.Repeat(" ", width-initVisible(row.label)) + "  "
		}
		hang := strings.Repeat(" ", initVisible(prefix))
		for i, part := range initFit(row.value, max(initWidth-len(hang), 12)) {
			if i > 0 {
				prefix = hang
			}
			p.sayVerbatim(prefix + p.style.paint(row.tone, part))
		}
		for _, command := range row.next {
			p.sayVerbatim(p.style.paint(initToneDim, "    -> "+command))
		}
	}
}

// detail prints text under a row, indented to its value.
func (p outPrinter) detail(text string, tone initTone) {
	for _, part := range initFit("    "+text, initWidth) {
		p.sayVerbatim(p.style.paint(tone, part))
	}
}

// next prints the commands to run next, one per line, never wrapped.
func (p outPrinter) next(commands ...string) {
	for _, command := range commands {
		p.sayVerbatim(p.style.paint(initToneDim, "  -> "+command))
	}
}

// spendingState is the mark and tone of a limit's state: dim under half the
// limit, the warning tone from its first alert and danger once reached. The
// mark and the percentage in the text say the same, so color is never the
// only signal.
func (p outPrinter) spendingState(status spending.Status) (string, initTone) {
	state, tone := spendingLevel(status)
	return p.style.markOf(state), tone
}

func spendingLevel(status spending.Status) (healthState, initTone) {
	percent := status.Percent()
	switch {
	case status.Reached():
		return healthFail, initToneDanger
	case len(status.Limit.AlertPercents) > 0 && percent >= uint64(status.Limit.AlertPercents[0]):
		return healthAttention, initToneWarning
	case percent < 50:
		return healthOK, initToneDim
	}
	return healthOK, initToneBody
}

// healthState is how a row of `trestle doctor`, `trestle status` or the home
// screen stands. Only a failure needs fixing; the others never fail a command.
type healthState string

const (
	healthOK        healthState = "ok"
	healthOptional  healthState = "optional"
	healthAttention healthState = "attention"
	healthFail      healthState = "fail"
)

// healthRow is one such row, in the JSON those commands print. Next are the
// commands that fix it.
type healthRow struct {
	Label string      `json:"label"`
	Value string      `json:"value"`
	State healthState `json:"state"`
	Next  []string    `json:"next,omitempty"`
	tone  initTone
}

func (s initStyle) markOf(state healthState) string {
	ok, wait, bad, optional := s.marks()
	switch state {
	case healthFail:
		return bad
	case healthAttention:
		return wait
	case healthOptional:
		return optional
	}
	return ok
}
