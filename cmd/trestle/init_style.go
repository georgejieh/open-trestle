package main

import (
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"
)

// The look of `trestle init`. It extends the product's identity rather than
// inventing one: the Ambassador Bridge mark and the web console's colors
// (web/src/styles.css). Body text keeps the terminal's own foreground so it
// reads on light and dark themes, and every state keeps its mark, so nothing
// depends on color alone.
//
// Color is used only on an interactive terminal: never when NO_COLOR is set
// (to any value), TERM is dumb, standard output is not a terminal, or with
// --no-input. TERM=dumb also selects ASCII marks and frames.

// initWidth is the widest line trestle init prints, the narrowest terminal it
// supports. Copyable commands keep their full paths and are the one exception.
const initWidth = 60

// bridgeCompactMark is the Ambassador Bridge in three lines for narrow
// headers: the two X-braced towers, the suspension cables leaving each tower
// and the deck. Every line is ASCII and the same width, so text can sit beside
// it.
var bridgeCompactMark = [3]string{
	"   |X|\\            /|X|   ",
	" __|X| \\___----___/ |X|__ ",
	"===|X|=|==|==|==|===|X|===",
}

const initSteps = 6

type initPalette int

const (
	initPlain initPalette = iota
	initColor256
	initColorTrue
)

type initTone int

const (
	initToneHeading initTone = iota // cobalt, bold: titles and the active step
	initTonePrompt                  // cobalt: questions
	initToneRule                    // slate: rules, frames and the mark
	initToneSuccess                 // lichen: ✓
	initToneWarning                 // amber: …
	initToneDanger                  // oxide: ✗
	initToneDim                     // faint: hints and not-yet steps
)

// Console tokens: --cobalt #1c5da8, --rule-dark #496069 (the slate rule that
// stays visible on dark backgrounds), --lichen #347158, --amber #875511 and
// --oxide #a43e2e, each with its nearest xterm-256 color.
var initToneCodes = map[initTone][2]string{
	initToneHeading: {"1;38;2;28;93;168", "1;38;5;25"},
	initTonePrompt:  {"38;2;28;93;168", "38;5;25"},
	initToneRule:    {"38;2;73;96;105", "38;5;59"},
	initToneSuccess: {"38;2;52;113;88", "38;5;65"},
	initToneWarning: {"38;2;135;85;17", "38;5;94"},
	initToneDanger:  {"38;2;164;62;46", "38;5;131"},
	initToneDim:     {"2", "2"},
}

type initStyle struct {
	palette initPalette
	ascii   bool
}

// initTerminal reports whether w is an interactive terminal. Tests replace it.
var initTerminal = func(w io.Writer) bool {
	file, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := file.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func newInitStyle(out io.Writer, noInput bool) initStyle {
	style := initStyle{ascii: os.Getenv("TERM") == "dumb"}
	if _, noColor := os.LookupEnv("NO_COLOR"); noColor || style.ascii || noInput || !initTerminal(out) {
		return style
	}
	style.palette = initColor256
	if colorterm := strings.ToLower(os.Getenv("COLORTERM")); colorterm == "truecolor" || colorterm == "24bit" {
		style.palette = initColorTrue
	}
	return style
}

// paint wraps text in the tone's color, or returns it unchanged without color.
func (s initStyle) paint(tone initTone, text string) string {
	if s.palette == initPlain || text == "" {
		return text
	}
	code := initToneCodes[tone][1]
	if s.palette == initColorTrue {
		code = initToneCodes[tone][0]
	}
	return "\x1b[" + code + "m" + text + "\x1b[0m"
}

var initANSI = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// initVisible is the number of columns text takes, ignoring color codes.
func initVisible(text string) int {
	return utf8.RuneCountInString(initANSI.ReplaceAllString(text, ""))
}

// initMarkers start a line whose continuation lines hang after them.
var initMarkers = regexp.MustCompile(`^(✓|…|✗|–|•|\[ok\]|\[\.\.\]|\[x\]|\[--\]|\d+\)|-)$`)

// initLabelColumn is a "Label:" followed by two or more spaces: a value
// column that continuation lines line up with.
var initLabelColumn = regexp.MustCompile(`^\S+: {2,}`)

// initFit breaks one line into lines of at most width columns at spaces,
// keeping its indentation; lines after the first hang after a leading mark
// or bullet. A single word longer than a line is left whole.
func initFit(line string, width int) []string {
	if initVisible(line) <= width {
		return []string{line}
	}
	trimmed := strings.TrimLeft(line, " ")
	indent := strings.Repeat(" ", len(line)-len(trimmed))
	// A `backticked command` is one word, so it is never split across lines.
	words := []string{}
	for _, word := range strings.Split(trimmed, " ") {
		if last := len(words) - 1; last >= 0 && strings.Count(words[last], "`")%2 == 1 {
			words[last] += " " + word
			continue
		}
		words = append(words, word)
	}
	hang := indent
	if label := initLabelColumn.FindString(trimmed); label != "" {
		hang += strings.Repeat(" ", initVisible(label))
	} else if len(words) > 1 && initMarkers.MatchString(initANSI.ReplaceAllString(words[0], "")) {
		hang += strings.Repeat(" ", initVisible(words[0])+1)
	}
	lines, current := []string{}, indent
	empty := true
	for _, word := range words {
		if !empty && initVisible(current)+1+initVisible(word) > width {
			lines, current, empty = append(lines, current), hang, true
		}
		if !empty {
			current += " "
		}
		current += word
		empty = false
	}
	return append(lines, current)
}

// banner is the opening: the compact bridge mark with the product name beside
// it, what a review does in three lines, then how to answer.
func (s initStyle) banner(noInput bool) []string {
	mark := bridgeCompactMark
	title := s.paint(initToneHeading, "Open Trestle · setup")
	lines := []string{s.paint(initToneRule, strings.TrimRight(mark[0], " ")), s.paint(initToneRule, mark[1]) + "  " + title, s.paint(initToneRule, strings.TrimRight(mark[2], " ")), ""}
	lines = append(lines,
		"  Two AI models review your change: one lists possible",
		"  problems, a different one double-checks each, and only",
		"  confirmed findings are reported. Setup sends no source.")
	if noInput {
		return append(lines, "  --no-input: every answer comes from a flag.")
	}
	return append(lines, s.paint(initToneDim, "  Enter accepts a value in [brackets]; Ctrl-D stops."))
}

// stepHeader is the step indicator, title and rule, for example
// "●●●○○○  Step 3 of 6 · The two models".
func (s initStyle) stepHeader(step int, title string) []string {
	done, todo := "●", "○"
	if s.ascii {
		done, todo = "#", "."
	}
	dots := s.paint(initToneHeading, strings.Repeat(done, step)) + s.paint(initToneDim, strings.Repeat(todo, initSteps-step))
	text := dots + "  " + s.paint(initToneHeading, "Step "+itoa(step)+" of "+itoa(initSteps)+" · "+title)
	return []string{"", text, s.paint(initToneRule, strings.Repeat("─", min(initVisible(text), initWidth)))}
}

func itoa(n int) string {
	if n < 0 || n > 9 {
		return "?"
	}
	return string(rune('0' + n))
}

// marks returns the ok, waiting, needs-a-fix and optional marks.
func (s initStyle) marks() (string, string, string, string) {
	if s.ascii {
		return "[ok]", "[..]", "[x]", "[--]"
	}
	return s.paint(initToneSuccess, "✓"), s.paint(initToneWarning, "…"), s.paint(initToneDanger, "✗"), s.paint(initToneDim, "–")
}

// initPanel draws rows of label and value in a box at most initWidth columns
// wide. Long values wrap inside the box.
func initPanel(title string, rows [][2]string, ascii bool) []string {
	horizontal, vertical, corners := "─", "│", [4]string{"┌", "┐", "└", "┘"}
	if ascii {
		horizontal, vertical, corners = "-", "|", [4]string{"+", "+", "+", "+"}
	}
	labelWidth := 0
	for _, row := range rows {
		labelWidth = max(labelWidth, utf8.RuneCountInString(row[0]))
	}
	inner := initWidth - 4
	valueWidth := inner - labelWidth - 2
	top := corners[0] + horizontal + " " + title + " "
	top += strings.Repeat(horizontal, max(0, initWidth-1-utf8.RuneCountInString(top))) + corners[1]
	lines := []string{top}
	for _, row := range rows {
		parts := initWrapWords(row[1], valueWidth)
		for i, part := range parts {
			label := ""
			if i == 0 {
				label = row[0]
			}
			cell := label + strings.Repeat(" ", labelWidth-utf8.RuneCountInString(label)) + "  " + part
			lines = append(lines, vertical+" "+cell+strings.Repeat(" ", max(0, inner-utf8.RuneCountInString(cell)))+" "+vertical)
		}
	}
	return append(lines, corners[2]+strings.Repeat(horizontal, initWidth-2)+corners[3])
}

// initWrapWords splits text into lines of at most width runes, breaking a
// word only when it alone is longer than a line.
func initWrapWords(text string, width int) []string {
	lines, line := []string{}, ""
	for _, word := range strings.Fields(text) {
		for utf8.RuneCountInString(word) > width {
			if line != "" {
				lines, line = append(lines, line), ""
			}
			runes := []rune(word)
			lines, word = append(lines, string(runes[:width])), string(runes[width:])
		}
		if line != "" && utf8.RuneCountInString(line)+1+utf8.RuneCountInString(word) > width {
			lines, line = append(lines, line), ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" || len(lines) == 0 {
		lines = append(lines, line)
	}
	return lines
}

// framed colors a panel's frame in the rule tone and leaves its text in the
// terminal's own color.
func (s initStyle) framed(lines []string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		if i == 0 || i == len(lines)-1 {
			out[i] = s.paint(initToneRule, line)
			continue
		}
		runes := []rune(line)
		out[i] = s.paint(initToneRule, string(runes[:1])) + string(runes[1:len(runes)-1]) + s.paint(initToneRule, string(runes[len(runes)-1:]))
	}
	return out
}
