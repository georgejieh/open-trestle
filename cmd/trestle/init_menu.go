package main

import (
	"bufio"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Arrow-key menus for `trestle init`. They are used only when standard input
// and output are both terminals, TERM is not dumb and --no-input is unset;
// otherwise the numbered line prompts are kept. The terminal is in raw mode
// only while a menu reads keys (initPrompter.menu restores it). A menu
// redraws in place: the cursor moves up over the previous frame and clears
// below it, so nothing above the menu changes.

type menuKeyKind int

const (
	menuNone menuKeyKind = iota
	menuRune
	menuUp
	menuDown
	menuLeft
	menuRight
	menuHome
	menuEnd
	menuPageUp
	menuPageDown
	menuEnter
	menuEscape
	menuBackspace
	menuClear      // Ctrl-U
	menuInterrupt  // Ctrl-C
	menuEndOfInput // Ctrl-D
)

type menuKey struct {
	kind menuKeyKind
	r    rune
}

// readMenuKey reads one key from raw terminal input. A lone Esc is told from
// an escape sequence by whether more bytes arrived with it.
func readMenuKey(reader *bufio.Reader) (menuKey, error) {
	r, _, err := reader.ReadRune()
	if err != nil {
		return menuKey{}, err
	}
	switch r {
	case '\r', '\n':
		if next, err := reader.Peek(1); r == '\r' && err == nil && reader.Buffered() > 0 && next[0] == '\n' {
			_, _ = reader.ReadByte()
		}
		return menuKey{kind: menuEnter}, nil
	case 0x7f, 0x08:
		return menuKey{kind: menuBackspace}, nil
	case 0x15:
		return menuKey{kind: menuClear}, nil
	case 0x03:
		return menuKey{kind: menuInterrupt}, nil
	case 0x04:
		return menuKey{kind: menuEndOfInput}, nil
	case 0x1b:
		if reader.Buffered() == 0 {
			return menuKey{kind: menuEscape}, nil
		}
		if next, _ := reader.Peek(1); next[0] != '[' && next[0] != 'O' {
			return menuKey{kind: menuEscape}, nil
		}
		_, _ = reader.ReadByte()
		params := ""
		for {
			b, err := reader.ReadByte()
			if err != nil {
				return menuKey{}, err
			}
			if b >= 0x40 && b <= 0x7e {
				return menuSequenceKey(b, params), nil
			}
			if len(params) < 16 {
				params += string(b)
			}
		}
	}
	if r == utf8.RuneError || unicode.IsControl(r) {
		return menuKey{}, nil
	}
	return menuKey{kind: menuRune, r: r}, nil
}

func menuSequenceKey(final byte, params string) menuKey {
	first, _, _ := strings.Cut(params, ";")
	switch {
	case final == 'A':
		return menuKey{kind: menuUp}
	case final == 'B':
		return menuKey{kind: menuDown}
	case final == 'C':
		return menuKey{kind: menuRight}
	case final == 'D':
		return menuKey{kind: menuLeft}
	case final == 'H', final == '~' && (first == "1" || first == "7"):
		return menuKey{kind: menuHome}
	case final == 'F', final == '~' && (first == "4" || first == "8"):
		return menuKey{kind: menuEnd}
	case final == '~' && first == "5":
		return menuKey{kind: menuPageUp}
	case final == '~' && first == "6":
		return menuKey{kind: menuPageDown}
	}
	return menuKey{}
}

type menuItem struct {
	label, value string
	shortcut     rune // a key that picks this item at once, such as y
}

// initMenu is one question shown as a list with a pointer. A filterable menu
// narrows its items to the text typed (match), and with free set, Enter on
// text that matches nothing returns the text itself.
type initMenu struct {
	title    string
	items    []menuItem
	selected int // an index into items: the item the pointer starts on
	match    func(text string) []int
	free     bool
	// accept checks the choice (index -1 for free text) and returns the value
	// to use; an error is shown under the list and the menu stays open.
	accept func(index int, text string) (string, error)
	back   bool // Esc and Left go back to the previous question
	window int  // rows shown at once; 0 shows every item

	text   string
	shown  []int // indices into items, in display order
	cursor int   // position in shown
	top    int   // first row of shown in the window
	status string
}

const menuFilterLimit = 256

func (m *initMenu) start() {
	m.shown = m.shown[:0]
	for i := range m.items {
		m.shown = append(m.shown, i)
	}
	m.cursor = max(0, min(m.selected, len(m.items)-1))
	m.scroll()
}

func (m *initMenu) refilter() {
	m.cursor, m.top = 0, 0
	if m.text != "" {
		m.shown = m.match(m.text)
		return
	}
	m.shown = []int{}
	for i := range m.items {
		m.shown = append(m.shown, i)
	}
}

func (m *initMenu) scroll() {
	if m.window <= 0 {
		m.top = 0
		return
	}
	if m.cursor < m.top {
		m.top = m.cursor
	}
	if m.cursor >= m.top+m.window {
		m.top = m.cursor - m.window + 1
	}
}

func (m *initMenu) move(delta int) {
	if len(m.shown) == 0 {
		return
	}
	m.cursor = (m.cursor + delta + len(m.shown)) % len(m.shown)
	m.scroll()
}

func (m *initMenu) jump(position int) {
	if len(m.shown) == 0 {
		return
	}
	m.cursor = max(0, min(position, len(m.shown)-1))
	m.scroll()
}

// choose accepts the item at position, or the typed text for position -1.
func (m *initMenu) choose(position int) (int, string, bool) {
	index, text := -1, m.text
	if position >= 0 {
		index, text = m.shown[position], m.items[m.shown[position]].value
	}
	if m.accept != nil {
		value, err := m.accept(index, text)
		if err != nil {
			m.status = err.Error()
			return 0, "", false
		}
		text = value
	}
	return index, text, true
}

// handle applies one key. done reports a choice; err is errInitBack,
// errInitCanceled or errInitInputEnded.
func (m *initMenu) handle(key menuKey) (index int, value string, done bool, err error) {
	m.status = ""
	filterable := m.match != nil
	page := max(1, m.window)
	if m.window <= 0 {
		page = len(m.shown)
	}
	switch key.kind {
	case menuUp:
		m.move(-1)
	case menuDown:
		m.move(1)
	case menuHome:
		m.jump(0)
	case menuEnd:
		m.jump(len(m.shown) - 1)
	case menuPageUp:
		m.jump(m.cursor - page)
	case menuPageDown:
		m.jump(m.cursor + page)
	case menuEnter:
		switch {
		case len(m.shown) != 0:
			index, value, done = m.choose(m.cursor)
		case m.free && m.text != "":
			index, value, done = m.choose(-1)
		}
	case menuEscape, menuLeft:
		if filterable && m.text != "" {
			if key.kind == menuEscape {
				m.text = ""
				m.refilter()
			}
		} else if m.back {
			return 0, "", false, errInitBack
		}
	case menuInterrupt:
		return 0, "", false, errInitCanceled
	case menuEndOfInput:
		return 0, "", false, errInitInputEnded
	case menuBackspace, menuClear:
		if filterable && m.text != "" {
			if key.kind == menuClear {
				m.text = ""
			} else {
				_, size := utf8.DecodeLastRuneInString(m.text)
				m.text = m.text[:len(m.text)-size]
			}
			m.refilter()
		}
	case menuRune:
		if filterable {
			if utf8.RuneCountInString(m.text) < menuFilterLimit && !unicode.IsSpace(key.r) {
				m.text += string(key.r)
				m.refilter()
			}
			break
		}
		for position, i := range m.shown {
			if m.items[i].shortcut != 0 && unicode.ToLower(key.r) == m.items[i].shortcut {
				m.cursor = position
				index, value, done = m.choose(position)
				return index, value, done, nil
			}
		}
		switch {
		case key.r == 'k':
			m.move(-1)
		case key.r == 'j':
			m.move(1)
		case key.r == 'q' || key.r == 'Q':
			return 0, "", false, errInitCanceled
		case key.r >= '1' && key.r <= '9' && int(key.r-'0') <= len(m.shown):
			m.cursor = int(key.r - '1')
			index, value, done = m.choose(m.cursor)
		}
	}
	return index, value, done, nil
}

// frame renders the menu: the question, a key hint, the filter line, the
// visible rows with the pointer, and a status line.
func (m *initMenu) frame(style initStyle) []string {
	lines := []string{}
	for _, part := range initFit("  "+m.title, initWidth) {
		lines = append(lines, style.paint(initTonePrompt, part))
	}
	hints := []string{"↑↓ move", "Enter select"}
	if m.match != nil {
		hints = append([]string{"type to filter"}, hints...)
	}
	if m.back {
		hints = append(hints, "Esc back")
	}
	if m.match == nil {
		hints = append(hints, "q quit")
	}
	lines = append(lines, style.paint(initToneDim, "  "+strings.Join(hints, " · ")))
	if m.match != nil {
		count := fmt.Sprintf("%d models", len(m.items))
		if m.text != "" {
			count = fmt.Sprintf("%d of %d", len(m.shown), len(m.items))
		}
		text := []rune(m.text)
		if room := initWidth - 14 - len(count); len(text) > room {
			text = append([]rune("…"), text[len(text)-room+1:]...)
		}
		lines = append(lines, "  Filter: "+string(text)+"_  "+style.paint(initToneDim, count))
	}
	end := len(m.shown)
	if m.window > 0 {
		end = min(end, m.top+m.window)
	}
	if m.top > 0 {
		lines = append(lines, style.paint(initToneDim, fmt.Sprintf("      ↑ %d more", m.top)))
	}
	for position := m.top; position < end; position++ {
		prefix := "    "
		if position == m.cursor {
			prefix = "  › "
		}
		if m.match == nil {
			prefix += fmt.Sprintf("%d) ", position+1)
		}
		width := utf8.RuneCountInString(prefix)
		for i, part := range initWrapWords(m.items[m.shown[position]].label, initWidth-width) {
			if i == 0 {
				part = prefix + part
			} else {
				part = strings.Repeat(" ", width) + part
			}
			if position == m.cursor {
				part = style.paint(initToneHeading, part)
			}
			lines = append(lines, part)
		}
	}
	if more := len(m.shown) - end; more > 0 {
		lines = append(lines, style.paint(initToneDim, fmt.Sprintf("      ↓ %d more", more)))
	}
	if m.text != "" && len(m.shown) == 0 {
		note := fmt.Sprintf("    No listed model contains %q.", m.text)
		if m.free {
			note += " Enter uses it exactly as typed."
		}
		lines = append(lines, initFit(note, initWidth)...)
	}
	if m.status != "" {
		lines = append(lines, initFit("    "+m.status, initWidth)...)
	}
	return lines
}

// run reads keys until a choice, back or cancel, redrawing the frame after
// each key. A choice leaves one line, the question and its answer; back and
// cancel leave nothing.
func (m *initMenu) run(out io.Writer, style initStyle, next func() (menuKey, error)) (int, string, error) {
	m.start()
	drawn := 0
	draw := func(lines []string) {
		if drawn > 0 {
			fmt.Fprintf(out, "\x1b[%dF\x1b[J", drawn)
		}
		for _, line := range lines {
			fmt.Fprint(out, line+"\n")
		}
		drawn = len(lines)
	}
	fmt.Fprint(out, "\x1b[?25l")
	defer fmt.Fprint(out, "\x1b[?25h")
	for {
		draw(m.frame(style))
		key, err := next()
		if err != nil {
			draw(nil)
			return 0, "", errInitInputEnded
		}
		index, value, done, err := m.handle(key)
		if err != nil {
			draw(nil)
			return 0, "", err
		}
		if done {
			answer := value
			if index >= 0 && m.match == nil {
				answer = m.items[index].label
			}
			draw(m.answered(style, answer))
			return index, value, nil
		}
	}
}

// answered is what a menu leaves on screen once chosen: the question in the
// prompt color and the answer after it.
func (m *initMenu) answered(style initStyle, answer string) []string {
	title := m.title
	if !strings.HasSuffix(title, "?") && !strings.HasSuffix(title, ":") {
		title += ":"
	}
	parts := initFit("  "+title, initWidth)
	lines := make([]string, len(parts))
	for i, part := range parts {
		lines[i] = style.paint(initTonePrompt, part)
	}
	last := len(parts) - 1
	if initVisible(parts[last])+1+utf8.RuneCountInString(answer) <= initWidth {
		lines[last] += " " + answer
		return lines
	}
	return append(lines, initFit("    "+answer, initWidth)...)
}
