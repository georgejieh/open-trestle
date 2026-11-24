package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// The init wizard reads plain lines so it works over SSH, in dumb terminals and
// with scripted input. On an interactive terminal it also shows arrow-key
// menus (init_menu.go), with the terminal in raw mode only while a menu or a
// key is read. Input is read only when a question asks for it, so nothing
// typed for a menu is taken as a line, or the other way round.

const initMaxAnswerBytes = 4096
const initMaxTries = 3

var (
	errInitInputEnded   = errors.New("input ended before setup finished")
	errInitTooManyTries = errors.New("too many invalid answers")
	// errInitBack asks for the previous question again.
	errInitBack = errors.New("back to the previous question")
	// errInitCanceled is q at a menu, or Ctrl-C while a menu or key is read.
	errInitCanceled = errors.New("setup was canceled")
	// errInitRawUnavailable is a terminal that cannot read single keys; the
	// line prompt is used instead.
	errInitRawUnavailable = errors.New("the terminal cannot read single keys")
)

type initLine struct {
	text string
	key  menuKey
	err  error
}

type initPrompter struct {
	ctx   context.Context
	out   io.Writer
	style initStyle
	say   func(string) // writes one wrapped line, as the wizard does
	// requests asks the reader for one line (false) or one key (true).
	requests chan bool
	replies  chan initLine
	done     chan struct{}
	// keys is the terminal that menus and key entry read in raw mode; nil
	// keeps the line prompts.
	keys keyTerminal
	// canBack lets b, back, Esc and Left return errInitBack.
	canBack bool
	// questions counts the questions asked, so the wizard can tell whether
	// back was pressed at a step's first question.
	questions int
}

func newInitPrompter(ctx context.Context, in io.Reader, out io.Writer, style initStyle, say func(string)) *initPrompter {
	p := &initPrompter{ctx: ctx, out: out, style: style, say: say, requests: make(chan bool), replies: make(chan initLine), done: make(chan struct{})}
	go func() {
		reader := bufio.NewReaderSize(in, initMaxAnswerBytes)
		var ended error
		for {
			var key bool
			select {
			case key = <-p.requests:
			case <-p.done:
				return
			}
			line := initLine{err: ended}
			if ended == nil {
				if key {
					line.key, line.err = readMenuKey(reader)
				} else {
					line.text, line.err = readInitLine(reader)
				}
				ended = line.err
			}
			select {
			case p.replies <- line:
			case <-p.done:
				return
			}
		}
	}()
	return p
}

func (p *initPrompter) close() { close(p.done) }

// readInitLine returns one answer without its line ending. An over-long line is
// consumed completely and reported as invalid instead of being split in two.
func readInitLine(reader *bufio.Reader) (string, error) {
	var line []byte
	tooLong := false
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(line)+len(chunk) > initMaxAnswerBytes {
			tooLong = true
		} else {
			line = append(line, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil && (len(line) == 0 || !errors.Is(err, io.EOF)) {
			return "", errInitInputEnded
		}
		break
	}
	if tooLong {
		return "\x00too-long", nil
	}
	return strings.TrimSpace(strings.TrimRight(string(line), "\r\n")), nil
}

// read waits for one line or key; any read error is the end of input.
func (p *initPrompter) read(key bool) (initLine, error) {
	select {
	case p.requests <- key:
	case <-p.ctx.Done():
		return initLine{}, errInitInputEnded
	}
	select {
	case <-p.ctx.Done():
		return initLine{}, errInitInputEnded
	case line := <-p.replies:
		if line.err != nil {
			return initLine{}, errInitInputEnded
		}
		return line, nil
	}
}

func (p *initPrompter) readKey() (menuKey, error) {
	line, err := p.read(true)
	return line.key, err
}

// menu shows m with the terminal in raw mode, which is restored before it
// returns, also on a panic.
func (p *initPrompter) menu(m *initMenu) (int, string, error) {
	restore, err := p.keys.rawInput()
	if err != nil {
		return 0, "", errInitRawUnavailable
	}
	defer p.restoreTerminal(restore)
	m.back = p.canBack
	return m.run(p.out, p.style, p.readKey)
}

func (p *initPrompter) restoreTerminal(restore func() error) {
	if restore() != nil {
		p.say("    Your terminal could not be restored; run `reset` if typed text stays hidden.")
	}
}

// isBack reports b or back typed at a line prompt that may go back.
func (p *initPrompter) isBack(answer string) bool {
	lower := strings.ToLower(answer)
	return p.canBack && (lower == "b" || lower == "back")
}

// next shows a question in the prompt color, wrapped so that its last line is
// where the answer is typed, and returns the answer.
func (p *initPrompter) next(prompt string) (string, error) {
	parts := initFit(prompt, initWidth)
	for _, part := range parts[:len(parts)-1] {
		fmt.Fprintln(p.out, p.style.paint(initTonePrompt, part))
	}
	last := parts[len(parts)-1]
	trailing := last[len(strings.TrimRight(last, " ")):]
	fmt.Fprint(p.out, p.style.paint(initTonePrompt, strings.TrimRight(last, " "))+trailing)
	line, err := p.read(false)
	if err != nil {
		fmt.Fprintln(p.out)
		return "", err
	}
	return line.text, nil
}

// ask returns the validated answer; Enter accepts the proposal shown in
// brackets. b or back goes back when it is not itself a valid answer.
func (p *initPrompter) ask(question, proposed string, validate func(string) (string, error)) (string, error) {
	p.questions++
	for range initMaxTries {
		prompt := "  " + question
		if proposed != "" {
			prompt += " [" + proposed + "]"
		}
		answer, err := p.next(prompt + ": ")
		if err != nil {
			return "", err
		}
		if answer == "\x00too-long" {
			p.say("    That answer is too long. Please try again.")
			continue
		}
		if answer == "" {
			answer = proposed
		}
		if answer == "" {
			p.say("    An answer is needed here.")
			continue
		}
		value, err := validate(answer)
		if err == nil {
			return value, nil
		}
		if p.isBack(answer) {
			return "", errInitBack
		}
		p.say("    " + err.Error())
	}
	return "", errInitTooManyTries
}

// choose offers options and returns the zero-based index of the choice;
// Enter takes the option at proposed. On a terminal it is a menu, otherwise
// numbered lines.
func (p *initPrompter) choose(question string, options []string, proposed int) (int, error) {
	if p.keys != nil {
		items := make([]menuItem, len(options))
		for i, option := range options {
			items[i] = menuItem{label: option}
		}
		p.questions++
		index, _, err := p.menu(&initMenu{title: question, items: items, selected: proposed})
		if !errors.Is(err, errInitRawUnavailable) {
			return index, err
		}
		p.questions--
	}
	for i, option := range options {
		p.say(fmt.Sprintf("    %d) %s", i+1, option))
	}
	answer, err := p.ask(fmt.Sprintf("%s (1-%d)", question, len(options)), strconv.Itoa(proposed+1), func(value string) (string, error) {
		n, err := strconv.Atoi(value)
		if err != nil || n < 1 || n > len(options) {
			return "", fmt.Errorf("Please type a number from 1 to %d.", len(options))
		}
		return value, nil
	})
	if err != nil {
		return 0, err
	}
	n, _ := strconv.Atoi(answer)
	return n - 1, nil
}

// confirm asks a yes or no question. On a terminal it is a Yes/No menu
// (y and n pick at once); otherwise the default is shown in capitals.
func (p *initPrompter) confirm(question string, defaultYes bool) (bool, error) {
	p.questions++
	if p.keys != nil {
		selected := 1
		if defaultYes {
			selected = 0
		}
		index, _, err := p.menu(&initMenu{title: question, items: []menuItem{{label: "Yes", shortcut: 'y'}, {label: "No", shortcut: 'n'}}, selected: selected})
		if !errors.Is(err, errInitRawUnavailable) {
			return index == 0 && err == nil, err
		}
	}
	proposed := "y/N"
	if defaultYes {
		proposed = "Y/n"
	}
	for range initMaxTries {
		answer, err := p.next("  " + question + " (" + proposed + "): ")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "":
			return defaultYes, nil
		case "y", "yes":
			return true, nil
		case "n", "no":
			return false, nil
		}
		if p.isBack(answer) {
			return false, errInitBack
		}
		p.say("    Please answer y or n.")
	}
	return false, errInitTooManyTries
}
