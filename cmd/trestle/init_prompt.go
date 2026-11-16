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
// with scripted input. It never puts the terminal into raw mode.

const initMaxAnswerBytes = 4096
const initMaxTries = 3

var (
	errInitInputEnded   = errors.New("input ended before setup finished")
	errInitTooManyTries = errors.New("too many invalid answers")
)

type initLine struct {
	text string
	err  error
}

type initPrompter struct {
	ctx   context.Context
	out   io.Writer
	style initStyle
	say   func(string) // writes one wrapped line, as the wizard does
	lines chan initLine
	done  chan struct{}
}

func newInitPrompter(ctx context.Context, in io.Reader, out io.Writer, style initStyle, say func(string)) *initPrompter {
	p := &initPrompter{ctx: ctx, out: out, style: style, say: say, lines: make(chan initLine), done: make(chan struct{})}
	go func() {
		defer close(p.lines)
		reader := bufio.NewReaderSize(in, initMaxAnswerBytes)
		for {
			text, err := readInitLine(reader)
			select {
			case p.lines <- initLine{text, err}:
			case <-p.done:
				return
			}
			if err != nil {
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
	select {
	case <-p.ctx.Done():
		fmt.Fprintln(p.out)
		return "", errInitInputEnded
	case line, ok := <-p.lines:
		if !ok || line.err != nil {
			fmt.Fprintln(p.out)
			return "", errInitInputEnded
		}
		return line.text, nil
	}
}

// ask returns the validated answer; Enter accepts the proposal shown in brackets.
func (p *initPrompter) ask(question, proposed string, validate func(string) (string, error)) (string, error) {
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
		p.say("    " + err.Error())
	}
	return "", errInitTooManyTries
}

// askOptional returns one answer that may be empty (Enter skips).
func (p *initPrompter) askOptional(question string) (string, error) {
	for range initMaxTries {
		answer, err := p.next("  " + question + ": ")
		if err != nil {
			return "", err
		}
		if answer != "\x00too-long" {
			return answer, nil
		}
		p.say("    That answer is too long. Please try again.")
	}
	return "", errInitTooManyTries
}

// choose prints numbered options and returns the zero-based index of the choice.
func (p *initPrompter) choose(question string, options []string) (int, error) {
	for i, option := range options {
		p.say(fmt.Sprintf("    %d) %s", i+1, option))
	}
	answer, err := p.ask(fmt.Sprintf("%s (1-%d)", question, len(options)), "", func(value string) (string, error) {
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

// confirm asks a y/n question. The default is shown in capitals.
func (p *initPrompter) confirm(question string, defaultYes bool) (bool, error) {
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
		p.say("    Please answer y or n.")
	}
	return false, errInitTooManyTries
}

// typedYes requires the full word "yes"; "no" declines. Nothing is pre-answered.
func (p *initPrompter) typedYes(question string) (bool, error) {
	for range initMaxTries {
		answer, err := p.next("  " + question + " Type yes or no: ")
		if err != nil {
			return false, err
		}
		switch strings.ToLower(answer) {
		case "yes":
			return true, nil
		case "no", "n":
			return false, nil
		}
		p.say("    Please type the full word yes to confirm, or no to stop.")
	}
	return false, errInitTooManyTries
}
