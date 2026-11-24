package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"unicode/utf8"
)

// Input for an API key. Where menus are shown, the key is read in raw mode
// and each character typed or pasted shows as one *. Otherwise the prompter
// reads a plain line with the terminal's echo off, so the characters typed
// are never shown, and turns echo back on before anything else is printed.
// Afterwards it shows the key's length and last four characters, so the
// person can tell what arrived. It needs a real terminal on standard input:
// stdlib termios on Linux and macOS, the console mode on Windows. Anything
// else, including a pipe or a file, is never asked for a key.

// errInitSecretUnavailable is a terminal whose echo could not be turned off,
// or back on; no key is read through it.
var errInitSecretUnavailable = errors.New("hidden input is not available on this terminal")

// echoTerminal is a terminal whose echo can be turned off while a key is
// typed.
type echoTerminal interface {
	// hideInput turns echo off and returns the function that restores the
	// terminal exactly as it was.
	hideInput() (restore func() error, err error)
}

// keyTerminal is a terminal that can also be read one key at a time.
type keyTerminal interface {
	echoTerminal
	// rawInput turns off echo, line editing and signal keys, keeping output
	// processing, and returns the function that restores the terminal.
	rawInput() (restore func() error, err error)
}

// openEchoTerminal returns standard input's terminal when it is an
// interactive terminal whose echo can be turned off. Tests replace it.
var openEchoTerminal = func(in io.Reader) (echoTerminal, bool) {
	file, ok := in.(*os.File)
	if !ok {
		return nil, false
	}
	if info, err := file.Stat(); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		return nil, false
	}
	return platformEchoTerminal(file)
}

// initEnableTerminalOutput prepares standard output for cursor movement and
// returns what undoes it. Tests replace it.
var initEnableTerminalOutput = enableTerminalOutput

// askSecret reads one answer that is never shown and returns it without
// surrounding spaces; "" means Enter on an empty line. The terminal is
// restored before askSecret returns, including when input ends or is
// interrupted. An answer that is one text pasted twice is asked for again.
func (p *initPrompter) askSecret(question string, terminal echoTerminal) (string, error) {
	p.questions++
	for range initMaxTries {
		answer, err := p.typeSecret("  " + question + ": ")
		if errors.Is(err, errInitRawUnavailable) {
			answer, err = p.hiddenSecret("  "+question+" (hidden): ", terminal)
		}
		if err != nil {
			return "", err
		}
		if answer == "\x00too-long" {
			p.say("    That is longer than any API key. Please try again.")
			continue
		}
		if half := len(answer) / 2; half >= minSecretReceiptLength && answer[:half] == answer[half:] {
			p.say(fmt.Sprintf("    That is the same text twice (%d characters each). Paste the key once.", half))
			continue
		}
		if answer != "" {
			p.say("    Received " + secretReceipt(answer) + ".")
		}
		return answer, nil
	}
	return "", errInitTooManyTries
}

// hiddenSecret reads one line with echo off; the prompt is shown only once
// echo is off.
func (p *initPrompter) hiddenSecret(prompt string, terminal echoTerminal) (string, error) {
	restore, err := terminal.hideInput()
	if err != nil {
		return "", errInitSecretUnavailable
	}
	answer, readErr := p.next(prompt)
	restoreErr := restore()
	// The Enter that ended the answer was not echoed either.
	fmt.Fprintln(p.out)
	if restoreErr != nil {
		p.say("    Your terminal's echo could not be turned back on; run `stty echo` (or `reset`) if typed text stays hidden.")
		return "", errInitSecretUnavailable
	}
	return answer, readErr
}

// typeSecret reads a key in raw mode, showing one * per character, and
// errInitRawUnavailable without a terminal that reads single keys. The stars
// scroll within the line, so a long key never wraps.
func (p *initPrompter) typeSecret(prompt string) (string, error) {
	if p.keys == nil {
		return "", errInitRawUnavailable
	}
	restore, err := p.keys.rawInput()
	if err != nil {
		return "", errInitRawUnavailable
	}
	defer p.restoreTerminal(restore)
	room := max(8, initWidth-initVisible(prompt)-1)
	typed, size, tooLong := []rune{}, 0, false
	draw := func() {
		stars := strings.Repeat("*", min(len(typed), room))
		if len(typed) > room {
			stars = "…" + stars[1:]
		}
		fmt.Fprint(p.out, "\x1b[G\x1b[K"+p.style.paint(initTonePrompt, strings.TrimRight(prompt, " "))+" "+stars)
	}
	draw()
	for {
		key, err := p.readKey()
		if err != nil {
			fmt.Fprintln(p.out)
			return "", err
		}
		switch key.kind {
		case menuRune:
			if size+utf8.RuneLen(key.r) > initMaxAnswerBytes {
				tooLong = true
				continue
			}
			typed, size = append(typed, key.r), size+utf8.RuneLen(key.r)
		case menuBackspace:
			if len(typed) > 0 {
				size -= utf8.RuneLen(typed[len(typed)-1])
				typed = typed[:len(typed)-1]
			}
		case menuClear:
			typed, size, tooLong = typed[:0], 0, false
		case menuEnter:
			fmt.Fprintln(p.out)
			if tooLong {
				return "\x00too-long", nil
			}
			return strings.TrimSpace(string(typed)), nil
		case menuInterrupt:
			fmt.Fprintln(p.out)
			return "", errInitCanceled
		case menuEndOfInput:
			if len(typed) == 0 {
				fmt.Fprintln(p.out)
				return "", errInitInputEnded
			}
		case menuEscape, menuLeft:
			if p.canBack {
				fmt.Fprintln(p.out)
				return "", errInitBack
			}
		}
		draw()
	}
}

// minSecretReceiptLength is the shortest answer whose last four characters
// are shown; a shorter one would show too much of itself.
const minSecretReceiptLength = 12

// secretReceipt describes a typed key without showing it: its length, and
// its last four characters when it is long enough.
func secretReceipt(answer string) string {
	characters := []rune(answer)
	if len(characters) < minSecretReceiptLength {
		return fmt.Sprintf("%d characters", len(characters))
	}
	return fmt.Sprintf("********%s (%d characters)", string(characters[len(characters)-4:]), len(characters))
}
