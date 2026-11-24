package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Hidden input for an API key. The prompter reads plain lines; for a key it
// turns the terminal's echo off first, so the characters typed are never
// shown, and turns it back on before anything else is printed. Afterwards it
// shows the key's length and last four characters, so the person can tell
// what arrived. It needs a real terminal on standard input: stdlib termios on
// Linux and macOS, the console mode on Windows. Anything else, including a
// pipe or a file, is never asked for a key.

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

// askSecret reads one answer with echo off and returns it without
// surrounding spaces; "" means Enter on an empty line. The prompt is shown
// only once echo is off, only the answer's receipt is printed, and echo is
// restored before askSecret returns, including when input ends or is
// interrupted. An answer that is one text pasted twice is asked for again.
func (p *initPrompter) askSecret(question string, terminal echoTerminal) (string, error) {
	p.questions++
	for range initMaxTries {
		restore, err := terminal.hideInput()
		if err != nil {
			return "", errInitSecretUnavailable
		}
		answer, readErr := p.next("  " + question + ": ")
		restoreErr := restore()
		// The Enter that ended the answer was not echoed either.
		fmt.Fprintln(p.out)
		if restoreErr != nil {
			p.say("    Your terminal's echo could not be turned back on; run `stty echo` (or `reset`) if typed text stays hidden.")
			return "", errInitSecretUnavailable
		}
		if readErr != nil {
			return "", readErr
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
