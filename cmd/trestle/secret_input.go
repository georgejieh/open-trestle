package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Hidden input for an API key. The prompter reads plain lines; for a key it
// turns the terminal's echo off first, so the characters typed are never
// shown and never reach scrollback, and turns it back on before anything else
// is printed. It needs a real terminal on standard input: stdlib termios on
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

// askSecret reads one answer with echo off and returns it without
// surrounding spaces; "" means Enter on an empty line. The prompt is shown
// only once echo is off, the answer is never printed, and echo is restored
// before askSecret returns, including when input ends or is interrupted.
func (p *initPrompter) askSecret(question string, terminal echoTerminal) (string, error) {
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
		return answer, nil
	}
	return "", errInitTooManyTries
}
