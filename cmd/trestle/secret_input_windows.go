package main

import (
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// consoleTerminal turns echo off with the console input mode, keeping line
// input and Ctrl-C processing.
type consoleTerminal struct{ handle syscall.Handle }

const (
	consoleEnableProcessedInput       = 0x0001
	consoleEnableLineInput            = 0x0002
	consoleEnableEchoInput            = 0x0004
	consoleEnableVirtualTerminalInput = 0x0200
	// consoleEnableVirtualTerminalProcessing is the output mode flag that
	// interprets escape sequences.
	consoleEnableVirtualTerminalProcessing = 0x0004
)

var setConsoleMode = syscall.NewLazyDLL("kernel32.dll").NewProc("SetConsoleMode")

func platformEchoTerminal(file *os.File) (echoTerminal, bool) {
	terminal := consoleTerminal{handle: syscall.Handle(file.Fd())}
	var mode uint32
	if syscall.GetConsoleMode(terminal.handle, &mode) != nil {
		return nil, false
	}
	return terminal, true
}

func (c consoleTerminal) setMode(mode uint32) error {
	if result, _, err := setConsoleMode.Call(uintptr(c.handle), uintptr(mode)); result == 0 {
		return err
	}
	return nil
}

func (c consoleTerminal) hideInput() (func() error, error) {
	var saved uint32
	if err := syscall.GetConsoleMode(c.handle, &saved); err != nil {
		return nil, err
	}
	if err := c.setMode(saved &^ consoleEnableEchoInput); err != nil {
		return nil, err
	}
	return func() error { return c.setMode(saved) }, nil
}

// rawInput reads single keys, with arrow keys as escape sequences and
// Ctrl-C as a key instead of an interrupt.
func (c consoleTerminal) rawInput() (func() error, error) {
	var saved uint32
	if err := syscall.GetConsoleMode(c.handle, &saved); err != nil {
		return nil, err
	}
	raw := saved&^(consoleEnableEchoInput|consoleEnableLineInput|consoleEnableProcessedInput) | consoleEnableVirtualTerminalInput
	if err := c.setMode(raw); err != nil {
		return nil, err
	}
	return func() error { return c.setMode(saved) }, nil
}

// enableTerminalOutput turns on escape-sequence processing for the console
// that out writes to, and returns what restores its mode.
func enableTerminalOutput(out io.Writer) (func(), bool) {
	file, ok := out.(*os.File)
	if !ok {
		return nil, false
	}
	console := consoleTerminal{handle: syscall.Handle(file.Fd())}
	var saved uint32
	if syscall.GetConsoleMode(console.handle, &saved) != nil {
		return nil, false
	}
	if saved&consoleEnableVirtualTerminalProcessing == 0 && console.setMode(saved|consoleEnableVirtualTerminalProcessing) != nil {
		return nil, false
	}
	return func() { _ = console.setMode(saved) }, true
}

// terminalColumns is the width of the console file is, or 0 when unknown.
func terminalColumns(file *os.File) int {
	var info windows.ConsoleScreenBufferInfo
	if windows.GetConsoleScreenBufferInfo(windows.Handle(file.Fd()), &info) != nil {
		return 0
	}
	return int(info.Window.Right-info.Window.Left) + 1
}
