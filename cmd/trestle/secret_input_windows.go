package main

import (
	"os"
	"syscall"
)

// consoleTerminal turns echo off with the console input mode, keeping line
// input and Ctrl-C processing.
type consoleTerminal struct{ handle syscall.Handle }

const consoleEnableEchoInput = 0x0004

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
