//go:build linux || darwin

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// termiosTerminal turns echo off with the terminal's termios flags, keeping
// line editing (ICANON) and Ctrl-C (ISIG), so backspace still works and an
// interrupt still stops the wizard.
type termiosTerminal struct{ fd uintptr }

func platformEchoTerminal(file *os.File) (echoTerminal, bool) {
	terminal := termiosTerminal{fd: file.Fd()}
	var current syscall.Termios
	if terminal.control(termiosGet, &current) != nil {
		return nil, false
	}
	return terminal, true
}

func (t termiosTerminal) control(request uintptr, state *syscall.Termios) error {
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, t.fd, request, uintptr(unsafe.Pointer(state))); errno != 0 {
		return errno
	}
	return nil
}

func (t termiosTerminal) hideInput() (func() error, error) {
	var saved syscall.Termios
	if err := t.control(termiosGet, &saved); err != nil {
		return nil, err
	}
	hidden := saved
	hidden.Lflag &^= syscall.ECHO | syscall.ECHOE | syscall.ECHOK | syscall.ECHONL
	hidden.Lflag |= syscall.ICANON | syscall.ISIG
	if err := t.control(termiosSet, &hidden); err != nil {
		return nil, err
	}
	return func() error { return t.control(termiosSet, &saved) }, nil
}
