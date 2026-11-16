package main

import "syscall"

const (
	termiosGet = syscall.TIOCGETA
	termiosSet = syscall.TIOCSETA
)
