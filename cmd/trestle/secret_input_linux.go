package main

import "syscall"

const (
	termiosGet = syscall.TCGETS
	termiosSet = syscall.TCSETS
)
