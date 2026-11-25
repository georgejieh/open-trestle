//go:build !linux && !darwin && !windows

package main

import (
	"io"
	"os"
)

// No hidden input on other systems: the wizard never asks for a key there and
// keeps the environment-variable instructions.
func platformEchoTerminal(*os.File) (echoTerminal, bool) { return nil, false }

func enableTerminalOutput(io.Writer) (func(), bool) { return nil, false }

func terminalColumns(*os.File) int { return 0 }
