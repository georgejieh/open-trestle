//go:build !linux && !darwin && !windows

package main

import "os"

// No hidden input on other systems: the wizard never asks for a key there and
// keeps the environment-variable instructions.
func platformEchoTerminal(*os.File) (echoTerminal, bool) { return nil, false }
