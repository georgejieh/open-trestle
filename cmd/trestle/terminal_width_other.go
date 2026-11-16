//go:build !linux && !darwin

package main

import "os"

func queryTerminalColumns(*os.File) int { return 0 }
