//go:build !darwin && !linux && !windows

package main

import (
	"errors"
	"os"
)

func openRegularInputFileNative(string) (*os.File, error) {
	return nil, errors.New("regular input files are unsupported on this platform")
}
