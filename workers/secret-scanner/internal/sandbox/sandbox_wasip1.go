//go:build wasip1

package sandbox

import "errors"

var ErrUnavailable = errors.New("secret scanner sandbox unavailable")

// Install does nothing in a wasip1 guest. The WebAssembly runtime is the
// sandbox: the guest has no file system, network, environment or process
// access beyond what its host grants, and the scan helper grants standard
// input and output only.
func Install() error {
	return nil
}

// SilenceStandardError does nothing in a wasip1 guest. The scan helper does
// not connect the guest's standard error to anything.
func SilenceStandardError() error {
	return nil
}
