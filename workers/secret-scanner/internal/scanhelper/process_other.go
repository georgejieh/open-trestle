//go:build !unix && !windows

package scanhelper

import (
	"errors"
	"os"
)

var errUnsupported = errors.New("scan helper is not supported on this system")

// IsolateStandardStreams is not supported on this system.
func IsolateStandardStreams() (*os.File, error) { return nil, errUnsupported }

// LimitResources is not supported on this system.
func LimitResources() error { return errUnsupported }

// ExitWithParent does nothing on this system.
func ExitWithParent() {}

// PrivateCacheDirectory is not supported on this system.
func PrivateCacheDirectory() (string, error) { return "", errUnsupported }
