//go:build !linux || !amd64

package sandbox

import "errors"

var ErrUnavailable = errors.New("secret scanner sandbox unavailable")
var ErrUnsupported = errors.New("secret scanner sandbox unsupported")

func Install() error {
	return ErrUnsupported
}

func SilenceStandardError() error {
	return ErrUnsupported
}
