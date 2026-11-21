//go:build linux && !amd64 && !arm64

package checksandbox

import "errors"

func installFilter() error {
	return errors.New("this processor architecture is not supported")
}
