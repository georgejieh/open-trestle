//go:build linux && amd64 && !race

package sandbox

import (
	"os"
	"testing"
)

func sandboxTestExecutable(t *testing.T) string {
	return os.Args[0]
}
