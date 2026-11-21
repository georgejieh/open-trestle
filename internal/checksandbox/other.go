//go:build !linux && !windows && !darwin

package checksandbox

import (
	"context"
	"runtime"
)

func available() error {
	return unavailable("checks cannot be sandboxed on %s", runtime.GOOS)
}

func run(context.Context, Spec) (Result, error) {
	return Result{}, available()
}
