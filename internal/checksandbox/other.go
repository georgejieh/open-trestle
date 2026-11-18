//go:build !linux && !windows && !darwin

package checksandbox

import (
	"context"
	"runtime"
)

func run(context.Context, Spec) (Result, error) {
	return Result{}, unavailable("checks cannot be sandboxed on %s", runtime.GOOS)
}
