//go:build !linux && !windows

package checksandbox

import "testing"

func platformProbe(string, []string) int { return 2 }

func environmentLeaks(string) bool { return false }

// assertNoneLeft cannot list the processes a run left here, so the test
// that needs it ends as skipped instead of passing unchecked.
func assertNoneLeft(t *testing.T, _ string, _ []byte) {
	t.Helper()
	t.Skip("the processes a run left cannot be listed on this system")
}

// processAlive is never called here: the fork bomb test, its only user,
// skips where there is no per-tree process limit.
func processAlive(int) bool { panic("processAlive is not available on this system") }
