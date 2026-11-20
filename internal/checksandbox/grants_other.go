//go:build !windows

package checksandbox

import "time"

// Only Windows grants toolchain folders to the sandbox and gives each run a
// profile of its own.

func removeToolchainGrants() error { return nil }

func sweepProfiles(time.Time) {}
