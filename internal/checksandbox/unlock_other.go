//go:build !darwin

package checksandbox

// unlockTree has nothing to do here: on Linux the scratch is a tmpfs that
// ends with the run, and on Windows the account that owns the scratch can
// always delete in it.
func unlockTree(string) {}
