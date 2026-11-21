//go:build !linux

package checksandbox

// RunChildIfRequested returns at once: only Linux re-executes this program
// to set up the sandbox.
func RunChildIfRequested() {}
