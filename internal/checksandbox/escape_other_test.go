//go:build !linux && !windows

package checksandbox

import "testing"

func platformProbe(string, []string) int { return 2 }

func environmentLeaks(string) bool { return false }

func assertNoneLeft(*testing.T, string, []byte) {}

func processAlive(int) bool { return true }
