//go:build unix

package spending

import "testing"

func TestDefaultDirectoryFollowsXDGStateHome(t *testing.T) {
	env := map[string]string{"XDG_STATE_HOME": "/srv/state", "HOME": "/home/someone"}
	getenv := func(name string) string { return env[name] }
	if dir, err := DefaultDirectory(getenv); err != nil || dir != "/srv/state/open-trestle/usage" {
		t.Fatalf("XDG_STATE_HOME: %q %v", dir, err)
	}
	env["XDG_STATE_HOME"] = "relative/state"
	if dir, err := DefaultDirectory(getenv); err != nil || dir != "/home/someone/.local/state/open-trestle/usage" {
		t.Fatalf("a relative XDG_STATE_HOME is ignored, as the specification says: %q %v", dir, err)
	}
	delete(env, "XDG_STATE_HOME")
	if dir, err := DefaultDirectory(getenv); err != nil || dir != "/home/someone/.local/state/open-trestle/usage" {
		t.Fatalf("default: %q %v", dir, err)
	}
}
