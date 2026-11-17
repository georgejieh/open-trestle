package setup

import "os"

// unixPermission is what a private entry's permission bits must satisfy on
// Unix. Windows keeps access in the owner and DACL instead, so the ownership
// checks ignore it there.
type unixPermission func(os.FileMode) bool

// exactPermission accepts only mode.
func exactPermission(mode os.FileMode) unixPermission {
	return func(permission os.FileMode) bool { return permission == mode }
}

// ownerOnlyPermission accepts any mode without a group or other bit.
func ownerOnlyPermission(permission os.FileMode) bool { return permission&0o077 == 0 }
