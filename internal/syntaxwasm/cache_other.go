//go:build !unix || darwin

package syntaxwasm

// privateCacheDirectory refuses every directory. On macOS an extended ACL,
// which a new directory can inherit from its parent, grants access
// independently of owner and mode bits, and on Windows access is decided by
// ACLs alone; neither is checked here. The analyzer still works without a
// cache, compiling each module once per process.
func privateCacheDirectory(string) (string, error) {
	return "", ErrCacheUntrusted
}
