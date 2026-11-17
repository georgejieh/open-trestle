//go:build darwin

package scanhelper

import "errors"

var errCacheDirectory = errors.New("private cache directories are not verified on macOS")

// PrivateCacheDirectory refuses every directory, so the helper exits with
// ExitCacheDirectory before it serves a request on macOS. Owner and mode bits
// do not prove that a directory is private there: an extended ACL, which a
// new directory can inherit from its parent, grants access independently of
// them, and this helper does not check ACLs.
func PrivateCacheDirectory() (string, error) {
	return "", errCacheDirectory
}
