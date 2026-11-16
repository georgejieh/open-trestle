//go:build !unix

package main

import "os"

// Without portable link-count proof, refuse this first-use shape.
func ownerConstructorLockInfo(os.FileInfo) bool {
	return false
}
