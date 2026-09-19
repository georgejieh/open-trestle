//go:build !unix

package fileauthority

import "os"

// TrustedOwner fails closed where ownership authority is not implemented.
func TrustedOwner(os.FileInfo) bool { return false }
