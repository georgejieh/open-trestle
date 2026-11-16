//go:build !unix

package update

import "os"

// fileOwner is unknown outside Unix, so no receipt is trusted there.
func fileOwner(os.FileInfo) (uint32, bool) { return 0, false }
