//go:build !unix && !windows

package setup

import "os"

func fileOwnedByCurrentProcess(os.FileInfo) bool { return false }

func fileOwnedByTrustedProcessOrRoot(os.FileInfo) bool { return false }

func fileOwnershipSupported() bool { return false }

func currentProcessIdentity() (string, bool) { return "", false }
