//go:build !linux

package controlplane

import "os"

func rootedScannerSupported() bool      { return false }
func rootedSingleLink(os.FileInfo) bool { return false }
