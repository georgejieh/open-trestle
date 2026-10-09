//go:build !linux

package main

import "os"

func physicalPacketInodeOwnerSame(os.FileInfo, os.FileInfo) bool { return false }
