//go:build !linux

package main

import (
	"fmt"
	"os"
)

func localSourceDirectoryIdentityFromInfo(os.FileInfo) (localSourceDirectoryIdentity, error) {
	return localSourceDirectoryIdentity{}, fmt.Errorf("%w: directory identity needs Linux", errLocalSourceOwnerUnsupported)
}
