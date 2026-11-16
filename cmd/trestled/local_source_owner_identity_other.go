//go:build !linux

package main

import (
	"os"

	"github.com/georgejieh/open-trestle/internal/localownerroot"
)

func localSourceDirectoryIdentityFromInfo(info os.FileInfo) (localSourceDirectoryIdentity, error) {
	return localownerroot.IdentityFromInfo(info)
}
