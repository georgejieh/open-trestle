//go:build !unix && !windows

package setup

import (
	"errors"
	"os"
)

var errOwnershipUnsupported = errors.New("file ownership is not checked on this system")

func fileOwnershipSupported() bool { return false }

func currentProcessIdentity() (string, bool) { return "", false }

func privateToProcess(string, os.FileInfo, unixPermission) bool { return false }

func openPrivateToProcess(*os.File, os.FileInfo, unixPermission) bool { return false }

func unwritableByOthers(string, os.FileInfo) bool { return false }

func trustedUnwritable(string, os.FileInfo) bool { return false }

func ancestorAuthority(string, os.FileInfo, string, os.FileInfo) bool { return false }

func configurationAncestorAuthority(string, os.FileInfo, string, os.FileInfo) bool { return false }

func createPrivateFile(string) (*os.File, error) { return nil, errOwnershipUnsupported }

func makePrivateDirectory(string) error { return errOwnershipUnsupported }
