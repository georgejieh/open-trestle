//go:build !linux && !darwin && !windows

package secretscan

import (
	"os"
	"os/exec"
)

// On other systems a session never starts: the helper cannot be verified
// and contained there.

func openVerifiedHelper(string, string) (verifiedHelper, error) {
	return verifiedHelper{}, ErrScannerUnsupportedPlatform
}

func openCacheDirectory(string, bool) (string, error) {
	return "", ErrScannerUnsupportedPlatform
}

func configureHelperCommand(*exec.Cmd) {}

type fileIdentity struct{}

type processGroup struct{}

func (*processGroup) attach(*os.Process, fileIdentity) error { return ErrScannerUnsupportedPlatform }

func (*processGroup) waitExit() {}

func (*processGroup) kill(process *os.Process) { _ = process.Kill() }

func (*processGroup) release() {}
