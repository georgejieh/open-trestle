//go:build !linux && !darwin

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

func helperWorkingDirectory(string) string { return "/" }

func configureHelperCommand(*exec.Cmd) {}

type processGroup struct{}

func (*processGroup) attach(*os.Process) error { return ErrScannerUnsupportedPlatform }

func (*processGroup) waitExit() {}

func (*processGroup) kill(process *os.Process) { _ = process.Kill() }

func (*processGroup) release() {}
