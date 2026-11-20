package checksandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
)

// grantRecordPath is the file listing the folders granted to the toolchain
// capability, one per line, beside the usage records:
// $XDG_STATE_HOME/open-trestle/sandbox-grants when XDG_STATE_HOME is
// absolute, and otherwise ~/.local/state/open-trestle/sandbox-grants.
func grantRecordPath() (string, error) {
	if state := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(state) {
		return filepath.Join(state, "open-trestle", "sandbox-grants"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return "", errors.New("the home folder is unknown, so a grant could not be recorded")
	}
	return filepath.Join(home, ".local", "state", "open-trestle", "sandbox-grants"), nil
}

// recordGrant adds path to the record before it is granted, so that a run
// killed in between leaves nothing unrecorded.
func recordGrant(path string) error {
	record, err := grantRecordPath()
	if err != nil {
		return err
	}
	if slices.Contains(recordedGrants(record), path) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(record), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(record, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.WriteString(path + "\n"); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func recordedGrants(record string) []string {
	data, err := os.ReadFile(record)
	if err != nil {
		return nil
	}
	var paths []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); filepath.IsAbs(line) && !slices.Contains(paths, line) {
			paths = append(paths, line)
		}
	}
	return paths
}

func removeToolchainGrants() error {
	record, err := grantRecordPath()
	if err != nil {
		return err
	}
	paths := recordedGrants(record)
	if len(paths) == 0 {
		return ignoreMissing(os.Remove(record))
	}
	capability, err := capabilitySid(toolchainCapability)
	if err != nil {
		return err
	}
	var kept []string
	var failures []error
	for _, path := range paths {
		if err := revokeExplicit(path, capability); err != nil {
			kept = append(kept, path)
			failures = append(failures, fmt.Errorf("%s: %w", path, err))
		}
	}
	if len(kept) == 0 {
		return errors.Join(append(failures, ignoreMissing(os.Remove(record)))...)
	}
	content := strings.Join(kept, "\n") + "\n"
	return errors.Join(append(failures, os.WriteFile(record, []byte(content), 0o600))...)
}

// revokeExplicit takes the capability's entry off path, if it still has
// one; a folder that is gone has nothing left to take back.
func revokeExplicit(path string, capability *windows.SID) error {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) || errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {
		return nil
	}
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return err
	}
	if !grantsExplicitly(dacl, capability) {
		return nil
	}
	return revoke(path, capability)
}

func ignoreMissing(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}
