//go:build linux

package secretscan

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstalledPrerequisiteDistinguishesMissingDigestsFromMissingInstall(t *testing.T) {
	if err := NewClient().InstalledPrerequisite(); !errors.Is(err, ErrScannerDigestsMissing) {
		t.Fatalf("development test binary reported %v, want missing digests", err)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	client := newClient(clientConfig{launcherPath: missing, workerPath: missing, expectedLauncherSHA256: strings.Repeat("a", 64), expectedWorkerSHA256: strings.Repeat("b", 64), expectedMode: scannerExecutableMode, trustRoot: "/"})
	if err := client.InstalledPrerequisite(); !errors.Is(err, ErrScannerNotInstalled) {
		t.Fatalf("absent executables reported %v, want not installed", err)
	}
}
