package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestPackagedRecoveryCommandInPlaceComparison(t *testing.T) {
	executable := os.Getenv("OPEN_TRESTLE_TEST_OFFLINE_BINARY")
	if executable == "" {
		t.Skip("explicit prebuilt offline binary required")
	}
	state, _ := stoppedRestoreFixture(t)
	flags := []string{"--state-dir", state, "--repository-authority", "local.test", "--repository-namespace", "team", "--repository-name", "repo"}
	flags = append(flags, recoveryAssetFlags(t)...)
	invoke := func(action string, extra ...string) ([]byte, error) {
		args := append(append([]string{action}, flags...), extra...)
		command := exec.CommandContext(context.Background(), executable, args...)
		command.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + t.TempDir()}
		return command.CombinedOutput()
	}
	raw, err := invoke("recovery-point")
	if err != nil {
		t.Fatalf("record executable: %s %v", raw, err)
	}
	recordPath := filepath.Join(t.TempDir(), "point.json")
	if err := os.WriteFile(recordPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := invoke("verify-restore", "--record", recordPath)
	if err != nil || !bytes.Contains(output, []byte(`"restart_authorized":false`)) {
		t.Fatalf("executable compare: %s %v", output, err)
	}
	leaf := filepath.Join(state, ".local-source-owner.json")
	original, err := os.ReadFile(leaf)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(leaf, []byte("invalid restored leaf"), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err = invoke("verify-restore", "--record", recordPath)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() == 0 {
		t.Fatalf("corruption accepted: %s %v", output, err)
	}
	if err := os.WriteFile(leaf, original, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err = invoke("verify-restore", "--record", recordPath)
	if err != nil {
		t.Fatalf("in-place restored leaf rejected: %s %v", output, err)
	}
}
