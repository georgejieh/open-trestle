//go:build linux

package secretscan

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestProductionClientSanitizesWithFreshChildProcesses(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	projection := client.Sanitize(context.Background(), [][]byte{[]byte("prefix TOKEN suffix")})
	if !projection.Complete() || string(projection.Sources()[0]) != "prefix ***** suffix" || projection.Initial().MatchCount != 1 || projection.Residual().MatchCount != 0 {
		t.Fatalf("unexpected end-to-end projection: %#v", projection)
	}
}

func TestProductionClientRejectsResidualFinding(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	projection := client.Sanitize(context.Background(), [][]byte{[]byte("helper:residual TOKEN")})
	if projection.Complete() || projection.Failure() != FailurePolicy || projection.Sources() != nil {
		t.Fatalf("residual finding did not fail closed: %#v", projection)
	}
}

func TestProjectionAlwaysUsesTwoFreshInvocations(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	var calls atomic.Int32
	base := client.config.command
	client.config.command = func(path, argument string) *exec.Cmd {
		calls.Add(1)
		return base(path, argument)
	}
	projection := client.Sanitize(context.Background(), [][]byte{[]byte("clean")})
	if !projection.Complete() || calls.Load() != 2 {
		t.Fatalf("clean projection did not use a fresh residual child: %#v, calls=%d", projection, calls.Load())
	}
}

func TestPrivateSandboxIntegration(t *testing.T) {
	directory := os.Getenv("OPEN_TRESTLE_SECRET_SCANNER_INTEGRATION_DIR")
	fixturePath := os.Getenv("OPEN_TRESTLE_SECRET_SCANNER_INTEGRATION_FIXTURE")
	if directory == "" || fixturePath == "" {
		t.Skip("private sandbox integration is not configured")
	}
	launcher := filepath.Join(directory, "open-trestle-secret-scanner")
	worker := filepath.Join(directory, "open-trestle-secret-scanner-worker")
	fixture, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal("private fixture is unavailable")
	}
	defer clear(fixture)
	client := newClient(clientConfig{
		launcherPath:           launcher,
		workerPath:             worker,
		expectedLauncherSHA256: fileSHA256ForTest(t, launcher),
		expectedWorkerSHA256:   fileSHA256ForTest(t, worker),
		expectedUID:            uint32(os.Getuid()),
		expectedGID:            uint32(os.Getgid()),
		expectedMode:           0555,
		trustRoot:              directory,
		watchdog:               scannerWatchdog,
		command:                func(path string, argument string) *exec.Cmd { return exec.Command(path, argument) },
	})
	projection := client.Sanitize(context.Background(), [][]byte{fixture})
	if !projection.Complete() || projection.Initial().MatchCount == 0 || projection.Residual().MatchCount != 0 || len(projection.Sources()) != 1 || len(projection.Sources()[0]) != len(fixture) {
		t.Fatal("private sandbox integration did not produce a complete redacted projection")
	}
}
