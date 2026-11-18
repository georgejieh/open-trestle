package checksandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMain(m *testing.M) {
	RunChildIfRequested()
	if len(os.Args) >= 3 && os.Args[1] == "__probe" {
		os.Exit(probe(os.Args[2:]))
	}
	os.Exit(m.Run())
}

func testLimits() Limits {
	return Limits{Time: 30 * time.Second, MemoryBytes: 1 << 30, Processes: 64, OutputBytes: 1 << 20, DiskBytes: 64 << 20}
}

// probeSpec runs this test binary in probe mode inside the sandbox.
func probeSpec(t *testing.T, args ...string) Spec {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tree := t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "README"), []byte("tree"), 0o644); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Dir(executable)
	return Spec{
		Tree:     tree,
		Args:     append([]string{filepath.Base(executable), "__probe"}, args...),
		Path:     []string{directory},
		ReadOnly: []string{directory},
		Limits:   testLimits(),
	}
}

// runProbe runs spec and skips the test when the sandbox is unavailable on
// this machine, so a missing facility never passes as a blocked escape.
func runProbe(t *testing.T, spec Spec) Result {
	t.Helper()
	result, err := Run(context.Background(), spec)
	if IsUnavailable(err) {
		if _, probeErr := Run(context.Background(), probeSpec(t, "true")); probeErr != nil {
			t.Skipf("the sandbox is unavailable here: %v", probeErr)
		}
		t.Fatalf("the probe could not run although the sandbox works: %v", err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func requireBlocked(t *testing.T, result Result) {
	t.Helper()
	if result.ExitCode != probeBlocked {
		t.Fatalf("exit code %d, want %d (blocked); stdout %q stderr %q", result.ExitCode, probeBlocked, result.Stdout, result.Stderr)
	}
}

func marker(t *testing.T) string {
	t.Helper()
	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	return "otescape" + hex.EncodeToString(random)
}

func TestSandboxRunsCommand(t *testing.T) {
	result := runProbe(t, probeSpec(t, "write-scratch"))
	if !result.Succeeded() {
		t.Fatalf("result %+v", result)
	}
}

func TestSandboxReportsMissingProgram(t *testing.T) {
	spec := probeSpec(t, "true")
	spec.Args[0] = "open-trestle-no-such-program"
	if _, err := Run(context.Background(), probeSpec(t, "true")); err != nil {
		t.Skipf("the sandbox is unavailable here: %v", err)
	}
	if _, err := Run(context.Background(), spec); !IsUnavailable(err) || !strings.Contains(err.Error(), "not installed") {
		t.Fatalf("error %v, want could not run: not installed", err)
	}
}

func TestEscapeReadHomeFile(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home folder")
	}
	planted := filepath.Join(home, ".open-trestle-escape-"+marker(t))
	if err := os.WriteFile(planted, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(planted)
	requireBlocked(t, runProbe(t, probeSpec(t, "read", planted)))
}

func TestEscapeReadEnvironmentSecret(t *testing.T) {
	value := marker(t)
	t.Setenv("OPEN_TRESTLE_PROVIDER_ESCAPE_TEST_KEY", value)
	requireBlocked(t, runProbe(t, probeSpec(t, "env", "OPEN_TRESTLE_PROVIDER_ESCAPE_TEST_KEY", value)))
}

func TestEscapeNetwork(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			connection.Close()
		}
	}()
	t.Run("host loopback", func(t *testing.T) {
		requireBlocked(t, runProbe(t, probeSpec(t, "tcp", listener.Addr().String())))
	})
	t.Run("public address", func(t *testing.T) {
		requireBlocked(t, runProbe(t, probeSpec(t, "tcp", "1.1.1.1:443")))
	})
	t.Run("dns", func(t *testing.T) {
		requireBlocked(t, runProbe(t, probeSpec(t, "dns", "example.com")))
	})
}

func TestEscapeWriteOutsideScratch(t *testing.T) {
	spec := probeSpec(t, "true")
	targets := map[string]string{
		"tree source": filepath.Join(spec.Tree, "escaped"),
		"toolchain":   filepath.Join(spec.ReadOnly[0], "escaped-"+marker(t)),
		"host temp":   filepath.Join(t.TempDir(), "escaped"),
	}
	if home, err := os.UserHomeDir(); err == nil {
		targets["home"] = filepath.Join(home, ".open-trestle-escape-"+marker(t))
	}
	for name, target := range targets {
		t.Run(name, func(t *testing.T) {
			spec.Args = []string{spec.Args[0], "__probe", "write", target}
			requireBlocked(t, runProbe(t, spec))
			if _, err := os.Stat(target); err == nil {
				os.Remove(target)
				t.Fatalf("%s was written", target)
			}
		})
	}
}

func TestEscapeForkBombIsBounded(t *testing.T) {
	spec := probeSpec(t, "spawn", "500")
	result := runProbe(t, spec)
	alive, ok := strings.CutPrefix(strings.TrimSpace(string(result.Stdout)), "alive ")
	count, err := strconv.Atoi(alive)
	if !ok || err != nil {
		t.Fatalf("stdout %q stderr %q", result.Stdout, result.Stderr)
	}
	if count == 0 {
		t.Fatalf("no process stayed alive, so the limit was not exercised; stderr %q", result.Stderr)
	}
	if count >= spec.Limits.Processes {
		t.Fatalf("%d processes alive, limit %d", count, spec.Limits.Processes)
	}
	t.Logf("%d of 500 processes alive under a limit of %d", count, spec.Limits.Processes)
}

func TestEscapeDiskFillIsBounded(t *testing.T) {
	spec := probeSpec(t, "fill")
	result := runProbe(t, spec)
	if !result.DiskExceeded {
		t.Fatalf("disk limit not reported; result %+v stdout %q", result, result.Stdout)
	}
	// The disk limit, not the time limit, must have stopped the writes.
	if result.TimedOut || result.Duration > spec.Limits.Time/3 {
		t.Fatalf("the writes ran for %v under a %v time limit", result.Duration, spec.Limits.Time)
	}
	if written, ok := strings.CutPrefix(strings.TrimSpace(string(result.Stdout)), "wrote "); ok {
		if count, _ := strconv.ParseInt(written, 10, 64); count > spec.Limits.DiskBytes {
			t.Fatalf("wrote %d bytes, limit %d", count, spec.Limits.DiskBytes)
		}
	}
}

func TestEscapeTimeLimitKillsTree(t *testing.T) {
	tag := marker(t)
	spec := probeSpec(t, "hang", tag)
	spec.Limits.Time = 3 * time.Second
	started := time.Now()
	result := runProbe(t, spec)
	if !result.TimedOut {
		t.Fatalf("time limit not reported: %+v", result)
	}
	if elapsed := time.Since(started); elapsed > 20*time.Second {
		t.Fatalf("run took %v", elapsed)
	}
	assertNoneLeft(t, tag, result.Stdout)
}

func TestEscapeOutputIsBounded(t *testing.T) {
	spec := probeSpec(t, "spew")
	spec.Limits.OutputBytes = 64 << 10
	result := runProbe(t, spec)
	if !result.OutputExceeded || len(result.Stdout) > spec.Limits.OutputBytes {
		t.Fatalf("output exceeded %v, %d bytes kept", result.OutputExceeded, len(result.Stdout))
	}
}
