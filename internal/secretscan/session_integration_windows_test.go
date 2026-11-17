//go:build windows

package secretscan

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
	"github.com/georgejieh/open-trestle/internal/ownersonly/ownersonlytest"
)

func (session *Session) helperPID() int {
	return session.process.command.Process.Pid
}

// windowsProcessRunning reports whether the process with ID pid exists and
// has not exited.
func windowsProcessRunning(pid int) bool {
	handle, err := syscall.OpenProcess(processQueryLimitedInformation|syscall.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer syscall.CloseHandle(handle)
	event, err := syscall.WaitForSingleObject(handle, 0)
	return err == nil && event == syscall.WAIT_TIMEOUT
}

func requireWindowsProcessGone(t *testing.T, pid int, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for windowsProcessRunning(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d survived for %v", pid, within)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// denseRequest is eight finding-dense sources of 256 KiB, a request at the
// protocol's size limit that keeps the helper busy for some seconds.
func denseRequest(t *testing.T) [][]byte {
	t.Helper()
	fixtures, _ := readScannerFixtures(t)
	dense := repeatedFixtures(fixtures, 256*1024)
	sources := make([][]byte, 8)
	for index := range sources {
		sources[index] = dense
	}
	return sources
}

// TestScanHelperDeadlineTerminatesTheJob lets a dense scan overrun a short
// watchdog and requires the helper to be gone at once, which only the job
// object's termination achieves while the helper is busy.
func TestScanHelperDeadlineTerminatesTheJob(t *testing.T) {
	config := scanHelperForTest(t)
	session, err := openSession(context.Background(), sessionSettings{
		config:         config,
		scanWatchdog:   200 * time.Millisecond,
		startAllowance: time.Minute,
		scanLimit:      sessionScanLimit,
		random:         rand.Reader,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	if result, err := session.Scan(context.Background(), [][]byte{[]byte("ordinary text")}); err != nil || !result.Complete() {
		t.Fatalf("first scan: %v, %v", result.Failure(), err)
	}
	pid := session.helperPID()
	started := time.Now()
	result, err := session.Scan(context.Background(), denseRequest(t))
	if result.Complete() || result.Failure() != FailurePolicy || !errors.Is(err, errHelperDeadline) {
		t.Fatalf("an overrunning scan did not fail at the deadline: %v, %v", result.Failure(), err)
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("the deadline kill took %v", elapsed)
	}
	requireWindowsProcessGone(t, pid, time.Second)
	if err := session.Close(); !errors.Is(err, errHelperDeadline) {
		t.Fatalf("close did not report the deadline failure: %v", err)
	}
}

// TestScanHelperDiesWithItsParent runs a parent process that opens a session
// and sends a dense request, kills that parent while the helper scans, and
// requires the helper to die with it. The busy helper does not read its
// input, so a closed pipe cannot be what stops it; the job object, whose
// last handle closes with the parent, must.
func TestScanHelperDiesWithItsParent(t *testing.T) {
	if pidPath := os.Getenv("SECRETSCAN_HELPER_PARENT_PID"); pidPath != "" {
		runHelperParentForTest(t, pidPath)
		return
	}
	config := scanHelperForTest(t)
	pidPath := filepath.Join(t.TempDir(), "pid")
	parent := exec.Command(os.Args[0], "-test.run=^TestScanHelperDiesWithItsParent$")
	parent.Env = append(os.Environ(),
		"SECRETSCAN_HELPER_PARENT_PID="+pidPath,
		"SECRETSCAN_HELPER_PARENT_PATH="+config.HelperPath,
		"SECRETSCAN_HELPER_PARENT_DIGEST="+config.HelperSHA256,
		"SECRETSCAN_HELPER_PARENT_CACHE="+config.CacheDirectory)
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = parent.Process.Kill()
		_ = parent.Wait()
	}()
	var pid int
	for deadline := time.Now().Add(time.Minute); ; {
		encoded, err := os.ReadFile(pidPath)
		if err == nil && strings.HasSuffix(string(encoded), "\n") {
			if pid, err = strconv.Atoi(strings.TrimSpace(string(encoded))); err != nil {
				t.Fatal(err)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the parent did not report a helper")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// The parent reports the helper as it sends the request. A second later
	// the helper is still scanning.
	time.Sleep(time.Second)
	if !windowsProcessRunning(pid) {
		t.Fatal("the helper finished before its parent was killed")
	}
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = parent.Wait()
	requireWindowsProcessGone(t, pid, time.Second)
}

func runHelperParentForTest(t *testing.T, pidPath string) {
	settings := sessionSettings{
		config: SessionConfig{
			HelperPath:     os.Getenv("SECRETSCAN_HELPER_PARENT_PATH"),
			HelperSHA256:   os.Getenv("SECRETSCAN_HELPER_PARENT_DIGEST"),
			BuildProfile:   HostRE2BuildProfile,
			CacheDirectory: os.Getenv("SECRETSCAN_HELPER_PARENT_CACHE"),
		},
		scanWatchdog:   time.Minute,
		startAllowance: time.Minute,
		scanLimit:      sessionScanLimit,
		random:         rand.Reader,
	}
	session, err := openSession(context.Background(), settings)
	if err != nil {
		os.Exit(2)
	}
	if result, err := session.Scan(context.Background(), [][]byte{[]byte("ordinary text")}); err != nil || !result.Complete() {
		os.Exit(3)
	}
	request := denseRequest(t)
	if err := os.WriteFile(pidPath, []byte(strconv.Itoa(session.helperPID())+"\n"), 0o600); err != nil {
		os.Exit(4)
	}
	_, _ = session.Scan(context.Background(), request)
	os.Exit(5)
}

func TestScanHelperCacheOthersCanReadIsRefused(t *testing.T) {
	config := scanHelperForTest(t)
	config.CacheDirectory = filepath.Join(ownersonlytest.TempDir(t), "cache")
	if err := ownersonly.Mkdir(config.CacheDirectory); err != nil {
		t.Fatal(err)
	}
	ownersonlytest.Grant(t, config.CacheDirectory, ownersonlytest.Users+":(RX)")
	if session, err := OpenSession(context.Background(), config); session != nil || !errors.Is(err, ErrCacheUntrusted) {
		t.Fatalf("session with a cache others can read was not refused: %v", err)
	}
	if err := Prewarm(context.Background(), config); !errors.Is(err, ErrCacheUntrusted) {
		t.Fatalf("prewarm with a cache others can read was not refused: %v", err)
	}
}

func TestScanHelperCacheBelowAFolderOthersCanChangeIsRefused(t *testing.T) {
	config := scanHelperForTest(t)
	parent := ownersonlytest.TempDir(t)
	config.CacheDirectory = filepath.Join(parent, "cache")
	ownersonlytest.Grant(t, parent, ownersonlytest.AuthenticatedUsers+":(DC)")
	if err := Prewarm(context.Background(), config); !errors.Is(err, ErrCacheUntrusted) {
		t.Fatalf("prewarm below a folder others can change was not refused: %v", err)
	}
	if _, err := os.Lstat(config.CacheDirectory); !os.IsNotExist(err) {
		t.Fatal("a refused prewarm created the cache directory")
	}
}

func TestScanHelperPrewarmCreatesAnOwnerOnlyCache(t *testing.T) {
	config := scanHelperForTest(t)
	parent := ownersonlytest.TempDir(t)
	// A folder that others may read and add to, as the volume root lets
	// them, is a usable parent; the cache inside it must still be private.
	ownersonlytest.Grant(t, parent, ownersonlytest.Users+":(OI)(CI)(RX)")
	ownersonlytest.Grant(t, parent, ownersonlytest.AuthenticatedUsers+":(AD,WD)")
	config.CacheDirectory = filepath.Join(parent, "cache")
	if err := Prewarm(context.Background(), config); err != nil {
		t.Fatalf("prewarm: %v", err)
	}
	ownersonlytest.RequireOwnerOnly(t, config.CacheDirectory)
	session := openHelperSessionForTest(t, config)
	if result, err := session.Scan(context.Background(), [][]byte{[]byte("ordinary text")}); err != nil || !result.Complete() {
		t.Fatalf("scan: %v, %v", result.Failure(), err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// TestScanHelperRefusesAWorkingDirectoryOthersCanRead starts the helper
// directly, without the session's own checks, in a directory that Users can
// read, and requires the helper's own check to refuse it.
func TestScanHelperRefusesAWorkingDirectoryOthersCanRead(t *testing.T) {
	config := scanHelperForTest(t)
	for _, test := range []struct {
		name  string
		grant string
		code  int
	}{
		{"private", "", 0},
		{"others can read", ownersonlytest.Users + ":(RX)", 78},
	} {
		t.Run(test.name, func(t *testing.T) {
			directory := filepath.Join(ownersonlytest.TempDir(t), "cache")
			if err := ownersonly.Mkdir(directory); err != nil {
				t.Fatal(err)
			}
			if test.grant != "" {
				ownersonlytest.Grant(t, directory, test.grant)
			}
			helper := exec.Command(config.HelperPath, helperSessionArgument)
			helper.Dir = directory
			helper.Env = []string{}
			helper.Stdin = strings.NewReader("")
			err := helper.Run()
			code := 0
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				code = exit.ExitCode()
			} else if err != nil {
				t.Fatal(err)
			}
			if code != test.code {
				t.Fatalf("helper exited %d, want %d", code, test.code)
			}
		})
	}
}
