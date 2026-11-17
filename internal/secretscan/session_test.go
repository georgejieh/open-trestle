//go:build linux

package secretscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func init() {
	if len(os.Args) != 2 || os.Args[1] != helperSessionArgument {
		return
	}
	os.Exit(runSessionTestHelper())
}

// sessionHelperClose is what the fake helper does when stdin reaches EOF at
// a frame boundary.
type sessionHelperClose struct {
	exitCode int
	trailing bool
	stderr   bool
}

// runSessionTestHelper is a fake helper speaking the session protocol. Its
// behaviour is selected by markers in the first source of each request,
// because the parent gives it no environment and fixed arguments.
func runSessionTestHelper() int {
	if !sessionHelperEnvironmentClean() {
		_, _ = os.Stderr.Write([]byte("x"))
		return 91
	}
	var atClose sessionHelperClose
	for {
		var prefix [framePrefixBytes]byte
		read, err := io.ReadFull(os.Stdin, prefix[:])
		if read == 0 && errors.Is(err, io.EOF) {
			if atClose.stderr {
				_, _ = os.Stderr.Write([]byte("x"))
			}
			if atClose.trailing {
				_, _ = os.Stdout.Write([]byte("x"))
			}
			return atClose.exitCode
		}
		if err != nil {
			return 92
		}
		declared := binary.BigEndian.Uint32(prefix[:])
		if declared == 0 || declared > maxRequestFrameBytes {
			return 93
		}
		frame := make([]byte, framePrefixBytes+int(declared))
		copy(frame, prefix[:])
		if _, err := io.ReadFull(os.Stdin, frame[framePrefixBytes:]); err != nil {
			return 92
		}
		request, err := ParseRequestFrame(frame)
		if err != nil {
			return 93
		}
		if code := respondSessionTestRequest(request, &atClose); code >= 0 {
			return code
		}
	}
}

// sessionHelperEnvironmentClean checks the spawn recipe from inside the
// helper: root working directory, empty environment, own process group, and
// no inherited descriptor that refers to a file.
func sessionHelperEnvironmentClean() bool {
	if cwd, err := os.Getwd(); err != nil || cwd != "/" || len(os.Environ()) != 0 || syscall.Getpgrp() != os.Getpid() {
		return false
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return false
	}
	for _, entry := range entries {
		descriptor, err := strconv.Atoi(entry.Name())
		if err != nil {
			return false
		}
		target, err := os.Readlink(filepath.Join("/proc/self/fd", entry.Name()))
		if err != nil {
			continue
		}
		if descriptor <= 2 {
			if !strings.HasPrefix(target, "pipe:") {
				return false
			}
			continue
		}
		if strings.HasPrefix(target, "/") && !strings.HasPrefix(target, "/proc/") && !strings.HasPrefix(target, "/sys/") && !strings.HasPrefix(target, "/dev/") {
			return false
		}
	}
	return true
}

func hangForever() {
	for {
		time.Sleep(time.Hour)
	}
}

func publishTestPIDs(path string, pids ...int) bool {
	fields := make([]string, len(pids))
	for index, pid := range pids {
		fields[index] = strconv.Itoa(pid)
	}
	// Publish by rename so the polling test never reads a partial file.
	if err := os.WriteFile(path+".tmp", []byte(strings.Join(fields, " ")), 0600); err != nil {
		return false
	}
	return os.Rename(path+".tmp", path) == nil
}

func startTestDescendant(holdStdout bool) (*exec.Cmd, bool) {
	child := exec.Command("/bin/sleep", "60")
	child.Dir = "/"
	child.Env = []string{}
	if holdStdout {
		child.Stdout = os.Stdout
	}
	return child, child.Start() == nil
}

// respondSessionTestRequest answers one request. It returns an exit code to
// end the helper, or -1 to read the next request.
func respondSessionTestRequest(request Request, atClose *sessionHelperClose) int {
	content := request.Sources[0].Content
	response := Response{
		SchemaVersion:   1,
		RequestID:       request.RequestID,
		Status:          StatusComplete,
		Scanner:         ScannerName,
		ScannerVersion:  ScannerVersion,
		ScannerCommit:   ScannerCommit,
		RulesetIdentity: RulesetIdentity,
		BuildProfile:    HostRE2BuildProfile,
		Matches:         []Match{},
	}
	exitAfterResponse := false
	for _, marker := range strings.Fields(string(content)) {
		name, argument, _ := strings.Cut(marker, "=")
		switch name {
		case "session:hang":
			hangForever()
		case "session:exit71":
			return 71
		case "session:stderr-hang":
			_, _ = os.Stderr.Write([]byte("secret-bearing diagnostic"))
			hangForever()
		case "session:stderr-respond":
			_, _ = os.Stderr.Write([]byte("secret-bearing diagnostic"))
		case "session:short":
			_, _ = os.Stdout.Write([]byte{0, 0, 0, 10, '{'})
			_ = os.Stdout.Close()
			hangForever()
		case "session:oversized":
			var prefix [framePrefixBytes]byte
			binary.BigEndian.PutUint32(prefix[:], maxResponseFrameBytes+1)
			_, _ = os.Stdout.Write(prefix[:])
			hangForever()
		case "session:zero":
			_, _ = os.Stdout.Write([]byte{0, 0, 0, 0})
			hangForever()
		case "session:malformed":
			_, _ = os.Stdout.Write([]byte{0, 0, 0, 11})
			_, _ = os.Stdout.Write([]byte("not a frame"))
			return -1
		case "session:wrong-id":
			response.RequestID = strings.Repeat("0", 64)
		case "session:native-profile":
			response.BuildProfile = BuildProfile
		case "session:recorded-profile":
			response.BuildProfile = go12610BuildProfile
		case "session:unknown-rule":
			match := Match{SourceOrdinal: 0, RuleID: "not-a-pinned-rule", StartByte: 0, EndByteExclusive: 1}
			match.OccurrenceID = OccurrenceID(match)
			response.Matches = []Match{match}
		case "session:scan-failed":
			response.Status = StatusScanFailed
		case "session:resource":
			response.Status = StatusResourceExhausted
		case "session:child-hang", "session:child-linger", "session:child-stdout":
			child, ok := startTestDescendant(name == "session:child-stdout")
			if !ok || !publishTestPIDs(argument, os.Getpid(), child.Process.Pid) {
				return 95
			}
			if name == "session:child-hang" {
				hangForever()
			}
		case "session:pid":
			if !publishTestPIDs(argument, os.Getpid()) {
				return 96
			}
		case "session:slow":
			delay, err := time.ParseDuration(argument)
			if err != nil {
				return 97
			}
			time.Sleep(delay)
		case "session:close-exit71":
			atClose.exitCode = 71
		case "session:close-trailing":
			atClose.trailing = true
		case "session:close-stderr":
			atClose.stderr = true
		case "session:exit-after":
			exitAfterResponse = true
		}
	}
	if response.Status == StatusComplete && len(response.Matches) == 0 {
		start := 0
		for {
			index := bytes.Index(content[start:], []byte("TOKEN"))
			if index < 0 {
				break
			}
			match := Match{SourceOrdinal: 0, RuleID: "github-pat", StartByte: start + index, EndByteExclusive: start + index + len("TOKEN")}
			match.OccurrenceID = OccurrenceID(match)
			response.Matches = append(response.Matches, match)
			start += index + len("TOKEN")
		}
	}
	encoded, err := encodeFrame(response, maxResponseFrameBytes)
	if err != nil {
		return 94
	}
	if _, err := os.Stdout.Write(encoded); err != nil {
		return 98
	}
	if exitAfterResponse {
		return 0
	}
	return -1
}

type sessionTestHelper struct {
	directory string
	path      string
	digest    string
}

func newSessionTestHelper(t *testing.T) sessionTestHelper {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "open-trestle-secret-scan-helper")
	if err := os.WriteFile(path, binary, 0555); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0555); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(binary)
	return sessionTestHelper{directory: directory, path: path, digest: hex.EncodeToString(digest[:])}
}

func (helper sessionTestHelper) settings(watchdog time.Duration) sessionSettings {
	return sessionSettings{
		config:         SessionConfig{HelperPath: helper.path, HelperSHA256: helper.digest, BuildProfile: HostRE2BuildProfile},
		scanWatchdog:   watchdog,
		startAllowance: 0,
		scanLimit:      sessionScanLimit,
		random:         &countingEntropy{},
	}
}

func openSessionForTest(t *testing.T, settings sessionSettings) *Session {
	t.Helper()
	session, err := openSession(context.Background(), settings)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// countingEntropy yields distinct request IDs for every scan.
type countingEntropy struct {
	mu      sync.Mutex
	counter uint64
}

func (entropy *countingEntropy) Read(buffer []byte) (int, error) {
	entropy.mu.Lock()
	defer entropy.mu.Unlock()
	for index := range buffer {
		if index%8 == 0 {
			entropy.counter++
		}
		buffer[index] = byte(entropy.counter >> (8 * (index % 8)))
	}
	return len(buffer), nil
}

func (session *Session) helperPID() int {
	return session.process.command.Process.Pid
}

// requireReapedAndGroupGone checks that the helper is no longer a child of
// this process (it was waited for, so no zombie remains) and that no process
// is left in its process group.
func requireReapedAndGroupGone(t *testing.T, pid int) {
	t.Helper()
	var status syscall.WaitStatus
	if waited, err := syscall.Wait4(pid, &status, syscall.WNOHANG, nil); waited != -1 || !errors.Is(err, syscall.ECHILD) {
		t.Fatalf("helper %d was not reaped: wait4=%d err=%v", pid, waited, err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := syscall.Kill(-pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process group %d still has members: %v", pid, err)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func requireProcessGone(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for processRunning(pid) {
		if time.Now().After(deadline) {
			t.Fatalf("process %d survived", pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func readTestPIDs(t *testing.T, path string) []int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		encoded, err := os.ReadFile(path)
		if err == nil {
			var pids []int
			for _, field := range strings.Fields(string(encoded)) {
				pid, err := strconv.Atoi(field)
				if err != nil {
					t.Fatal("invalid pid file")
				}
				pids = append(pids, pid)
			}
			return pids
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not publish its pids")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// requirePoisoned checks that a later scan fails at once with
// ErrSessionPoisoned wrapping cause and writes nothing to the helper.
func requirePoisoned(t *testing.T, session *Session, cause error) {
	t.Helper()
	sent := session.process.requestsSent.Load()
	started := time.Now()
	result, err := session.Scan(context.Background(), [][]byte{[]byte("clean")})
	if result.Complete() || result.Failure() != FailurePolicy || !errors.Is(err, ErrSessionPoisoned) || !errors.Is(err, cause) {
		t.Fatalf("later scan was not refused as poisoned: %v, %v", result.Failure(), err)
	}
	if session.process.requestsSent.Load() != sent || time.Since(started) > 500*time.Millisecond {
		t.Fatal("poisoned session wrote to the helper or did not fail immediately")
	}
	if !errors.Is(session.Err(), cause) {
		t.Fatalf("session error does not report the first failure: %v", session.Err())
	}
}

func TestSessionScansSeveralRequestsAndClosesCleanly(t *testing.T) {
	helper := newSessionTestHelper(t)
	session := openSessionForTest(t, helper.settings(5*time.Second))
	pid := session.helperPID()
	if pgid, err := syscall.Getpgid(pid); err != nil || pgid != pid {
		t.Fatalf("helper is not its own process group leader: pgid=%d err=%v", pgid, err)
	}
	inputs := []string{"clean", "a TOKEN here", "TOKEN and TOKEN", "", "π and TOKEN"}
	for index, input := range inputs {
		result, err := session.Scan(context.Background(), [][]byte{[]byte(input), []byte("second source")})
		if err != nil || !result.Complete() {
			t.Fatalf("scan %d failed: %v, %v", index, result.Failure(), err)
		}
		want := strings.Count(input, "TOKEN")
		metadata := result.Metadata()
		if len(result.Matches()) != want || metadata.MatchCount != want || metadata.SourceCount != 2 || metadata.ScannedByteCount != len(input)+len("second source") ||
			metadata.BuildProfile != HostRE2BuildProfile || metadata.HelperSHA256 != helper.digest || metadata.LauncherSHA256 != "" || metadata.WorkerSHA256 != "" {
			t.Fatalf("scan %d returned unexpected result: %d matches, %+v", index, len(result.Matches()), metadata)
		}
	}
	if sent := session.process.requestsSent.Load(); sent != int64(len(inputs)) {
		t.Fatalf("sent %d requests, want %d", sent, len(inputs))
	}
	if err := session.Close(); err != nil {
		t.Fatalf("clean close failed: %v", err)
	}
	if session.Err() != nil {
		t.Fatalf("clean session reports a failure: %v", session.Err())
	}
	requireReapedAndGroupGone(t, pid)
	if err := session.Close(); err != nil {
		t.Fatalf("second close changed the result: %v", err)
	}
	result, err := session.Scan(context.Background(), [][]byte{[]byte("clean")})
	if result.Complete() || !errors.Is(err, ErrSessionClosed) || session.process.requestsSent.Load() != int64(len(inputs)) {
		t.Fatalf("scan after close was not refused: %v", err)
	}
}

func TestSessionSpawnRecipe(t *testing.T) {
	helper := newSessionTestHelper(t)
	session := openSessionForTest(t, helper.settings(5*time.Second))
	command := session.process.command
	attributes := command.SysProcAttr
	if attributes == nil || !attributes.Setpgid || attributes.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("missing process group or parent-death signal: %#v", attributes)
	}
	if command.Dir != "/" || command.Env == nil || len(command.Env) != 0 || command.ExtraFiles != nil {
		t.Fatal("helper is not started with an empty environment, root directory and only stdio")
	}
	if !strings.HasPrefix(command.Path, "/proc/self/fd/") || len(command.Args) != 2 || command.Args[0] != helper.path || command.Args[1] != helperSessionArgument {
		t.Fatalf("helper is not executed through its verified descriptor: %q %q", command.Path, command.Args)
	}
	// The fake helper exits 91 and writes to stderr if its environment,
	// working directory, process group or descriptors are wrong.
	if result, err := session.Scan(context.Background(), [][]byte{[]byte("clean")}); err != nil || !result.Complete() {
		t.Fatalf("helper rejected its spawn environment: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionExecutesTheVerifiedFileWhenThePathIsSwapped(t *testing.T) {
	helper := newSessionTestHelper(t)
	settings := helper.settings(5 * time.Second)
	settings.beforeStart = func() {
		if err := os.Rename(helper.path, helper.path+".moved"); err != nil {
			panic(err)
		}
		if err := os.WriteFile(helper.path, []byte("#!/bin/sh\nexit 3\n"), 0555); err != nil {
			panic(err)
		}
	}
	session := openSessionForTest(t, settings)
	if result, err := session.Scan(context.Background(), [][]byte{[]byte("a TOKEN")}); err != nil || len(result.Matches()) != 1 {
		t.Fatalf("swapped path changed what was executed: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestOpenSessionRefusesUntrustedHelperBeforeSpawn(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testing.T, *sessionSettings, sessionTestHelper)
		want   error
	}{
		{"digest mismatch", func(_ *testing.T, settings *sessionSettings, _ sessionTestHelper) {
			settings.config.HelperSHA256 = strings.Repeat("0", 64)
		}, ErrHelperUntrusted},
		{"malformed digest", func(_ *testing.T, settings *sessionSettings, helper sessionTestHelper) {
			settings.config.HelperSHA256 = strings.ToUpper(helper.digest)
		}, ErrSessionConfig},
		{"empty digest", func(_ *testing.T, settings *sessionSettings, _ sessionTestHelper) { settings.config.HelperSHA256 = "" }, ErrSessionConfig},
		{"relative path", func(_ *testing.T, settings *sessionSettings, _ sessionTestHelper) {
			settings.config.HelperPath = "open-trestle-secret-scan-helper"
		}, ErrSessionConfig},
		{"unclean path", func(_ *testing.T, settings *sessionSettings, helper sessionTestHelper) {
			settings.config.HelperPath = helper.directory + "/./open-trestle-secret-scan-helper"
		}, ErrSessionConfig},
		{"missing file", func(_ *testing.T, settings *sessionSettings, helper sessionTestHelper) {
			settings.config.HelperPath = helper.path + ".missing"
		}, ErrHelperUntrusted},
		{"writable file", func(t *testing.T, _ *sessionSettings, helper sessionTestHelper) {
			if err := os.Chmod(helper.path, 0755); err != nil {
				t.Fatal(err)
			}
		}, ErrHelperUntrusted},
		{"setuid file", func(t *testing.T, _ *sessionSettings, helper sessionTestHelper) {
			if err := os.Chmod(helper.path, 0555|os.ModeSetuid); err != nil {
				t.Fatal(err)
			}
		}, ErrHelperUntrusted},
		{"symbolic link", func(t *testing.T, settings *sessionSettings, helper sessionTestHelper) {
			link := helper.path + ".link"
			if err := os.Symlink(helper.path, link); err != nil {
				t.Fatal(err)
			}
			settings.config.HelperPath = link
		}, ErrHelperUntrusted},
		{"directory", func(t *testing.T, settings *sessionSettings, helper sessionTestHelper) {
			directory := filepath.Join(helper.directory, "directory")
			if err := os.Mkdir(directory, 0555); err != nil {
				t.Fatal(err)
			}
			settings.config.HelperPath = directory
		}, ErrHelperUntrusted},
		{"fifo", func(t *testing.T, settings *sessionSettings, helper sessionTestHelper) {
			fifo := filepath.Join(helper.directory, "fifo")
			if err := syscall.Mkfifo(fifo, 0444); err != nil {
				t.Fatal(err)
			}
			settings.config.HelperPath = fifo
		}, ErrHelperUntrusted},
		{"recorded build profile", func(_ *testing.T, settings *sessionSettings, _ sessionTestHelper) {
			settings.config.BuildProfile = go12610BuildProfile
		}, ErrSessionConfig},
		{"native build profile", func(_ *testing.T, settings *sessionSettings, _ sessionTestHelper) {
			settings.config.BuildProfile = BuildProfile
		}, ErrSessionConfig},
		{"unknown build profile", func(_ *testing.T, settings *sessionSettings, _ sessionTestHelper) {
			settings.config.BuildProfile = "public_detect_run_unknown_v1"
		}, ErrSessionConfig},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			helper := newSessionTestHelper(t)
			settings := helper.settings(5 * time.Second)
			test.mutate(t, &settings, helper)
			var spawned atomic.Bool
			settings.beforeStart = func() { spawned.Store(true) }
			session, err := openSession(context.Background(), settings)
			if session != nil || !errors.Is(err, test.want) || spawned.Load() {
				t.Fatalf("untrusted helper was not refused before spawn: %v, spawned=%v", err, spawned.Load())
			}
		})
	}
}

func TestOpenSessionRefusesCanceledContextAndMissingContext(t *testing.T) {
	helper := newSessionTestHelper(t)
	settings := helper.settings(5 * time.Second)
	var spawned atomic.Bool
	settings.beforeStart = func() { spawned.Store(true) }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if session, err := openSession(ctx, settings); session != nil || !errors.Is(err, errScanCanceled) {
		t.Fatalf("canceled open was not refused: %v", err)
	}
	var missing context.Context
	if session, err := openSession(missing, settings); session != nil || !errors.Is(err, ErrSessionConfig) {
		t.Fatalf("nil context was not refused: %v", err)
	}
	if spawned.Load() {
		t.Fatal("refused open spawned the helper")
	}
}

func TestSessionDeadlineKillsHungHelper(t *testing.T) {
	helper := newSessionTestHelper(t)
	session := openSessionForTest(t, helper.settings(200*time.Millisecond))
	pid := session.helperPID()
	started := time.Now()
	result, err := session.Scan(context.Background(), [][]byte{[]byte("session:hang")})
	elapsed := time.Since(started)
	if result.Complete() || result.Failure() != FailurePolicy || !errors.Is(err, errHelperDeadline) || len(result.Matches()) != 0 {
		t.Fatalf("hung helper did not fail closed at the deadline: %v, %v", result.Failure(), err)
	}
	if elapsed < 200*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("deadline kill took %v", elapsed)
	}
	requireReapedAndGroupGone(t, pid)
	requirePoisoned(t, session, errHelperDeadline)
	if err := session.Close(); !errors.Is(err, errHelperDeadline) {
		t.Fatalf("close did not report the deadline failure: %v", err)
	}
}

func TestSessionGroupKillRemovesDescendantOfHungHelper(t *testing.T) {
	helper := newSessionTestHelper(t)
	session := openSessionForTest(t, helper.settings(300*time.Millisecond))
	pidPath := filepath.Join(t.TempDir(), "pids")
	result, err := session.Scan(context.Background(), [][]byte{[]byte("session:child-hang=" + pidPath)})
	if result.Complete() || !errors.Is(err, errHelperDeadline) {
		t.Fatalf("hung helper with a descendant did not fail closed: %v", err)
	}
	pids := readTestPIDs(t, pidPath)
	if len(pids) != 2 || pids[0] != session.helperPID() {
		t.Fatalf("unexpected pids %v", pids)
	}
	requireProcessGone(t, pids[1])
	requireReapedAndGroupGone(t, pids[0])
}

func TestSessionCloseRemovesDescendantThatIgnoresEOF(t *testing.T) {
	t.Run("descendant without the pipes", func(t *testing.T) {
		helper := newSessionTestHelper(t)
		session := openSessionForTest(t, helper.settings(5*time.Second))
		pidPath := filepath.Join(t.TempDir(), "pids")
		if result, err := session.Scan(context.Background(), [][]byte{[]byte("session:child-linger=" + pidPath)}); err != nil || !result.Complete() {
			t.Fatalf("scan failed: %v", err)
		}
		pids := readTestPIDs(t, pidPath)
		if !processRunning(pids[1]) {
			t.Fatal("descendant did not start")
		}
		if err := session.Close(); err != nil {
			t.Fatalf("close failed: %v", err)
		}
		requireProcessGone(t, pids[1])
		requireReapedAndGroupGone(t, pids[0])
	})
	t.Run("descendant holding stdout", func(t *testing.T) {
		helper := newSessionTestHelper(t)
		session := openSessionForTest(t, helper.settings(300*time.Millisecond))
		pidPath := filepath.Join(t.TempDir(), "pids")
		if result, err := session.Scan(context.Background(), [][]byte{[]byte("session:child-stdout=" + pidPath)}); err != nil || !result.Complete() {
			t.Fatalf("scan failed: %v", err)
		}
		pids := readTestPIDs(t, pidPath)
		started := time.Now()
		if err := session.Close(); !errors.Is(err, errHelperDeadline) || time.Since(started) > 2*time.Second {
			t.Fatalf("close with a lingering stdout holder did not fail at the deadline: %v", err)
		}
		requireProcessGone(t, pids[1])
		requireReapedAndGroupGone(t, pids[0])
	})
}

func TestSessionFailsClosedOnEveryHelperFault(t *testing.T) {
	tests := []struct {
		name    string
		content string
		causes  []error
		failure FailureClass
		quick   bool
	}{
		{"exit 71 without response", "session:exit71", []error{errHelperNoResponse, errHelperExited}, FailurePolicy, true},
		{"stderr byte", "session:stderr-hang", []error{errHelperStderr}, FailurePolicy, true},
		{"short frame", "session:short", []error{errHelperFrame}, FailurePolicy, true},
		{"oversized frame", "session:oversized", []error{errHelperFrame}, FailurePolicy, true},
		{"empty frame", "session:zero", []error{errHelperFrame}, FailurePolicy, true},
		{"malformed frame", "session:malformed", []error{errHelperResponse}, FailurePolicy, true},
		{"wrong request id", "session:wrong-id", []error{errHelperResponse}, FailurePolicy, true},
		{"native build profile", "session:native-profile", []error{errHelperResponse}, FailurePolicy, true},
		{"recorded build profile", "session:recorded-profile", []error{errHelperResponse}, FailurePolicy, true},
		{"unpinned rule id", "session:unknown-rule", []error{errHelperResponse}, FailurePolicy, true},
		{"scan failed status", "session:scan-failed", []error{errScanIncomplete}, FailurePolicy, true},
		{"resource exhausted status", "session:resource", []error{errScanIncomplete}, FailureResourceLimit, true},
		{"hang", "session:hang", []error{errHelperDeadline}, FailurePolicy, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			helper := newSessionTestHelper(t)
			watchdog := 3 * time.Second
			if !test.quick {
				watchdog = 200 * time.Millisecond
			}
			session := openSessionForTest(t, helper.settings(watchdog))
			pid := session.helperPID()
			if result, err := session.Scan(context.Background(), [][]byte{[]byte("a TOKEN first")}); err != nil || !result.Complete() {
				t.Fatalf("healthy first scan failed: %v", err)
			}
			started := time.Now()
			result, err := session.Scan(context.Background(), [][]byte{[]byte("TOKEN " + test.content)})
			if result.Complete() || result.Failure() != test.failure || len(result.Matches()) != 0 || !errorIsAny(err, test.causes) {
				t.Fatalf("fault was not closed: %v, %v", result.Failure(), err)
			}
			if test.quick && time.Since(started) > time.Second {
				t.Fatalf("fault was detected only after %v", time.Since(started))
			}
			requireReapedAndGroupGone(t, pid)
			requirePoisoned(t, session, err)
			if closeErr := session.Close(); !errors.Is(closeErr, err) {
				t.Fatalf("close did not report the first failure: %v", closeErr)
			}
		})
	}
}

func errorIsAny(err error, targets []error) bool {
	for _, target := range targets {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}

func TestSessionCloseFailsWhenHelperMisbehavesAtClose(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    error
	}{
		{"non-zero exit after the last response", "session:close-exit71", errHelperExit},
		{"output after the last response", "session:close-trailing", errHelperTrailingOutput},
		{"stderr at close", "session:close-stderr", errHelperStderr},
		{"stderr racing a response", "session:stderr-respond", errHelperStderr},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			helper := newSessionTestHelper(t)
			session := openSessionForTest(t, helper.settings(3*time.Second))
			pid := session.helperPID()
			result, scanErr := session.Scan(context.Background(), [][]byte{[]byte("TOKEN " + test.content)})
			if scanErr == nil && !result.Complete() {
				t.Fatal("scan without error is not complete")
			}
			closeErr := session.Close()
			if !errors.Is(closeErr, test.want) {
				t.Fatalf("close did not fail closed: %v", closeErr)
			}
			if scanErr != nil && !errors.Is(scanErr, test.want) {
				t.Fatalf("scan failed for another reason: %v", scanErr)
			}
			if test.want == errHelperExit && !strings.Contains(closeErr.Error(), "exit status 71") {
				t.Fatalf("close does not name the exit status: %v", closeErr)
			}
			requireReapedAndGroupGone(t, pid)
			if !errors.Is(session.Close(), test.want) || !errors.Is(session.Err(), test.want) {
				t.Fatal("close result is not stable")
			}
			if err := RunReviewSession(context.Background(), helper.settings(time.Second).config.Opener(), func(ctx context.Context, review ReviewSession) error {
				_, err := review.Scan(ctx, [][]byte{[]byte(test.content)})
				return err
			}); err == nil {
				t.Fatal("review over a helper that fails at close succeeded")
			}
		})
	}
}

func TestSessionHelperExitingBeforeCloseFailsClosed(t *testing.T) {
	helper := newSessionTestHelper(t)
	session := openSessionForTest(t, helper.settings(3*time.Second))
	pid := session.helperPID()
	if _, err := session.Scan(context.Background(), [][]byte{[]byte("session:exit-after")}); err != nil && !errors.Is(err, errHelperExited) {
		t.Fatalf("unexpected scan failure: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for session.Err() == nil && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	requirePoisoned(t, session, errHelperExited)
	requireReapedAndGroupGone(t, pid)
	if err := session.Close(); !errors.Is(err, errHelperExited) {
		t.Fatalf("close did not report the early exit: %v", err)
	}
}

func TestSessionCallerCancellation(t *testing.T) {
	t.Run("mid-scan", func(t *testing.T) {
		helper := newSessionTestHelper(t)
		session := openSessionForTest(t, helper.settings(5*time.Second))
		pid := session.helperPID()
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(50*time.Millisecond, cancel)
		started := time.Now()
		result, err := session.Scan(ctx, [][]byte{[]byte("session:hang")})
		if result.Complete() || result.Failure() != FailureCanceled || !errors.Is(err, errScanCanceled) || time.Since(started) > time.Second {
			t.Fatalf("cancellation did not stop the helper promptly: %v, %v", result.Failure(), err)
		}
		requireReapedAndGroupGone(t, pid)
		requirePoisoned(t, session, errScanCanceled)
	})
	t.Run("caller deadline shorter than the watchdog", func(t *testing.T) {
		helper := newSessionTestHelper(t)
		session := openSessionForTest(t, helper.settings(5*time.Second))
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
		defer cancel()
		started := time.Now()
		result, err := session.Scan(ctx, [][]byte{[]byte("session:hang")})
		if result.Failure() != FailureCanceled || !errors.Is(err, errScanCanceled) || time.Since(started) > time.Second {
			t.Fatalf("caller deadline was not honoured: %v", err)
		}
	})
	t.Run("already canceled", func(t *testing.T) {
		helper := newSessionTestHelper(t)
		session := openSessionForTest(t, helper.settings(5*time.Second))
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		result, err := session.Scan(ctx, [][]byte{[]byte("clean")})
		if result.Failure() != FailureCanceled || !errors.Is(err, errScanCanceled) || session.process.requestsSent.Load() != 0 {
			t.Fatalf("canceled scan reached the helper: %v", err)
		}
		requirePoisoned(t, session, errScanCanceled)
	})
}

func TestSessionRefusesInvalidInputAndEntropyFailureWithoutWriting(t *testing.T) {
	t.Run("invalid input", func(t *testing.T) {
		helper := newSessionTestHelper(t)
		session := openSessionForTest(t, helper.settings(5*time.Second))
		result, err := session.Scan(context.Background(), [][]byte{{0xff}})
		if result.Failure() != FailureInvalidInput || !errors.Is(err, errScanInput) || session.process.requestsSent.Load() != 0 {
			t.Fatalf("invalid input was not refused before the helper: %v", err)
		}
		requirePoisoned(t, session, errScanInput)
	})
	t.Run("entropy failure", func(t *testing.T) {
		helper := newSessionTestHelper(t)
		session := openSessionForTest(t, helper.settings(5*time.Second))
		session.settings.random = failingReader{}
		result, err := session.Scan(context.Background(), [][]byte{[]byte("clean")})
		if result.Failure() != FailurePolicy || !errors.Is(err, errScanRequest) || session.process.requestsSent.Load() != 0 {
			t.Fatalf("entropy failure was not closed: %v", err)
		}
		requirePoisoned(t, session, errScanRequest)
	})
}

func TestSessionScanLimit(t *testing.T) {
	helper := newSessionTestHelper(t)
	session := openSessionForTest(t, helper.settings(5*time.Second))
	for index := 0; index < sessionScanLimit; index++ {
		if result, err := session.Scan(context.Background(), [][]byte{[]byte("clean")}); err != nil || !result.Complete() {
			t.Fatalf("scan %d failed: %v", index, err)
		}
	}
	result, err := session.Scan(context.Background(), [][]byte{[]byte("clean")})
	if result.Complete() || result.Failure() != FailurePolicy || !errors.Is(err, ErrSessionScanLimit) || session.process.requestsSent.Load() != sessionScanLimit {
		t.Fatalf("scan past the limit was not refused: %v", err)
	}
	requirePoisoned(t, session, ErrSessionScanLimit)
	if err := session.Close(); !errors.Is(err, ErrSessionScanLimit) {
		t.Fatalf("close after the limit did not fail: %v", err)
	}
}

func TestSessionDeadlineIncludesStartAllowanceOnlyForTheFirstExchange(t *testing.T) {
	spawned := time.Unix(1000, 0)
	session := &Session{settings: sessionSettings{scanWatchdog: 6 * time.Second, startAllowance: 10 * time.Second}, spawned: spawned}
	if got := session.deadline(spawned.Add(time.Second)); !got.Equal(spawned.Add(16 * time.Second)) {
		t.Fatalf("early first exchange deadline %v", got.Sub(spawned))
	}
	if got := session.deadline(spawned.Add(30 * time.Second)); !got.Equal(spawned.Add(36 * time.Second)) {
		t.Fatalf("late first exchange deadline %v", got.Sub(spawned))
	}
	session.exchanged = true
	if got := session.deadline(spawned.Add(time.Second)); !got.Equal(spawned.Add(7 * time.Second)) {
		t.Fatalf("later exchange deadline %v", got.Sub(spawned))
	}
	if sessionScanWatchdog != 6*time.Second || sessionStartAllowance != 10*time.Second || sessionScanLimit != 64 || helperSessionArgument != "--stdio-v1-session" {
		t.Fatal("production session limits changed")
	}
}

func TestSessionFirstScanUsesStartAllowance(t *testing.T) {
	helper := newSessionTestHelper(t)
	settings := helper.settings(150 * time.Millisecond)
	settings.startAllowance = 2 * time.Second
	session := openSessionForTest(t, settings)
	if result, err := session.Scan(context.Background(), [][]byte{[]byte("session:slow=400ms")}); err != nil || !result.Complete() {
		t.Fatalf("first scan did not get the start allowance: %v", err)
	}
	result, err := session.Scan(context.Background(), [][]byte{[]byte("session:slow=400ms")})
	if result.Complete() || !errors.Is(err, errHelperDeadline) {
		t.Fatalf("later scan was not held to the watchdog: %v", err)
	}
}

func TestSessionSanitizeMasksAndRescansInTheSession(t *testing.T) {
	helper := newSessionTestHelper(t)
	session := openSessionForTest(t, helper.settings(5*time.Second))
	projection := session.Sanitize(context.Background(), [][]byte{[]byte("a TOKEN b")})
	if !projection.Complete() || string(projection.Sources()[0]) != "a ***** b" || projection.MaskedByteCount() != 5 || session.process.requestsSent.Load() != 2 {
		t.Fatalf("sanitize did not mask and rescan: %v", projection.Failure())
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestSessionConcurrentScansAreSerialized(t *testing.T) {
	helper := newSessionTestHelper(t)
	session := openSessionForTest(t, helper.settings(5*time.Second))
	const workers, scansPerWorker = 4, 8
	var group sync.WaitGroup
	failures := make(chan error, workers*scansPerWorker)
	stop := make(chan struct{})
	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_ = session.Err()
				time.Sleep(time.Millisecond)
			}
		}
	}()
	for worker := 0; worker < workers; worker++ {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for scan := 0; scan < scansPerWorker; scan++ {
				input := fmt.Sprintf("worker %d scan %d TOKEN", worker, scan)
				result, err := session.Scan(context.Background(), [][]byte{[]byte(input)})
				if err != nil || !result.Complete() || len(result.Matches()) != 1 {
					failures <- fmt.Errorf("worker %d scan %d: %v", worker, scan, err)
				}
			}
		}(worker)
	}
	group.Wait()
	close(stop)
	close(failures)
	for err := range failures {
		t.Error(err)
	}
	if err := session.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestRunReviewSession(t *testing.T) {
	helper := newSessionTestHelper(t)
	opener := helper.settings(time.Second).config.Opener()
	var captured ReviewSession
	if err := RunReviewSession(context.Background(), opener, func(ctx context.Context, review ReviewSession) error {
		captured = review
		result, err := review.Scan(ctx, [][]byte{[]byte("a TOKEN")})
		if err != nil || len(result.Matches()) != 1 {
			return fmt.Errorf("scan: %w", err)
		}
		return nil
	}); err != nil {
		t.Fatalf("clean review failed: %v", err)
	}
	if _, err := captured.Scan(context.Background(), [][]byte{[]byte("clean")}); !errors.Is(err, ErrSessionClosed) {
		t.Fatal("review session was not closed at the end of the review")
	}
	reviewFailure := errors.New("review failure")
	err := RunReviewSession(context.Background(), opener, func(ctx context.Context, review ReviewSession) error {
		_, _ = review.Scan(ctx, [][]byte{[]byte("session:close-exit71")})
		return reviewFailure
	})
	if !errors.Is(err, reviewFailure) || !errors.Is(err, errHelperExit) {
		t.Fatalf("review and close failures were not both reported: %v", err)
	}
	untrusted := SessionConfig{HelperPath: helper.path, HelperSHA256: strings.Repeat("0", 64), BuildProfile: HostRE2BuildProfile}
	ran := false
	if err := RunReviewSession(context.Background(), untrusted.Opener(), func(context.Context, ReviewSession) error { ran = true; return nil }); !errors.Is(err, ErrHelperUntrusted) || ran {
		t.Fatalf("review ran without a trusted helper: %v", err)
	}
}

// TestSessionHelperDiesWithItsParent runs a parent process that opens a
// session and leaves the helper hanging in a scan, kills that parent with
// SIGKILL, and requires the helper to die through its parent-death signal.
// The hanging helper does not read stdin, so EOF cannot be what stops it.
func TestSessionHelperDiesWithItsParent(t *testing.T) {
	if pidPath := os.Getenv("SECRETSCAN_SESSION_PARENT_PIDS"); pidPath != "" {
		runSessionParentForTest(pidPath, os.Getenv("SECRETSCAN_SESSION_PARENT_HELPER"), os.Getenv("SECRETSCAN_SESSION_PARENT_DIGEST"))
		return
	}
	helper := newSessionTestHelper(t)
	pidPath := filepath.Join(t.TempDir(), "pids")
	parent := exec.Command(os.Args[0], "-test.run=^TestSessionHelperDiesWithItsParent$")
	parent.Env = append(os.Environ(),
		"SECRETSCAN_SESSION_PARENT_PIDS="+pidPath,
		"SECRETSCAN_SESSION_PARENT_HELPER="+helper.path,
		"SECRETSCAN_SESSION_PARENT_DIGEST="+helper.digest)
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	pids := readTestPIDs(t, pidPath)
	if len(pids) != 1 || !processRunning(pids[0]) {
		_ = parent.Process.Kill()
		_ = parent.Wait()
		t.Fatalf("helper did not start: %v", pids)
	}
	if err := parent.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = parent.Wait()
	requireProcessGone(t, pids[0])
}

func runSessionParentForTest(pidPath, helperPath, digest string) {
	settings := sessionSettings{
		config:         SessionConfig{HelperPath: helperPath, HelperSHA256: digest, BuildProfile: HostRE2BuildProfile},
		scanWatchdog:   time.Minute,
		startAllowance: time.Minute,
		scanLimit:      sessionScanLimit,
		random:         &countingEntropy{},
	}
	session, err := openSession(context.Background(), settings)
	if err != nil {
		os.Exit(2)
	}
	// Another goroutine scans, so the helper's spawning thread is not the
	// one that blocks in the scan.
	go func() {
		_, _ = session.Scan(context.Background(), [][]byte{[]byte("session:pid=" + pidPath + " session:hang")})
	}()
	time.Sleep(time.Minute)
	os.Exit(3)
}

func TestSessionFailureFormattingRetainsNoInputOrStderr(t *testing.T) {
	helper := newSessionTestHelper(t)
	session := openSessionForTest(t, helper.settings(3*time.Second))
	input := "session:stderr-hang PRIVATE_INPUT_MARKER"
	result, err := session.Scan(context.Background(), [][]byte{[]byte(input)})
	closeErr := session.Close()
	formatted := fmt.Sprintf("%v %#v %v %v %v", result, result, err, closeErr, session.Err())
	for _, forbidden := range []string{"PRIVATE_INPUT_MARKER", "secret-bearing diagnostic", helper.path} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("failure formatting retained private content: %q", forbidden)
		}
	}
}
