//go:build linux

package secretscan

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func init() {
	if len(os.Args) != 2 || os.Args[1] != scannerLauncherArgument {
		return
	}
	runClientTestHelper()
	os.Exit(0)
}

func runClientTestHelper() {
	if cwd, err := os.Getwd(); err != nil || cwd != "/" || len(os.Environ()) != 0 {
		_, _ = os.Stderr.Write([]byte("x"))
		os.Exit(91)
	}
	frame, err := io.ReadAll(io.LimitReader(os.Stdin, maxRequestFrameBytes+framePrefixBytes+1))
	if err != nil {
		os.Exit(92)
	}
	request, err := ParseRequestFrame(frame)
	if err != nil {
		os.Exit(93)
	}
	content := request.Sources[0].Content
	if bytes.HasPrefix(content, []byte("helper:descendant:")) {
		child := exec.Command("/bin/sleep", "60")
		child.Dir = "/"
		child.Env = []string{}
		if err := child.Start(); err != nil {
			os.Exit(95)
		}
		pidPath := string(bytes.TrimPrefix(content, []byte("helper:descendant:")))
		// Publish the pid by rename so the polling test never reads the
		// empty file that os.WriteFile creates before it writes.
		if err := os.WriteFile(pidPath+".tmp", []byte(strconv.Itoa(child.Process.Pid)), 0600); err != nil {
			os.Exit(96)
		}
		if err := os.Rename(pidPath+".tmp", pidPath); err != nil {
			os.Exit(96)
		}
		for {
			time.Sleep(time.Hour)
		}
	}
	switch {
	case bytes.Contains(content, []byte("helper:hang")):
		for {
			time.Sleep(time.Hour)
		}
	case bytes.Contains(content, []byte("helper:stderr")):
		_, _ = os.Stderr.Write([]byte("secret-bearing diagnostic"))
	case bytes.Contains(content, []byte("helper:exit")):
		os.Exit(9)
	case bytes.Contains(content, []byte("helper:malformed")):
		_, _ = os.Stdout.Write([]byte("not a frame"))
		return
	}

	status := StatusComplete
	switch {
	case bytes.Contains(content, []byte("helper:scan-failed")):
		status = StatusScanFailed
	case bytes.Contains(content, []byte("helper:resource")):
		status = StatusResourceExhausted
	case bytes.Contains(content, []byte("helper:input-rejected")):
		status = StatusInputRejected
	}
	matches := []Match{}
	addMatch := func(start, end int, rule string) {
		match := Match{SourceOrdinal: 0, RuleID: rule, StartByte: start, EndByteExclusive: end}
		match.OccurrenceID = OccurrenceID(match)
		matches = append(matches, match)
	}
	if index := bytes.Index(content, []byte("TOKEN")); index >= 0 {
		addMatch(index, index+len("TOKEN"), "github-pat")
	}
	if bytes.Contains(content, []byte("helper:residual")) {
		if index := bytes.IndexByte(content, '*'); index >= 0 {
			addMatch(index, index+1, "generic-api-key")
		}
	}
	response := Response{
		SchemaVersion:   1,
		RequestID:       request.RequestID,
		Status:          status,
		Scanner:         ScannerName,
		ScannerVersion:  ScannerVersion,
		ScannerCommit:   ScannerCommit,
		RulesetIdentity: RulesetIdentity,
		BuildProfile:    BuildProfile,
		Matches:         matches,
	}
	if status != StatusComplete {
		response.Matches = []Match{}
	}
	if bytes.Contains(content, []byte("helper:recorded-profile")) {
		response.BuildProfile = go12610BuildProfile
	}
	encoded, err := EncodeResponseFrame(response, ResponseExpectation{
		Request:         request,
		RulesetIdentity: RulesetIdentity,
		RuleIDs:         pinnedRuleIDSet(),
	})
	if err != nil {
		os.Exit(94)
	}
	if bytes.Contains(content, []byte("helper:oversized")) {
		_, _ = os.Stdout.Write(make([]byte, maxResponseFrameBytes+framePrefixBytes+1))
		return
	}
	_, _ = os.Stdout.Write(encoded)
	if bytes.Contains(content, []byte("helper:trailing")) {
		_, _ = os.Stdout.Write([]byte("x"))
	}
	if bytes.Contains(content, []byte("helper:frame-exit")) {
		os.Exit(9)
	}
	if bytes.Contains(content, []byte("helper:frame-hang")) {
		for {
			time.Sleep(time.Hour)
		}
	}
}

func pinnedRuleIDSet() map[string]struct{} {
	rules := make(map[string]struct{}, len(betterleaksRuleIDsV1))
	for _, rule := range betterleaksRuleIDsV1 {
		rules[rule] = struct{}{}
	}
	return rules
}

func trustedClientForTest(t *testing.T, watchdog time.Duration) (*Client, string, string) {
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
	launcher := filepath.Join(directory, "open-trestle-secret-scanner")
	worker := filepath.Join(directory, "open-trestle-secret-scanner-worker")
	for _, path := range []string{launcher, worker} {
		if err := os.WriteFile(path, binary, 0555); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0555); err != nil {
			t.Fatal(err)
		}
	}
	digest := sha256.Sum256(binary)
	expected := hex.EncodeToString(digest[:])
	client := newClient(clientConfig{
		launcherPath:           launcher,
		workerPath:             worker,
		expectedLauncherSHA256: expected,
		expectedWorkerSHA256:   expected,
		expectedUID:            uint32(os.Getuid()),
		expectedGID:            uint32(os.Getgid()),
		expectedMode:           0555,
		trustRoot:              directory,
		watchdog:               watchdog,
		command: func(path string, argument string) *exec.Cmd {
			return exec.Command(path, argument)
		},
	})
	return client, launcher, worker
}

func TestProductionClientUsesOnlyFixedInvocationAndTrustPins(t *testing.T) {
	client := NewClient()
	if client == nil {
		t.Fatal("nil production client")
	}
	if scannerLauncherPath != "/usr/local/libexec/open-trestle/open-trestle-secret-scanner" || scannerLauncherArgument != "--stdio-v1" || scannerWorkerPath != "/usr/local/libexec/open-trestle/open-trestle-secret-scanner-worker" {
		t.Fatal("production invocation is not fixed")
	}
	if client.config.launcherPath != scannerLauncherPath || client.config.workerPath != scannerWorkerPath || client.config.command == nil {
		t.Fatal("production client does not use the fixed child")
	}
}

func TestClientInvokesWithEmptyEnvironmentAndRootWorkingDirectory(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	result := client.scan(context.Background(), [][]byte{[]byte("clean")})
	if !result.Complete() || result.Failure() != FailureNone || result.Metadata().SourceCount != 1 || result.Metadata().ScannedByteCount != 5 || result.Metadata().MatchCount != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestClientRejectsUntrustedExecutablesBeforeSpawn(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*clientConfig, string, string) error
	}{
		{"empty launcher digest", func(config *clientConfig, _, _ string) error { config.expectedLauncherSHA256 = ""; return nil }},
		{"empty worker digest", func(config *clientConfig, _, _ string) error { config.expectedWorkerSHA256 = ""; return nil }},
		{"launcher digest mismatch", func(config *clientConfig, _, _ string) error {
			config.expectedLauncherSHA256 = strings.Repeat("0", 64)
			return nil
		}},
		{"worker digest mismatch", func(config *clientConfig, _, _ string) error {
			config.expectedWorkerSHA256 = strings.Repeat("0", 64)
			return nil
		}},
		{"launcher writable", func(_ *clientConfig, launcher, _ string) error { return os.Chmod(launcher, 0755) }},
		{"worker writable", func(_ *clientConfig, _, worker string) error { return os.Chmod(worker, 0755) }},
		{"wrong owner", func(config *clientConfig, _, _ string) error { config.expectedUID++; return nil }},
		{"launcher symlink", func(config *clientConfig, launcher, _ string) error {
			target := launcher + ".target"
			if err := os.Rename(launcher, target); err != nil {
				return err
			}
			if err := os.Symlink(target, launcher); err != nil {
				return err
			}
			config.expectedLauncherSHA256 = fileSHA256ForTest(t, target)
			return nil
		}},
		{"worker is not regular", func(config *clientConfig, _, worker string) error {
			if err := os.Remove(worker); err != nil {
				return err
			}
			if err := os.Mkdir(worker, 0555); err != nil {
				return err
			}
			config.expectedWorkerSHA256 = strings.Repeat("0", 64)
			return nil
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, launcher, worker := trustedClientForTest(t, 5*time.Second)
			config := client.config
			if err := test.mutate(&config, launcher, worker); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			config.command = func(path, argument string) *exec.Cmd {
				calls.Add(1)
				return exec.Command(path, argument)
			}
			result := newClient(config).scan(context.Background(), [][]byte{[]byte("clean")})
			if result.Complete() || result.Failure() != FailurePolicy || calls.Load() != 0 {
				t.Fatalf("untrusted executable was not rejected before spawn: %#v, calls=%d", result, calls.Load())
			}
		})
	}
}

func fileSHA256ForTest(t *testing.T, path string) string {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func TestClientClosesEveryFailureClass(t *testing.T) {
	tests := []struct {
		name    string
		content []byte
		failure FailureClass
	}{
		{"malformed response", []byte("helper:malformed"), FailurePolicy},
		{"stderr", []byte("helper:stderr"), FailurePolicy},
		{"abnormal exit", []byte("helper:exit"), FailurePolicy},
		{"worker scan failure", []byte("helper:scan-failed"), FailurePolicy},
		{"worker resource limit", []byte("helper:resource"), FailureResourceLimit},
		{"worker input rejection", []byte("helper:input-rejected"), FailureInvalidInput},
		{"trailing stdout", []byte("helper:trailing"), FailurePolicy},
		{"oversized stdout", []byte("helper:oversized"), FailurePolicy},
		{"valid frame then abnormal exit", []byte("helper:frame-exit"), FailurePolicy},
		{"recorded go1.26.10 profile from a live worker", []byte("helper:recorded-profile TOKEN"), FailurePolicy},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, _, _ := trustedClientForTest(t, 5*time.Second)
			result := client.scan(context.Background(), [][]byte{test.content})
			if result.Complete() || result.Failure() != test.failure || len(result.Matches()) != 0 {
				t.Fatalf("unexpected closed failure: %#v", result)
			}
		})
	}
}

func TestClientFailureFormattingRetainsNoInputOrStderr(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	input := "helper:stderr PRIVATE_INPUT_MARKER"
	result := client.scan(context.Background(), [][]byte{[]byte(input)})
	formatted := fmt.Sprintf("%v %#v", result, result)
	for _, forbidden := range []string{input, "PRIVATE_INPUT_MARKER", "secret-bearing diagnostic"} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("failure formatting retained private content: %q", forbidden)
		}
	}
}

func TestClientCancellationAndWatchdogKillAndReapChild(t *testing.T) {
	t.Run("caller cancellation", func(t *testing.T) {
		client, _, _ := trustedClientForTest(t, 5*time.Second)
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(30*time.Millisecond, cancel)
		started := time.Now()
		result := client.scan(ctx, [][]byte{[]byte("helper:hang")})
		if result.Failure() != FailureCanceled || time.Since(started) > 700*time.Millisecond {
			t.Fatalf("cancellation did not promptly stop child: %#v", result)
		}
	})
	t.Run("watchdog", func(t *testing.T) {
		client, _, _ := trustedClientForTest(t, 60*time.Millisecond)
		started := time.Now()
		result := client.scan(context.Background(), [][]byte{[]byte("helper:hang")})
		if result.Failure() != FailurePolicy || time.Since(started) > 700*time.Millisecond {
			t.Fatalf("watchdog did not promptly stop child: %#v", result)
		}
	})
}

func TestClientShortensWatchdogToCallerDeadline(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	started := time.Now()
	result := client.scan(ctx, [][]byte{[]byte("helper:hang")})
	if result.Failure() != FailureCanceled || time.Since(started) > 700*time.Millisecond {
		t.Fatalf("caller deadline was not honored: %#v", result)
	}
}

type failingReader struct{}

func (failingReader) Read(_ []byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestClientEntropyFailureIsPolicyFailureWithoutSpawn(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	client.config.random = failingReader{}
	var calls atomic.Int32
	client.config.command = func(path, argument string) *exec.Cmd {
		calls.Add(1)
		return exec.Command(path, argument)
	}
	result := client.scan(context.Background(), [][]byte{[]byte("clean")})
	if result.Failure() != FailurePolicy || calls.Load() != 0 {
		t.Fatalf("entropy failure was not closed: %#v", result)
	}
}

func TestClientRejectsEveryInputBoundBeforeSpawn(t *testing.T) {
	tests := []struct {
		name    string
		sources [][]byte
	}{
		{"source count", make([][]byte, maxSources+1)},
		{"source bytes", [][]byte{make([]byte, maxSourceBytes+1)}},
		{"aggregate bytes", [][]byte{make([]byte, maxSourceBytes), make([]byte, maxSourceBytes), make([]byte, maxSourceBytes), make([]byte, maxSourceBytes), make([]byte, maxSourceBytes), make([]byte, maxSourceBytes), make([]byte, maxSourceBytes), make([]byte, maxSourceBytes), make([]byte, 1)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for index := range test.sources {
				if test.sources[index] == nil {
					test.sources[index] = make([]byte, 0)
				}
			}
			client, _, _ := trustedClientForTest(t, 5*time.Second)
			var calls atomic.Int32
			client.config.command = func(path, argument string) *exec.Cmd {
				calls.Add(1)
				return exec.Command(path, argument)
			}
			result := client.scan(context.Background(), test.sources)
			if result.Failure() != FailureInvalidInput || calls.Load() != 0 {
				t.Fatalf("unbounded input reached child: %#v", result)
			}
		})
	}
}

func TestClientRequestEncoderMatchesCanonicalProtocolWithoutTemporaryJSON(t *testing.T) {
	request := Request{
		SchemaVersion: 1,
		RequestID:     strings.Repeat("01", sha256.Size),
		Sources:       []Source{{Ordinal: 0, Content: make([]byte, 0)}, {Ordinal: 1, Content: []byte("π\r\n")}},
	}
	got, err := encodeClientRequestFrame(request)
	if err != nil {
		t.Fatal(err)
	}
	want, err := EncodeRequestFrame(request)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("client request encoding differs from protocol")
	}
	clear(got)
}

func TestClientAcceptsEmptyNonNilSourceAndRejectsNilSource(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	empty := client.scan(context.Background(), [][]byte{make([]byte, 0)})
	if !empty.Complete() || empty.Metadata().ScannedByteCount != 0 {
		t.Fatalf("empty source was rejected: %#v", empty)
	}
	nilSource := client.scan(context.Background(), [][]byte{nil})
	if nilSource.Failure() != FailureInvalidInput {
		t.Fatalf("nil source was accepted: %#v", nilSource)
	}
}

func TestClientRejectsInvalidInputWithoutSpawn(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	var calls atomic.Int32
	client.config.command = func(path, argument string) *exec.Cmd {
		calls.Add(1)
		return exec.Command(path, argument)
	}
	result := client.scan(context.Background(), [][]byte{[]byte{0xff}})
	if result.Failure() != FailureInvalidInput || calls.Load() != 0 {
		t.Fatalf("invalid input reached child: %#v", result)
	}
}

func TestClientAlreadyCanceledDoesNotSpawn(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	var calls atomic.Int32
	client.config.command = func(path, argument string) *exec.Cmd {
		calls.Add(1)
		return exec.Command(path, argument)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := client.scan(ctx, [][]byte{[]byte("clean")})
	if result.Failure() != FailureCanceled || calls.Load() != 0 {
		t.Fatalf("canceled request spawned child: %#v, calls=%d", result, calls.Load())
	}
}

func TestClientRejectsWritableTrustedAncestor(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	if err := os.Chmod(client.config.trustRoot, 0722); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	client.config.command = func(path, argument string) *exec.Cmd {
		calls.Add(1)
		return exec.Command(path, argument)
	}
	result := client.scan(context.Background(), [][]byte{[]byte("clean")})
	if result.Failure() != FailurePolicy || calls.Load() != 0 {
		t.Fatalf("writable ancestor was trusted: %#v", result)
	}
}

func TestClientRejectsValidFrameWithoutTimelyNormalExit(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 60*time.Millisecond)
	result := client.scan(context.Background(), [][]byte{[]byte("helper:frame-hang")})
	if result.Complete() || result.Failure() != FailurePolicy {
		t.Fatalf("response was accepted before normal exit: %#v", result)
	}
}

func TestClientCancellationKillsProcessGroupDescendant(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	pidPath := filepath.Join(t.TempDir(), "descendant.pid")
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan ScanResult, 1)
	go func() {
		result <- client.scan(ctx, [][]byte{[]byte("helper:descendant:" + pidPath)})
	}()
	var pid int
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		encoded, err := os.ReadFile(pidPath)
		if err == nil {
			pid, err = strconv.Atoi(string(encoded))
			if err != nil {
				t.Fatal("invalid descendant pid")
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		cancel()
		<-result
		t.Fatal("descendant did not start")
	}
	cancel()
	scanResult := <-result
	if scanResult.Failure() != FailureCanceled {
		t.Fatalf("cancellation failure mismatch: %#v", scanResult)
	}
	deadline = time.Now().Add(time.Second)
	running := processRunning(pid)
	for running && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
		running = processRunning(pid)
	}
	if running {
		t.Fatal("process-group descendant survived cancellation")
	}
}

// processRunning reports whether pid is still a live process. A missing /proc
// entry or a zombie or dead state means it is gone; any other read error is
// treated as running, because a process that is exiting can fail one read.
func processRunning(pid int) bool {
	status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	closing := bytes.LastIndexByte(status, ')')
	if closing < 0 || closing+2 >= len(status) {
		return true
	}
	state := status[closing+2]
	return state != 'Z' && state != 'X'
}

func TestClientProcessUsesParentDeathSignalAndOwnProcessGroup(t *testing.T) {
	client, _, _ := trustedClientForTest(t, 5*time.Second)
	var command *exec.Cmd
	client.config.command = func(path, argument string) *exec.Cmd {
		command = exec.Command(path, argument)
		return command
	}
	result := client.scan(context.Background(), [][]byte{[]byte("clean")})
	if !result.Complete() || command == nil || command.SysProcAttr == nil || !command.SysProcAttr.Setpgid || command.SysProcAttr.Pdeathsig != syscall.SIGKILL {
		t.Fatalf("missing process cleanup controls: %#v, %#v", result, command)
	}
}
