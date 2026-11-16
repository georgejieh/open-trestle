//go:build linux && amd64

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/adapter"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
	"golang.org/x/sys/unix"
)

type qualificationInput struct {
	Fixtures []struct {
		ContentBase64 string `json:"content_base64"`
	} `json:"fixtures"`
}

func TestSandboxedWorkerScansOneFrameWithoutLeaksOrFiles(t *testing.T) {
	temporary := t.TempDir()
	workerPath := buildWorker(t, temporary)
	launcherPath := buildLauncher(t, temporary, workerPath)
	secret := readQualificationSecret(t)
	request := protocol.Request{
		SchemaVersion: 1,
		RequestID:     strings.Repeat("a", 64),
		Sources:       []protocol.Source{{Ordinal: 0, Content: secret}},
	}
	frame, err := protocol.EncodeRequestFrame(request)
	if err != nil {
		t.Fatal(err)
	}
	before := directoryNames(t, temporary)

	command := exec.Command(launcherPath, "--stdio-v1")
	command.Env = []string{"HOME=/secret-home", "HTTPS_PROXY=http://credential.invalid"}
	command.Stdin = bytes.NewReader(frame)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("worker failed: %v; stdout=%q stderr=%q", err, stdout.Bytes(), stderr.Bytes())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr leaked %q", stderr.Bytes())
	}
	if bytes.Contains(stdout.Bytes(), secret) || bytes.Contains(stdout.Bytes(), []byte(base64.StdEncoding.EncodeToString(secret))) {
		t.Fatal("response contains source material")
	}
	response, err := protocol.ParseResponseFrame(stdout.Bytes(), protocol.ResponseExpectation{
		Request:         request,
		RulesetIdentity: protocol.RulesetIdentity,
		RuleIDs:         adapter.PinnedRuleIDs(),
	})
	if err != nil {
		t.Fatalf("invalid response: %v; bytes=%q", err, stdout.Bytes())
	}
	if response.Status != protocol.StatusComplete || len(response.Matches) == 0 {
		t.Fatalf("unexpected response status=%q matches=%d", response.Status, len(response.Matches))
	}
	if response.BuildProfile != protocol.BuildProfile {
		t.Fatalf("sandboxed worker emitted build profile %q, want %q", response.BuildProfile, protocol.BuildProfile)
	}
	after := directoryNames(t, temporary)
	if strings.Join(before, "\x00") != strings.Join(after, "\x00") {
		t.Fatalf("worker changed filesystem: before=%v after=%v", before, after)
	}
}

func TestWorkerRefusesMissingLauncherSandboxWithoutReading(t *testing.T) {
	noNewPrivileges, _, errno := unix.RawSyscall6(unix.SYS_PRCTL, unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0, 0)
	if errno != 0 || noNewPrivileges != 0 {
		t.Skipf("parent already has NO_NEW_PRIVS=%d, so launcher omission cannot be induced: %v", noNewPrivileges, errno)
	}
	temporary := t.TempDir()
	workerPath := buildWorker(t, temporary)
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readPipe.Close()
	requestBytes := []byte("repository-secret")
	if _, err := writePipe.Write(requestBytes); err != nil {
		t.Fatal(err)
	}
	if err := writePipe.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(workerPath, "--sandboxed-stdio-v1")
	command.Stdin = readPipe
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err = command.Run()
	if err == nil {
		t.Fatal("worker accepted a direct unsandboxed invocation")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("unsandboxed refusal emitted output: stdout=%q stderr=%q", stdout.Bytes(), stderr.Bytes())
	}
	remaining, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(remaining, requestBytes) {
		t.Fatalf("worker read request before sandbox success: remaining=%q", remaining)
	}
}

func TestSandboxedWorkerCancellationIsSilent(t *testing.T) {
	temporary := t.TempDir()
	workerPath := buildWorker(t, temporary)
	launcherPath := buildLauncher(t, temporary, workerPath)
	contextWithCancel, cancel := context.WithCancel(context.Background())
	command := exec.CommandContext(contextWithCancel, launcherPath, "--stdio-v1")
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := stdin.Write([]byte{0, 0, 1, 0, '{'}); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitErr := command.Wait()
	if waitErr == nil {
		t.Fatal("canceled worker exited successfully")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("canceled worker emitted output: stdout=%q stderr=%q", stdout.Bytes(), stderr.Bytes())
	}
}

func TestSandboxedWorkerRejectsSecondFrameWithoutOutput(t *testing.T) {
	temporary := t.TempDir()
	workerPath := buildWorker(t, temporary)
	launcherPath := buildLauncher(t, temporary, workerPath)
	request := protocol.Request{
		SchemaVersion: 1,
		RequestID:     strings.Repeat("b", 64),
		Sources:       []protocol.Source{{Ordinal: 0, Content: []byte("ordinary text")}},
	}
	frame, err := protocol.EncodeRequestFrame(request)
	if err != nil {
		t.Fatal(err)
	}
	input := append(append([]byte(nil), frame...), frame...)
	command := exec.Command(launcherPath, "--stdio-v1")
	command.Stdin = bytes.NewReader(input)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err == nil {
		t.Fatal("worker accepted a second frame")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("second-frame refusal emitted output: stdout=%q stderr=%q", stdout.Bytes(), stderr.Bytes())
	}
}

func TestWorkerRejectsEveryOtherEntrypoint(t *testing.T) {
	temporary := t.TempDir()
	workerPath := buildWorker(t, temporary)
	for _, arguments := range [][]string{nil, {"--stdio-v1"}, {"--sandboxed-stdio-v1", "extra"}} {
		command := exec.Command(workerPath, arguments...)
		var stdout bytes.Buffer
		var stderr bytes.Buffer
		command.Stdout = &stdout
		command.Stderr = &stderr
		if err := command.Run(); err == nil {
			t.Fatalf("entrypoint %q unexpectedly accepted", arguments)
		}
		if stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("entrypoint %q emitted output", arguments)
		}
	}
}

func buildWorker(t *testing.T, directory string) string {
	t.Helper()
	workerPath := filepath.Join(directory, "worker")
	command := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", workerPath, ".")
	command.Dir = "."
	command.Env = append(os.Environ(), "GOWORK=off", "GOTOOLCHAIN=go1.26.11", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("worker build failed: %v; output=%s", err, output)
	}
	return workerPath
}

func buildLauncher(t *testing.T, directory, workerPath string) string {
	t.Helper()
	sourcePath, err := filepath.Abs(filepath.Join("..", "..", "launcher", "launcher.c"))
	if err != nil {
		t.Fatal(err)
	}
	launcherPath := filepath.Join(directory, "launcher")
	definition := "-DOPEN_TRESTLE_TEST_WORKER_PATH=" + strconv.Quote(workerPath)
	arguments := []string{definition, "-std=c17", "-O2", "-fPIE", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-Wall", "-Wextra", "-Werror", "-Wformat=2", "-Wconversion", "-Wshadow", "-Wstrict-prototypes", "-static-pie", "-Wl,-z,relro,-z,now,-z,noexecstack,--build-id=none", "-o", launcherPath, sourcePath}
	command := exec.Command("/usr/bin/gcc", arguments...)
	command.Env = append(os.Environ(), "LC_ALL=C", "SOURCE_DATE_EPOCH=0")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("launcher build failed: %v; output=%s", err, output)
	}
	return launcherPath
}

func readQualificationSecret(t *testing.T) []byte {
	t.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "testdata", "coverage-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest qualificationInput
	if err := json.Unmarshal(content, &manifest); err != nil || len(manifest.Fixtures) == 0 {
		t.Fatalf("invalid qualification fixture: %v", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(manifest.Fixtures[0].ContentBase64)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func directoryNames(t *testing.T, directory string) []string {
	t.Helper()
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}
