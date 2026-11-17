//go:build linux && amd64

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

const sandboxHelperEnvironment = "OPEN_TRESTLE_SANDBOX_TEST_HELPER"

func TestInstallAppliesDenyRulesToPreexistingLockedThread(t *testing.T) {
	if os.Getenv(sandboxHelperEnvironment) == "1" {
		runSeccompHelper()
		return
	}
	command := exec.Command(sandboxTestExecutable(t), "-test.run=^TestInstallAppliesDenyRulesToPreexistingLockedThread$")
	command.Env = append(os.Environ(), sandboxHelperEnvironment+"=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("sandbox helper failed: %v; output=%q", err, output)
	}
	if !strings.Contains(string(output), "sandbox-ok\n") {
		t.Fatalf("unexpected helper output %q", output)
	}
}

func runSeccompHelper() {
	runtime.GOMAXPROCS(4)
	ready := make(chan struct{})
	run := make(chan struct{})
	result := make(chan error)
	go func() {
		runtime.LockOSThread()
		close(ready)
		<-run
		descriptor, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
		if err == nil {
			unix.Close(descriptor)
			result <- errors.New("socket unexpectedly succeeded")
			return
		}
		if !errors.Is(err, syscall.EPERM) {
			result <- fmt.Errorf("socket error = %v", err)
			return
		}
		_, _, errno := unix.RawSyscall(unix.SYS_EXECVE, 0, 0, 0)
		if !errors.Is(errno, syscall.EPERM) {
			result <- fmt.Errorf("execve error = %v", errno)
			return
		}
		descriptor, err = unix.Open(os.Args[0], unix.O_WRONLY, 0)
		if err == nil {
			unix.Close(descriptor)
			result <- errors.New("write open unexpectedly succeeded")
			return
		}
		if !errors.Is(err, syscall.EPERM) {
			result <- fmt.Errorf("write open error = %v", err)
			return
		}
		result <- nil
	}()
	<-ready
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stdout, "no-new-privileges failed: %v\n", err)
		os.Exit(2)
	}
	if err := Install(); err != nil {
		fmt.Fprintf(os.Stdout, "install failed: %v\n", err)
		os.Exit(2)
	}
	close(run)
	if err := <-result; err != nil {
		fmt.Fprintln(os.Stdout, err)
		os.Exit(3)
	}
	denied := []struct {
		name string
		call func() error
	}{
		{"mount", func() error { return unix.Mount("none", "/", "", 0, "") }},
		{"unshare", func() error { return unix.Unshare(unix.CLONE_NEWNET) }},
		{"ptrace", func() error { return unix.PtraceAttach(os.Getpid()) }},
		{"execve", func() error {
			_, _, errno := unix.RawSyscall(unix.SYS_EXECVE, 0, 0, 0)
			if errno == 0 {
				return nil
			}
			return errno
		}},
	}
	for _, probe := range denied {
		if err := probe.call(); !errors.Is(err, syscall.EPERM) {
			fmt.Fprintf(os.Stdout, "%s error = %v\n", probe.name, err)
			os.Exit(4)
		}
	}
	fmt.Fprintln(os.Stdout, "sandbox-ok")
}

func TestSilenceStandardErrorSuppressesUnrecoveredPanic(t *testing.T) {
	const helperEnvironment = "OPEN_TRESTLE_PANIC_TEST_HELPER"
	if os.Getenv(helperEnvironment) == "1" {
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			os.Exit(10)
		}
		if err := Install(); err != nil {
			os.Exit(11)
		}
		if err := SilenceStandardError(); err != nil {
			os.Exit(12)
		}
		go func() { panic("repository secret") }()
		select {}
	}
	command := exec.Command(sandboxTestExecutable(t), "-test.run=^TestSilenceStandardErrorSuppressesUnrecoveredPanic$")
	command.Env = append(os.Environ(), helperEnvironment+"=1")
	output, err := command.CombinedOutput()
	if err == nil {
		t.Fatal("panic helper exited successfully")
	}
	if len(output) != 0 {
		t.Fatalf("panic reached output: %q", output)
	}
}

func TestUnsupportedImplementationIsSelectedOutsideLinuxAMD64(t *testing.T) {
	source, err := os.ReadFile("sandbox_unsupported.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	if !strings.Contains(text, "//go:build (!linux || !amd64) && !wasip1\n") || !strings.Contains(text, "ErrUnsupported") {
		t.Fatal("unsupported platforms must fail closed")
	}
	// The only other implementation is the wasip1 guest's, where the
	// WebAssembly runtime is the sandbox.
	guest, err := os.ReadFile("sandbox_wasip1.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(guest), "//go:build wasip1\n") {
		t.Fatal("the no-op sandbox must be limited to wasip1")
	}
}
