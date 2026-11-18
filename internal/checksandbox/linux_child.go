//go:build linux

package checksandbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"syscall"

	"golang.org/x/sys/unix"
)

// RunChildIfRequested runs the sandbox's first process and exits when this
// program was started as one; otherwise it returns at once. Programs that
// use Run call it first thing in main (and in TestMain).
func RunChildIfRequested() {
	if len(os.Args) == 2 && os.Args[1] == childArgument && os.Getpid() == 1 {
		os.Exit(child())
	}
}

// child runs as process 1 of new user, mount, PID, network, IPC, UTS and
// cgroup namespaces, as an unprivileged user that holds capabilities only
// inside them. It builds the private root, drops every way out, runs the
// command, reaps every process and reports.
func child() int {
	configFile, statusFile := os.NewFile(3, "config"), os.NewFile(4, "status")
	var config childConfig
	if err := json.NewDecoder(io.LimitReader(configFile, 1<<20)).Decode(&config); err != nil {
		return 1
	}
	configFile.Close()
	status := runInSandbox(config)
	if json.NewEncoder(statusFile).Encode(status) != nil {
		return 1
	}
	return 0
}

func runInSandbox(config childConfig) childStatus {
	// Capabilities, no_new_privs and the filter belong to a thread; the
	// command is started from this one.
	runtime.LockOSThread()
	if err := buildRoot(config); err != nil {
		return childStatus{Error: "the sandbox's private root could not be built: " + err.Error() + restrictedHint()}
	}
	if err := isolateHost(); err != nil {
		return childStatus{Error: err.Error()}
	}
	if err := setLimits(config.Limits); err != nil {
		return childStatus{Error: "the resource limits could not be set: " + err.Error()}
	}
	if err := lockDown(); err != nil {
		return childStatus{Error: "the system call filter could not be installed: " + err.Error()}
	}
	program, err := findProgram(config.Args[0], config.Path)
	if err != nil {
		return childStatus{Error: err.Error()}
	}
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		return childStatus{Error: "the null device is missing"}
	}
	process, err := os.StartProcess(program, config.Args, &os.ProcAttr{
		Dir:   filepath.Join(sandboxWork, config.Dir),
		Env:   config.Env,
		Files: []*os.File{devNull, os.Stdout, os.Stderr},
	})
	devNull.Close()
	if err != nil {
		return childStatus{Error: fmt.Sprintf("%s could not be started: %v", config.Args[0], errors.Unwrap(err))}
	}
	status := childStatus{ExitCode: reapAll(process.Pid)}
	if status.ExitCode == -int(syscall.SIGXFSZ) || scratchFull() {
		status.DiskFull = true
	}
	if status.ExitCode < 0 {
		status.ExitCode = -1
	}
	if config.Report != "" {
		status.Report = readReport(filepath.Join(sandboxTemp, config.Report))
	}
	return status
}

// reapAll waits for the command, then kills and reaps whatever it left
// behind. It returns the command's exit status, or the negated signal that
// ended it.
func reapAll(pid int) int {
	code := -1
	for {
		var wait syscall.WaitStatus
		got, err := syscall.Wait4(-1, &wait, 0, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return code
		}
		if got != pid {
			continue
		}
		switch {
		case wait.Exited():
			code = wait.ExitStatus()
		case wait.Signaled():
			code = -int(wait.Signal())
		}
		// Process 1 is never signalled by kill(-1).
		_ = syscall.Kill(-1, syscall.SIGKILL)
	}
}

// scratchFull reports whether less than 1 MiB of the scratch is free.
func scratchFull() bool {
	var stat unix.Statfs_t
	return unix.Statfs("/", &stat) == nil && stat.Bavail*uint64(stat.Bsize) < 1<<20
}

func readReport(path string) []byte {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, reportLimit+1))
	if err != nil || len(data) > reportLimit {
		return nil
	}
	return data
}

// isolateHost names the host and brings up the namespace's own loopback
// interface, which reaches nothing outside the sandbox.
func isolateHost() error {
	if err := unix.Sethostname([]byte("sandbox")); err != nil {
		return errors.New("the host name could not be set")
	}
	socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return errors.New("the loopback interface could not be configured")
	}
	defer unix.Close(socket)
	request, err := unix.NewIfreq("lo")
	if err == nil {
		err = unix.IoctlIfreq(socket, unix.SIOCGIFFLAGS, request)
	}
	if err == nil {
		request.SetUint16(request.Uint16() | unix.IFF_UP)
		err = unix.IoctlIfreq(socket, unix.SIOCSIFFLAGS, request)
	}
	if err != nil {
		return errors.New("the loopback interface could not be configured")
	}
	return nil
}

func setLimits(limits Limits) error {
	for _, limit := range []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_NPROC, uint64(limits.Processes)},
		{unix.RLIMIT_DATA, limits.MemoryBytes},
		{unix.RLIMIT_FSIZE, uint64(limits.DiskBytes)},
		{unix.RLIMIT_NOFILE, 4096},
		{unix.RLIMIT_CORE, 0},
	} {
		var current unix.Rlimit
		if err := unix.Getrlimit(limit.resource, &current); err != nil {
			return err
		}
		value := min(limit.value, current.Max)
		if err := unix.Setrlimit(limit.resource, &unix.Rlimit{Cur: value, Max: value}); err != nil {
			return err
		}
	}
	return nil
}

// lockDown clears this thread's ambient capabilities and capability
// bounding set, so the command starts with no capability even inside the
// namespaces, sets no_new_privs and installs the system call filter on
// every thread.
func lockDown() error {
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return err
	}
	for capability := 0; ; capability++ {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0); err == unix.EINVAL {
			break
		} else if err != nil {
			return err
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	return installFilter()
}
