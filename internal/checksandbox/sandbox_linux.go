//go:build linux

package checksandbox

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Paths inside the Linux sandbox.
const (
	sandboxWork = "/work"
	sandboxHome = "/home/sandbox"
	sandboxTemp = "/tmp"
	sandboxUID  = 1000
)

// childArgument makes this program, re-executed in new namespaces, set up
// the sandbox and run the command; see RunChildIfRequested.
const childArgument = "__open-trestle-check-sandbox"

// childConfig is what the parent sends the sandbox's first process.
type childConfig struct {
	Root     string
	Tree     string
	Dir      string
	Args     []string
	Path     []string
	ReadOnly []string
	Env      []string
	Report   string
	HomeSeed string
	Limits   Limits
}

// childStatus is what the sandbox's first process sends back. Error means
// the command never ran.
type childStatus struct {
	Error    string `json:",omitempty"`
	ExitCode int
	DiskFull bool   `json:",omitempty"`
	Report   []byte `json:",omitempty"`
}

const namespaceFlags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNET |
	syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS | syscall.CLONE_NEWCGROUP

func available() error {
	if reason := userNamespacesDisabled(); reason != "" {
		return unavailable("%s", reason)
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return unavailable("the system call filter supports only amd64 and arm64")
	}
	return nil
}

func run(ctx context.Context, spec Spec) (result Result, err error) {
	if err := available(); err != nil {
		return Result{}, err
	}
	scratch, err := os.MkdirTemp("", scratchFolderPrefix)
	if err != nil {
		return Result{}, unavailable("the scratch folder could not be created")
	}
	defer func() { result.Leftover = leftover(scratch) }()

	paths := sandboxPaths{home: sandboxHome, temporary: sandboxTemp, work: sandboxWork}
	env := append([]string{
		"PATH=" + strings.Join(spec.Path, ":"),
		"HOME=" + sandboxHome, "TMPDIR=" + sandboxTemp, "USER=sandbox", "LANG=C.UTF-8", "TZ=UTC",
	}, paths.env(spec.Env)...)
	limits := spec.Limits
	limits.Processes = processLimit(limits.Processes)
	config := childConfig{
		Root: scratch, Tree: spec.Tree, Dir: spec.Dir, Args: paths.args(spec.Args), Path: spec.Path,
		ReadOnly: spec.ReadOnly, Env: env, Report: spec.Report, HomeSeed: spec.HomeSeed, Limits: limits,
	}

	configRead, configWrite, err := os.Pipe()
	if err != nil {
		return Result{}, unavailable("a pipe could not be created")
	}
	defer configWrite.Close()
	statusRead, statusWrite, err := os.Pipe()
	if err != nil {
		configRead.Close()
		return Result{}, unavailable("a pipe could not be created")
	}
	defer statusRead.Close()

	ctx, cancel := context.WithTimeout(ctx, spec.Limits.Time)
	defer cancel()
	stdout := newCapture(spec.Limits.OutputBytes, cancel)
	stderr := newCapture(spec.Limits.OutputBytes, cancel)
	command := exec.Command("/proc/self/exe", childArgument)
	command.Env = []string{}
	command.Dir = "/"
	command.Stdout, command.Stderr = stdout, stderr
	command.ExtraFiles = []*os.File{configRead, statusWrite}
	command.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  namespaceFlags,
		UidMappings: []syscall.SysProcIDMap{{ContainerID: sandboxUID, HostID: os.Getuid(), Size: 1}},
		GidMappings: []syscall.SysProcIDMap{{ContainerID: sandboxUID, HostID: os.Getgid(), Size: 1}},
		// The sandbox's first process runs as an ordinary user inside the
		// namespaces and keeps only what building the root needs; it
		// clears these before it starts the command.
		AmbientCaps: []uintptr{unix.CAP_SYS_ADMIN, unix.CAP_NET_ADMIN, unix.CAP_SETPCAP},
		Pdeathsig:   syscall.SIGKILL,
		// A new session has no controlling terminal, so nothing in the
		// sandbox can read from or write to the user's terminal.
		Setsid: true,
	}
	started := time.Now()
	err = command.Start()
	configRead.Close()
	statusWrite.Close()
	if err != nil {
		return Result{}, unavailable("unprivileged user namespaces are not available here (%v)", errors.Unwrap(err))
	}
	go func() {
		<-ctx.Done()
		_ = command.Process.Kill()
	}()
	if err := json.NewEncoder(configWrite).Encode(config); err != nil {
		_ = command.Process.Kill()
	}
	configWrite.Close()
	statusBytes, _ := io.ReadAll(io.LimitReader(statusRead, 2*reportLimit))
	_ = command.Wait()
	outputExceeded := stdout.exceededLimit() || stderr.exceededLimit()
	result = Result{
		ExitCode: -1, Stdout: stdout.bytes(), Stderr: stderr.bytes(), Duration: time.Since(started), Work: sandboxWork,
		OutputExceeded: outputExceeded,
		TimedOut:       !outputExceeded && errors.Is(ctx.Err(), context.DeadlineExceeded),
	}
	var status childStatus
	if json.Unmarshal(statusBytes, &status) != nil {
		if result.TimedOut || result.OutputExceeded {
			return result, nil
		}
		if ctx.Err() != nil {
			return Result{}, unavailable("the run was cancelled")
		}
		return Result{}, unavailable("the sandbox stopped before it reported a result")
	}
	if status.Error != "" {
		return Result{}, unavailable("%s", status.Error)
	}
	result.ExitCode, result.DiskExceeded, result.Report = status.ExitCode, status.DiskFull, status.Report
	return result, nil
}

// userNamespacesDisabled names the setting that turns unprivileged user
// namespaces off, or returns "" when none does.
func userNamespacesDisabled() string {
	read := func(path string) string {
		value, _ := os.ReadFile(path)
		return strings.TrimSpace(string(value))
	}
	if read("/proc/sys/kernel/unprivileged_userns_clone") == "0" {
		return "unprivileged user namespaces are turned off (kernel.unprivileged_userns_clone is 0)"
	}
	if read("/proc/sys/user/max_user_namespaces") == "0" {
		return "unprivileged user namespaces are turned off (user.max_user_namespaces is 0)"
	}
	return ""
}

// restrictedHint explains a setup failure when AppArmor restricts
// unprivileged user namespaces, as recent Ubuntu releases do by default.
func restrictedHint() string {
	value, _ := os.ReadFile("/proc/sys/kernel/apparmor_restrict_unprivileged_userns")
	if strings.TrimSpace(string(value)) == "1" {
		return "; AppArmor restricts unprivileged user namespaces here (kernel.apparmor_restrict_unprivileged_userns is 1)"
	}
	return ""
}
