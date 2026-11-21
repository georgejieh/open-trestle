package checksandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const sandboxExec = "/usr/bin/sandbox-exec"

func available() error {
	if _, err := os.Stat(sandboxExec); err != nil {
		return unavailable("sandbox-exec is missing")
	}
	return nil
}

// run starts the command under sandbox-exec with a deny-by-default profile
// in its own process group. macOS has no unprivileged per-tree process or
// memory limit, so those rely on the system's per-user limits. A process
// that starts a new session leaves the group, so the kill at the end of
// the run misses it: it stays inside the profile but has no time bound.
// File size, open files, time, output and scratch size are bounded here.
func run(ctx context.Context, spec Spec) (result Result, err error) {
	if err := available(); err != nil {
		return Result{}, err
	}
	created, err := os.MkdirTemp("", scratchFolderPrefix)
	if err != nil {
		return Result{}, unavailable("the scratch folder could not be created")
	}
	defer func() { result.Leftover = leftover(created) }()
	// The profile matches resolved paths, and the temporary folder is
	// usually reached through the /var link.
	scratch, err := filepath.EvalSymlinks(created)
	if err != nil {
		return Result{}, unavailable("the scratch folder could not be resolved")
	}
	work, home, temporary := filepath.Join(scratch, "work"), filepath.Join(scratch, "home"), filepath.Join(scratch, "tmp")
	for _, folder := range []string{work, home, temporary} {
		if err := os.Mkdir(folder, 0o700); err != nil {
			return Result{}, unavailable("the scratch folder could not be prepared")
		}
	}
	if err := copyTree(spec.Tree, work, spec.Limits.DiskBytes); err != nil {
		return Result{}, unavailable("the tree could not be copied into the scratch (%v)", err)
	}
	if spec.HomeSeed != "" {
		if err := copyTree(spec.HomeSeed, home, spec.Limits.DiskBytes); err != nil {
			return Result{}, unavailable("the home seed could not be copied into the scratch (%v)", err)
		}
	}
	readOnly := make([]string, 0, len(spec.ReadOnly))
	for _, path := range spec.ReadOnly {
		if resolved, err := filepath.EvalSymlinks(path); err == nil {
			readOnly = append(readOnly, resolved)
		}
	}
	program, err := findProgram(spec.Args[0], spec.Path)
	if err != nil {
		return Result{}, unavailable("%s", err.Error())
	}

	ctx, cancel := context.WithTimeout(ctx, spec.Limits.Time)
	defer cancel()
	stdout := newCapture(spec.Limits.OutputBytes, cancel)
	stderr := newCapture(spec.Limits.OutputBytes, cancel)
	paths := sandboxPaths{home: home, temporary: temporary, work: work}
	limits := "ulimit -n 4096 && ulimit -c 0 && ulimit -f " + strconv.FormatInt(spec.Limits.DiskBytes/512, 10) + ` && exec "$@"`
	profile := seatbeltProfile(scratch, []string{work, home, temporary}, readOnly)
	command := exec.Command(sandboxExec, append([]string{"-p", profile, "/bin/sh", "-c", limits, "sh", program}, paths.args(spec.Args)[1:]...)...)
	command.Dir = filepath.Join(work, spec.Dir)
	command.Env = append([]string{
		"PATH=" + strings.Join(append(append([]string{}, spec.Path...), "/usr/bin", "/bin", "/usr/sbin", "/sbin"), ":"),
		"HOME=" + home, "TMPDIR=" + temporary, "USER=sandbox", "LANG=en_US.UTF-8", "TZ=UTC",
	}, paths.env(spec.Env)...)
	command.Stdout, command.Stderr = stdout, stderr
	// A new session has no controlling terminal and leads its own process
	// group, which the kill below targets.
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// A descendant that left the process group with setsid survives the
	// group kill, still inside the sandbox; it must not keep the run open
	// by holding the output pipes.
	command.WaitDelay = time.Second
	meter := newScratchMeter([]string{scratch}, spec.Limits.DiskBytes)
	started := time.Now()
	if err := command.Start(); err != nil {
		return Result{}, unavailable("%s could not be started (%v)", spec.Args[0], err)
	}
	group := command.Process.Pid
	go func() {
		<-ctx.Done()
		_ = syscall.Kill(-group, syscall.SIGKILL)
	}()
	diskOver := watchDisk(ctx, meter, cancel)
	err = command.Wait()
	_ = syscall.Kill(-group, syscall.SIGKILL)
	outputExceeded := stdout.exceededLimit() || stderr.exceededLimit()
	result = Result{
		ExitCode: -1, Stdout: stdout.bytes(), Stderr: stderr.bytes(), Duration: time.Since(started),
		OutputExceeded: outputExceeded, DiskExceeded: diskOver.Load() || meter.exceeded(),
	}
	var exit *exec.ExitError
	if err == nil {
		result.ExitCode = 0
	} else if errors.As(err, &exit) && exit.Exited() {
		result.ExitCode = exit.ExitCode()
	}
	if status, ok := command.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() && status.Signal() == syscall.SIGXFSZ {
		result.DiskExceeded = true
	}
	result.TimedOut = !outputExceeded && !result.DiskExceeded && errors.Is(ctx.Err(), context.DeadlineExceeded)
	if spec.Report != "" {
		result.Report = readRegularFile(filepath.Join(temporary, spec.Report))
	}
	return result, nil
}
