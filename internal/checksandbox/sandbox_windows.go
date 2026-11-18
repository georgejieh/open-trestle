package checksandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/georgejieh/open-trestle/internal/jobobject"
)

// available is nil: AppContainers and job objects exist on every supported
// Windows version.
func available() error { return nil }

// run starts the command in a fresh AppContainer with no capability but
// the toolchain one, so it has no network and reaches only its scratch and
// the folders granted to every sandbox, inside a job object that bounds and
// kills the whole tree.
func run(ctx context.Context, spec Spec) (Result, error) {
	container, err := newAppContainer()
	if err != nil {
		return Result{}, unavailable("an AppContainer could not be created (%v)", err)
	}
	defer container.close()
	for _, path := range spec.ReadOnly {
		if err := ensureReadable(path, container.capability); err != nil {
			return Result{}, unavailable("the sandbox could not be given read access to %s (%v)", path, err)
		}
	}
	scratch, err := os.MkdirTemp("", "open-trestle-check-")
	if err != nil {
		return Result{}, unavailable("the scratch folder could not be created")
	}
	defer os.RemoveAll(scratch)
	if err := grant(scratch, container.sid, windows.GENERIC_ALL); err != nil {
		return Result{}, unavailable("the scratch folder could not be shared with the sandbox (%v)", err)
	}
	// Windows gives an AppContainer process the temporary folder of its
	// package inside LOCALAPPDATA, whatever TEMP says.
	work, home := filepath.Join(scratch, "work"), filepath.Join(scratch, "home")
	temporary := filepath.Join(home, "AppData", "Local", "Packages", strings.ToLower(container.name), "AC", "Temp")
	for _, folder := range []string{work, filepath.Join(home, "AppData", "Roaming"), temporary} {
		if err := os.MkdirAll(folder, 0o755); err != nil {
			return Result{}, unavailable("the scratch folder could not be prepared")
		}
	}
	if err := copyTree(spec.Tree, work, spec.Limits.DiskBytes); err != nil {
		return Result{}, unavailable("the tree could not be copied into the scratch (%v)", err)
	}
	paths := sandboxPaths{home: home, temporary: temporary, work: work}
	application, commandLine, err := commandFor(paths.args(spec.Args), spec.Path)
	if err != nil {
		return Result{}, err
	}
	environment := environmentFor(spec, paths)
	return runContained(ctx, spec, container, application, commandLine, environment, filepath.Join(work, spec.Dir), scratch, temporary)
}

func runContained(ctx context.Context, spec Spec, container *appContainer, application, commandLine string, environment []uint16, directory, scratch, temporary string) (Result, error) {
	job, err := jobobject.Create(jobobject.Limits{ActiveProcesses: uint32(spec.Limits.Processes), MemoryBytes: uintptr(spec.Limits.MemoryBytes)})
	if err != nil {
		return Result{}, unavailable("a job object could not be created (%v)", err)
	}
	defer windows.CloseHandle(job)
	restrictUserInterface(job)

	ctx, cancel := context.WithTimeout(ctx, spec.Limits.Time)
	defer cancel()
	stdout, stdoutWrite, err := inheritablePipe()
	if err != nil {
		return Result{}, unavailable("a pipe could not be created")
	}
	defer stdout.Close()
	stderr, stderrWrite, err := inheritablePipe()
	if err != nil {
		windows.CloseHandle(stdoutWrite)
		return Result{}, unavailable("a pipe could not be created")
	}
	defer stderr.Close()
	null, err := inheritableNull()
	if err != nil {
		windows.CloseHandle(stdoutWrite)
		windows.CloseHandle(stderrWrite)
		return Result{}, unavailable("the null device could not be opened")
	}
	information, err := container.startSuspended(application, commandLine, environment, directory, []windows.Handle{null, stdoutWrite, stderrWrite})
	windows.CloseHandle(null)
	windows.CloseHandle(stdoutWrite)
	windows.CloseHandle(stderrWrite)
	if err != nil {
		return Result{}, unavailable("%s could not be started in the sandbox (%v)", spec.Args[0], err)
	}
	defer windows.CloseHandle(information.Process)
	defer windows.CloseHandle(information.Thread)
	terminate := func() { _ = windows.TerminateJobObject(job, 1) }
	if err := windows.AssignProcessToJobObject(job, information.Process); err != nil {
		_ = windows.TerminateProcess(information.Process, 1)
		return Result{}, unavailable("the command could not be placed in its job object (%v)", err)
	}
	started := time.Now()
	if _, err := windows.ResumeThread(information.Thread); err != nil {
		terminate()
		return Result{}, unavailable("the command could not be resumed (%v)", err)
	}

	stdoutCapture := newCapture(spec.Limits.OutputBytes, cancel)
	stderrCapture := newCapture(spec.Limits.OutputBytes, cancel)
	var readers sync.WaitGroup
	for _, pair := range []struct {
		from *os.File
		to   io.Writer
	}{{stdout, stdoutCapture}, {stderr, stderrCapture}} {
		readers.Add(1)
		go func() {
			defer readers.Done()
			_, _ = io.Copy(pair.to, pair.from)
		}()
	}
	writable := []string{scratch, container.folder}
	diskOver := watchDisk(ctx, writable, spec.Limits.DiskBytes, cancel)
	exited := make(chan struct{})
	go func() {
		_, _ = windows.WaitForSingleObject(information.Process, windows.INFINITE)
		close(exited)
	}()
	select {
	case <-exited:
	case <-ctx.Done():
	}
	// Whatever the command left running dies with it.
	terminate()
	<-exited
	readers.Wait()

	var code uint32
	_ = windows.GetExitCodeProcess(information.Process, &code)
	outputExceeded := stdoutCapture.exceededLimit() || stderrCapture.exceededLimit()
	result := Result{
		ExitCode: int(int32(code)), Stdout: stdoutCapture.bytes(), Stderr: stderrCapture.bytes(),
		Duration: time.Since(started), OutputExceeded: outputExceeded, DiskExceeded: diskOver.Load(),
	}
	result.TimedOut = !outputExceeded && !result.DiskExceeded && errors.Is(ctx.Err(), context.DeadlineExceeded)
	if !result.DiskExceeded && foldersSize(writable, spec.Limits.DiskBytes) > spec.Limits.DiskBytes {
		result.DiskExceeded = true
	}
	if spec.Report != "" {
		result.Report = readRegularFile(filepath.Join(temporary, spec.Report))
	}
	if !result.Succeeded() && deniedNullDevice(result) && nullDeviceClosed() {
		return Result{}, unavailable("%s needs the NUL device, which grants nothing to sandboxed (AppContainer) processes on this system; only an administrator can change that", spec.Args[0])
	}
	return result, nil
}

// deniedNullDevice reports whether the output shows a program failing to
// open NUL, as Go, Python and Git report it.
func deniedNullDevice(result Result) bool {
	output := strings.ToLower(string(result.Stderr) + string(result.Stdout))
	for _, text := range []string{"open nul: access is denied", "permission denied: 'nul'", "nul: access is denied", "nul: permission denied"} {
		if strings.Contains(output, text) {
			return true
		}
	}
	return false
}

// nullDeviceClosed reports whether the NUL device grants nothing to
// application packages; only an administrator can change its DACL.
func nullDeviceClosed() bool {
	name, err := windows.UTF16PtrFromString(`\\.\NUL`)
	if err != nil {
		return true
	}
	device, err := windows.CreateFile(name, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, nil, windows.OPEN_EXISTING, 0, 0)
	if err != nil {
		return true
	}
	defer windows.CloseHandle(device)
	descriptor, err := windows.GetSecurityInfo(device, windows.SE_KERNEL_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return true
	}
	dacl, _, err := descriptor.DACL()
	everyPackage, sidErr := windows.StringToSid(allApplicationPackages)
	return err != nil || sidErr != nil || !grantsRead(dacl, everyPackage)
}

// restrictUserInterface keeps the tree away from the clipboard, global
// atoms, other processes' window handles and system settings.
func restrictUserInterface(job windows.Handle) {
	restrictions := windows.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: windows.JOB_OBJECT_UILIMIT_DESKTOP |
		windows.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS | windows.JOB_OBJECT_UILIMIT_EXITWINDOWS | windows.JOB_OBJECT_UILIMIT_GLOBALATOMS |
		windows.JOB_OBJECT_UILIMIT_HANDLES | windows.JOB_OBJECT_UILIMIT_READCLIPBOARD | windows.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
		windows.JOB_OBJECT_UILIMIT_WRITECLIPBOARD}
	_, _ = windows.SetInformationJobObject(job, windows.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&restrictions)), uint32(unsafe.Sizeof(restrictions)))
}

// inheritablePipe returns the parent's read end and an inheritable write
// end.
func inheritablePipe() (*os.File, windows.Handle, error) {
	var read, write windows.Handle
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	if err := windows.CreatePipe(&read, &write, &attributes, 0); err != nil {
		return nil, 0, err
	}
	if err := windows.SetHandleInformation(read, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		windows.CloseHandle(read)
		windows.CloseHandle(write)
		return nil, 0, err
	}
	return os.NewFile(uintptr(read), "pipe"), write, nil
}

func inheritableNull() (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString("NUL")
	if err != nil {
		return 0, err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), InheritHandle: 1}
	return windows.CreateFile(name, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, &attributes, windows.OPEN_EXISTING, 0, 0)
}

// commandFor finds the program in path and returns the application to run
// and its command line. Batch files run through cmd.exe.
func commandFor(args []string, path []string) (string, string, error) {
	program, err := findWindowsProgram(args[0], path)
	if err != nil {
		return "", "", err
	}
	line := windows.ComposeCommandLine(append([]string{program}, args[1:]...))
	if extension := strings.ToLower(filepath.Ext(program)); extension == ".cmd" || extension == ".bat" {
		shell := filepath.Join(systemRoot(), "System32", "cmd.exe")
		return shell, windows.EscapeArg(shell) + ` /d /s /c "` + line + `"`, nil
	}
	return program, line, nil
}

func findWindowsProgram(name string, path []string) (string, error) {
	var candidates []string
	names := []string{name}
	if filepath.Ext(name) == "" {
		names = []string{name + ".exe", name + ".cmd", name + ".bat"}
	}
	if filepath.IsAbs(name) {
		candidates = names
	} else {
		for _, directory := range path {
			for _, each := range names {
				candidates = append(candidates, filepath.Join(directory, each))
			}
		}
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.Mode().IsRegular() {
			return candidate, nil
		}
	}
	return "", unavailable("%s is not installed in a place the sandbox can see", name)
}

func systemRoot() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return root
	}
	return `C:\Windows`
}

// environmentFor builds the sandbox's environment block: the system
// variables Windows programs need, a private home and temporary folder, the
// search path and the spec's own entries. Nothing else of the parent's
// environment is passed.
func environmentFor(spec Spec, paths sandboxPaths) []uint16 {
	root, home, temporary := systemRoot(), paths.home, paths.temporary
	values := map[string]string{
		"SystemRoot": root, "windir": root, "SystemDrive": filepath.VolumeName(root),
		"ComSpec": filepath.Join(root, "System32", "cmd.exe"), "PATHEXT": ".COM;.EXE;.BAT;.CMD",
		"OS": "Windows_NT", "PROCESSOR_ARCHITECTURE": os.Getenv("PROCESSOR_ARCHITECTURE"),
		"NUMBER_OF_PROCESSORS": os.Getenv("NUMBER_OF_PROCESSORS"),
		"PATH":                 strings.Join(append(append([]string{}, spec.Path...), filepath.Join(root, "System32"), root), ";"),
		"USERPROFILE":          home, "HOME": home, "APPDATA": filepath.Join(home, "AppData", "Roaming"),
		"LOCALAPPDATA": filepath.Join(home, "AppData", "Local"), "TEMP": temporary, "TMP": temporary, "TMPDIR": temporary,
		"USERNAME": "sandbox", "TZ": "UTC",
	}
	for _, entry := range paths.env(spec.Env) {
		key, value, _ := strings.Cut(entry, "=")
		values[key] = value
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return strings.ToUpper(keys[i]) < strings.ToUpper(keys[j]) })
	var block []uint16
	for _, key := range keys {
		entry, err := windows.UTF16FromString(fmt.Sprintf("%s=%s", key, values[key]))
		if err != nil {
			continue
		}
		block = append(block, entry...)
	}
	return append(block, 0)
}
