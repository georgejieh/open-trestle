//go:build windows

package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
)

const (
	createSuspended                        = 0x00000004
	createNoWindow                         = 0x08000000
	processSetQuota                        = 0x0100
	processSuspendResume                   = 0x0800
	processQueryLimitedInformation         = 0x1000
	fileReadAttributes                     = 0x0080
	maximumLongPath                        = 32768
	jobObjectExtendedLimitInformationClass = 9
	jobObjectLimitKillOnJobClose           = 0x00002000
)

// kernel32 and ntdll are known DLLs, which Windows always loads from the
// system directory.
var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procTerminateJobObject       = kernel32.NewProc("TerminateJobObject")
	procQueryFullProcessImage    = kernel32.NewProc("QueryFullProcessImageNameW")
	ntdll                        = syscall.NewLazyDLL("ntdll.dll")
	procNtResumeProcess          = ntdll.NewProc("NtResumeProcess")

	errJobObject   = errors.New("secret scan helper job object could not be set up")
	errHelperImage = errors.New("secret scan helper process does not run the verified file")
)

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectExtendedLimitInformation struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// openVerifiedHelper opens the helper with a share mode that allows only
// other readers, so the file cannot be written, renamed or deleted while the
// handle is open, hashes it through that handle and keeps the handle open
// until the helper has started. Reparse points are refused. The path must
// end in .exe, so os/exec runs exactly that path instead of trying other
// extensions. As on Unix, the file must also be owned by the current user,
// LocalSystem, Administrators or TrustedInstaller, and no other principal
// may write it, delete it or change its security; the digest already pins
// its content, so this is defence in depth.
func openVerifiedHelper(path string, expectedDigest string) (verifiedHelper, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !strings.EqualFold(filepath.Ext(path), ".exe") || !validDigest(expectedDigest) {
		return verifiedHelper{}, ErrHelperUntrusted
	}
	name, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return verifiedHelper{}, ErrHelperUntrusted
	}
	handle, err := syscall.CreateFile(name, syscall.GENERIC_READ, syscall.FILE_SHARE_READ, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return verifiedHelper{}, ErrHelperUntrusted
	}
	var information syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(handle, &information); err != nil || information.FileAttributes&(syscall.FILE_ATTRIBUTE_DIRECTORY|syscall.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		ownersonly.CheckHandle(handle, ownersonly.Rule{Owner: ownersonly.OwnerTrusted, Others: ownersonly.OthersRead}) != nil {
		_ = syscall.CloseHandle(handle)
		return verifiedHelper{}, ErrHelperUntrusted
	}
	file := os.NewFile(uintptr(handle), path)
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil || hex.EncodeToString(digest.Sum(nil)) != expectedDigest {
		_ = file.Close()
		return verifiedHelper{}, ErrHelperUntrusted
	}
	return verifiedHelper{file: file, execPath: path, displayPath: path, identity: identityOf(information)}, nil
}

// fileIdentity is the volume serial number and file index of a file, which
// identify it whatever path reaches it.
type fileIdentity struct {
	volume    uint32
	indexHigh uint32
	indexLow  uint32
}

func identityOf(information syscall.ByHandleFileInformation) fileIdentity {
	return fileIdentity{volume: information.VolumeSerialNumber, indexHigh: information.FileIndexHigh, indexLow: information.FileIndexLow}
}

// imageIdentity returns the identity of the executable file that process
// runs.
func imageIdentity(process syscall.Handle) (fileIdentity, error) {
	name := make([]uint16, maximumLongPath)
	size := uint32(len(name))
	if ok, _, _ := procQueryFullProcessImage.Call(uintptr(process), 0, uintptr(unsafe.Pointer(&name[0])), uintptr(unsafe.Pointer(&size))); ok == 0 || size == 0 || size >= uint32(len(name)) {
		return fileIdentity{}, errHelperImage
	}
	file, err := syscall.CreateFile(&name[0], fileReadAttributes, syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE, nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return fileIdentity{}, errHelperImage
	}
	defer syscall.CloseHandle(file)
	var information syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(file, &information); err != nil {
		return fileIdentity{}, errHelperImage
	}
	return identityOf(information), nil
}

// openCacheDirectory checks the helper's cache directory and returns the path
// to start the helper in, as the Linux version does, with the owner and DACL
// of each entry in place of its owner and mode bits; see package ownersonly.
// Symbolic links above the directory are resolved once; a junction or other
// reparse point on the resolved path is refused, since filepath.EvalSymlinks
// does not resolve junctions. Every directory above the cache must be owned
// by the current user, LocalSystem, Administrators or TrustedInstaller and
// may let other principals at most read it and add entries. The cache itself
// must be owned by the current user, must grant other principals no access
// beyond reading its attributes and DACL, also through ACEs that entries
// created inside it would inherit, and every entry already inside it must be
// owned by a trusted identity and grant others nothing. The helper requires
// the same of its working directory.
//
// With create, a missing cache is first created owner-only; nothing above it
// is ever created. Another principal that may add entries to an empty parent
// could turn the parent into a junction between the check and the creation,
// so the cache must afterwards resolve to the expected path; once the cache
// exists the parent is no longer empty and cannot become a junction.
func openCacheDirectory(path string, create bool) (string, error) {
	if !validAbsolutePath(path) || filepath.Dir(path) == path {
		return "", ErrSessionConfig
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || !filepath.IsAbs(parent) || ownersonly.CheckAncestors(parent) != nil {
		return "", ErrCacheUntrusted
	}
	directory := filepath.Join(parent, filepath.Base(path))
	if create {
		if err := ownersonly.Mkdir(directory); err != nil && !errors.Is(err, fs.ErrExist) {
			return "", ErrCacheUntrusted
		}
	}
	if ownersonly.CheckPrivateDirectoryTree(directory) != nil {
		return "", ErrCacheUntrusted
	}
	return directory, nil
}

// configureHelperCommand starts the helper suspended, so it runs no code
// before attach has placed it in its job object. The os/exec package adds
// SYSTEMROOT to the otherwise empty environment on Windows.
func configureHelperCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: createSuspended | createNoWindow}
}

// processGroup is a job object that kills every process in it when it is
// terminated or when its last handle closes, including when the parent dies.
type processGroup struct {
	job     syscall.Handle
	process syscall.Handle
}

// attach requires that the suspended helper runs the verified file, then
// places it in a new job object and resumes it.
func (group *processGroup) attach(process *os.Process, verified fileIdentity) error {
	job, _, _ := procCreateJobObjectW.Call(0, 0)
	if job == 0 {
		return errJobObject
	}
	group.job = syscall.Handle(job)
	var limits jobObjectExtendedLimitInformation
	limits.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose
	if ok, _, _ := procSetInformationJobObject.Call(job, jobObjectExtendedLimitInformationClass, uintptr(unsafe.Pointer(&limits)), unsafe.Sizeof(limits)); ok == 0 {
		return errJobObject
	}
	handle, err := syscall.OpenProcess(processSetQuota|syscall.PROCESS_TERMINATE|syscall.SYNCHRONIZE|processSuspendResume|processQueryLimitedInformation, false, uint32(process.Pid))
	if err != nil {
		return errJobObject
	}
	group.process = handle
	if image, err := imageIdentity(handle); err != nil || image != verified {
		return errHelperImage
	}
	if ok, _, _ := procAssignProcessToJobObject.Call(job, uintptr(handle)); ok == 0 {
		return errJobObject
	}
	if status, _, _ := procNtResumeProcess.Call(uintptr(handle)); status != 0 {
		return errJobObject
	}
	return nil
}

// waitExit blocks until the helper has exited. Windows has no reaping, and
// the job handle stays valid regardless of process ID reuse.
func (group *processGroup) waitExit() {
	if group.process != 0 {
		_, _ = syscall.WaitForSingleObject(group.process, syscall.INFINITE)
	}
}

func (group *processGroup) kill(process *os.Process) {
	if group.job != 0 {
		_, _, _ = procTerminateJobObject.Call(uintptr(group.job), 1)
	}
	_ = process.Kill()
}

func (group *processGroup) release() {
	if group.job != 0 {
		_ = syscall.CloseHandle(group.job)
		group.job = 0
	}
	if group.process != 0 {
		_ = syscall.CloseHandle(group.process)
		group.process = 0
	}
}
