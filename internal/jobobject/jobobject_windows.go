package jobobject

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Limits are optional limits for the whole job; zero leaves one unset.
type Limits struct {
	ActiveProcesses uint32
	MemoryBytes     uintptr
}

// Create returns a new job object with kill-on-close, the given limits,
// and no error dialog for a crashing process.
func Create(limits Limits) (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	var information windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	flags := uint32(windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | windows.JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION)
	if limits.ActiveProcesses > 0 {
		flags |= windows.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		information.BasicLimitInformation.ActiveProcessLimit = limits.ActiveProcesses
	}
	if limits.MemoryBytes > 0 {
		flags |= windows.JOB_OBJECT_LIMIT_JOB_MEMORY
		information.JobMemoryLimit = limits.MemoryBytes
	}
	information.BasicLimitInformation.LimitFlags = flags
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&information)), uint32(unsafe.Sizeof(information))); err != nil {
		_ = windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}
