//go:build unix

package scanhelper

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// IsolateStandardStreams moves standard output to a new close-on-exec
// descriptor, which it returns for the protocol, and points descriptors 1
// and 2 at the null device. Anything else that writes to standard output or
// error afterwards, such as libre2 through go-re2 or the Go runtime on a
// crash, reaches the null device and can neither corrupt a response frame
// nor reach the parent.
func IsolateStandardStreams() (*os.File, error) {
	protocolDescriptor, err := unix.FcntlInt(1, unix.F_DUPFD_CLOEXEC, 3)
	if err != nil {
		return nil, err
	}
	null, err := unix.Open(os.DevNull, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = unix.Close(protocolDescriptor)
		return nil, err
	}
	for _, descriptor := range []int{1, 2} {
		if descriptor == null {
			continue
		}
		if err := duplicateOnto(null, descriptor); err != nil {
			_ = unix.Close(protocolDescriptor)
			return nil, err
		}
	}
	// A null descriptor at 1 or 2 means that descriptor was closed at start
	// and is now the null device; it stays open.
	if null > 2 {
		_ = unix.Close(null)
	}
	return os.NewFile(uintptr(protocolDescriptor), "protocol"), nil
}

// LimitResources sets the core file size limit to zero, so a crash cannot
// write guest memory, which holds source text, to disk, and the descriptor
// limit to MaximumDescriptors. Both hard limits are lowered too, so they
// cannot be raised again. The parent cannot set a child's limits through
// os/exec, so the helper sets its own.
func LimitResources() error {
	if err := unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0}); err != nil {
		return err
	}
	return unix.Setrlimit(unix.RLIMIT_NOFILE, &unix.Rlimit{Cur: MaximumDescriptors, Max: MaximumDescriptors})
}

// ExitWithParent ends the process with ExitInternal once its parent is gone,
// that is once the parent process ID changes. Linux parents also set a
// parent-death signal; macOS has none, so this is the only stop there.
func ExitWithParent() {
	parent := unix.Getppid()
	go func() {
		for {
			time.Sleep(parentPollInterval)
			if unix.Getppid() != parent {
				os.Exit(ExitInternal)
			}
		}
	}()
}
