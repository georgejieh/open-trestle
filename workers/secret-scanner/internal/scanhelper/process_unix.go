//go:build unix

package scanhelper

import (
	"errors"
	"os"
	"runtime"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

var errDescriptorList = errors.New("open descriptors cannot be listed")

// CloseInheritedDescriptors closes every open descriptor above standard error
// that is not close-on-exec. The Go runtime opens all of its own descriptors
// close-on-exec, so a descriptor without the flag was inherited: os/exec in
// the parent passes only standard input, output and error, but a descriptor
// that the parent itself inherited without close-on-exec reaches the helper
// too. The helper keeps none of them. It fails when the open descriptors
// cannot be listed.
func CloseInheritedDescriptors() error {
	var listing string
	switch runtime.GOOS {
	case "linux":
		listing = "/proc/self/fd"
	case "darwin":
		listing = "/dev/fd"
	default:
		return errDescriptorList
	}
	directory, err := os.Open(listing)
	if err != nil {
		return errDescriptorList
	}
	names, err := directory.Readdirnames(-1)
	if closeErr := directory.Close(); err != nil || closeErr != nil {
		return errDescriptorList
	}
	for _, name := range names {
		descriptor, err := strconv.Atoi(name)
		if err != nil || descriptor < 0 {
			return errDescriptorList
		}
		if descriptor <= 2 {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0)
		if errors.Is(err, unix.EBADF) {
			// The listing's own descriptor, closed above.
			continue
		}
		if err != nil {
			return err
		}
		if flags&unix.FD_CLOEXEC == 0 {
			if err := unix.Close(descriptor); err != nil {
				return err
			}
		}
	}
	return nil
}

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

// WatchInputHangup ends the process with ExitInternal as soon as descriptor,
// the read end of a pipe, hangs up because no process holds its write end
// any more, until stop is called. poll reports the hangup without reading,
// so no request byte is consumed. A hangup that poll reports after stop was
// called is ignored, so the parent closing the pipe after the work that the
// watch covered is not mistaken for its death.
func WatchInputHangup(descriptor int) (stop func()) {
	done := make(chan struct{})
	go func() {
		// No event is requested: poll always reports a hangup or an error.
		descriptors := []unix.PollFd{{Fd: int32(descriptor)}}
		for {
			select {
			case <-done:
				return
			default:
			}
			descriptors[0].Revents = 0
			count, err := unix.Poll(descriptors, int(hangupPollInterval/time.Millisecond))
			if errors.Is(err, unix.EINTR) || err == nil && count == 0 {
				continue
			}
			select {
			case <-done:
				return
			default:
				os.Exit(ExitInternal)
			}
		}
	}()
	return func() { close(done) }
}

// ExitWithParent ends the process with ExitInternal once its parent is gone,
// that is once the parent process ID changes. Linux parents also set a
// parent-death signal; macOS has none. A parent that died before the first
// sample is not seen here; during a scan WatchInputHangup sees it.
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
