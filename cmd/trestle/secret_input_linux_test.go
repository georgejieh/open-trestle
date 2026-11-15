package main

import (
	"bytes"
	"errors"
	"os"
	"strconv"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// openTestPTY opens a pseudo-terminal pair with the kernel's /dev/ptmx, no
// library: the controller side plays the person at the keyboard, the
// terminal side is what trestle reads.
func openTestPTY(t *testing.T) (controller, terminal *os.File) {
	t.Helper()
	controller, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pseudo-terminals here: %v", err)
	}
	t.Cleanup(func() { _ = controller.Close() })
	// The controller's descriptor is used through its raw connection, not
	// Fd(), which would make it blocking and disable read deadlines.
	raw, err := controller.SyscallConn()
	if err != nil {
		t.Skipf("no raw connection to the pseudo-terminal: %v", err)
	}
	unlock := 0
	var number uint32
	var errno syscall.Errno
	if err := raw.Control(func(fd uintptr) {
		if _, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCSPTLCK, uintptr(unsafe.Pointer(&unlock))); errno == 0 {
			_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCGPTN, uintptr(unsafe.Pointer(&number)))
		}
	}); err != nil || errno != 0 {
		t.Skipf("cannot unlock or name the pseudo-terminal: %v %v", err, errno)
	}
	terminal, err = os.OpenFile("/dev/pts/"+strconv.FormatUint(uint64(number), 10), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("cannot open the pseudo-terminal: %v", err)
	}
	t.Cleanup(func() { _ = terminal.Close() })
	return controller, terminal
}

func ptyEcho(t *testing.T, terminal *os.File) bool {
	t.Helper()
	var state syscall.Termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, terminal.Fd(), syscall.TCGETS, uintptr(unsafe.Pointer(&state))); errno != 0 {
		t.Fatal(errno)
	}
	return state.Lflag&syscall.ECHO != 0
}

// readEcho collects what the terminal echoed back within a short window.
func readEcho(t *testing.T, controller *os.File) []byte {
	t.Helper()
	var echoed []byte
	buffer := make([]byte, 256)
	for {
		if err := controller.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Skipf("the pseudo-terminal does not support deadlines: %v", err)
		}
		n, err := controller.Read(buffer)
		echoed = append(echoed, buffer[:n]...)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return echoed
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

// On a real (pseudo-)terminal, hideInput turns kernel echo off: a key typed
// while it is hidden comes back as nothing, and restoring turns echo on again.
func TestTermiosHideInputStopsTheKernelEcho(t *testing.T) {
	controller, terminal := openTestPTY(t)
	hider, ok := platformEchoTerminal(terminal)
	if !ok || !ptyEcho(t, terminal) {
		t.Fatal("the pseudo-terminal is not a terminal with echo on")
	}
	restore, err := hider.hideInput()
	if err != nil || ptyEcho(t, terminal) {
		t.Fatalf("echo still on after hideInput: %v", err)
	}
	if _, err := controller.Write([]byte(remoteTestKey + "\n")); err != nil {
		t.Fatal(err)
	}
	line := make([]byte, 128)
	n, err := terminal.Read(line)
	if err != nil || string(line[:n]) != remoteTestKey+"\n" {
		t.Fatalf("the hidden line was not delivered: %q %v", line[:n], err)
	}
	if echoed := readEcho(t, controller); bytes.Contains(echoed, []byte(remoteTestKey)) || len(echoed) != 0 {
		t.Fatalf("the terminal echoed hidden input: %q", echoed)
	}
	if err := restore(); err != nil || !ptyEcho(t, terminal) {
		t.Fatalf("echo not restored: %v", err)
	}
	if _, err := controller.Write([]byte("visible\n")); err != nil {
		t.Fatal(err)
	}
	if echoed := readEcho(t, controller); !bytes.Contains(echoed, []byte("visible")) {
		t.Fatalf("echo did not come back: %q", echoed)
	}
}
