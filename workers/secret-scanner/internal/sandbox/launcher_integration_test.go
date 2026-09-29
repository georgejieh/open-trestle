//go:build linux && amd64

package sandbox

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestLauncherEstablishesInheritedLandlockBeforeGoThreads(t *testing.T) {
	requireLandlockABI5(t)
	temporary := t.TempDir()
	workerPath := filepath.Join(temporary, "probe-worker")
	existingPath := filepath.Join(temporary, "existing")
	if err := os.WriteFile(existingPath, []byte("unchanged"), 0o600); err != nil {
		t.Fatal(err)
	}
	buildLandlockProbe(t, workerPath, existingPath, temporary)
	launcherPath := buildTestLauncher(t, temporary, workerPath)

	command := exec.Command(launcherPath, "--stdio-v1")
	command.Env = []string{"MUST_NOT_SURVIVE=1"}
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("launcher probe failed: %v; stdout=%q stderr=%q", err, stdout.Bytes(), stderr.Bytes())
	}
	if stdout.String() != "landlock-ok\n" {
		t.Fatalf("unexpected stdout %q", stdout.Bytes())
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr leaked %q", stderr.Bytes())
	}
	content, err := os.ReadFile(existingPath)
	if err != nil || string(content) != "unchanged" {
		t.Fatalf("existing file changed: content=%q error=%v", content, err)
	}
	entries, err := os.ReadDir(temporary)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 4 {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("sandbox created filesystem entries: %v", names)
	}
}

func TestLauncherRejectsArgumentsWithoutStartingWorker(t *testing.T) {
	temporary := t.TempDir()
	markerPath := filepath.Join(temporary, "worker-started")
	workerPath := filepath.Join(temporary, "marker-worker")
	source := fmt.Sprintf("package main\nimport \"os\"\nfunc main(){ _ = os.WriteFile(%s, []byte(\"started\"), 0600) }\n", strconv.Quote(markerPath))
	sourcePath := filepath.Join(temporary, "marker.go")
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	runBuild(t, temporary, nil, "go", "build", "-trimpath", "-o", workerPath, sourcePath)
	launcherPath := buildTestLauncher(t, temporary, workerPath)

	for _, arguments := range [][]string{nil, {"--wrong"}, {"--stdio-v1", "extra"}} {
		command := exec.Command(launcherPath, arguments...)
		command.Stdin = strings.NewReader("repository secret bytes")
		if err := command.Run(); err == nil {
			t.Fatalf("arguments %q unexpectedly accepted", arguments)
		}
	}
	if _, err := os.Stat(markerPath); !os.IsNotExist(err) {
		t.Fatalf("worker started for invalid launcher argument: %v", err)
	}
}

func TestLauncherRejectsSymlinkWorkerPath(t *testing.T) {
	temporary := t.TempDir()
	workerPath := filepath.Join(temporary, "worker-link")
	if err := os.Symlink("/bin/true", workerPath); err != nil {
		t.Fatal(err)
	}
	launcherPath := buildTestLauncher(t, temporary, workerPath)
	command := exec.Command(launcherPath, "--stdio-v1")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err == nil {
		t.Fatal("launcher executed a symlink worker path")
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("symlink refusal emitted output: stdout=%q stderr=%q", stdout.Bytes(), stderr.Bytes())
	}
}

func buildLandlockProbe(t *testing.T, workerPath, existingPath, directory string) {
	t.Helper()
	source := fmt.Sprintf(`package main

import (
    "errors"
    "fmt"
    "os"
    "runtime"
    "sync"
    "syscall"
)

const existingPath = %s
const directory = %s

func main() {
    if len(os.Args) != 2 || os.Args[1] != "--sandboxed-stdio-v1" || len(os.Environ()) != 0 {
        os.Exit(10)
    }
    cwd, err := os.Getwd()
    if err != nil || cwd != "/" {
        os.Exit(11)
    }
    value, _, errno := syscall.RawSyscall6(syscall.SYS_PRCTL, 39, 0, 0, 0, 0, 0)
    if errno != 0 || value != 1 {
        os.Exit(12)
    }
    var core syscall.Rlimit
    var cpu syscall.Rlimit
    var files syscall.Rlimit
    if syscall.Getrlimit(syscall.RLIMIT_CORE, &core) != nil || core.Cur != 0 || core.Max != 0 ||
        syscall.Getrlimit(syscall.RLIMIT_CPU, &cpu) != nil || cpu.Cur != 6 || cpu.Max != 6 ||
        syscall.Getrlimit(syscall.RLIMIT_NOFILE, &files) != nil || files.Cur != 16 || files.Max != 16 {
        os.Exit(13)
    }
    runtime.GOMAXPROCS(8)
    results := make(chan error, 8)
    var ready sync.WaitGroup
    ready.Add(8)
    start := make(chan struct{})
    for index := 0; index < 8; index++ {
        go func(index int) {
            runtime.LockOSThread()
            ready.Done()
            <-start
            if file, err := os.OpenFile(existingPath, os.O_WRONLY, 0); err == nil {
                file.Close()
                results <- errors.New("write open succeeded")
                return
            }
            if file, err := os.OpenFile("/dev/null", os.O_RDONLY, 0); err == nil {
                file.Close()
                results <- errors.New("device open succeeded")
                return
            }
            created := fmt.Sprintf("%%s/created-%%d", directory, index)
            if file, err := os.OpenFile(created, os.O_CREATE|os.O_WRONLY, 0600); err == nil {
                file.Close()
                results <- errors.New("create succeeded")
                return
            }
            if err := os.Rename(existingPath, created); err == nil {
                results <- errors.New("rename succeeded")
                return
            }
            if err := os.Link(existingPath, created); err == nil {
                results <- errors.New("link succeeded")
                return
            }
            if err := os.Remove(existingPath); err == nil {
                results <- errors.New("remove succeeded")
                return
            }
            results <- nil
        }(index)
    }
    ready.Wait()
    close(start)
    for index := 0; index < 8; index++ {
        if err := <-results; err != nil {
            os.Exit(20)
        }
    }
    fmt.Println("landlock-ok")
}
`, strconv.Quote(existingPath), strconv.Quote(directory))
	sourcePath := filepath.Join(filepath.Dir(workerPath), "probe.go")
	if err := os.WriteFile(sourcePath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	runBuild(t, filepath.Dir(workerPath), []string{"CGO_ENABLED=0"}, "go", "build", "-trimpath", "-ldflags=-s -w -buildid=", "-o", workerPath, sourcePath)
}

func buildTestLauncher(t *testing.T, directory, workerPath string) string {
	t.Helper()
	sourcePath, err := filepath.Abs(filepath.Join("..", "..", "launcher", "launcher.c"))
	if err != nil {
		t.Fatal(err)
	}
	launcherPath := filepath.Join(directory, "launcher")
	definition := "-DOPEN_TRESTLE_TEST_WORKER_PATH=" + strconv.Quote(workerPath)
	runBuild(t, directory, nil, "/usr/bin/gcc", definition, "-std=c17", "-O2", "-fPIE", "-fstack-protector-strong", "-D_FORTIFY_SOURCE=3", "-Wall", "-Wextra", "-Werror", "-Wformat=2", "-Wconversion", "-Wshadow", "-Wstrict-prototypes", "-static-pie", "-Wl,-z,relro,-z,now,-z,noexecstack,--build-id=none", "-o", launcherPath, sourcePath)
	return launcherPath
}

func requireLandlockABI5(t *testing.T) {
	t.Helper()
	abi, _, errno := unix.RawSyscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, 1)
	if errno != 0 || abi < 5 {
		t.Skipf("host Landlock ABI %d cannot enforce required ABI 5: %v", abi, errno)
	}
}

func runBuild(t *testing.T, directory string, environment []string, name string, arguments ...string) {
	t.Helper()
	command := exec.Command(name, arguments...)
	command.Dir = directory
	command.Env = append(os.Environ(), environment...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("%s failed: %v; output=%s", name, err, output)
	}
}
