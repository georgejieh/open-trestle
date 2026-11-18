package checksandbox

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// Exit codes of the probe: blocked means the attempt failed, as it must;
// escaped means it succeeded.
const (
	probeBlocked = 3
	probeEscaped = 4
)

// probe runs inside the sandbox as this test binary. Each mode attempts one
// escape and exits with probeEscaped if it worked.
func probe(args []string) int {
	mode, args := args[0], args[1:]
	switch mode {
	case "true":
		return 0
	case "read":
		if _, err := os.ReadFile(args[0]); err == nil {
			return probeEscaped
		}
	case "env":
		if os.Getenv(args[0]) != "" {
			return probeEscaped
		}
		if environmentLeaks(args[1]) {
			return probeEscaped
		}
	case "tcp":
		if connection, err := net.DialTimeout("tcp", args[0], 3*time.Second); err == nil {
			connection.Close()
			return probeEscaped
		}
	case "dns":
		if addresses, err := net.LookupHost(args[0]); err == nil && len(addresses) > 0 {
			return probeEscaped
		}
	case "write":
		if os.WriteFile(args[0], []byte("escaped"), 0o644) == nil {
			return probeEscaped
		}
	case "spawn":
		return spawnMany(args[0])
	case "fill":
		return fillDisk()
	case "hang":
		child := exec.Command(os.Args[0], "__probe", "sleep", args[0])
		if child.Start() != nil {
			return 1
		}
		fmt.Printf("pid %d\npid %d\n", os.Getpid(), child.Process.Pid)
		time.Sleep(time.Hour)
	case "sleep":
		time.Sleep(time.Hour)
	case "spew":
		chunk := make([]byte, 64<<10)
		for {
			if _, err := os.Stdout.Write(chunk); err != nil {
				return 1
			}
		}
	case "write-scratch":
		if os.WriteFile(filepath.Join(os.Getenv("TMPDIR"), "ok"), []byte("ok"), 0o644) != nil {
			return 1
		}
		return 0
	default:
		return platformProbe(mode, args)
	}
	return probeBlocked
}

// spawnMany starts sleeping copies of itself until starting fails or count
// are running, prints how many started, and exits 0.
func spawnMany(count string) int {
	limit, _ := strconv.Atoi(count)
	started := 0
	for started < limit {
		child := exec.Command(os.Args[0], "__probe", "sleep", "spawned")
		if child.Start() != nil {
			break
		}
		started++
	}
	fmt.Printf("started %d\n", started)
	return 0
}

// fillDisk writes to the scratch until writing fails and prints how much
// it wrote.
func fillDisk() int {
	file, err := os.Create(filepath.Join(os.Getenv("TMPDIR"), "fill"))
	if err != nil {
		return 1
	}
	chunk := make([]byte, 1<<20)
	var written int64
	for {
		n, err := file.Write(chunk)
		written += int64(n)
		if err != nil {
			break
		}
	}
	file.Close()
	fmt.Printf("wrote %d\n", written)
	return 0
}
