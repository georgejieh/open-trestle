package checksandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestToolchainsRunInSandbox runs a passing and a failing test with each
// toolchain found on this machine. Each must either run, telling the
// failing test apart, or report precisely why it could not run.
func TestToolchainsRunInSandbox(t *testing.T) {
	files := map[string]string{
		"go.mod":       "module example.com/sandboxed\n\ngo 1.22\n",
		"x_test.go":    "package sandboxed\n\nimport \"testing\"\n\nfunc TestPass(t *testing.T) {}\n\nfunc TestFail(t *testing.T) { t.Fatal(\"expected\") }\n",
		"test_x.py":    "import unittest\n\n\nclass T(unittest.TestCase):\n    def test_pass(self):\n        pass\n\n    def test_fail(self):\n        self.fail('expected')\n",
		"x.test.mjs":   "import test from 'node:test';\nimport assert from 'node:assert';\ntest('pass', () => {});\ntest('fail', () => { assert.fail('expected'); });\n",
		"package.json": "{\"type\": \"module\"}\n",
	}
	tree := t.TempDir()
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(tree, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	python := "python3"
	if runtime.GOOS == "windows" {
		python = "python"
	}
	for _, tool := range []struct {
		program string
		args    []string
		env     []string
		pass    string
		fail    string
	}{
		{"go", []string{"test", "-json", "./..."}, []string{"GOCACHE=$HOME/gocache", "GOPATH=$HOME/go", "GOPROXY=off", "GOTOOLCHAIN=local", "GOTELEMETRY=off", "GOFLAGS=-mod=mod"}, `"Test":"TestPass","Elapsed"`, `"Action":"fail","Package":"example.com/sandboxed","Test":"TestFail"`},
		{python, []string{"-m", "unittest", "-v"}, nil, "test_pass", "FAIL: test_fail"},
		{"node", []string{"--test", "--test-reporter=tap"}, nil, "ok 1 - pass", "not ok 2 - fail"},
	} {
		t.Run(tool.program, func(t *testing.T) {
			host, err := exec.LookPath(tool.program)
			if err != nil {
				t.Skipf("%s is not installed here", tool.program)
			}
			host, _ = filepath.EvalSymlinks(host)
			bin := filepath.Dir(host)
			root := bin
			if filepath.Base(bin) == "bin" {
				root = filepath.Dir(bin)
			}
			args := tool.args
			if runtime.GOOS == "windows" && tool.program == "node" {
				// What the repository checks add for Node inside an
				// AppContainer; see repochecks.
				args = append([]string{"--preserve-symlinks", "--preserve-symlinks-main", "--test-isolation=none"}, args...)
			}
			limits := DefaultLimits()
			limits.Time = 5 * time.Minute
			started := time.Now()
			result, err := Run(context.Background(), Spec{
				Tree: tree, Args: append([]string{tool.program}, args...),
				Path: []string{bin}, ReadOnly: []string{root}, Env: tool.env, Limits: limits,
			})
			if IsUnavailable(err) {
				if strings.Contains(err.Error(), "unprivileged user namespaces") || strings.Contains(err.Error(), "AppContainer") || strings.Contains(err.Error(), "read access") {
					t.Skipf("could not run, as reported: %v", err)
				}
				t.Fatalf("unexpected reason: %v", err)
			}
			if err != nil {
				t.Fatal(err)
			}
			output := string(result.Stdout) + string(result.Stderr)
			if result.ExitCode == 0 || !strings.Contains(output, tool.pass) || !strings.Contains(output, tool.fail) {
				t.Fatalf("exit %d after %v; output:\n%s", result.ExitCode, time.Since(started), output)
			}
			t.Logf("ran in %v and told the failing test apart", time.Since(started))
		})
	}
}
