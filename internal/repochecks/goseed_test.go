package repochecks

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

func TestStandardImportsKeepsOnlyTheStandardLibrary(t *testing.T) {
	goroot := t.TempDir()
	for _, folder := range []string{"src/fmt", "src/net/http", "src/testing", "src/testing/internal/testdeps"} {
		if err := os.MkdirAll(filepath.Join(goroot, filepath.FromSlash(folder)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tree := writeTree(t, map[string]string{
		"go.mod":        "module m\n",
		"a/a.go":        "package a\n\nimport (\n\t\"fmt\"\n\t\"m/b\"\n\t\"example.com/x\"\n)\n",
		"b/b_test.go":   "package b\n\nimport \"net/http\"\n",
		"vendor/v/v.go": "package v\n\nimport \"os\"\n",
		"broken/c.go":   "package c\nimport (",
	})
	want := []string{"fmt", "net/http", "testing", "testing/internal/testdeps"}
	if got := standardImports(context.Background(), goroot, []string{tree}); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

// A hostile import path cleans to a real GOROOT folder; it must never reach
// the host go command, where it would read as a flag.
func TestSeedNeverPassesARepositoryImportAsAFlag(t *testing.T) {
	goroot := t.TempDir()
	for _, folder := range []string{"bin", "src/runtime", "src/fmt", "src/testing", "src/testing/internal/testdeps", "src/cmd/go", "src/internal/abi", "src/vendor/x"} {
		if err := os.MkdirAll(filepath.Join(goroot, filepath.FromSlash(folder)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	marker := filepath.Join(t.TempDir(), "ran")
	tree := writeTree(t, map[string]string{
		"a/a.go": "package a\n\nimport (\n\t_ \"-toolexec=touch " + filepath.ToSlash(marker) + " /../../fmt\"\n\t_ \"./../fmt\"\n\t_ \"fmt/../fmt\"\n\t_ \"cmd/go\"\n\t_ \"internal/abi\"\n\t_ \"vendor/x\"\n\t_ \"FMT\"\n\t_ \"fmt\"\n)\n",
	})
	if got := standardImports(context.Background(), goroot, []string{tree}); !slices.Equal(got, []string{"fmt", "testing", "testing/internal/testdeps"}) {
		t.Fatalf("got %v", got)
	}
	// A recording go command shows exactly what the seed build passes.
	if _, err := exec.LookPath("sh"); err != nil || runtime.GOOS == "windows" {
		t.Skip("the seed is not built here")
	}
	record := filepath.Join(t.TempDir(), "args")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > " + record + "\n"
	if err := os.WriteFile(filepath.Join(goroot, "bin", "go"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	home, cleanup := buildGoSeed(context.Background(), "go", toolchain{path: []string{filepath.Join(goroot, "bin")}, readOnly: []string{goroot}}, []string{tree})
	defer cleanup()
	args, err := os.ReadFile(record)
	if err != nil || home == "" {
		t.Fatalf("the seed build did not run: %v", err)
	}
	if got := strings.Fields(string(args)); !slices.Equal(got, []string{"build", "--", "fmt", "testing", "testing/internal/testdeps"}) {
		t.Fatalf("go was run with %q", got)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a repository import ran a command")
	}
}
