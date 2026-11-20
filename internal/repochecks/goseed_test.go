package repochecks

import (
	"os"
	"path/filepath"
	"slices"
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
	if got := standardImports(goroot, []string{tree}); !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}
