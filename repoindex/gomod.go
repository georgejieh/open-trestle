package repoindex

import (
	"context"
	"path"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// maxGoModFiles and maxGoModBytes bound the go.mod files a build reads.
const (
	maxGoModFiles = 1024
	maxGoModBytes = 1 << 20
)

// goModules reads the module path of every go.mod file outside vendored
// code. It counts the go.mod files it leaves out, past its bounds,
// unreadable or without a module directive; the packages under them
// resolve by path suffix instead and the coverage is incomplete.
func goModules(ctx context.Context, tree Tree, files []FileEntry) ([]GoModule, int, error) {
	found, leftOut := []FileEntry{}, 0
	for _, f := range files {
		if path.Base(f.Path) == "go.mod" && f.Status == StatusNotAnalysed && f.Role != RoleVendored {
			if len(found) == maxGoModFiles {
				leftOut++
				continue
			}
			found = append(found, f)
		}
	}
	modules := []GoModule{}
	next := 0
	err := tree.ReadBlobs(ctx, func() (string, bool) {
		if next >= len(found) {
			return "", false
		}
		next++
		return found[next-1].Object, true
	}, func(content []byte, err error) error {
		module := ""
		if err == nil && len(content) <= maxGoModBytes {
			module = goModulePath(content)
		}
		if module == "" {
			leftOut++
		} else {
			modules = append(modules, GoModule{Dir: path.Dir(found[next-1].Path), Path: module})
		}
		return ctx.Err()
	})
	slices.SortStableFunc(modules, func(a, b GoModule) int { return len(b.Path) - len(a.Path) })
	return modules, leftOut, err
}

// goModulePath returns the path of a go.mod file's module directive.
func goModulePath(content []byte) string {
	for _, line := range strings.Split(string(content), "\n") {
		line, _, _ = strings.Cut(line, "//")
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "module" {
			module := strings.Trim(fields[1], "\"`")
			if syntaxanalysis.ValidPath(module) && !strings.ContainsAny(module, " \\") {
				return module
			}
			return ""
		}
	}
	return ""
}
