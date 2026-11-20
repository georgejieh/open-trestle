package repochecks

import (
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// trees are the base and head trees of a change, with the Go module paths
// they declare, read once.
type trees struct {
	base, head string
	modules    []string
}

func newTrees(base, head string) trees {
	return trees{base: base, head: head, modules: append(goModules(base), goModules(head)...)}
}

// provides reports whether name is part of the repository: a path (a test
// runner names a file it could not load), a Python package or module at
// the top of either tree, or a package of a Go module declared in either
// tree. A module the repository provides is never a missing dependency: a
// change that renamed or removed it broke the tests that use it.
func (t trees) provides(name string) bool {
	if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
		return true
	}
	if strings.HasPrefix(name, ".") {
		return filepath.IsLocal(filepath.Clean(name))
	}
	top := strings.SplitN(name, ".", 2)[0]
	for _, tree := range []string{t.base, t.head} {
		if isDir(filepath.Join(tree, top)) || isFile(filepath.Join(tree, top+".py")) || isDir(filepath.Join(tree, "src", top)) {
			return true
		}
	}
	for _, module := range t.modules {
		if name == module || strings.HasPrefix(name, module+"/") {
			return true
		}
	}
	return false
}

var moduleLine = regexp.MustCompile(`(?m)^module\s+"?([^\s"]+)"?\s*$`)

// goModules are the module paths of the go.mod files in tree.
func goModules(tree string) []string {
	files, err := listFiles(tree)
	if err != nil {
		return nil
	}
	var modules []string
	for _, file := range files {
		if path.Base(file) != "go.mod" {
			continue
		}
		if module := goModulePath(tree, path.Dir(file)); module != "" {
			modules = append(modules, module)
		}
	}
	return modules
}

// goModulePath is the module path of the go.mod file in folder of tree, or
// "".
func goModulePath(tree, folder string) string {
	data, err := os.ReadFile(filepath.Join(tree, filepath.FromSlash(folder), "go.mod"))
	if err != nil {
		return ""
	}
	if match := moduleLine.FindSubmatch(data); match != nil {
		return string(match[1])
	}
	return ""
}

func isFile(name string) bool {
	info, err := os.Stat(name)
	return err == nil && info.Mode().IsRegular()
}
