package repoindex

import (
	"path"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// family groups languages whose files can refer to each other, with the
// visibility rules the reference candidates follow.
type family struct {
	name string
	// packages: files in one directory form one unit, a package or
	// namespace, whose definitions they see without an import.
	packages bool
	// global: an exported definition is visible to every file of the
	// family without an import that names its file, as with C and C++
	// linkage, Ruby constants and PHP, C# and Swift names.
	global bool
}

func familyOf(language syntaxanalysis.Language) family {
	switch language {
	case syntaxanalysis.LanguageGo:
		return family{name: "go", packages: true}
	case syntaxanalysis.LanguageJava:
		return family{name: "jvm", packages: true}
	case syntaxanalysis.LanguageJavaScript, syntaxanalysis.LanguageTypeScript, syntaxanalysis.LanguageTSX, syntaxanalysis.LanguageHTML:
		return family{name: "web"}
	case syntaxanalysis.LanguagePython:
		return family{name: "python"}
	case syntaxanalysis.LanguageC, syntaxanalysis.LanguageCPP:
		return family{name: "native", global: true}
	case syntaxanalysis.LanguageCSharp:
		return family{name: "dotnet", packages: true, global: true}
	case syntaxanalysis.LanguageSwift:
		return family{name: "swift", packages: true, global: true}
	case syntaxanalysis.LanguageRust:
		return family{name: "rust"}
	case syntaxanalysis.LanguagePHP:
		return family{name: "php", packages: true, global: true}
	case syntaxanalysis.LanguageRuby:
		return family{name: "ruby", global: true}
	}
	return family{}
}

// resolver finds the files an import names.
type resolver struct {
	g      *Graph
	byBase map[string][]int32
	dirs   map[string][]string // last directory segment -> directories with files
}

func (g *Graph) newResolver() *resolver {
	r := &resolver{g: g, byBase: map[string][]int32{}, dirs: map[string][]string{}}
	seenDir := map[string]bool{}
	for i, f := range g.files {
		p := f.entry.Path
		r.byBase[path.Base(p)] = append(r.byBase[path.Base(p)], int32(i))
		if d := path.Dir(p); !seenDir[d] {
			seenDir[d] = true
			r.dirs[path.Base(d)] = append(r.dirs[path.Base(d)], d)
		}
	}
	return r
}

// resolveImports records, per file, the units its imports resolve to and
// the number of imports that resolve to no file of the repository.
func (g *Graph) resolveImports() {
	r := g.newResolver()
	type edge struct{ file, unit int32 }
	edges := []edge{}
	g.goImports = map[int32]map[string]int32{}
	g.unresolved = make([]int32, len(g.files))
	for i, f := range g.files {
		seen := map[int32]bool{}
		for k := f.imports.start; k < f.imports.end; k++ {
			targets := r.resolve(int32(i), g.imports[k])
			if len(targets) == 0 {
				g.unresolved[i]++
			}
			if f.family.name == "go" {
				g.addGoImportName(int32(i), g.imports[k], targets)
			}
			for _, t := range targets {
				unit := g.files[t].unit
				if t != int32(i) && !seen[unit] && g.files[t].family.name == f.family.name {
					seen[unit] = true
					edges = append(edges, edge{int32(i), unit})
				}
			}
		}
	}
	g.importEdges = buildPostings(len(g.files), len(edges), func(i int) int32 { return edges[i].file }, func(i int) int32 { return edges[i].unit })
	units := len(g.unitFiles.offsets) - 1
	g.importers = buildPostings(units, len(edges), func(i int) int32 { return edges[i].unit }, func(i int) int32 { return edges[i].file })
}

// addGoImportName records the name a Go file uses for an imported package:
// its alias, or the last element of the import path that is not a major
// version suffix. The unit is -1 for a package outside the repository.
func (g *Graph) addGoImportName(file int32, imp graphImport, targets []int32) {
	name := g.names[imp.alias].Untrusted()
	if name == "" {
		elements := strings.Split(g.names[imp.source].Untrusted(), "/")
		name = elements[len(elements)-1]
		if len(elements) > 1 && len(name) > 1 && name[0] == 'v' && strings.Trim(name[1:], "0123456789") == "" {
			name = elements[len(elements)-2]
		}
	}
	if name == "" || name == "_" || name == "." {
		return
	}
	unit := int32(-1)
	if len(targets) > 0 {
		unit = g.files[targets[0]].unit
	}
	if g.goImports[file] == nil {
		g.goImports[file] = map[string]int32{}
	}
	g.goImports[file][name] = unit
}

func (r *resolver) text(id int32) string { return r.g.names[id].Untrusted() }

func (r *resolver) resolve(file int32, imp graphImport) []int32 {
	f := r.g.files[file]
	dir := path.Dir(f.entry.Path)
	source, name := r.text(imp.source), r.text(imp.name)
	switch f.family.name {
	case "go":
		return r.goPackage(source)
	case "jvm":
		return r.java(source, name)
	case "dotnet":
		return r.unit("dotnet", "pkg:"+source)
	case "web":
		return r.relativeModule(dir, strings.TrimSpace(source), []string{"", ".ts", ".tsx", ".d.ts", ".js", ".jsx", ".mjs", ".cjs", ".mts", ".cts", "/index.ts", "/index.tsx", "/index.js", "/index.jsx"})
	case "python":
		return r.python(dir, source, name)
	case "native":
		include := strings.Trim(source, "<>\"")
		if found := r.exact(path.Join(dir, include)); len(found) > 0 {
			return found
		}
		return r.suffix(include)
	case "rust":
		return r.rust(source, name)
	case "ruby":
		return r.scriptPath(dir, source, ".rb")
	case "php":
		if strings.Contains(source, "/") || strings.HasSuffix(source, ".php") {
			return r.scriptPath(dir, source, ".php")
		}
		return r.php(source, name)
	}
	return nil
}

// exact returns the file at a cleaned repository path.
func (r *resolver) exact(p string) []int32 {
	p = path.Clean(p)
	if id, ok := r.g.byPath[p]; ok {
		return []int32{id}
	}
	return nil
}

// suffix returns the files whose path is p or ends with "/" and p: an
// import written relative to a source root the index does not know.
func (r *resolver) suffix(p string) []int32 {
	p = path.Clean(p)
	if p == "." || strings.HasPrefix(p, "../") || strings.HasPrefix(p, "/") {
		return nil
	}
	out := []int32{}
	for _, id := range r.byBase[path.Base(p)] {
		if q := r.g.files[id].entry.Path; q == p || strings.HasSuffix(q, "/"+p) {
			out = append(out, id)
		}
	}
	return out
}

// goPackage returns the files of the directory an import path names: the
// longest directory that is the import path or ends it.
func (r *resolver) goPackage(importPath string) []int32 {
	best := ""
	for _, d := range r.dirs[path.Base(importPath)] {
		if (importPath == d || strings.HasSuffix(importPath, "/"+d)) && len(d) > len(best) {
			best = d
		}
	}
	if best == "" {
		return nil
	}
	return r.unit("go", "dir:"+best)
}

// unit returns the files of a unit.
func (r *resolver) unit(familyName, scope string) []int32 {
	id, ok := r.g.units[unitKey(familyName, scope)]
	if !ok {
		return nil
	}
	return r.g.unitFiles.get(id)
}

// java resolves a class import to its file, a static member import to its
// class's file and a wildcard import to the package.
func (r *resolver) java(source, name string) []int32 {
	if name == "*" {
		return r.unit("jvm", "pkg:"+source)
	}
	segments := strings.Split(source, ".")
	for n := len(segments); n >= 1; n-- {
		if found := r.suffix(strings.Join(segments[:n], "/") + ".java"); len(found) > 0 {
			return found
		}
	}
	return nil
}

func (r *resolver) relativeModule(dir, source string, extensions []string) []int32 {
	if !strings.HasPrefix(source, "./") && !strings.HasPrefix(source, "../") {
		return nil
	}
	base := path.Join(dir, source)
	for _, extension := range extensions {
		if found := r.exact(base + extension); len(found) > 0 {
			return found
		}
	}
	return nil
}

// python resolves "a.b", ".b" and "from a import b" to a/b.py,
// a/b/__init__.py or a/b.pyi, relative to the importing file for leading
// dots and to any source root otherwise.
func (r *resolver) python(dir, source, name string) []int32 {
	dots := len(source) - len(strings.TrimLeft(source, "."))
	module := strings.ReplaceAll(strings.TrimLeft(source, "."), ".", "/")
	candidates := []string{}
	for _, m := range []string{path.Join(module, name), module} {
		if m == "" || m == "." {
			continue
		}
		candidates = append(candidates, m+".py", m+".pyi", m+"/__init__.py")
	}
	if dots > 0 {
		base := dir
		for i := 1; i < dots; i++ {
			base = path.Dir(base)
		}
		for _, c := range candidates {
			if found := r.exact(path.Join(base, c)); len(found) > 0 {
				return found
			}
		}
		return nil
	}
	for _, c := range candidates {
		if found := r.suffix(c); len(found) > 0 {
			return found
		}
	}
	return nil
}

// rust maps a use path to a module file: the longest prefix of its segments
// that names a.rs or a/mod.rs.
func (r *resolver) rust(source, name string) []int32 {
	segments := []string{}
	for _, s := range strings.Split(source, "::") {
		if s != "" && s != "crate" && s != "self" && s != "super" {
			segments = append(segments, s)
		}
	}
	if first, _, _ := strings.Cut(name, "::"); first != "" && first != "self" && first != "*" && !strings.ContainsAny(first, "{ ,") {
		segments = append(segments, first)
	}
	for n := len(segments); n >= 1; n-- {
		p := strings.Join(segments[:n], "/")
		for _, c := range []string{p + ".rs", p + "/mod.rs"} {
			if found := r.suffix(c); len(found) > 0 {
				return found
			}
		}
	}
	return nil
}

// scriptPath resolves a required path relative to the importing file, then
// relative to any source root, adding the extension when it is missing.
func (r *resolver) scriptPath(dir, source, extension string) []int32 {
	p := strings.TrimSpace(source)
	if path.Ext(p) == "" {
		p += extension
	}
	if found := r.exact(path.Join(dir, p)); len(found) > 0 {
		return found
	}
	return r.suffix(p)
}

// php maps a namespaced name to a file named after its last segment in
// directories named after the segments before it, dropping leading
// namespace segments that a source root maps away.
func (r *resolver) php(source, name string) []int32 {
	segments := slices.DeleteFunc(strings.Split(source, "\\"), func(s string) bool { return s == "" })
	if name != "" {
		segments = append(segments, slices.DeleteFunc(strings.Split(name, "\\"), func(s string) bool { return s == "" })...)
	}
	for start := 0; len(segments)-start >= 2; start++ {
		if found := r.suffix(strings.Join(segments[start:], "/") + ".php"); len(found) > 0 {
			return found
		}
	}
	return nil
}

// Imports returns the files a file's imports resolve to, and the number of
// its imports that resolve to no file of the repository.
func (g *Graph) Imports(filePath string) ([]string, int, bool) {
	id, ok := g.byPath[filePath]
	if !ok {
		return nil, 0, false
	}
	out := []string{}
	for _, unit := range g.importEdges.get(id) {
		for _, f := range g.unitFiles.get(unit) {
			// The tests of a package are not part of what a non-test file
			// imports from it.
			if g.files[f].entry.Role != RoleTest || g.files[id].entry.Role == RoleTest {
				out = append(out, g.files[f].entry.Path)
			}
		}
	}
	return out, int(g.unresolved[id]), true
}

// Importers returns the files whose imports resolve to a file's unit.
func (g *Graph) Importers(filePath string) ([]string, bool) {
	id, ok := g.byPath[filePath]
	if !ok {
		return nil, false
	}
	out := []string{}
	for _, f := range g.importers.get(g.files[id].unit) {
		out = append(out, g.files[f].entry.Path)
	}
	return out, true
}

// importsUnit reports whether a file imports a unit.
func (g *Graph) importsUnit(file, unit int32) bool {
	return slices.Contains(g.importEdges.get(file), unit)
}
