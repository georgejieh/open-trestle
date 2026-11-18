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

// resolution is what an import names: whole units, as a Go or C# package
// import or a Java wildcard does, or single files.
type resolution struct {
	files []int32
	unit  bool
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

func (r *resolver) text(id int32) string { return r.g.names[id].Untrusted() }

func (r *resolver) resolve(file int32, imp graphImport) resolution {
	f := r.g.files[file]
	dir := path.Dir(f.entry.Path)
	source, name := r.text(imp.source), r.text(imp.name)
	switch {
	case f.family.name == "go":
		return resolution{files: r.goPackage(dir, source), unit: true}
	case f.family.name == "jvm" && name == "*":
		return resolution{files: r.unit("jvm", "pkg:"+source), unit: true}
	case f.family.name == "dotnet":
		return resolution{files: r.unit("dotnet", "pkg:"+source), unit: true}
	}
	return resolution{files: r.resolveFile(f, dir, source, name)}
}

// resolveFile resolves an import that names files.
func (r *resolver) resolveFile(f graphFile, dir, source, name string) []int32 {
	switch f.family.name {
	case "jvm":
		return r.javaClass(source)
	case "web":
		if f.entry.Language == syntaxanalysis.LanguageHTML {
			return r.pageResource(dir, strings.TrimSpace(source))
		}
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

// goPackage returns the files of the package an import path names: the
// directory under the Go module whose path starts the import path. A file
// inside a known module imports nothing else of the repository, so any
// other import path stays unresolved. Only a file outside every known module
// falls back to the longest directory that is the import path or ends it.
func (r *resolver) goPackage(dir, importPath string) []int32 {
	inModule := false
	for _, m := range r.g.goModules {
		if rest, ok := strings.CutPrefix(importPath, m.Path); ok && (rest == "" || rest[0] == '/') {
			return r.unit("go", "dir:"+path.Join(m.Dir, strings.TrimPrefix(rest, "/")))
		}
		inModule = inModule || m.Dir == "." || dir == m.Dir || strings.HasPrefix(dir, m.Dir+"/")
	}
	if inModule {
		return nil
	}
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

// javaClass resolves a class import to its file, and a static member
// import to its class's file.
func (r *resolver) javaClass(source string) []int32 {
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

// pageResource resolves a page's src, href or action value to the file it
// names relative to the page, leaving out URLs and site-absolute paths.
func (r *resolver) pageResource(dir, value string) []int32 {
	value, _, _ = strings.Cut(value, "#")
	value, _, _ = strings.Cut(value, "?")
	if value == "" || strings.Contains(value, ":") || strings.HasPrefix(value, "/") {
		return nil
	}
	return r.exact(path.Join(dir, value))
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
