package repoindex

import (
	"slices"
	"strings"
)

// resolveImports records, per file, the units and files its imports
// resolve to, the number of imports that resolve to no file of the
// repository, and for Go the name each import binds.
func (g *Graph) resolveImports() {
	r := g.newResolver()
	type edge struct{ file, target int32 }
	unitEdges, fileEdges := []edge{}, []edge{}
	g.goImports = map[int32]map[string]int32{}
	g.unresolved = make([]int32, len(g.files))
	for i, f := range g.files {
		file := int32(i)
		seenUnits, seenFiles := map[int32]bool{}, map[int32]bool{}
		for k := f.imports.start; k < f.imports.end; k++ {
			found := r.resolve(file, g.imports[k])
			if len(found.files) == 0 {
				g.unresolved[i]++
			}
			if f.family.name == "go" {
				g.addGoImportName(file, g.imports[k], found.files)
			}
			for _, t := range found.files {
				if t == file || g.files[t].family.name != f.family.name {
					continue
				}
				if unit := g.files[t].unit; found.unit && !seenUnits[unit] {
					seenUnits[unit] = true
					unitEdges = append(unitEdges, edge{file, unit})
				} else if !found.unit && !seenFiles[t] {
					seenFiles[t] = true
					fileEdges = append(fileEdges, edge{file, t})
				}
			}
		}
	}
	files, units := len(g.files), len(g.units)
	g.importUnits = buildPostings(files, len(unitEdges), func(i int) int32 { return unitEdges[i].file }, func(i int) int32 { return unitEdges[i].target })
	g.unitImporters = buildPostings(units, len(unitEdges), func(i int) int32 { return unitEdges[i].target }, func(i int) int32 { return unitEdges[i].file })
	g.importFiles = buildPostings(files, len(fileEdges), func(i int) int32 { return fileEdges[i].file }, func(i int) int32 { return fileEdges[i].target })
	g.fileImporters = buildPostings(files, len(fileEdges), func(i int) int32 { return fileEdges[i].target }, func(i int) int32 { return fileEdges[i].file })
}

// addGoImportName records the name a Go file uses for an imported package:
// its alias, else the declared name of a package of the repository, else
// the last element of the import path that is not a major version suffix.
// The unit is -1 for a package outside the repository.
func (g *Graph) addGoImportName(file int32, imp graphImport, targets []int32) {
	unit := int32(-1)
	if len(targets) > 0 {
		unit = g.files[targets[0]].unit
	}
	name := g.names[imp.alias].Untrusted()
	if name == "" && unit >= 0 && g.unitPackage[unit] != 0 {
		name = g.names[g.unitPackage[unit]].Untrusted()
	}
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
	if g.goImports[file] == nil {
		g.goImports[file] = map[string]int32{}
	}
	g.goImports[file][name] = unit
}

// Imports returns the files a file's imports resolve to, and the number of
// its imports that resolve to no file of the repository.
func (g *Graph) Imports(filePath string) ([]string, int, bool) {
	id, ok := g.byPath[filePath]
	if !ok {
		return nil, 0, false
	}
	out := []string{}
	for _, unit := range g.importUnits.get(id) {
		for _, f := range g.unitFiles.get(unit) {
			// The tests of a package are not part of what a non-test file
			// imports from it.
			if g.files[f].entry.Role != RoleTest || g.files[id].entry.Role == RoleTest {
				out = append(out, g.files[f].entry.Path)
			}
		}
	}
	for _, f := range g.importFiles.get(id) {
		out = append(out, g.files[f].entry.Path)
	}
	return out, int(g.unresolved[id]), true
}

// ImportSources returns the import text of a file as its analysis recorded
// it, such as a package path or a module name, in file order.
func (g *Graph) ImportSources(filePath string) ([]string, bool) {
	id, ok := g.byPath[filePath]
	if !ok {
		return nil, false
	}
	f := g.files[id]
	out := []string{}
	for k := f.imports.start; k < f.imports.end; k++ {
		out = append(out, g.names[g.imports[k].source].Untrusted())
	}
	return out, true
}

// Importers returns the files whose imports resolve to a file or its unit.
func (g *Graph) Importers(filePath string) ([]string, bool) {
	id, ok := g.byPath[filePath]
	if !ok {
		return nil, false
	}
	out := []string{}
	for _, f := range g.importersOf(id) {
		out = append(out, g.files[f].entry.Path)
	}
	return out, true
}

// importersOf returns the files that import a file or its unit, each once.
func (g *Graph) importersOf(file int32) []int32 {
	out := append(append([]int32(nil), g.unitImporters.get(g.files[file].unit)...), g.fileImporters.get(file)...)
	slices.Sort(out)
	return slices.Compact(out)
}

// importsTarget reports whether a file imports a definition's file or unit.
func (g *Graph) importsTarget(file int32, t target) bool {
	return t.unit >= 0 && slices.Contains(g.importUnits.get(file), t.unit) || t.file >= 0 && slices.Contains(g.importFiles.get(file), t.file)
}
