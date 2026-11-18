package repoindex

import (
	"path"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// Scope says why a reference is a candidate for a definition. Every
// candidate has the definition's exact name and a file of the same language
// family; the scope is the visibility rule that connects the two files.
// Names are never resolved to declarations, so a candidate may name another
// definition of the same name.
type Scope string

const (
	// ScopeFile: the reference is in the definition's file.
	ScopeFile Scope = "file"
	// ScopePackage: the files share a package directory (Go, Java, C#,
	// Swift and PHP), whose definitions they see without an import.
	ScopePackage Scope = "package"
	// ScopeImport: the referencing file imports the definition's file or
	// package, as resolved from the import's text, and the definition is
	// exported. In Go, a top-level definition of another package is
	// reached only through the package's name, and a method or field
	// through a selector in a file that imports its package.
	ScopeImport Scope = "import"
	// ScopeName: the definition is exported and its language makes it
	// visible across the repository without an import of its file (C and
	// C++ linkage, Ruby, PHP, C# and Swift).
	ScopeName Scope = "name"
)

// Use is a reference candidate.
type Use struct {
	Path      string                       `json:"path"`
	Role      Role                         `json:"role"`
	Language  syntaxanalysis.Language      `json:"language"`
	Kind      syntaxanalysis.ReferenceKind `json:"kind"`
	Name      syntaxanalysis.Text          `json:"name"`
	Qualifier syntaxanalysis.Text          `json:"qualifier,omitzero"`
	Range     syntaxanalysis.Range         `json:"range"`
	// Enclosing is the qualified name of the innermost definition around
	// the reference; it is empty at the top level of a file.
	Enclosing syntaxanalysis.Text `json:"enclosing,omitzero"`
	Scope     Scope               `json:"scope"`
}

// target is what candidates are matched against: a definition of the graph,
// or one that exists only in another snapshot, such as a removed function.
type target struct {
	file     int32 // -1 when the file is not in the graph
	dir      string
	family   family
	name     int32
	exported bool
	// topLevel is a definition at the top level of its file that is not a
	// method or field of a type, which Go reaches only through a package.
	topLevel bool
	// importers are the files that imported the definition's file in the
	// base, for a definition whose file the head no longer has.
	importers map[int32]bool
}

func (g *Graph) targetOf(i int32) target {
	d := g.defs[i]
	f := g.files[d.file]
	member := d.kind == syntaxanalysis.KindMethod || d.kind == syntaxanalysis.KindField || d.container != 0
	return target{file: d.file, dir: path.Dir(f.entry.Path), family: f.family, name: d.name, exported: d.exported, topLevel: d.parent < 0 && !member}
}

func (g *Graph) unitOf(t target) int32 {
	if t.file >= 0 {
		return g.files[t.file].unit
	}
	if id, ok := g.units[unitKey(t.family.name, "dir:"+t.dir)]; ok && t.family.packages {
		return id
	}
	return -1
}

// scope applies the candidate rules to one reference.
func (g *Graph) scope(t target, unit int32, r graphRef) Scope {
	from := g.files[r.file]
	if from.family.name != t.family.name || t.family.name == "" {
		return ""
	}
	if t.importers[r.file] && t.exported {
		return ScopeImport
	}
	if t.family.name == "go" {
		return g.goScope(t, unit, r)
	}
	switch {
	case r.file == t.file:
		return ScopeFile
	case t.family.packages && unit >= 0 && from.unit == unit:
		return ScopePackage
	case !t.exported:
		return ""
	case unit >= 0 && g.importsUnit(r.file, unit):
		return ScopeImport
	case t.family.global:
		return ScopeName
	}
	return ""
}

// goScope applies Go's rules: a reference qualified by the name of an
// imported package refers to that package only, a top-level definition of
// another package is reached only through such a qualifier, and a selector
// on a value may reach a method or field of any package the file imports.
func (g *Graph) goScope(t target, unit int32, r graphRef) Scope {
	qualifier := g.names[r.qualifier].Untrusted()
	if imported, ok := g.goImports[r.file][qualifier]; ok && qualifier != "" {
		if imported == unit && unit >= 0 && t.exported && t.topLevel {
			return ScopeImport
		}
		return ""
	}
	switch {
	case r.file == t.file:
		return ScopeFile
	case unit >= 0 && g.files[r.file].unit == unit:
		return ScopePackage
	case t.exported && !t.topLevel && r.qualifier != 0 && unit >= 0 && g.importsUnit(r.file, unit):
		return ScopeImport
	}
	return ""
}

// candidates calls fn for every reference candidate of a target, in tree
// order, until fn returns false.
func (g *Graph) candidates(t target, fn func(int32, Scope) bool) {
	unit := g.unitOf(t)
	for _, i := range g.refsByName.get(t.name) {
		if s := g.scope(t, unit, g.refs[i]); s != "" && !fn(i, s) {
			return
		}
	}
}

func (g *Graph) use(i int32, s Scope) Use {
	r := g.refs[i]
	f := g.files[r.file]
	u := Use{Path: f.entry.Path, Role: f.entry.Role, Language: f.entry.Language, Kind: r.kind, Name: g.names[r.name], Qualifier: g.names[r.qualifier], Range: r.rng.Range(), Scope: s}
	if r.enclosing >= 0 {
		u.Enclosing = g.qualifiedName(r.enclosing)
	}
	return u
}

// References returns the reference candidates of a definition, in tree
// order.
func (g *Graph) References(id SymbolID) []Use {
	out := []Use{}
	if id < 0 || int(id) >= len(g.defs) {
		return out
	}
	g.candidates(g.targetOf(int32(id)), func(i int32, s Scope) bool {
		out = append(out, g.use(i, s))
		return true
	})
	return out
}

// TestReferences returns the reference candidates of a definition that are
// in test files.
func (g *Graph) TestReferences(id SymbolID) []Use {
	out := []Use{}
	for _, u := range g.References(id) {
		if u.Role == RoleTest {
			out = append(out, u)
		}
	}
	return out
}
