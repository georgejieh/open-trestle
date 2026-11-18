package repoindex

import (
	"slices"

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
	// file is -1 when the head has no file at the definition's path, and
	// unit is the definition's unit in the graph, or -1.
	file, unit int32
	family     family
	name       int32
	exported   bool
	// topLevel is a definition at the top level of its file that is not a
	// method or field of a type, which Go reaches only through a package;
	// member is a method or field, which Go reaches only through a selector.
	topLevel, member bool
	// importers are the files that imported the definition's file in the
	// base, for a definition whose file the head no longer has.
	importers map[int32]bool
}

func (g *Graph) targetOf(i int32) target {
	d := g.defs[i]
	f := g.files[d.file]
	member := d.kind == syntaxanalysis.KindMethod || d.kind == syntaxanalysis.KindField || d.container != 0
	return target{file: d.file, unit: f.unit, family: f.family, name: d.name, exported: d.exported, topLevel: d.parent < 0 && !member, member: member}
}

// scope applies the candidate rules to one reference.
func (g *Graph) scope(t target, r graphRef) Scope {
	from := g.files[r.file]
	if from.family.name != t.family.name || t.family.name == "" {
		return ""
	}
	if t.importers[r.file] && t.exported {
		return ScopeImport
	}
	if t.family.name == "go" {
		return g.goScope(t, r)
	}
	switch {
	case r.file == t.file:
		return ScopeFile
	case t.family.packages && t.unit >= 0 && from.unit == t.unit:
		return ScopePackage
	case !t.exported:
		return ""
	case g.importsTarget(r.file, t):
		return ScopeImport
	case t.family.global:
		return ScopeName
	}
	return ""
}

// goScope applies Go's rules: a reference qualified by the name an import
// binds refers to that package only, a top-level definition of another
// package is reached only through such a qualifier, a selector on a value
// reaches only a method or field, of its own package or of any package the
// file imports, and a bare name never reaches a method or field.
func (g *Graph) goScope(t target, r graphRef) Scope {
	qualifier := g.names[r.qualifier].Untrusted()
	if imported, ok := g.goImports[r.file][qualifier]; ok && qualifier != "" {
		if imported == t.unit && t.unit >= 0 && t.exported && t.topLevel {
			return ScopeImport
		}
		return ""
	}
	if t.topLevel && r.qualifier != 0 || t.member && r.qualifier == 0 {
		return ""
	}
	switch {
	case r.file == t.file:
		return ScopeFile
	case t.unit >= 0 && g.files[r.file].unit == t.unit:
		return ScopePackage
	case t.exported && !t.topLevel && r.qualifier != 0 && g.importsTarget(r.file, t):
		return ScopeImport
	}
	return ""
}

// searchUnits are the units whose references can be candidates of a target
// of a family without repository-wide names: its own unit, and the units of
// the files that import its file or unit.
func (g *Graph) searchUnits(t target) []int32 {
	importers := g.unitImporters.get(t.unit)
	if t.file >= 0 {
		importers = g.importersOf(t.file)
	}
	units := []int32{}
	if t.unit >= 0 {
		units = append(units, t.unit)
	}
	for _, f := range importers {
		units = append(units, g.files[f].unit)
	}
	for f := range t.importers {
		units = append(units, g.files[f].unit)
	}
	slices.Sort(units)
	return slices.Compact(units)
}

// candidates calls fn for every reference candidate of a target, in tree
// order, until fn returns false. Each reference it checks costs one unit of
// work; with a budget, it stops when the budget is spent and reports false.
func (g *Graph) candidates(t target, work *int, fn func(int32, Scope) bool) bool {
	var refs []int32
	if t.family.global {
		refs = g.refsByName.get(t.name)
	} else {
		for _, unit := range g.searchUnits(t) {
			refs = append(refs, g.refsIn(unit, t.name)...)
		}
		slices.Sort(refs)
	}
	for _, i := range refs {
		if work != nil {
			if *work <= 0 {
				return false
			}
			*work--
		}
		if s := g.scope(t, g.refs[i]); s != "" && !fn(i, s) {
			return true
		}
	}
	return true
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
	g.candidates(g.targetOf(int32(id)), nil, func(i int32, s Scope) bool {
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
