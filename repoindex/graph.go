package repoindex

import (
	"path"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// Graph is the symbol graph of one snapshot, built in memory from the
// stored records. Its layout is compact so that a repository of a hundred
// thousand files fits: every name is interned once, records refer to names
// and files by number, and the indexes are flat posting lists.
type Graph struct {
	coverage GraphCoverage
	files    []graphFile
	byPath   map[string]int32
	names    []syntaxanalysis.Text
	nameIDs  map[string]int32
	defs     []graphDef
	refs     []graphRef
	imports  []graphImport
	// defsByName lists definitions by name and refsByName references by
	// name; refsByUnit lists the references of each unit sorted by name.
	defsByName, refsByName, refsByUnit postings
	// units group files that see each other's definitions without an
	// import: a package for languages with packages, the file otherwise.
	unitFiles postings
	units     map[string]int32
	// unitPackage is the declared name of each Go package unit, or 0.
	unitPackage []int32
	// goModules are the snapshot's Go modules, which map import paths to
	// directories.
	goModules []GoModule
	// goImports maps, per Go file, the name each imported package binds to
	// its unit, or to -1 for a package outside the repository.
	goImports map[int32]map[string]int32
	// importUnits and importFiles list, per file, the units and the files
	// its imports resolve to; unitImporters and fileImporters reverse them.
	importUnits, importFiles, unitImporters, fileImporters postings
	unresolved                                             []int32
}

// span is a half-open range of a record slice.
type span struct{ start, end int32 }

type graphFile struct {
	entry    FileEntry
	analyzer string
	gaps     []syntaxanalysis.Gap
	family   family
	unit     int32
	defs     span
	refs     span
	imports  span
}

type range32 struct{ startByte, endByte, startLine, startColumn, endLine, endColumn int32 }

func toRange32(r syntaxanalysis.Range) range32 {
	return range32{int32(r.StartByte), int32(r.EndByte), int32(r.Start.Line), int32(r.Start.Column), int32(r.End.Line), int32(r.End.Column)}
}

func (r range32) Range() syntaxanalysis.Range {
	return syntaxanalysis.Range{StartByte: int(r.startByte), EndByte: int(r.endByte),
		Start: syntaxanalysis.Position{Line: int(r.startLine), Column: int(r.startColumn)},
		End:   syntaxanalysis.Position{Line: int(r.endLine), Column: int(r.endColumn)}}
}

// lines returns the first and last line of a range. A range that ends at
// column 1 ends on the line before, after its final newline.
func (r range32) lines() (int32, int32) {
	end := r.endLine
	if r.endColumn == 1 && end > r.startLine {
		end--
	}
	return r.startLine, end
}

type graphDef struct {
	file, parent    int32
	name, container int32
	kind            syntaxanalysis.DefinitionKind
	exported        bool
	rng, nameRange  range32
}

type graphRef struct {
	file, enclosing int32
	name, qualifier int32
	kind            syntaxanalysis.ReferenceKind
	rng             range32
}

type graphImport struct {
	file, enclosing     int32
	source, name, alias int32
	rng                 range32
}

// postings maps a dense key to a list of int32 values.
type postings struct{ offsets, values []int32 }

func (p postings) get(key int32) []int32 {
	if key < 0 || int(key)+1 >= len(p.offsets) {
		return nil
	}
	return p.values[p.offsets[key]:p.offsets[key+1]]
}

// buildPostings groups values by key with a counting sort, keeping the
// order of the values within each key.
func buildPostings(keys int, n int, keyOf func(int) int32, valueOf func(int) int32) postings {
	offsets := make([]int32, keys+1)
	for i := 0; i < n; i++ {
		if k := keyOf(i); k >= 0 {
			offsets[k+1]++
		}
	}
	for k := 1; k <= keys; k++ {
		offsets[k] += offsets[k-1]
	}
	values := make([]int32, offsets[keys])
	next := append([]int32(nil), offsets[:keys]...)
	for i := 0; i < n; i++ {
		if k := keyOf(i); k >= 0 {
			values[next[k]] = valueOf(i)
			next[k]++
		}
	}
	return postings{offsets: offsets, values: values}
}

func newGraph(s Snapshot) *Graph {
	return &Graph{coverage: newCoverage(s), byPath: map[string]int32{}, nameIDs: map[string]int32{}, names: []syntaxanalysis.Text{{}}, goModules: s.Modules}
}

func (g *Graph) intern(t syntaxanalysis.Text) int32 {
	v := t.Untrusted()
	if v == "" {
		return 0
	}
	if id, ok := g.nameIDs[v]; ok {
		return id
	}
	id := int32(len(g.names))
	g.names = append(g.names, t)
	g.nameIDs[v] = id
	return id
}

// add appends a file and its analysis. Record indices of the analysis
// become indices into the graph's slices.
func (g *Graph) add(f FileEntry, a *syntaxanalysis.FileAnalysis) {
	id := int32(len(g.files))
	gf := graphFile{entry: f, family: familyOf(f.Language)}
	base := int32(len(g.defs))
	gf.defs.start, gf.refs.start, gf.imports.start = base, int32(len(g.refs)), int32(len(g.imports))
	if a != nil {
		gf.analyzer, gf.gaps = a.Analyzer, a.Gaps
		gf.entry.Language = a.Language
		gf.family = familyOf(a.Language)
		g.coverage.addGaps(a.Gaps)
		global := func(i int) int32 {
			if i < 0 {
				return -1
			}
			return base + int32(i)
		}
		for _, d := range a.Definitions {
			g.defs = append(g.defs, graphDef{file: id, parent: global(d.Parent), name: g.intern(d.Name), container: g.intern(d.Container), kind: d.Kind, exported: d.Exported, rng: toRange32(d.Range), nameRange: toRange32(d.NameRange)})
		}
		for _, r := range a.References {
			g.refs = append(g.refs, graphRef{file: id, enclosing: global(r.Enclosing), name: g.intern(r.Name), qualifier: g.intern(r.Qualifier), kind: r.Kind, rng: toRange32(r.Range)})
		}
		for _, i := range a.Imports {
			g.imports = append(g.imports, graphImport{file: id, enclosing: global(i.Enclosing), source: g.intern(i.Source), name: g.intern(i.Name), alias: g.intern(i.Alias), rng: toRange32(i.Range)})
		}
	}
	gf.defs.end, gf.refs.end, gf.imports.end = int32(len(g.defs)), int32(len(g.refs)), int32(len(g.imports))
	g.files = append(g.files, gf)
	g.byPath[f.Path] = id
}

// finish builds the name indexes, the units and the import edges.
func (g *Graph) finish() {
	g.defsByName = buildPostings(len(g.names), len(g.defs), func(i int) int32 { return g.defs[i].name }, func(i int) int32 { return int32(i) })
	g.refsByName = buildPostings(len(g.names), len(g.refs), func(i int) int32 { return g.refs[i].name }, func(i int) int32 { return int32(i) })
	g.units = map[string]int32{}
	for i := range g.files {
		f := &g.files[i]
		key := "file\x00" + f.entry.Path
		if f.family.packages {
			key = unitKey(f.family.name, g.packageScope(int32(i)))
		}
		id, ok := g.units[key]
		if !ok {
			id = int32(len(g.units))
			g.units[key] = id
		}
		f.unit = id
	}
	g.unitFiles = buildPostings(len(g.units), len(g.files), func(i int) int32 { return g.files[i].unit }, func(i int) int32 { return int32(i) })
	// refsByName lists references in name order within each name, so the
	// references of a unit come out sorted by name.
	byName := g.refsByName.values
	g.refsByUnit = buildPostings(len(g.units), len(byName), func(i int) int32 { return g.files[g.refs[byName[i]].file].unit }, func(i int) int32 { return byName[i] })
	g.unitPackage = make([]int32, len(g.units))
	for i, f := range g.files {
		if f.family.name == "go" && g.unitPackage[f.unit] == 0 && !strings.HasSuffix(f.entry.Path, "_test.go") {
			g.unitPackage[f.unit] = g.declaredPackage(int32(i))
		}
	}
	g.resolveImports()
}

// refsIn returns the references of a unit that have a name.
func (g *Graph) refsIn(unit, name int32) []int32 {
	refs := g.refsByUnit.get(unit)
	lo, _ := slices.BinarySearchFunc(refs, name, func(r, n int32) int { return int(g.refs[r].name - n) })
	hi := lo
	for hi < len(refs) && g.refs[refs[hi]].name == name {
		hi++
	}
	return refs[lo:hi]
}

func unitKey(familyName, scope string) string { return "unit\x00" + familyName + "\x00" + scope }

// declaredPackage returns the name of the first top-level module
// definition of a file: its package or namespace declaration.
func (g *Graph) declaredPackage(file int32) int32 {
	f := g.files[file]
	for i := f.defs.start; i < f.defs.end; i++ {
		if g.defs[i].kind == syntaxanalysis.KindModule && g.defs[i].parent < 0 {
			return g.defs[i].name
		}
	}
	return 0
}

// packageScope names the package of a file of a language with packages:
// the declared package or namespace for Java, C# and PHP (the first one a
// file declares), and the directory otherwise.
func (g *Graph) packageScope(file int32) string {
	f := g.files[file]
	switch f.family.name {
	case "jvm", "dotnet", "php":
		if name := g.declaredPackage(file); name != 0 {
			return "pkg:" + g.names[name].Untrusted()
		}
	}
	return "dir:" + path.Dir(f.entry.Path)
}
