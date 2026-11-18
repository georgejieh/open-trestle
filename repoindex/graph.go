package repoindex

import (
	"context"
	"errors"
	"path"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// Graph is the symbol graph of one snapshot, built in memory from the
// stored records. Its layout is compact so that a repository of a hundred
// thousand files fits: every name is interned once, records refer to names
// and files by number, and the name indexes are flat posting lists.
type Graph struct {
	coverage GraphCoverage
	files    []graphFile
	byPath   map[string]int32
	names    []syntaxanalysis.Text
	nameIDs  map[string]int32
	defs     []graphDef
	refs     []graphRef
	imports  []graphImport
	// defsByName and refsByName list definitions and references by name.
	defsByName, refsByName postings
	// units group files that see each other's definitions without an
	// import: a directory for languages with packages, the file otherwise.
	unitFiles postings
	units     map[string]int32
	// goModules are the snapshot's Go modules, which map import paths to
	// directories.
	goModules []GoModule
	// goImports maps, per Go file, the name of each imported package to
	// its unit, or -1 for a package outside the repository.
	goImports map[int32]map[string]int32
	// importEdges lists, per file, the units its imports resolve to, and
	// importers, per unit, the files that import it.
	importEdges, importers postings
	unresolved             []int32
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

// Snapshot returns the snapshot of an indexed commit.
func (s *Store) Snapshot(ctx context.Context, algorithm, commit string) (Snapshot, error) {
	sess, err := s.open(ctx, false)
	if err != nil {
		return Snapshot{}, err
	}
	defer sess.close()
	return sess.snapshot(algorithm, commit)
}

func (sess *session) snapshot(algorithm, commit string) (Snapshot, error) {
	snapshot, ok, err := sess.readSnapshot(snapshotName(algorithm, commit))
	if err == nil && !ok {
		err = ErrNotIndexed
	}
	return snapshot, err
}

// Load builds the graph of an indexed commit.
func (s *Store) Load(ctx context.Context, algorithm, commit string) (*Graph, error) {
	sess, err := s.open(ctx, false)
	if err != nil {
		return nil, err
	}
	defer sess.close()
	snapshot, err := sess.snapshot(algorithm, commit)
	if err != nil {
		return nil, err
	}
	g := newGraph(snapshot)
	for i, f := range snapshot.Files {
		if i%1024 == 0 && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var analysis *syntaxanalysis.FileAnalysis
		if f.Status == StatusIndexed {
			key := snapshot.key(f)
			record, err := sess.record(key)
			if err == nil && !record.binary {
				var decoded syntaxanalysis.FileAnalysis
				if decoded, err = record.decode(f.Path); err == nil {
					analysis = &decoded
				}
			}
			if errors.Is(err, errCorrupt) {
				// The next build analyses the files of a removed segment again.
				if sess.removeSegmentOf(key) == nil {
					return nil, ErrDamaged
				}
			}
			if err != nil {
				return nil, ErrUnavailable
			}
		}
		g.add(f, analysis)
	}
	g.finish()
	return g, nil
}

func newGraph(s Snapshot) *Graph {
	coverage := GraphCoverage{Commit: s.Commit, Coverage: s.Coverage, Statuses: map[Status]int{}}
	for _, f := range s.Files {
		coverage.Statuses[f.Status]++
	}
	coverage.Complete = !s.Coverage.TreeTruncated && s.Coverage.InvalidPaths == 0
	for _, status := range []Status{StatusUnavailable, StatusFileLimit, StatusByteLimit, StatusTimeLimit, StatusStoreLimit, StatusFailed} {
		coverage.Complete = coverage.Complete && coverage.Statuses[status] == 0
	}
	return &Graph{coverage: coverage, byPath: map[string]int32{}, nameIDs: map[string]int32{}, names: []syntaxanalysis.Text{{}}, goModules: s.Modules}
}

// GraphCoverage says how much of a commit a graph covers. Complete is false
// when the tree was cut, a path was left out, or a file that should have an
// analysis has none: a reference in such a file is not seen.
type GraphCoverage struct {
	Commit   string         `json:"commit"`
	Complete bool           `json:"complete"`
	Statuses map[Status]int `json:"files_by_status"`
	Coverage Coverage       `json:"build"`
}

// Coverage returns what the graph covers.
func (g *Graph) Coverage() GraphCoverage { return g.coverage }

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
	g.resolveImports()
}

func unitKey(familyName, scope string) string { return "unit\x00" + familyName + "\x00" + scope }

// packageScope names the package of a file of a language with packages:
// the declared package or namespace for Java, C# and PHP (the first one a
// file declares), and the directory otherwise.
func (g *Graph) packageScope(file int32) string {
	f := g.files[file]
	switch f.family.name {
	case "jvm", "dotnet", "php":
		for i := f.defs.start; i < f.defs.end; i++ {
			if g.defs[i].kind == syntaxanalysis.KindModule && g.defs[i].parent < 0 {
				return "pkg:" + g.names[g.defs[i].name].Untrusted()
			}
		}
	}
	return "dir:" + path.Dir(f.entry.Path)
}

// Files returns every file of the graph in tree order.
func (g *Graph) Files() []FileEntry {
	out := make([]FileEntry, len(g.files))
	for i, f := range g.files {
		out[i] = f.entry
	}
	return out
}

// Symbol is a definition. ID identifies it within its graph.
type Symbol struct {
	ID            SymbolID                      `json:"-"`
	Path          string                        `json:"path"`
	Role          Role                          `json:"role"`
	Language      syntaxanalysis.Language       `json:"language"`
	Kind          syntaxanalysis.DefinitionKind `json:"kind"`
	Name          syntaxanalysis.Text           `json:"name"`
	QualifiedName syntaxanalysis.Text           `json:"qualified_name"`
	Container     syntaxanalysis.Text           `json:"container,omitzero"`
	Exported      bool                          `json:"exported"`
	Range         syntaxanalysis.Range          `json:"range"`
	NameRange     syntaxanalysis.Range          `json:"name_range"`
}

// SymbolID identifies a definition within one graph.
type SymbolID int32

func (g *Graph) symbol(i int32) Symbol {
	d := g.defs[i]
	f := g.files[d.file]
	return Symbol{ID: SymbolID(i), Path: f.entry.Path, Role: f.entry.Role, Language: f.entry.Language, Kind: d.kind,
		Name: g.names[d.name], QualifiedName: g.qualifiedName(i), Container: g.names[d.container],
		Exported: d.exported, Range: d.rng.Range(), NameRange: d.nameRange.Range()}
}

func (g *Graph) qualifiedName(i int32) syntaxanalysis.Text {
	parts := []string{}
	for depth := 0; i >= 0 && depth < 256; i, depth = g.defs[i].parent, depth+1 {
		parts = append(parts, g.names[g.defs[i].name].Untrusted())
	}
	for l, r := 0, len(parts)-1; l < r; l, r = l+1, r-1 {
		parts[l], parts[r] = parts[r], parts[l]
	}
	return syntaxanalysis.NewText(strings.Join(parts, "."))
}

// Definitions returns the definitions with exactly this name, in tree
// order.
func (g *Graph) Definitions(name string) []Symbol {
	id, ok := g.nameIDs[name]
	if !ok {
		return []Symbol{}
	}
	out := []Symbol{}
	for _, i := range g.defsByName.get(id) {
		out = append(out, g.symbol(i))
	}
	return out
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
