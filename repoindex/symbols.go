package repoindex

import (
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

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

// Files returns every file of the graph in tree order.
func (g *Graph) Files() []FileEntry {
	out := make([]FileEntry, len(g.files))
	for i, f := range g.files {
		out[i] = f.entry
	}
	return out
}
