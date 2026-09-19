package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// Bounds sorting and identity construction while allowing dense changes.
const maxChangeImpactSymbols = 1 << 16

// ChangeImpactProfile binds canonical changed Symbols to an exact Change.
type ChangeImpactProfile struct {
	identity          string
	changeIdentity    string
	symbols           []Symbol
	symbolsByIdentity map[string]int
}

// NewChangeImpactProfile creates an immutable canonical changed-Symbol profile.
func NewChangeImpactProfile(change evidence.Change, symbols []Symbol) (ChangeImpactProfile, error) {
	canonicalChange, err := evidence.NewChange(change.FileChanges(), change.LineMaps())
	if err != nil || canonicalChange.Identity() != change.Identity() {
		return ChangeImpactProfile{}, fmt.Errorf("change is not canonical")
	}
	if len(symbols) > maxChangeImpactSymbols {
		return ChangeImpactProfile{}, fmt.Errorf("change impact profile exceeds %d Symbols", maxChangeImpactSymbols)
	}

	fileChanges := canonicalChange.FileChanges()
	lineMaps := canonicalChange.LineMaps()
	bindings := make(map[string]changeImpactBinding, len(fileChanges))
	for i, fileChange := range fileChanges {
		bindings[fileChange.Path()] = changeImpactBinding{fileChange: fileChange, lineMap: lineMaps[i]}
	}

	canonicalSymbols := make([]Symbol, len(symbols))
	seenIdentities := make(map[string]struct{}, len(symbols))
	for i, symbol := range symbols {
		if !isSHA256Identity(symbol.Identity()) {
			return ChangeImpactProfile{}, fmt.Errorf("symbol %d has an invalid identity", i)
		}
		if _, exists := seenIdentities[symbol.Identity()]; exists {
			return ChangeImpactProfile{}, fmt.Errorf("duplicate Symbol identity at index %d", i)
		}
		binding, ok := bindings[symbol.Path()]
		if !ok || symbol.FileChangeIdentity() != binding.fileChange.Identity() {
			return ChangeImpactProfile{}, fmt.Errorf("symbol %d does not match Change file evidence", i)
		}
		if symbol.LineMapIdentity() != binding.lineMap.Identity() {
			return ChangeImpactProfile{}, fmt.Errorf("symbol %d does not match Change line evidence", i)
		}
		canonical, err := NewSymbol(binding.lineMap, symbol.Language(), symbol.Kind(), symbol.QualifiedName(), symbol.SourceRange())
		if err != nil || canonical.Identity() != symbol.Identity() {
			return ChangeImpactProfile{}, fmt.Errorf("symbol %d is not canonical", i)
		}
		seenIdentities[symbol.Identity()] = struct{}{}
		canonicalSymbols[i] = canonical
	}

	sort.Slice(canonicalSymbols, func(i, j int) bool {
		return changeImpactSymbolLess(canonicalSymbols[i], canonicalSymbols[j])
	})
	wireSymbols := make([]changeImpactSymbolWire, len(canonicalSymbols))
	for i, symbol := range canonicalSymbols {
		wireSymbols[i] = changeImpactSymbolWire{Path: symbol.Path(), SymbolIdentity: symbol.Identity()}
	}
	preimage := struct {
		Contract       string                   `json:"contract"`
		SchemaVersion  int                      `json:"schema_version"`
		ChangeIdentity string                   `json:"change_identity"`
		Symbols        []changeImpactSymbolWire `json:"symbols"`
	}{
		Contract:       "open-trestle/change-impact-profile",
		SchemaVersion:  1,
		ChangeIdentity: canonicalChange.Identity(),
		Symbols:        wireSymbols,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return ChangeImpactProfile{}, fmt.Errorf("encode change impact profile identity: %w", err)
	}
	digest := sha256.Sum256(encoded)
	byIdentity := make(map[string]int, len(canonicalSymbols))
	for i, symbol := range canonicalSymbols {
		byIdentity[symbol.Identity()] = i
	}
	return ChangeImpactProfile{
		identity:          hex.EncodeToString(digest[:]),
		changeIdentity:    canonicalChange.Identity(),
		symbols:           canonicalSymbols,
		symbolsByIdentity: byIdentity,
	}, nil
}

type changeImpactBinding struct {
	fileChange evidence.FileChange
	lineMap    evidence.LineMap
}

type changeImpactSymbolWire struct {
	Path           string `json:"path"`
	SymbolIdentity string `json:"symbol_identity"`
}

func changeImpactSymbolLess(left, right Symbol) bool {
	if left.Path() != right.Path() {
		return left.Path() < right.Path()
	}
	if left.SourceRange().StartLine() != right.SourceRange().StartLine() {
		return left.SourceRange().StartLine() < right.SourceRange().StartLine()
	}
	if left.SourceRange().EndLine() != right.SourceRange().EndLine() {
		return left.SourceRange().EndLine() < right.SourceRange().EndLine()
	}
	if left.Kind() != right.Kind() {
		return left.Kind() < right.Kind()
	}
	if left.QualifiedName() != right.QualifiedName() {
		return left.QualifiedName() < right.QualifiedName()
	}
	return left.Identity() < right.Identity()
}

// Identity returns the versioned canonical SHA-256 identity.
func (p ChangeImpactProfile) Identity() string {
	return p.identity
}

// ChangeIdentity returns the exact owning Change identity.
func (p ChangeImpactProfile) ChangeIdentity() string {
	return p.changeIdentity
}

// Symbols returns the canonical changed Symbols.
func (p ChangeImpactProfile) Symbols() []Symbol {
	result := make([]Symbol, len(p.symbols))
	copy(result, p.symbols)
	return result
}

// SymbolsForPath returns canonical Symbols for one exact path.
func (p ChangeImpactProfile) SymbolsForPath(path string) []Symbol {
	start := sort.Search(len(p.symbols), func(i int) bool {
		return p.symbols[i].Path() >= path
	})
	end := start
	for end < len(p.symbols) && p.symbols[end].Path() == path {
		end++
	}
	result := make([]Symbol, end-start)
	copy(result, p.symbols[start:end])
	return result
}

// SymbolByIdentity returns one exact canonical Symbol.
func (p ChangeImpactProfile) SymbolByIdentity(identity string) (Symbol, bool) {
	if !isSHA256Identity(identity) {
		return Symbol{}, false
	}
	index, ok := p.symbolsByIdentity[identity]
	if !ok {
		return Symbol{}, false
	}
	return p.symbols[index], true
}
