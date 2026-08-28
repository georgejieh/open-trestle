package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestNewChangeImpactProfileBindsChangeAndSymbol(t *testing.T) {
	change, lineMaps := mustImpactChange(t, impactFileSpec{path: "main.go", headDigest: impactDigest(1), lineCount: 8})
	symbol := mustSymbol(t, lineMaps["main.go"], LanguageGo, SymbolKindFunction, "worker.Process", mustAnalysisRange(t, "main.go", 2, 6))
	profile, err := NewChangeImpactProfile(change, []Symbol{symbol})
	if err != nil {
		t.Fatalf("NewChangeImpactProfile() error = %v", err)
	}
	if len(profile.Identity()) != 64 || profile.ChangeIdentity() != change.Identity() {
		t.Fatalf("profile binding = (%q, %q)", profile.Identity(), profile.ChangeIdentity())
	}
	if got := profile.Symbols(); len(got) != 1 || got[0] != symbol {
		t.Fatalf("Symbols() = %#v", got)
	}
	if got := profile.SymbolsForPath("main.go"); len(got) != 1 || got[0] != symbol {
		t.Fatalf("SymbolsForPath() = %#v", got)
	}
	if got, ok := profile.SymbolByIdentity(symbol.Identity()); !ok || got != symbol {
		t.Fatalf("SymbolByIdentity() = (%#v, %t)", got, ok)
	}
}

func TestChangeImpactProfileIdentityUsesCanonicalPreimage(t *testing.T) {
	change, lineMaps := mustImpactChange(t, impactFileSpec{path: "main.go", headDigest: impactDigest(2), lineCount: 8})
	symbol := mustSymbol(t, lineMaps["main.go"], LanguageGo, SymbolKindMethod, "worker.Runner.Run", mustAnalysisRange(t, "main.go", 2, 6))
	profile, err := NewChangeImpactProfile(change, []Symbol{symbol})
	if err != nil {
		t.Fatalf("NewChangeImpactProfile() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/change-impact-profile","schema_version":1,"change_identity":"%s","symbols":[{"path":"main.go","symbol_identity":"%s"}]}`, change.Identity(), symbol.Identity())
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); profile.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", profile.Identity(), preimage)
	}
}

func TestNewChangeImpactProfileCanonicalizesSymbolOrder(t *testing.T) {
	change, lineMaps := mustImpactChange(t,
		impactFileSpec{path: "zeta.go", headDigest: impactDigest(3), lineCount: 12},
		impactFileSpec{path: "alpha.go", headDigest: impactDigest(4), lineCount: 12},
	)
	alphaLate := mustSymbol(t, lineMaps["alpha.go"], LanguageGo, SymbolKindMethod, "worker.T.Z", mustAnalysisRange(t, "alpha.go", 8, 10))
	alphaEarly := mustSymbol(t, lineMaps["alpha.go"], LanguageGo, SymbolKindFunction, "worker.A", mustAnalysisRange(t, "alpha.go", 2, 5))
	zeta := mustSymbol(t, lineMaps["zeta.go"], LanguageGo, SymbolKindFunction, "worker.Z", mustAnalysisRange(t, "zeta.go", 2, 5))
	permutations := [][]Symbol{
		{zeta, alphaLate, alphaEarly},
		{alphaEarly, zeta, alphaLate},
		{alphaLate, alphaEarly, zeta},
	}
	var wantIdentity string
	for i, symbols := range permutations {
		profile, err := NewChangeImpactProfile(change, symbols)
		if err != nil {
			t.Fatalf("permutation %d error = %v", i, err)
		}
		got := profile.Symbols()
		if len(got) != 3 || got[0] != alphaEarly || got[1] != alphaLate || got[2] != zeta {
			t.Fatalf("permutation %d Symbols() = %#v", i, got)
		}
		if i == 0 {
			wantIdentity = profile.Identity()
		} else if profile.Identity() != wantIdentity {
			t.Fatalf("permutation %d Identity() = %q, want %q", i, profile.Identity(), wantIdentity)
		}
	}
}

func TestNewChangeImpactProfileAcceptsEmptySymbols(t *testing.T) {
	change, _ := mustImpactChange(t, impactFileSpec{path: "notes.txt", headDigest: impactDigest(5), lineCount: 2})
	first, err := NewChangeImpactProfile(change, nil)
	if err != nil {
		t.Fatalf("NewChangeImpactProfile(nil) error = %v", err)
	}
	second, err := NewChangeImpactProfile(change, []Symbol{})
	if err != nil || second.Identity() != first.Identity() || first.Identity() == "" {
		t.Fatalf("empty profiles = (%q, %q, %v)", first.Identity(), second.Identity(), err)
	}
	if symbols := first.Symbols(); symbols == nil || len(symbols) != 0 {
		t.Fatalf("Symbols() = %#v, want non-nil empty", symbols)
	}
}

func TestChangeImpactProfileIdentityBindsChangeAndSymbols(t *testing.T) {
	baseChange, lineMaps := mustImpactChange(t, impactFileSpec{path: "main.go", headDigest: impactDigest(6), lineCount: 8})
	symbol := mustSymbol(t, lineMaps["main.go"], LanguageGo, SymbolKindFunction, "worker.Process", mustAnalysisRange(t, "main.go", 2, 6))
	base, err := NewChangeImpactProfile(baseChange, []Symbol{symbol})
	if err != nil {
		t.Fatalf("NewChangeImpactProfile(base) error = %v", err)
	}
	largerChange, _ := mustImpactChange(t,
		impactFileSpec{path: "main.go", headDigest: impactDigest(6), lineCount: 8},
		impactFileSpec{path: "notes.txt", headDigest: impactDigest(7), lineCount: 2},
	)
	larger, err := NewChangeImpactProfile(largerChange, []Symbol{symbol})
	if err != nil || larger.Identity() == base.Identity() {
		t.Fatalf("larger profile = (%q, %v), base %q", larger.Identity(), err, base.Identity())
	}
	changed, changedMaps := mustImpactChange(t, impactFileSpec{path: "main.go", headDigest: impactDigest(70), lineCount: 8})
	changedSymbol := mustSymbol(t, changedMaps["main.go"], LanguageGo, SymbolKindFunction, "worker.Process", mustAnalysisRange(t, "main.go", 2, 6))
	changedProfile, err := NewChangeImpactProfile(changed, []Symbol{changedSymbol})
	if err != nil || changedProfile.Identity() == base.Identity() {
		t.Fatalf("changed profile = (%q, %v), base %q", changedProfile.Identity(), err, base.Identity())
	}
	empty, err := NewChangeImpactProfile(baseChange, nil)
	if err != nil || empty.Identity() == base.Identity() {
		t.Fatalf("empty profile = (%q, %v), base %q", empty.Identity(), err, base.Identity())
	}
	other := mustSymbol(t, lineMaps["main.go"], LanguageGo, SymbolKindMethod, "worker.Runner.Run", mustAnalysisRange(t, "main.go", 2, 6))
	replaced, err := NewChangeImpactProfile(baseChange, []Symbol{other})
	if err != nil || replaced.Identity() == base.Identity() {
		t.Fatalf("replaced profile = (%q, %v), base %q", replaced.Identity(), err, base.Identity())
	}
}

func TestNewChangeImpactProfileRejectsInvalidBindings(t *testing.T) {
	change, lineMaps := mustImpactChange(t, impactFileSpec{path: "main.go", headDigest: impactDigest(8), lineCount: 8})
	valid := mustSymbol(t, lineMaps["main.go"], LanguageGo, SymbolKindFunction, "worker.Process", mustAnalysisRange(t, "main.go", 2, 6))
	otherChange, otherMaps := mustImpactChange(t, impactFileSpec{path: "main.go", headDigest: impactDigest(9), lineCount: 8})
	stale := mustSymbol(t, otherMaps["main.go"], LanguageGo, SymbolKindFunction, "worker.Process", mustAnalysisRange(t, "main.go", 2, 6))
	absentChange, absentMaps := mustImpactChange(t, impactFileSpec{path: "other.go", headDigest: impactDigest(10), lineCount: 8})
	absent := mustSymbol(t, absentMaps["other.go"], LanguageGo, SymbolKindFunction, "worker.Process", mustAnalysisRange(t, "other.go", 2, 6))
	_ = absentChange

	invalidIdentity := valid
	invalidIdentity.identity = "not-sha256"
	forgedIdentity := valid
	forgedIdentity.identity = impactDigest(99)
	forgedPath := valid
	forgedPath.path = "other.go"
	forgedFile := valid
	forgedFile.fileChangeIdentity = impactDigest(98)
	forgedMap := valid
	forgedMap.lineMapIdentity = impactDigest(97)
	forgedKind := valid
	forgedKind.kind = SymbolKindMethod
	forgedName := valid
	forgedName.qualifiedName = "worker.Other"
	forgedRange := valid
	forgedRange.sourceRange = mustAnalysisRange(t, "main.go", 1, 6)

	testCases := []struct {
		name    string
		change  evidence.Change
		symbols []Symbol
	}{
		{name: "zero change", symbols: []Symbol{valid}},
		{name: "zero symbol", change: change, symbols: []Symbol{{}}},
		{name: "invalid identity shape", change: change, symbols: []Symbol{invalidIdentity}},
		{name: "stale symbol", change: change, symbols: []Symbol{stale}},
		{name: "absent path", change: change, symbols: []Symbol{absent}},
		{name: "forged identity", change: change, symbols: []Symbol{forgedIdentity}},
		{name: "forged path", change: change, symbols: []Symbol{forgedPath}},
		{name: "forged file identity", change: change, symbols: []Symbol{forgedFile}},
		{name: "forged line map identity", change: change, symbols: []Symbol{forgedMap}},
		{name: "forged kind", change: change, symbols: []Symbol{forgedKind}},
		{name: "forged name", change: change, symbols: []Symbol{forgedName}},
		{name: "forged range", change: change, symbols: []Symbol{forgedRange}},
		{name: "duplicate", change: change, symbols: []Symbol{valid, valid}},
		{name: "wrong change", change: otherChange, symbols: []Symbol{valid}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			profile, err := NewChangeImpactProfile(testCase.change, testCase.symbols)
			if err == nil || profile.Identity() != "" {
				t.Fatalf("NewChangeImpactProfile() = (%#v, %v), want zero error result", profile, err)
			}
		})
	}
}

func TestNewChangeImpactProfileEnforcesSymbolLimit(t *testing.T) {
	change, lineMaps := mustImpactChange(t, impactFileSpec{path: "main.go", headDigest: impactDigest(11), lineCount: 8})
	atLimit := make([]Symbol, maxChangeImpactSymbols)
	for i := range atLimit {
		atLimit[i] = mustSymbol(t, lineMaps["main.go"], LanguageGo, SymbolKindFunction, fmt.Sprintf("worker.F%d", i), mustAnalysisRange(t, "main.go", 2, 6))
	}
	profile, err := NewChangeImpactProfile(change, atLimit)
	if err != nil || len(profile.Symbols()) != maxChangeImpactSymbols {
		t.Fatalf("NewChangeImpactProfile(at limit) = (%d Symbols, %v)", len(profile.Symbols()), err)
	}
	tooMany := make([]Symbol, maxChangeImpactSymbols+1)
	profile, err = NewChangeImpactProfile(change, tooMany)
	if err == nil || !strings.Contains(err.Error(), "exceeds") || profile.Identity() != "" {
		t.Fatalf("NewChangeImpactProfile(over limit) = (%#v, %v), want bounded zero error result", profile, err)
	}
}

func TestChangeImpactProfileAccessorsAreImmutableAndExact(t *testing.T) {
	change, lineMaps := mustImpactChange(t,
		impactFileSpec{path: "alpha.go", headDigest: impactDigest(12), lineCount: 8},
		impactFileSpec{path: "zeta.go", headDigest: impactDigest(13), lineCount: 8},
	)
	alpha := mustSymbol(t, lineMaps["alpha.go"], LanguageGo, SymbolKindFunction, "worker.Alpha", mustAnalysisRange(t, "alpha.go", 2, 6))
	zeta := mustSymbol(t, lineMaps["zeta.go"], LanguageGo, SymbolKindFunction, "worker.Zeta", mustAnalysisRange(t, "zeta.go", 2, 6))
	input := []Symbol{zeta, alpha}
	profile, err := NewChangeImpactProfile(change, input)
	if err != nil {
		t.Fatalf("NewChangeImpactProfile() error = %v", err)
	}
	identity := profile.Identity()
	input[0] = Symbol{}
	all := profile.Symbols()
	all[0] = Symbol{}
	byPath := profile.SymbolsForPath("alpha.go")
	byPath[0] = Symbol{}
	if profile.Identity() != identity || profile.Symbols()[0] != alpha || profile.SymbolsForPath("alpha.go")[0] != alpha {
		t.Fatal("caller mutation changed profile")
	}
	if got := profile.SymbolsForPath("missing.go"); got == nil || len(got) != 0 {
		t.Fatalf("missing path = %#v", got)
	}
	for _, invalidPath := range []string{"", "./alpha.go", "../alpha.go"} {
		if got := profile.SymbolsForPath(invalidPath); got == nil || len(got) != 0 {
			t.Fatalf("invalid path %q = %#v", invalidPath, got)
		}
	}
	for _, identity := range []string{"", "bad", impactDigest(14)} {
		if got, ok := profile.SymbolByIdentity(identity); ok || got != (Symbol{}) {
			t.Fatalf("unknown identity %q = (%#v, %t)", identity, got, ok)
		}
	}
}

type impactFileSpec struct {
	path       string
	headDigest string
	lineCount  int
}

func mustImpactChange(t *testing.T, specs ...impactFileSpec) (evidence.Change, map[string]evidence.LineMap) {
	t.Helper()
	fileChanges := make([]evidence.FileChange, len(specs))
	lineMaps := make([]evidence.LineMap, len(specs))
	byPath := make(map[string]evidence.LineMap, len(specs))
	for i, spec := range specs {
		changedRange := mustAnalysisRange(t, spec.path, 2, 2)
		fileChange, err := evidence.NewFileChange(spec.path, testBaseDigest, spec.headDigest, []evidence.SourceRange{changedRange})
		if err != nil {
			t.Fatalf("NewFileChange() error = %v", err)
		}
		hunk, err := evidence.NewHunk(fileChange, 2, 1, 2, 1)
		if err != nil {
			t.Fatalf("NewHunk() error = %v", err)
		}
		lineMap, err := evidence.NewLineMap(fileChange, spec.lineCount, spec.lineCount, []evidence.Hunk{hunk})
		if err != nil {
			t.Fatalf("NewLineMap() error = %v", err)
		}
		fileChanges[i] = fileChange
		lineMaps[i] = lineMap
		byPath[spec.path] = lineMap
	}
	change, err := evidence.NewChange(fileChanges, lineMaps)
	if err != nil {
		t.Fatalf("NewChange() error = %v", err)
	}
	return change, byPath
}

func impactDigest(value int) string {
	return fmt.Sprintf("%064x", value)
}
