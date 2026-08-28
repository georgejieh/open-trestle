package analysis

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestResolveGoChangeSymbolsReturnsCanonicalFileOrder(t *testing.T) {
	alpha := []byte("package worker\n\nfunc Alpha() { println(1) }\n")
	zeta := []byte("package worker\n\nfunc Zeta() { println(2) }\n")
	change := mustCombinedAnalysisChange(t,
		mustChangedSymbolChange(t, "zeta.go", zeta, []evidence.SourceRange{mustAnalysisRange(t, "zeta.go", 3, 3)}),
		mustChangedSymbolChange(t, "alpha.go", alpha, []evidence.SourceRange{mustAnalysisRange(t, "alpha.go", 3, 3)}),
	)
	contents := make(map[string][]byte)
	contents["zeta.go"] = zeta
	contents["alpha.go"] = alpha

	symbols, err := ResolveGoChangeSymbols(change, contents)
	if err != nil {
		t.Fatalf("ResolveGoChangeSymbols() error = %v", err)
	}
	if len(symbols) != 2 || symbols[0].Path() != "alpha.go" || symbols[1].Path() != "zeta.go" {
		t.Fatalf("Symbol paths = %#v", symbolPaths(symbols))
	}
	for i := 0; i < 20; i++ {
		reordered := make(map[string][]byte)
		if i%2 == 0 {
			reordered["alpha.go"] = alpha
			reordered["zeta.go"] = zeta
		} else {
			reordered["zeta.go"] = zeta
			reordered["alpha.go"] = alpha
		}
		repeated, err := ResolveGoChangeSymbols(change, reordered)
		if err != nil || len(repeated) != len(symbols) || repeated[0] != symbols[0] || repeated[1] != symbols[1] {
			t.Fatalf("iteration %d = (%#v, %v), want %#v", i, repeated, err, symbols)
		}
	}
}

func TestResolveGoChangeSymbolsKeepsSameNamesInDifferentFiles(t *testing.T) {
	first := []byte("package worker\n\nfunc Process() {}\n")
	second := append([]byte(nil), first...)
	change := mustCombinedAnalysisChange(t,
		mustChangedSymbolChange(t, "a.go", first, []evidence.SourceRange{mustAnalysisRange(t, "a.go", 3, 3)}),
		mustChangedSymbolChange(t, "b.go", second, []evidence.SourceRange{mustAnalysisRange(t, "b.go", 3, 3)}),
	)
	symbols, err := ResolveGoChangeSymbols(change, map[string][]byte{"b.go": second, "a.go": first})
	if err != nil || len(symbols) != 2 {
		t.Fatalf("ResolveGoChangeSymbols() = (%#v, %v)", symbols, err)
	}
	if symbols[0].QualifiedName() != symbols[1].QualifiedName() || symbols[0].Identity() == symbols[1].Identity() {
		t.Fatalf("same-name Symbols = (%#v, %#v)", symbols[0], symbols[1])
	}
}

func TestResolveGoChangeSymbolsPreservesPerFileResolution(t *testing.T) {
	source := []byte("package worker\n\nfunc First() {\n\tone := 1\n\tprintln(one)\n}\n\nfunc Second() {}\n")
	ranges := []evidence.SourceRange{
		mustAnalysisRange(t, "main.go", 4, 4),
		mustAnalysisRange(t, "main.go", 6, 6),
		mustAnalysisRange(t, "main.go", 8, 8),
	}
	change := mustChangedSymbolChange(t, "main.go", source, ranges)
	symbols, err := ResolveGoChangeSymbols(change, map[string][]byte{"main.go": source})
	if err != nil || len(symbols) != 2 {
		t.Fatalf("ResolveGoChangeSymbols() = (%#v, %v)", symbols, err)
	}
	if symbols[0].QualifiedName() != "worker.First" || symbols[1].QualifiedName() != "worker.Second" {
		t.Fatalf("qualified names = (%q, %q)", symbols[0].QualifiedName(), symbols[1].QualifiedName())
	}
}

func TestResolveGoChangeSymbolsUsesExactGoManifest(t *testing.T) {
	goSource := []byte("package worker\n\nfunc Process() {}\n")
	textSource := []byte("notes\n")
	goChange := mustChangedSymbolChange(t, "main.go", goSource, []evidence.SourceRange{mustAnalysisRange(t, "main.go", 3, 3)})
	textChange := mustChangedSymbolChange(t, "notes.txt", textSource, []evidence.SourceRange{mustAnalysisRange(t, "notes.txt", 1, 1)})
	change := mustCombinedAnalysisChange(t, textChange, goChange)

	symbols, err := ResolveGoChangeSymbols(change, map[string][]byte{"main.go": goSource})
	if err != nil || len(symbols) != 1 || symbols[0].Path() != "main.go" {
		t.Fatalf("ResolveGoChangeSymbols() = (%#v, %v)", symbols, err)
	}

	invalidManifests := []map[string][]byte{
		{},
		{"main.go": goSource, "missing.go": goSource},
		{"main.go": goSource, "notes.txt": textSource},
		{"main.go": goSource, "./main.go": goSource},
		{"main.go": goSource, "../main.go": goSource},
	}
	for i, manifest := range invalidManifests {
		symbols, err := ResolveGoChangeSymbols(change, manifest)
		if err == nil || symbols != nil {
			t.Fatalf("manifest %d result = (%#v, %v), want nil error result", i, symbols, err)
		}
	}
}

func TestResolveGoChangeSymbolsReturnsEmptyForChangeWithoutGo(t *testing.T) {
	text := []byte("notes\n")
	change := mustChangedSymbolChange(t, "notes.txt", text, []evidence.SourceRange{mustAnalysisRange(t, "notes.txt", 1, 1)})
	for _, contents := range []map[string][]byte{nil, {}} {
		symbols, err := ResolveGoChangeSymbols(change, contents)
		if err != nil || symbols == nil || len(symbols) != 0 {
			t.Fatalf("ResolveGoChangeSymbols() = (%#v, %v), want non-nil empty", symbols, err)
		}
	}
}

func TestResolveGoChangeSymbolsRequiresDeletionOnlyContent(t *testing.T) {
	change := mustDeletionChange(t, "deleted.go")
	symbols, err := ResolveGoChangeSymbols(change, map[string][]byte{"deleted.go": nil})
	if err != nil || symbols == nil || len(symbols) != 0 {
		t.Fatalf("ResolveGoChangeSymbols() = (%#v, %v), want non-nil empty", symbols, err)
	}
	for _, contents := range []map[string][]byte{nil, {"deleted.go": []byte("wrong")}} {
		symbols, err := ResolveGoChangeSymbols(change, contents)
		if err == nil || symbols != nil {
			t.Fatalf("invalid deletion manifest = (%#v, %v), want nil error result", symbols, err)
		}
	}

	remaining := []byte("not valid Go\n")
	remainingChange := mustDeletionOnlySourceChange(t, "remaining.go", remaining)
	symbols, err = ResolveGoChangeSymbols(remainingChange, map[string][]byte{"remaining.go": remaining})
	if err != nil || symbols == nil || len(symbols) != 0 {
		t.Fatalf("remaining deletion-only result = (%#v, %v)", symbols, err)
	}
}

func TestResolveGoChangeSymbolsFailsAtomically(t *testing.T) {
	valid := []byte("package worker\n\nfunc First() {}\n")
	invalidSources := []struct {
		name   string
		path   string
		source []byte
		line   int
	}{
		{name: "malformed", path: "z.go", source: []byte("package worker\n\nfunc Broken( {\n"), line: 3},
		{name: "unsupported receiver", path: "z.go", source: []byte("package worker\n\ntype T struct{}\nfunc (**T) Bad() {}\n"), line: 4},
	}
	for _, testCase := range invalidSources {
		t.Run(testCase.name, func(t *testing.T) {
			change := mustCombinedAnalysisChange(t,
				mustChangedSymbolChange(t, "a.go", valid, []evidence.SourceRange{mustAnalysisRange(t, "a.go", 3, 3)}),
				mustChangedSymbolChange(t, testCase.path, testCase.source, []evidence.SourceRange{mustAnalysisRange(t, testCase.path, testCase.line, testCase.line)}),
			)
			symbols, err := ResolveGoChangeSymbols(change, map[string][]byte{"a.go": valid, testCase.path: testCase.source})
			if err == nil || symbols != nil {
				t.Fatalf("ResolveGoChangeSymbols() = (%#v, %v), want nil error result", symbols, err)
			}
		})
	}
}

func TestResolveGoChangeSymbolsPropagatesContentErrors(t *testing.T) {
	valid := []byte("package worker\n\nfunc Process() {}\n")
	validRange := mustAnalysisRange(t, "main.go", 3, 3)
	nul := []byte("package worker\x00\n")
	invalidUTF8 := []byte{'p', 'a', 'c', 'k', 'a', 'g', 'e', ' ', 0xff, '\n'}
	oversized := append([]byte("package worker\n"), bytes.Repeat([]byte{' '}, maxGoSourceBytes)...)
	testCases := []struct {
		name    string
		change  evidence.Change
		path    string
		content []byte
	}{
		{name: "zero change", path: "main.go", content: valid},
		{name: "wrong digest", change: mustChangedSymbolChange(t, "main.go", valid, []evidence.SourceRange{validRange}), path: "main.go", content: []byte("package other\n")},
		{name: "wrong count", change: mustResolverChange(t, "main.go", valid, validRange, physicalGoLineCount(valid)+1), path: "main.go", content: valid},
		{name: "NUL", change: mustChangedSymbolChange(t, "nul.go", nul, []evidence.SourceRange{mustAnalysisRange(t, "nul.go", 1, 1)}), path: "nul.go", content: nul},
		{name: "invalid UTF-8", change: mustChangedSymbolChange(t, "utf.go", invalidUTF8, []evidence.SourceRange{mustAnalysisRange(t, "utf.go", 1, 1)}), path: "utf.go", content: invalidUTF8},
		{name: "oversized", change: mustChangedSymbolChange(t, "large.go", oversized, []evidence.SourceRange{mustAnalysisRange(t, "large.go", 1, 1)}), path: "large.go", content: oversized},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			symbols, err := ResolveGoChangeSymbols(testCase.change, map[string][]byte{testCase.path: testCase.content})
			if err == nil || symbols != nil {
				t.Fatalf("ResolveGoChangeSymbols() = (%#v, %v), want nil error result", symbols, err)
			}
		})
	}
}

func TestResolveGoChangeSymbolsUsesPhysicalPathsAndRanges(t *testing.T) {
	alpha := []byte("package worker\n//line z.go:900\nfunc Alpha() { println(1) }\n")
	zeta := []byte("package worker\n//line a.go:1\nfunc Zeta() { println(2) }\n")
	change := mustCombinedAnalysisChange(t,
		mustChangedSymbolChange(t, "zeta.go", zeta, []evidence.SourceRange{mustAnalysisRange(t, "zeta.go", 3, 3)}),
		mustChangedSymbolChange(t, "alpha.go", alpha, []evidence.SourceRange{mustAnalysisRange(t, "alpha.go", 3, 3)}),
	)
	symbols, err := ResolveGoChangeSymbols(change, map[string][]byte{"zeta.go": zeta, "alpha.go": alpha})
	if err != nil || len(symbols) != 2 {
		t.Fatalf("ResolveGoChangeSymbols() = (%#v, %v)", symbols, err)
	}
	if symbols[0].Path() != "alpha.go" || symbols[0].SourceRange().StartLine() != 3 || symbols[1].Path() != "zeta.go" || symbols[1].SourceRange().StartLine() != 3 {
		t.Fatalf("physical Symbols = (%#v, %#v)", symbols[0], symbols[1])
	}
}

func TestResolveGoChangeSymbolsIsDeterministicAndImmutable(t *testing.T) {
	source := []byte("package worker\n\nfunc Process() {}\n")
	change := mustChangedSymbolChange(t, "main.go", source, []evidence.SourceRange{mustAnalysisRange(t, "main.go", 3, 3)})
	contents := map[string][]byte{"main.go": source}
	first, err := ResolveGoChangeSymbols(change, contents)
	if err != nil || len(first) != 1 {
		t.Fatalf("first = (%#v, %v)", first, err)
	}
	identity := first[0].Identity()
	for i := range source {
		source[i] = 'x'
	}
	first[0] = Symbol{}
	fresh := []byte("package worker\n\nfunc Process() {}\n")
	repeated, err := ResolveGoChangeSymbols(change, map[string][]byte{"main.go": fresh})
	if err != nil || len(repeated) != 1 || repeated[0].Identity() != identity {
		t.Fatalf("repeated = (%#v, %v), want identity %q", repeated, err, identity)
	}
}

func TestResolveGoChangeSymbolsHandlesManyFiles(t *testing.T) {
	const fileCount = 128
	changes := make([]evidence.Change, 0, fileCount)
	contents := make(map[string][]byte, fileCount)
	for i := fileCount - 1; i >= 0; i-- {
		path := fmt.Sprintf("pkg/%03d.go", i)
		source := []byte(fmt.Sprintf("package worker\n\nfunc F%03d() {}\n", i))
		contents[path] = source
		changes = append(changes, mustChangedSymbolChange(t, path, source, []evidence.SourceRange{mustAnalysisRange(t, path, 3, 3)}))
	}
	change := mustCombinedAnalysisChange(t, changes...)
	symbols, err := ResolveGoChangeSymbols(change, contents)
	if err != nil || len(symbols) != fileCount {
		t.Fatalf("ResolveGoChangeSymbols() returned %d Symbols, error = %v", len(symbols), err)
	}
	if symbols[0].Path() != "pkg/000.go" || symbols[fileCount-1].Path() != "pkg/127.go" {
		t.Fatalf("boundary paths = (%q, %q)", symbols[0].Path(), symbols[fileCount-1].Path())
	}
}

func mustCombinedAnalysisChange(t *testing.T, changes ...evidence.Change) evidence.Change {
	t.Helper()
	fileChanges := make([]evidence.FileChange, 0, len(changes))
	lineMaps := make([]evidence.LineMap, 0, len(changes))
	for _, change := range changes {
		fileChanges = append(fileChanges, change.FileChanges()...)
		lineMaps = append(lineMaps, change.LineMaps()...)
	}
	combined, err := evidence.NewChange(fileChanges, lineMaps)
	if err != nil {
		t.Fatalf("NewChange() error = %v", err)
	}
	return combined
}

func symbolPaths(symbols []Symbol) []string {
	paths := make([]string, len(symbols))
	for i, symbol := range symbols {
		paths[i] = symbol.Path()
	}
	return paths
}
