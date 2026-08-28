package analysis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestResolveGoEnclosingSymbolFindsPackageFunction(t *testing.T) {
	source := []byte("package worker\n\nfunc Process() {\n\tprintln(\"x\")\n}\n")
	selection := mustAnalysisRange(t, "main.go", 4, 4)
	change := mustResolverChange(t, "main.go", source, selection, physicalGoLineCount(source))
	symbol, found, err := ResolveGoEnclosingSymbol(change, source, selection)
	if err != nil || !found {
		t.Fatalf("ResolveGoEnclosingSymbol() = (%#v, %t, %v)", symbol, found, err)
	}
	if symbol.Language() != LanguageGo || symbol.Kind() != SymbolKindFunction || symbol.QualifiedName() != "worker.Process" {
		t.Fatalf("Symbol = (%q, %q, %q)", symbol.Language(), symbol.Kind(), symbol.QualifiedName())
	}
	if symbol.SourceRange() != mustAnalysisRange(t, "main.go", 3, 5) {
		t.Fatalf("SourceRange() = %#v, want main.go:3-5", symbol.SourceRange())
	}
	lineMap, _ := change.LineMapForPath("main.go")
	if symbol.LineMapIdentity() != lineMap.Identity() || symbol.FileChangeIdentity() != lineMap.FileChangeIdentity() {
		t.Fatal("Symbol does not bind exact line evidence")
	}
}

func TestResolveGoEnclosingSymbolNormalizesMethodReceivers(t *testing.T) {
	testCases := []struct {
		name     string
		source   string
		wantName string
	}{
		{name: "value", source: "package worker\n\ntype Runner struct{}\nfunc (Runner) Run() { println(1) }\n", wantName: "worker.Runner.Run"},
		{name: "pointer", source: "package worker\n\ntype Runner struct{}\nfunc (*Runner) Run() { println(1) }\n", wantName: "worker.Runner.Run"},
		{name: "generic value", source: "package worker\n\ntype Box[T any] struct{}\nfunc (Box[T]) Get() { println(1) }\n", wantName: "worker.Box.Get"},
		{name: "generic pointer", source: "package worker\n\ntype Box[T any] struct{}\nfunc (*Box[T]) Get() { println(1) }\n", wantName: "worker.Box.Get"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := []byte(testCase.source)
			selection := mustAnalysisRange(t, "method.go", 4, 4)
			change := mustResolverChange(t, "method.go", source, selection, physicalGoLineCount(source))
			symbol, found, err := ResolveGoEnclosingSymbol(change, source, selection)
			if err != nil || !found {
				t.Fatalf("ResolveGoEnclosingSymbol() = (%#v, %t, %v)", symbol, found, err)
			}
			if symbol.Kind() != SymbolKindMethod || symbol.QualifiedName() != testCase.wantName {
				t.Fatalf("method = (%q, %q), want (%q, %q)", symbol.Kind(), symbol.QualifiedName(), SymbolKindMethod, testCase.wantName)
			}
		})
	}
}

func TestResolveGoEnclosingSymbolUsesWholeDeclarationContainment(t *testing.T) {
	source := []byte("package worker\n\nfunc Process(\n\tvalue int,\n) int {\n\tcallback := func() int {\n\t\treturn value\n\t}\n\treturn callback()\n}\n")
	for _, line := range []int{3, 4, 5, 6, 7, 8, 9, 10} {
		t.Run(strconv.Itoa(line), func(t *testing.T) {
			selection := mustAnalysisRange(t, "main.go", line, line)
			change := mustResolverChange(t, "main.go", source, selection, physicalGoLineCount(source))
			symbol, found, err := ResolveGoEnclosingSymbol(change, source, selection)
			if err != nil || !found || symbol.QualifiedName() != "worker.Process" || symbol.SourceRange() != mustAnalysisRange(t, "main.go", 3, 10) {
				t.Fatalf("line %d result = (%#v, %t, %v)", line, symbol, found, err)
			}
		})
	}
}

func TestResolveGoEnclosingSymbolIncludesAttachedDocumentation(t *testing.T) {
	testCases := []struct {
		name      string
		source    string
		selection evidence.SourceRange
		wantRange evidence.SourceRange
		found     bool
	}{
		{
			name:      "line documentation",
			source:    "package worker\n// Process runs work.\nfunc Process() {}\n",
			selection: mustAnalysisRange(t, "main.go", 2, 2),
			wantRange: mustAnalysisRange(t, "main.go", 2, 3),
			found:     true,
		},
		{
			name:      "block documentation",
			source:    "package worker\n/* Process runs\nwork. */\nfunc Process() {}\n",
			selection: mustAnalysisRange(t, "main.go", 2, 3),
			wantRange: mustAnalysisRange(t, "main.go", 2, 4),
			found:     true,
		},
		{
			name:      "detached comment",
			source:    "package worker\n// Detached.\n\nfunc Process() {}\n",
			selection: mustAnalysisRange(t, "main.go", 2, 2),
			found:     false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			source := []byte(testCase.source)
			change := mustResolverChange(t, "main.go", source, testCase.selection, physicalGoLineCount(source))
			symbol, found, err := ResolveGoEnclosingSymbol(change, source, testCase.selection)
			if err != nil || found != testCase.found {
				t.Fatalf("ResolveGoEnclosingSymbol() = (%#v, %t, %v)", symbol, found, err)
			}
			if found && symbol.SourceRange() != testCase.wantRange {
				t.Fatalf("SourceRange() = %#v, want %#v", symbol.SourceRange(), testCase.wantRange)
			}
			if !found && symbol != (Symbol{}) {
				t.Fatalf("not-found Symbol = %#v", symbol)
			}
		})
	}
}

func TestResolveGoEnclosingSymbolReturnsNotFoundForTopLevelSelection(t *testing.T) {
	source := []byte("package worker\n\nimport \"fmt\"\n\ntype Runner struct{}\n\nvar value = fmt.Sprint(1)\n")
	for _, line := range []int{1, 2, 3, 5, 7} {
		selection := mustAnalysisRange(t, "main.go", line, line)
		change := mustResolverChange(t, "main.go", source, selection, physicalGoLineCount(source))
		symbol, found, err := ResolveGoEnclosingSymbol(change, source, selection)
		if err != nil || found || symbol != (Symbol{}) {
			t.Fatalf("line %d result = (%#v, %t, %v), want not found", line, symbol, found, err)
		}
	}
}

func TestResolveGoEnclosingSymbolDoesNotGuessAcrossDeclarations(t *testing.T) {
	source := []byte("package worker\n\nfunc First() {}\nfunc Second() {}\n")
	selection := mustAnalysisRange(t, "main.go", 3, 4)
	change := mustResolverChange(t, "main.go", source, selection, physicalGoLineCount(source))
	symbol, found, err := ResolveGoEnclosingSymbol(change, source, selection)
	if err != nil || found || symbol != (Symbol{}) {
		t.Fatalf("ResolveGoEnclosingSymbol() = (%#v, %t, %v), want not found", symbol, found, err)
	}
}

func TestResolveGoEnclosingSymbolUsesPhysicalPositions(t *testing.T) {
	source := []byte("package worker\n//line other.go:100\nfunc Process() {\n\t//line fake.go:200\n\tprintln(1)\n}\n")
	selection := mustAnalysisRange(t, "main.go", 5, 5)
	change := mustResolverChange(t, "main.go", source, selection, physicalGoLineCount(source))
	symbol, found, err := ResolveGoEnclosingSymbol(change, source, selection)
	if err != nil || !found {
		t.Fatalf("ResolveGoEnclosingSymbol() = (%#v, %t, %v)", symbol, found, err)
	}
	if symbol.Path() != "main.go" || symbol.SourceRange() != mustAnalysisRange(t, "main.go", 3, 6) {
		t.Fatalf("physical Symbol = (%q, %#v)", symbol.Path(), symbol.SourceRange())
	}
}

func TestResolveGoEnclosingSymbolRejectsInvalidEvidenceBinding(t *testing.T) {
	source := []byte("package worker\n\nfunc Process() {\n\tprintln(1)\n}\n")
	changed := mustAnalysisRange(t, "main.go", 4, 4)
	change := mustResolverChange(t, "main.go", source, changed, physicalGoLineCount(source))
	outside := mustAnalysisRange(t, "main.go", 3, 3)
	emptyChange := mustDeletionChange(t, "empty.go")
	testCases := []struct {
		name      string
		change    evidence.Change
		content   []byte
		selection evidence.SourceRange
	}{
		{name: "zero change", content: source, selection: changed},
		{name: "zero selection", change: change, content: source},
		{name: "missing path", change: change, content: source, selection: mustAnalysisRange(t, "other.go", 4, 4)},
		{name: "outside changed range", change: change, content: source, selection: outside},
		{name: "crosses changed range", change: change, content: source, selection: mustAnalysisRange(t, "main.go", 3, 4)},
		{name: "past head", change: change, content: source, selection: mustAnalysisRange(t, "main.go", 1, 99)},
		{name: "deletion-only empty head", change: emptyChange, content: nil, selection: mustAnalysisRange(t, "empty.go", 1, 1)},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			assertGoResolverError(t, testCase.change, testCase.content, testCase.selection)
		})
	}
}

func TestResolveGoEnclosingSymbolAcceptsSourceAtByteLimit(t *testing.T) {
	prefix := []byte("package worker\n\nfunc Process() {\n\t//")
	suffix := []byte("\n}\n")
	padding := maxGoSourceBytes - len(prefix) - len(suffix)
	source := append(append(append([]byte(nil), prefix...), bytes.Repeat([]byte{'x'}, padding)...), suffix...)
	if len(source) != maxGoSourceBytes {
		t.Fatalf("source length = %d, want %d", len(source), maxGoSourceBytes)
	}
	selection := mustAnalysisRange(t, "large.go", 3, 3)
	change := mustResolverChange(t, "large.go", source, selection, physicalGoLineCount(source))
	symbol, found, err := ResolveGoEnclosingSymbol(change, source, selection)
	if err != nil || !found || symbol.QualifiedName() != "worker.Process" {
		t.Fatalf("ResolveGoEnclosingSymbol(at limit) = (%#v, %t, %v)", symbol, found, err)
	}
}

func TestResolveGoEnclosingSymbolRejectsInvalidContent(t *testing.T) {
	source := []byte("package worker\n\nfunc Process() {\n\tprintln(1)\n}\n")
	selection := mustAnalysisRange(t, "main.go", 4, 4)
	change := mustResolverChange(t, "main.go", source, selection, physicalGoLineCount(source))
	assertGoResolverError(t, change, []byte("package worker\n\nfunc Other() {}\n"), selection)

	wrongCountChange := mustResolverChange(t, "main.go", source, selection, physicalGoLineCount(source)+1)
	assertGoResolverError(t, wrongCountChange, source, selection)

	oversized := append([]byte("package worker\n"), bytes.Repeat([]byte{' '}, maxGoSourceBytes)...)
	overSelection := mustAnalysisRange(t, "large.go", 1, 1)
	overChange := mustResolverChange(t, "large.go", oversized, overSelection, physicalGoLineCount(oversized))
	assertGoResolverError(t, overChange, oversized, overSelection)

	nulContent := []byte("package worker\x00\n")
	nulSelection := mustAnalysisRange(t, "nul.go", 1, 1)
	nulChange := mustResolverChange(t, "nul.go", nulContent, nulSelection, physicalGoLineCount(nulContent))
	assertGoResolverError(t, nulChange, nulContent, nulSelection)

	invalidUTF8 := []byte{'p', 'a', 'c', 'k', 'a', 'g', 'e', ' ', 'x', 0xff, '\n'}
	utfSelection := mustAnalysisRange(t, "utf.go", 1, 1)
	utfChange := mustResolverChange(t, "utf.go", invalidUTF8, utfSelection, physicalGoLineCount(invalidUTF8))
	assertGoResolverError(t, utfChange, invalidUTF8, utfSelection)

	textSelection := mustAnalysisRange(t, "main.txt", 1, 1)
	textChange := mustResolverChange(t, "main.txt", []byte("package worker\n"), textSelection, 1)
	assertGoResolverError(t, textChange, []byte("package worker\n"), textSelection)
}

func TestResolveGoEnclosingSymbolRejectsMalformedGo(t *testing.T) {
	testCases := []string{
		"pack worker\n",
		"package worker\nfunc Process( {\n",
		"package worker\nfunc Process() {\n",
		"package worker\nfunc (x interface{}) Method() {}\n",
	}
	for i, sourceText := range testCases {
		path := "bad.go"
		source := []byte(sourceText)
		selection := mustAnalysisRange(t, path, 1, 1)
		if i > 0 {
			selection = mustAnalysisRange(t, path, 2, 2)
		}
		change := mustResolverChange(t, path, source, selection, physicalGoLineCount(source))
		assertGoResolverError(t, change, source, selection)
	}
}

func TestResolveGoEnclosingSymbolIsDeterministicAndDoesNotRetainContent(t *testing.T) {
	firstContent := []byte("package worker\n\nfunc Process() { var value = 1 }\n")
	secondContent := []byte("package worker\n\nfunc Process() { var value = 2 }\n")
	selection := mustAnalysisRange(t, "main.go", 3, 3)
	firstChange := mustResolverChange(t, "main.go", firstContent, selection, physicalGoLineCount(firstContent))
	secondChange := mustResolverChange(t, "main.go", secondContent, selection, physicalGoLineCount(secondContent))
	first, found, err := ResolveGoEnclosingSymbol(firstChange, firstContent, selection)
	if err != nil || !found {
		t.Fatalf("first resolution = (%#v, %t, %v)", first, found, err)
	}
	repeated, found, err := ResolveGoEnclosingSymbol(firstChange, firstContent, selection)
	if err != nil || !found || repeated != first {
		t.Fatalf("repeated resolution = (%#v, %t, %v), want %#v", repeated, found, err, first)
	}
	second, found, err := ResolveGoEnclosingSymbol(secondChange, secondContent, selection)
	if err != nil || !found || second.Identity() == first.Identity() {
		t.Fatalf("second resolution = (%#v, %t, %v)", second, found, err)
	}
	identity := first.Identity()
	for i := range firstContent {
		firstContent[i] = 'x'
	}
	if first.Identity() != identity || first.QualifiedName() != "worker.Process" {
		t.Fatal("mutating source changed returned Symbol")
	}
}

func mustResolverChange(t *testing.T, path string, headContent []byte, changedRange evidence.SourceRange, headLineCount int) evidence.Change {
	t.Helper()
	headDigest := resolverContentDigest(headContent)
	fileChange, err := evidence.NewFileChange(path, testBaseDigest, headDigest, []evidence.SourceRange{changedRange})
	if err != nil {
		t.Fatalf("NewFileChange() error = %v", err)
	}
	count := changedRange.EndLine() - changedRange.StartLine() + 1
	hunk, err := evidence.NewHunk(fileChange, changedRange.StartLine(), count, changedRange.StartLine(), count)
	if err != nil {
		t.Fatalf("NewHunk() error = %v", err)
	}
	lineMap, err := evidence.NewLineMap(fileChange, headLineCount, headLineCount, []evidence.Hunk{hunk})
	if err != nil {
		t.Fatalf("NewLineMap() error = %v", err)
	}
	change, err := evidence.NewChange([]evidence.FileChange{fileChange}, []evidence.LineMap{lineMap})
	if err != nil {
		t.Fatalf("NewChange() error = %v", err)
	}
	return change
}

func mustDeletionChange(t *testing.T, path string) evidence.Change {
	t.Helper()
	emptyDigest := resolverContentDigest(nil)
	fileChange, err := evidence.NewFileChange(path, testBaseDigest, emptyDigest, nil)
	if err != nil {
		t.Fatalf("NewFileChange() error = %v", err)
	}
	hunk, err := evidence.NewHunk(fileChange, 1, 1, 1, 0)
	if err != nil {
		t.Fatalf("NewHunk() error = %v", err)
	}
	lineMap, err := evidence.NewLineMap(fileChange, 1, 0, []evidence.Hunk{hunk})
	if err != nil {
		t.Fatalf("NewLineMap() error = %v", err)
	}
	change, err := evidence.NewChange([]evidence.FileChange{fileChange}, []evidence.LineMap{lineMap})
	if err != nil {
		t.Fatalf("NewChange() error = %v", err)
	}
	return change
}

func assertGoResolverError(t *testing.T, change evidence.Change, content []byte, selection evidence.SourceRange) {
	t.Helper()
	symbol, found, err := ResolveGoEnclosingSymbol(change, content, selection)
	if err == nil || found || symbol != (Symbol{}) {
		t.Fatalf("ResolveGoEnclosingSymbol() = (%#v, %t, %v), want zero error result", symbol, found, err)
	}
}

func resolverContentDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func physicalGoLineCount(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	count := bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		count++
	}
	return count
}
