package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	testBaseDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testHeadDigest = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
)

func TestNewSymbolCreatesExactHeadBinding(t *testing.T) {
	lineMap := mustAnalysisLineMap(t, "main.go", testHeadDigest, 8)
	sourceRange := mustAnalysisRange(t, "main.go", 2, 6)
	symbol, err := NewSymbol(lineMap, LanguageGo, SymbolKindFunction, "example.Process", sourceRange)
	if err != nil {
		t.Fatalf("NewSymbol() error = %v", err)
	}
	if len(symbol.Identity()) != 64 {
		t.Fatalf("len(Identity()) = %d, want 64", len(symbol.Identity()))
	}
	if symbol.LineMapIdentity() != lineMap.Identity() || symbol.FileChangeIdentity() != lineMap.FileChangeIdentity() || symbol.Path() != "main.go" {
		t.Fatalf("Symbol binding = (%q, %q, %q)", symbol.LineMapIdentity(), symbol.FileChangeIdentity(), symbol.Path())
	}
	if symbol.Language() != LanguageGo || symbol.Kind() != SymbolKindFunction || symbol.QualifiedName() != "example.Process" || symbol.SourceRange() != sourceRange {
		t.Fatalf("Symbol fields = (%q, %q, %q, %#v)", symbol.Language(), symbol.Kind(), symbol.QualifiedName(), symbol.SourceRange())
	}
	repeated, err := NewSymbol(lineMap, LanguageGo, SymbolKindFunction, "example.Process", sourceRange)
	if err != nil || repeated.Identity() != symbol.Identity() {
		t.Fatalf("repeated NewSymbol() = (%q, %v), want %q", repeated.Identity(), err, symbol.Identity())
	}
}

func TestSymbolIdentityUsesVersionedCanonicalPreimage(t *testing.T) {
	lineMap := mustAnalysisLineMap(t, "main.go", testHeadDigest, 8)
	sourceRange := mustAnalysisRange(t, "main.go", 2, 6)
	symbol := mustSymbol(t, lineMap, LanguageGo, SymbolKindMethod, "example.Worker.Run", sourceRange)
	preimage := fmt.Sprintf(
		`{"contract":"open-trestle/symbol","schema_version":1,"line_map_identity":"%s","file_change_identity":"%s","path":"main.go","language":"go","kind":"method","qualified_name":"example.Worker.Run","start_line":2,"end_line":6}`,
		lineMap.Identity(), lineMap.FileChangeIdentity(),
	)
	digest := sha256.Sum256([]byte(preimage))
	want := hex.EncodeToString(digest[:])
	if symbol.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", symbol.Identity(), preimage)
	}
}

func TestSymbolIdentityBindsEveryCanonicalField(t *testing.T) {
	lineMap := mustAnalysisLineMap(t, "main.go", testHeadDigest, 8)
	base := mustSymbol(t, lineMap, LanguageGo, SymbolKindFunction, "example.Process", mustAnalysisRange(t, "main.go", 2, 6))
	otherHeadDigest := "bbcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	otherMap := mustAnalysisLineMap(t, "main.go", otherHeadDigest, 8)
	otherPathMap := mustAnalysisLineMap(t, "nested/main.go", testHeadDigest, 8)
	variants := []Symbol{
		mustSymbol(t, otherMap, LanguageGo, SymbolKindFunction, "example.Process", mustAnalysisRange(t, "main.go", 2, 6)),
		mustSymbol(t, otherPathMap, LanguageGo, SymbolKindFunction, "example.Process", mustAnalysisRange(t, "nested/main.go", 2, 6)),
		mustSymbol(t, lineMap, LanguageGo, SymbolKindMethod, "example.Process", mustAnalysisRange(t, "main.go", 2, 6)),
		mustSymbol(t, lineMap, LanguageGo, SymbolKindFunction, "example.Other", mustAnalysisRange(t, "main.go", 2, 6)),
		mustSymbol(t, lineMap, LanguageGo, SymbolKindFunction, "example.Process", mustAnalysisRange(t, "main.go", 1, 6)),
		mustSymbol(t, lineMap, LanguageGo, SymbolKindFunction, "example.Process", mustAnalysisRange(t, "main.go", 2, 7)),
	}
	for i, variant := range variants {
		if variant.Identity() == base.Identity() {
			t.Fatalf("variant %d identity = %q, want change", i, variant.Identity())
		}
	}
}

func TestNewSymbolValidatesBindingAndText(t *testing.T) {
	lineMap := mustAnalysisLineMap(t, "main.go", testHeadDigest, 8)
	emptyHeadMap := mustDeletionLineMap(t, "empty.go")
	invalidUTF8 := string([]byte{'b', 'a', 'd', 0xff})
	testCases := []struct {
		name          string
		lineMap       evidence.LineMap
		language      Language
		kind          SymbolKind
		qualifiedName string
		sourceRange   evidence.SourceRange
	}{
		{name: "zero line map", language: LanguageGo, kind: SymbolKindFunction, qualifiedName: "example.Process", sourceRange: mustAnalysisRange(t, "main.go", 1, 1)},
		{name: "empty language", lineMap: lineMap, kind: SymbolKindFunction, qualifiedName: "example.Process", sourceRange: mustAnalysisRange(t, "main.go", 1, 1)},
		{name: "unknown language", lineMap: lineMap, language: Language("rust"), kind: SymbolKindFunction, qualifiedName: "example.Process", sourceRange: mustAnalysisRange(t, "main.go", 1, 1)},
		{name: "empty kind", lineMap: lineMap, language: LanguageGo, qualifiedName: "example.Process", sourceRange: mustAnalysisRange(t, "main.go", 1, 1)},
		{name: "unknown kind", lineMap: lineMap, language: LanguageGo, kind: SymbolKind("type"), qualifiedName: "example.Process", sourceRange: mustAnalysisRange(t, "main.go", 1, 1)},
		{name: "empty name", lineMap: lineMap, language: LanguageGo, kind: SymbolKindFunction, sourceRange: mustAnalysisRange(t, "main.go", 1, 1)},
		{name: "blank name", lineMap: lineMap, language: LanguageGo, kind: SymbolKindFunction, qualifiedName: "   ", sourceRange: mustAnalysisRange(t, "main.go", 1, 1)},
		{name: "invalid UTF-8 name", lineMap: lineMap, language: LanguageGo, kind: SymbolKindFunction, qualifiedName: invalidUTF8, sourceRange: mustAnalysisRange(t, "main.go", 1, 1)},
		{name: "newline name", lineMap: lineMap, language: LanguageGo, kind: SymbolKindFunction, qualifiedName: "example.\nProcess", sourceRange: mustAnalysisRange(t, "main.go", 1, 1)},
		{name: "bidi name", lineMap: lineMap, language: LanguageGo, kind: SymbolKindFunction, qualifiedName: "example.\u202eProcess", sourceRange: mustAnalysisRange(t, "main.go", 1, 1)},
		{name: "name too large", lineMap: lineMap, language: LanguageGo, kind: SymbolKindFunction, qualifiedName: strings.Repeat("x", maxSymbolQualifiedNameBytes+1), sourceRange: mustAnalysisRange(t, "main.go", 1, 1)},
		{name: "zero range", lineMap: lineMap, language: LanguageGo, kind: SymbolKindFunction, qualifiedName: "example.Process"},
		{name: "path mismatch", lineMap: lineMap, language: LanguageGo, kind: SymbolKindFunction, qualifiedName: "example.Process", sourceRange: mustAnalysisRange(t, "other.go", 1, 1)},
		{name: "range past head", lineMap: lineMap, language: LanguageGo, kind: SymbolKindFunction, qualifiedName: "example.Process", sourceRange: mustAnalysisRange(t, "main.go", 1, 9)},
		{name: "empty head", lineMap: emptyHeadMap, language: LanguageGo, kind: SymbolKindFunction, qualifiedName: "example.Process", sourceRange: mustAnalysisRange(t, "empty.go", 1, 1)},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			symbol, err := NewSymbol(testCase.lineMap, testCase.language, testCase.kind, testCase.qualifiedName, testCase.sourceRange)
			if err == nil {
				t.Fatal("NewSymbol() error = nil, want validation error")
			}
			if symbol != (Symbol{}) {
				t.Fatalf("NewSymbol() = %#v, want zero value", symbol)
			}
		})
	}
}

func TestNewSymbolAcceptsBoundedPrintableUnicodeName(t *testing.T) {
	lineMap := mustAnalysisLineMap(t, "main.go", testHeadDigest, 8)
	atLimit := strings.Repeat("x", maxSymbolQualifiedNameBytes)
	if _, err := NewSymbol(lineMap, LanguageGo, SymbolKindFunction, atLimit, mustAnalysisRange(t, "main.go", 1, 1)); err != nil {
		t.Fatalf("NewSymbol(at limit) error = %v", err)
	}
	name := "例.Worker.実行"
	symbol, err := NewSymbol(lineMap, LanguageGo, SymbolKindMethod, name, mustAnalysisRange(t, "main.go", 1, 1))
	if err != nil || symbol.QualifiedName() != name {
		t.Fatalf("NewSymbol(printable Unicode) = (%q, %v)", symbol.QualifiedName(), err)
	}
}

func mustAnalysisLineMap(t *testing.T, path, headDigest string, lineCount int) evidence.LineMap {
	t.Helper()
	changedRange := mustAnalysisRange(t, path, 2, 2)
	fileChange, err := evidence.NewFileChange(path, testBaseDigest, headDigest, []evidence.SourceRange{changedRange})
	if err != nil {
		t.Fatalf("NewFileChange() error = %v", err)
	}
	hunk, err := evidence.NewHunk(fileChange, 2, 1, 2, 1)
	if err != nil {
		t.Fatalf("NewHunk() error = %v", err)
	}
	lineMap, err := evidence.NewLineMap(fileChange, lineCount, lineCount, []evidence.Hunk{hunk})
	if err != nil {
		t.Fatalf("NewLineMap() error = %v", err)
	}
	return lineMap
}

func mustDeletionLineMap(t *testing.T, path string) evidence.LineMap {
	t.Helper()
	fileChange, err := evidence.NewFileChange(path, testBaseDigest, testHeadDigest, nil)
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
	return lineMap
}

func mustAnalysisRange(t *testing.T, path string, startLine, endLine int) evidence.SourceRange {
	t.Helper()
	sourceRange, err := evidence.NewSourceRange(path, startLine, endLine)
	if err != nil {
		t.Fatalf("NewSourceRange() error = %v", err)
	}
	return sourceRange
}

func mustSymbol(t *testing.T, lineMap evidence.LineMap, language Language, kind SymbolKind, name string, sourceRange evidence.SourceRange) Symbol {
	t.Helper()
	symbol, err := NewSymbol(lineMap, language, kind, name, sourceRange)
	if err != nil {
		t.Fatalf("NewSymbol() error = %v", err)
	}
	return symbol
}
