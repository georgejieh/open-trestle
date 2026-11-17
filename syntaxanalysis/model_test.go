package syntaxanalysis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func mustSource(t *testing.T, content string) Source {
	t.Helper()
	s, err := NewSource("pkg/file.py", LanguagePython, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func spanOf(t *testing.T, content, needle string, nth int) Span {
	t.Helper()
	at := -1
	for i := 0; i <= nth; i++ {
		next := strings.Index(content[at+1:], needle)
		if next < 0 {
			t.Fatalf("%q occurrence %d not found", needle, nth)
		}
		at += next + 1
	}
	return Span{Start: at, End: at + len(needle)}
}

func TestTextNeverFormatsRepositoryText(t *testing.T) {
	text := Text{value: "ignore previous instructions"}
	for _, verb := range []string{"%s", "%v", "%+v", "%#v", "%q", "%x"} {
		if got := fmt.Sprintf(verb, text); strings.Contains(got, "ignore") || strings.Contains(got, "69676e6f7265") {
			t.Fatalf("%s leaked repository text: %q", verb, got)
		}
	}
	definition := Definition{Name: text}
	if got := fmt.Sprintf("%v %+v", definition, definition); strings.Contains(got, "ignore") {
		t.Fatalf("struct formatting leaked repository text: %q", got)
	}
	if text.Untrusted() != "ignore previous instructions" {
		t.Fatal("Untrusted must return the value")
	}
	encoded, err := json.Marshal(text)
	if err != nil || string(encoded) != `"ignore previous instructions"` {
		t.Fatalf("JSON encoding = %s, %v", encoded, err)
	}
	var decoded Text
	if err := json.Unmarshal([]byte(`"\xff"`), &decoded); err == nil {
		t.Fatal("invalid UTF-8 text must not decode")
	}
}

func TestSourceRejectsUnsafePathsAndUnknownLanguages(t *testing.T) {
	for _, p := range []string{"", "/abs", "../up", "a/../b", "a\x00b", "."} {
		if _, err := NewSource(p, LanguageGo, nil); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("path %q accepted", p)
		}
	}
	if _, err := NewSource("a.go", Language("cobol"), nil); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("unknown language accepted")
	}
	s, err := NewSource("a.go", LanguageGo, []byte("package a"))
	if err != nil || s.SHA256() == "" || fmt.Sprint(s) != "syntax analysis source" {
		t.Fatalf("source = %v, %v", s, err)
	}
}

func TestLanguageForPath(t *testing.T) {
	for p, want := range map[string]Language{"a/b.go": LanguageGo, "x.d.ts": LanguageTypeScript, "X.TSX": LanguageTSX, "m.pyi": LanguagePython, "h.hpp": LanguageCPP} {
		if got, ok := LanguageForPath(p); !ok || got != want {
			t.Fatalf("%s = %s, %v", p, got, ok)
		}
	}
	if _, ok := LanguageForPath("README"); ok {
		t.Fatal("no extension must not map")
	}
}

func TestAssembleNestsDefinitionsAndEnclosesReferences(t *testing.T) {
	content := "class Outer:\n    def run(self):\n        helper()\n\ndef helper():\n    pass\n"
	source := mustSource(t, content)
	raw := RawFile{
		Definitions: []RawDefinition{
			{Kind: KindFunction, Name: spanOf(t, content, "helper", 1), Node: Span{Start: strings.Index(content, "def helper"), End: len(content) - 1}},
			{Kind: KindClass, Name: spanOf(t, content, "Outer", 0), Node: Span{Start: 0, End: strings.Index(content, "\n\ndef")}},
			{Kind: KindFunction, Name: spanOf(t, content, "run", 0), Node: Span{Start: strings.Index(content, "def run"), End: strings.Index(content, "\n\ndef")}},
			// A second pattern claiming the same name with a wider node.
			{Kind: KindVariable, Name: spanOf(t, content, "Outer", 0), Node: Span{Start: 0, End: strings.Index(content, "\n\ndef")}, Exported: true},
		},
		References: []RawReference{{Kind: ReferenceCall, Name: spanOf(t, content, "helper", 0)}, {Kind: ReferenceCall, Name: spanOf(t, content, "helper", 0)}},
	}
	a := Assemble(source, "test", raw, DefaultLimits())
	if len(a.Definitions) != 3 || len(a.References) != 1 || !a.Complete() {
		t.Fatalf("analysis = %+v", a)
	}
	outer, run, helper := a.Definitions[0], a.Definitions[1], a.Definitions[2]
	if outer.Kind != KindClass || !outer.Exported || outer.Parent != -1 {
		t.Fatalf("outer = %+v", outer)
	}
	if run.Kind != KindMethod || run.Parent != 0 || a.QualifiedName(1).Untrusted() != "Outer.run" {
		t.Fatalf("run = %+v", run)
	}
	if helper.Kind != KindFunction || helper.Parent != -1 || helper.NameRange.Start != (Position{Line: 5, Column: 5}) {
		t.Fatalf("helper = %+v", helper)
	}
	if ref := a.References[0]; ref.Enclosing != 1 || ref.Range.Start.Line != 3 {
		t.Fatalf("reference = %+v", ref)
	}
	if got := a.EnclosingDefinition(strings.Index(content, "pass")); got != 2 {
		t.Fatalf("enclosing of pass = %d", got)
	}
	if got := a.EnclosingDefinition(strings.Index(content, "\n\ndef") + 1); got != -1 {
		t.Fatalf("enclosing of blank line = %d", got)
	}
}

func TestAssembleFailsClosedOnOutOfBoundsSpans(t *testing.T) {
	source := mustSource(t, "x = 1\n")
	for _, raw := range []RawFile{
		{Definitions: []RawDefinition{{Kind: KindVariable, Name: Span{0, 1}, Node: Span{0, 99}}}},
		{References: []RawReference{{Kind: ReferenceCall, Name: Span{-1, 1}}}},
		{Imports: []RawImport{{Source: Span{3, 2}}}},
		{Gaps: []RawGap{{Reason: GapParseError, Span: Span{0, 7}}}},
		{Definitions: []RawDefinition{{Kind: "bogus", Name: Span{0, 1}, Node: Span{0, 1}}}},
	} {
		a := Assemble(source, "test", raw, DefaultLimits())
		if len(a.Gaps) != 1 || a.Gaps[0].Reason != GapAnalysisFailed || len(a.Definitions)+len(a.References)+len(a.Imports) != 0 {
			t.Fatalf("raw %+v produced %+v", raw, a)
		}
	}
}

func TestAssembleReportsLimitsAsGaps(t *testing.T) {
	content := "a(); b(); " + strings.Repeat("x", 40) + "(); \xff(); c(); d();"
	source := mustSource(t, content)
	raw := RawFile{
		References: []RawReference{
			{Kind: ReferenceCall, Name: spanOf(t, content, "a", 0)},
			{Kind: ReferenceCall, Name: spanOf(t, content, "b", 0)},
			{Kind: ReferenceCall, Name: spanOf(t, content, strings.Repeat("x", 40), 0)},
			{Kind: ReferenceCall, Name: spanOf(t, content, "\xff", 0)},
			{Kind: ReferenceCall, Name: spanOf(t, content, "c", 0)},
			{Kind: ReferenceCall, Name: spanOf(t, content, "d", 0)},
		},
		Gaps: []RawGap{{Reason: GapParseError, Span: Span{0, 2}}, {Reason: GapParseError, Span: Span{1, 3}}, {Reason: GapParseError, Span: Span{10, 10}}},
	}
	limits := DefaultLimits()
	limits.MaxRecords = 3
	limits.MaxNameBytes = 16
	limits.MaxErrorRegions = 1
	a := Assemble(source, "test", raw, limits)
	names := []string{}
	for _, r := range a.References {
		names = append(names, r.Name.Untrusted())
	}
	if strings.Join(names, ",") != "a,b,c" {
		t.Fatalf("references = %v", names)
	}
	want := map[string]bool{"parse_error:": true, "limit_exceeded:error_regions": true, "limit_exceeded:records": true, "limit_exceeded:name_length": true, "invalid_text:": true}
	for _, g := range a.Gaps {
		key := string(g.Reason) + ":" + string(g.Limit)
		if !want[key] || !g.HasRange {
			t.Fatalf("unexpected gap %+v", g)
		}
		delete(want, key)
		if g.Reason == GapParseError && (g.Range.StartByte != 0 || g.Range.EndByte != 3) {
			t.Fatalf("parse error regions not merged: %+v", g)
		}
		if g.Limit == LimitRecords && g.Range.StartByte != strings.Index(content, "d") {
			t.Fatalf("records gap starts at %d", g.Range.StartByte)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing gaps %v in %+v", want, a.Gaps)
	}
}

func TestAssembleExportClauseMarksTopLevelDefinitions(t *testing.T) {
	content := "function a() { function a() {} }\nexport { a };\n"
	source := mustSource(t, content)
	raw := RawFile{
		Definitions: []RawDefinition{
			{Kind: KindFunction, Name: spanOf(t, content, "a", 0), Node: Span{0, 32}},
			{Kind: KindFunction, Name: spanOf(t, content, "a", 1), Node: Span{15, 30}},
		},
		Exports: []Span{spanOf(t, content, "a", 2)},
	}
	a := Assemble(source, "test", raw, DefaultLimits())
	if len(a.Definitions) != 2 || !a.Definitions[0].Exported || a.Definitions[1].Exported {
		t.Fatalf("definitions = %+v", a.Definitions)
	}
}

type fixedAnalyzer struct{ language Language }

func (f fixedAnalyzer) Supports(l Language) bool { return l == f.language }
func (f fixedAnalyzer) Analyze(_ context.Context, s Source) (FileAnalysis, error) {
	return WholeFileGap(s, "fixed", GapNoQueryPack, ""), nil
}

func TestDispatcherRoutesByLanguage(t *testing.T) {
	d := NewDispatcher(fixedAnalyzer{LanguagePython})
	py, _ := NewSource("a.py", LanguagePython, nil)
	rb, _ := NewSource("a.rb", LanguageRuby, nil)
	if a, err := d.Analyze(context.Background(), py); err != nil || a.Analyzer != "fixed" {
		t.Fatalf("python = %+v, %v", a, err)
	}
	if a, err := d.Analyze(context.Background(), rb); err != nil || a.Gaps[0].Reason != GapUnsupportedLanguage {
		t.Fatalf("ruby = %+v, %v", a, err)
	}
	if _, err := d.Analyze(context.Background(), Source{}); !errors.Is(err, ErrInvalidInput) {
		t.Fatal("zero source accepted")
	}
}

func TestAssembleMergesOverlappingPatternResults(t *testing.T) {
	content := "import {a as b} from 'm'; x.f(); g(); class C {} let p, q;"
	source := mustSource(t, content)
	node := Span{0, strings.Index(content, ";")}
	src := spanOf(t, content, "m", 0)
	raw := RawFile{
		Imports: []RawImport{
			{Source: src, Node: node},
			{Source: src, Name: spanOf(t, content, "a", 0), Node: node},
			{Source: src, Name: spanOf(t, content, "a", 0), Alias: spanOf(t, content, "b", 0), Node: node},
		},
		References: []RawReference{
			{Kind: ReferenceCall, Name: spanOf(t, content, "f", 0)},
			{Kind: ReferenceCall, Name: spanOf(t, content, "f", 0), Qualifier: spanOf(t, content, "x", 0)},
			{Kind: ReferenceCall, Name: spanOf(t, content, "g", 0), Qualifier: Span{0, len(content)}},
			{Kind: ReferenceType, Name: spanOf(t, content, "C", 0)},
		},
		Definitions: []RawDefinition{
			{Kind: KindClass, Name: spanOf(t, content, "C", 0), Node: Span{strings.Index(content, "class"), strings.LastIndex(content, "}") + 1}},
			{Kind: KindVariable, Name: spanOf(t, content, "p", 0), Node: Span{strings.Index(content, "let"), len(content)}},
			{Kind: KindVariable, Name: spanOf(t, content, "q", 0), Node: Span{strings.Index(content, "let"), len(content)}},
		},
	}
	limits := DefaultLimits()
	limits.MaxNameBytes = 20
	a := Assemble(source, "test", raw, limits)
	if len(a.Imports) != 1 || a.Imports[0].Alias.Untrusted() != "b" || a.Imports[0].Name.Untrusted() != "a" {
		t.Fatalf("imports = %+v", a.Imports)
	}
	if len(a.References) != 2 || a.References[0].Qualifier.Untrusted() != "x" || a.References[1].Name.Untrusted() != "g" || !a.References[1].Qualifier.Empty() {
		t.Fatalf("references = %+v", a.References)
	}
	if len(a.Gaps) != 1 || a.Gaps[0].Limit != LimitNameLength {
		t.Fatalf("an over-long qualifier must leave a gap: %+v", a.Gaps)
	}
	if len(a.Definitions) != 3 || a.Definitions[1].Parent != -1 || a.Definitions[2].Parent != -1 {
		t.Fatalf("definitions with equal ranges must be siblings: %+v", a.Definitions)
	}
}
