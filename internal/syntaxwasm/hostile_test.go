package syntaxwasm

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// hostileInput holds, for one language, a file whose syntax error sits
// between the definitions before and after, where after calls before; a
// file with invalid UTF-8 and a definition named good; deeply nested
// files; and a file of n repeated units, each giving a few records.
type hostileInput struct {
	broken string
	bad    string
	nested map[string][]byte
	wide   func(n int) string
}

func wrap(prefix, open, close, suffix string, depth int) []byte {
	return []byte(prefix + strings.Repeat(open, depth) + strings.Repeat(close, depth) + suffix)
}

func repeat(n int, head, unit, tail string) string {
	var b strings.Builder
	b.WriteString(head)
	for i := range n {
		fmt.Fprintf(&b, strings.ReplaceAll(unit, "%d", "%[1]d"), i)
	}
	b.WriteString(tail)
	return b.String()
}

const depth = 100000

// Markup and block structure cost the parser more per level than brackets
// do, so they use a smaller depth to keep the tests short.
const shallow = 10000

var hostileInputs = map[string]hostileInput{
	"py": {
		broken: "def before():\n    pass\n\ndef broken(:\n    return )\n\ndef after():\n    before()\n",
		bad:    "def caf\xff\xfe():\n    pass\n\ndef good():\n    caf\xff\xfe()\n",
		nested: map[string][]byte{"nested.py": wrap("x = ", "(", ")", "", depth)},
		wide:   func(n int) string { return repeat(n, "", "import m%d\ndef f%d():\n    g%d()\n", "") },
	},
	"java": {
		broken: "class A {\n  void before() {}\n  void broken( { int x = ; }\n  void after() { before(); }\n}\n",
		bad:    "class C\xff { void m\xe2\x82() {} void good() {} }\n",
		nested: map[string][]byte{"Nested.java": wrap("class A { int x = ", "(", ")", "1; }", depth)},
		wide: func(n int) string {
			return repeat(n, "", "import p.C%d;\n", "") + repeat(n, "class A {\n", "  void m%d() { n%d(); }\n", "}\n")
		},
	},
	"js": {
		broken: "function before() {}\nconst x = (;\nfunction after() { before(); }\n",
		bad:    "function \xc3\x28x() {}\nimport y from \"mod\xff\";\nfunction good() {}\n",
		nested: map[string][]byte{"nested.js": wrap("const x = ", "[", "]", "", depth)},
		wide:   func(n int) string { return repeat(n, "", "import x%d from \"m%d\";\nfunction f%d() { g%d(); }\n", "") },
	},
	"ts": {
		broken: "function before(): void {}\nfunction broken(a: ) { let = ; }\nfunction after() { before(); }\n",
		bad:    "function caf\xff\xfe(): void {}\nfunction good(): void { caf\xff\xfe(); }\n",
		nested: map[string][]byte{"open.ts": bytes.Repeat([]byte("{"), depth)},
		wide: func(n int) string {
			return repeat(n, "", "import { x%d } from \"m%d\";\nfunction f%d(a: T%d): void { g%d(a); }\n", "")
		},
	},
	"tsx": {
		broken: "function before() { return <a/>; }\nfunction broken(a: ) { let = ; }\nfunction after() { return before(); }\n",
		bad:    "function caf\xff\xfe() { return <b/>; }\nfunction good() { return caf\xff\xfe(); }\n",
		nested: map[string][]byte{"nested.tsx": wrap("const x = ", "<div>", "</div>", ";", shallow)},
		wide: func(n int) string {
			return repeat(n, "", "import { X%d } from \"m%d\";\nfunction F%d() { return <X%d />; }\n", "")
		},
	},
	"c": {
		broken: "int before(void) { return 1; }\nint broken(int a { return ; }\nint after(void) { return before(); }\n",
		bad:    "int caf\xff\xfe(void) { return 0; }\nint good(void) { return caf\xff\xfe(); }\n",
		nested: map[string][]byte{"nested.c": wrap("int x = ", "(", ")", ";", depth)},
		wide:   func(n int) string { return repeat(n, "", "#include \"h%d.h\"\nint f%d(void) { return g%d(); }\n", "") },
	},
	"cpp": {
		broken: "void before() {}\nint broken(std::vector<int> a { return ; }\nvoid after() { before(); }\n",
		bad:    "struct S\xc3\x28 { void m\xe2\x82() {} };\nvoid good() { S\xc3\x28 s; }\n",
		nested: map[string][]byte{
			"nested.cpp": wrap("auto x = ", "{", "}", ";", depth),
			"deep.cpp":   bytes.Repeat([]byte("namespace a { "), depth/10),
		},
		wide: func(n int) string {
			return repeat(n, "class W {\n", "  DECLARE(T%d);\n", "};\n") + repeat(n, "", "namespace n%d { void f%d(); }\n", "")
		},
	},
	"cs": {
		broken: "class A {\n  void before() {}\n  void broken( { int x = ; }\n  void after() { before(); }\n}\n",
		bad:    "class C\xff { void m\xe2\x82() {} void good() {} }\n",
		nested: map[string][]byte{"Nested.cs": wrap("class A { int x = ", "(", ")", "1; }", depth)},
		wide: func(n int) string {
			return repeat(n, "", "using N%d;\n", "") + repeat(n, "namespace M;\nclass A {\n", "  void M%d() { N%d(); }\n", "}\n")
		},
	},
	"rs": {
		broken: "fn before() {}\nfn broken( { let x = ; }\nfn after() { before(); }\n",
		bad:    "fn caf\xff\xfe() {}\nfn good() { caf\xff\xfe(); }\n",
		nested: map[string][]byte{
			"nested.rs": wrap("const X: u8 = ", "(", ")", ";", depth),
			"open.rs":   bytes.Repeat([]byte("{"), depth),
		},
		wide: func(n int) string { return repeat(n, "", "impl<T> Tr%d for T {}\nfn f%d() { g%d(); }\n", "") },
	},
	"swift": {
		broken: "func before() {}\nfunc broken( { let x = }\nfunc after() { before() }\n",
		bad:    "func caf\xff\xfe() {}\nfunc good() { caf\xff\xfe() }\n",
		nested: map[string][]byte{
			"nested.swift": wrap("let x = ", "[", "]", "", depth),
			"open.swift":   bytes.Repeat([]byte("{"), depth),
		},
		wide: func(n int) string { return repeat(n, "", "import M%d\nfunc f%d() { g%d() }\n", "") },
	},
	"php": {
		broken: "<?php\nfunction before() {}\nfunction broken() { $x = ; }\nfunction after() { before(); }\n",
		bad:    "<?php\nfunction caf\xff\xfe() {}\nfunction good() { caf\xff\xfe(); }\nrequire 'x\xc3\x28.php';\n",
		nested: map[string][]byte{
			"nested.php": wrap("<?php $x = ", "[", "]", ";", depth),
			"open.php":   []byte("<?php " + strings.Repeat("{", shallow)),
		},
		wide: func(n int) string { return repeat(n, "<?php\n", "namespace N%d;\nfunction f%d() { g%d(); }\n", "") },
	},
	"rb": {
		broken: "def before\nend\n\ndef broken(\n  x = = 1\nend\n\ndef after\n  before()\nend\n",
		bad:    "# caf\xff\xfe\ndef good\n  helper()\nend\nrequire 'x\xc3\x28'\n",
		nested: map[string][]byte{
			"nested.rb": wrap("x = ", "[", "]", "", depth),
			"open.rb":   bytes.Repeat([]byte("begin\n"), shallow),
		},
		wide: func(n int) string { return repeat(n, "", "require \"m%d\"\ndef f%d\n  g%d()\nend\n", "") },
	},
	"html": {
		broken: "<div id=\"before\"><a href=\"one.html\">x</a></div>\n<p <<< id=\"bad\">\n<div id=\"after\"><a href=\"two.html\">y</a></div>\n",
		bad:    "<div id=\"caf\xff\xfe\"></div>\n<a href=\"x\xc3\x28.html\">y</a>\n<p id=\"good\"></p>\n",
		nested: map[string][]byte{"nested.html": wrap("", "<div>", "</div>", "", shallow)},
		wide: func(n int) string {
			return repeat(n, "<body>\n", "<a id=\"a%d\" href=\"p%d.html\">x</a>\n", "</body>\n")
		},
	},
}

func definitionNames(a syntaxanalysis.FileAnalysis) map[string]bool {
	names := map[string]bool{}
	for _, d := range a.Definitions {
		names[d.Name.Untrusted()] = true
	}
	return names
}

func TestSyntaxErrorsAreRegionsAndTheRestIsAnalysed(t *testing.T) {
	a := testAnalyzer(t)
	for extension, input := range hostileInputs {
		path := "broken." + extension
		analysis := analyze(t, a, path, []byte(input.broken))
		if names := definitionNames(analysis); !names["before"] || !names["after"] {
			t.Errorf("%s: definitions around the error are missing: %v", path, names)
		}
		regions := 0
		for _, g := range analysis.Gaps {
			if g.Reason != syntaxanalysis.GapParseError || !g.HasRange {
				t.Errorf("%s: unexpected gap %+v", path, g)
			}
			regions++
		}
		if regions == 0 {
			t.Errorf("%s: no parse error region", path)
		}
		if extension == "html" {
			if len(analysis.Imports) < 2 {
				t.Errorf("%s: imports around the error are missing: %+v", path, analysis.Imports)
			}
			continue
		}
		calls := 0
		for _, r := range analysis.References {
			if r.Kind == syntaxanalysis.ReferenceCall && r.Name.Untrusted() == "before" && r.Enclosing >= 0 && analysis.Definitions[r.Enclosing].Name.Untrusted() == "after" {
				calls++
			}
		}
		if calls != 1 {
			t.Errorf("%s: call after the error region not found", path)
		}
	}
}

func TestInvalidUTF8NeverReachesText(t *testing.T) {
	a := testAnalyzer(t)
	for extension, input := range hostileInputs {
		path := "bad." + extension
		analysis := analyze(t, a, path, []byte(input.bad))
		texts := []syntaxanalysis.Text{}
		for _, d := range analysis.Definitions {
			texts = append(texts, d.Name)
		}
		for _, r := range analysis.References {
			texts = append(texts, r.Name, r.Qualifier)
		}
		for _, i := range analysis.Imports {
			texts = append(texts, i.Source)
		}
		for _, text := range texts {
			if !utf8.ValidString(text.Untrusted()) {
				t.Errorf("%s: invalid UTF-8 escaped into a record", path)
			}
		}
		if !definitionNames(analysis)["good"] || analysis.Complete() {
			t.Errorf("%s: definitions %v, gaps %+v", path, definitionNames(analysis), analysis.Gaps)
		}
	}
}

func TestDeeplyNestedInputDoesNotCrashOrHang(t *testing.T) {
	a := testAnalyzer(t)
	for _, input := range hostileInputs {
		for path, content := range input.nested {
			started := time.Now()
			analysis := analyze(t, a, path, content)
			if elapsed := time.Since(started); elapsed > 2*syntaxanalysis.DefaultLimits().FileDeadline {
				t.Errorf("%s took %v", path, elapsed)
			}
			if analysis.Path != path {
				t.Errorf("%s: analysis for %s", path, analysis.Path)
			}
		}
	}
	if got := analyze(t, a, "ok.py", []byte("def f():\n    pass\n")); len(got.Definitions) != 1 || !got.Complete() {
		t.Fatalf("analysis after hostile input = %+v", got)
	}
}

func TestVeryLongLines(t *testing.T) {
	// The deadline is not what this test is about: on a loaded machine the
	// default five seconds can pass before the megabyte line is parsed.
	limits := syntaxanalysis.DefaultLimits()
	limits.FileDeadline = 10 * time.Minute
	a := newTestAnalyzer(t, Config{Limits: limits})
	var b strings.Builder
	for i := 0; b.Len() < 1<<20; i++ {
		b.WriteString("function f")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString("() { return g(1, 2, 3, 4, 5, 6, 7, 8, 9, 10); } ")
	}
	analysis := analyze(t, a, "long.js", []byte(b.String()))
	if !analysis.Complete() || len(analysis.Definitions) < 1000 {
		t.Fatalf("%d definitions, gaps %+v", len(analysis.Definitions), analysis.Gaps)
	}
	last := analysis.References[len(analysis.References)-1]
	if last.Range.Start.Line != 1 || last.Range.Start.Column < 1<<19 {
		t.Fatalf("last reference at %+v", last.Range.Start)
	}
}

// TestWideInputsScaleLinearly checks that the host's work after the guest
// call grows in proportion to the number of records. It compares the
// fastest of three runs at n and at 4n units: linear work takes about four
// times as long, quadratic work sixteen times.
func TestWideInputsScaleLinearly(t *testing.T) {
	if testing.Short() {
		t.Skip("measures the host's work over large inputs")
	}
	limits := syntaxanalysis.DefaultLimits()
	limits.FileDeadline = 10 * time.Minute
	a := newTestAnalyzer(t, Config{Limits: limits})
	const n = 2500
	for extension, input := range hostileInputs {
		path := "wide." + extension
		cost := func(units int) time.Duration {
			content := []byte(input.wide(units))
			language, _ := syntaxanalysis.LanguageForPath(path)
			source, err := syntaxanalysis.NewSource(path, language, content)
			if err != nil {
				t.Fatal(err)
			}
			entry := a.languages[language]
			p, fail := a.parse(context.Background(), entry, language, content, limits, syntaxanalysis.Span{})
			if fail != nil {
				t.Fatalf("%s: %+v", path, fail)
			}
			raw := p.raw
			best := time.Duration(1 << 62)
			for range 3 {
				copied := raw
				copied.Definitions = append([]syntaxanalysis.RawDefinition(nil), raw.Definitions...)
				copied.References = append([]syntaxanalysis.RawReference(nil), raw.References...)
				copied.Imports = append([]syntaxanalysis.RawImport(nil), raw.Imports...)
				started := time.Now()
				analysis, err := a.finishFile(context.Background(), source, entry, content, copied, p.embedded, time.Now().Add(time.Minute))
				elapsed := time.Since(started)
				if err != nil || hasGap(analysis, syntaxanalysis.GapAnalysisFailed) || hasGap(analysis, syntaxanalysis.GapDeadlineExceeded) {
					t.Fatalf("%s: %v %+v", path, err, analysis.Gaps)
				}
				best = min(best, elapsed)
			}
			return best
		}
		small, large := cost(n), cost(4*n)
		if ratio := float64(large) / float64(max(small, time.Millisecond)); ratio > 10 {
			t.Errorf("%s: %v for %d units, %v for %d", path, small, n, large, 4*n)
		}
	}
}

func TestHostWorkPastTheDeadlineIsADeadlineGap(t *testing.T) {
	a := testAnalyzer(t)
	content := []byte("def f():\n    g()\n")
	source, _ := syntaxanalysis.NewSource("late.py", syntaxanalysis.LanguagePython, content)
	entry := a.languages[syntaxanalysis.LanguagePython]
	p, fail := a.parse(context.Background(), entry, syntaxanalysis.LanguagePython, content, a.limits, syntaxanalysis.Span{})
	if fail != nil {
		t.Fatal(fail)
	}
	analysis, err := a.finishFile(context.Background(), source, entry, content, p.raw, p.embedded, time.Now().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	onlyGap(t, analysis, syntaxanalysis.GapDeadlineExceeded, "")
}
