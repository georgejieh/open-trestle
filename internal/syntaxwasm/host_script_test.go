package syntaxwasm

import (
	"bytes"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

func TestScriptLanguagesSyntaxErrorsAreRegionsAndTheRestIsAnalysed(t *testing.T) {
	a := testAnalyzer(t)
	cases := map[string]string{
		"broken.php": "<?php\nfunction before() {}\nfunction broken() { $x = ; }\nfunction after() { before(); }\n",
		"broken.rb":  "def before\nend\n\ndef broken(\n  x = = 1\nend\n\ndef after\n  before()\nend\n",
	}
	for path, content := range cases {
		analysis := analyze(t, a, path, []byte(content))
		names := map[string]bool{}
		for _, d := range analysis.Definitions {
			names[d.Name.Untrusted()] = true
		}
		if !names["before"] || !names["after"] {
			t.Fatalf("%s: definitions around the error are missing: %v", path, names)
		}
		regions := 0
		for _, g := range analysis.Gaps {
			if g.Reason != syntaxanalysis.GapParseError || !g.HasRange {
				t.Fatalf("%s: unexpected gap %+v", path, g)
			}
			regions++
		}
		if regions == 0 {
			t.Fatalf("%s: no parse error region", path)
		}
		calls := 0
		for _, r := range analysis.References {
			if r.Kind == syntaxanalysis.ReferenceCall && r.Name.Untrusted() == "before" && r.Enclosing >= 0 && analysis.Definitions[r.Enclosing].Name.Untrusted() == "after" {
				calls++
			}
		}
		if calls != 1 {
			t.Fatalf("%s: call after the error region not found", path)
		}
	}
	html := analyze(t, a, "broken.html", []byte("<div id=\"before\"><a href=\"one.html\">x</a></div>\n<p <<< id=\"bad\">\n<div id=\"after\"><a href=\"two.html\">y</a></div>\n"))
	ids := map[string]bool{}
	for _, d := range html.Definitions {
		ids[d.Name.Untrusted()] = true
	}
	if !ids["before"] || !ids["after"] || len(html.Imports) < 2 {
		t.Fatalf("html: definitions %v, imports %d, gaps %+v", ids, len(html.Imports), html.Gaps)
	}
}

func TestScriptLanguagesInvalidUTF8NeverReachesText(t *testing.T) {
	a := testAnalyzer(t)
	cases := map[string]string{
		"bad.php":  "<?php\nfunction caf\xff\xfe() {}\nfunction good() { caf\xff\xfe(); }\nrequire 'x\xc3\x28.php';\n",
		"bad.rb":   "# caf\xff\xfe\ndef good\n  helper()\nend\nrequire 'x\xc3\x28'\n",
		"bad.html": "<div id=\"caf\xff\xfe\"></div>\n<a href=\"x\xc3\x28.html\">y</a>\n<p id=\"good\"></p>\n",
	}
	for path, content := range cases {
		analysis := analyze(t, a, path, []byte(content))
		check := func(text syntaxanalysis.Text) {
			if !utf8.ValidString(text.Untrusted()) {
				t.Fatalf("%s: invalid UTF-8 escaped into a record", path)
			}
		}
		good := false
		for _, d := range analysis.Definitions {
			check(d.Name)
			good = good || d.Name.Untrusted() == "good"
		}
		for _, r := range analysis.References {
			check(r.Name)
			check(r.Qualifier)
		}
		for _, i := range analysis.Imports {
			check(i.Source)
		}
		if !good || analysis.Complete() {
			t.Fatalf("%s: good=%v gaps=%+v", path, good, analysis.Gaps)
		}
	}
}

func TestScriptLanguagesDeeplyNestedInputDoesNotCrashOrHang(t *testing.T) {
	a := testAnalyzer(t)
	depth := 100000
	// Markup and block structure cost the parser more per level than
	// brackets do, so they use a smaller depth to keep the test short.
	shallow := 10000
	cases := map[string][]byte{
		"nested.php":  append(append([]byte("<?php $x = "), bytes.Repeat([]byte("["), depth)...), bytes.Repeat([]byte("]"), depth)...),
		"nested.rb":   append(append([]byte("x = "), bytes.Repeat([]byte("["), depth)...), bytes.Repeat([]byte("]"), depth)...),
		"nested.html": append(bytes.Repeat([]byte("<div>"), shallow), bytes.Repeat([]byte("</div>"), shallow)...),
		"open.php":    append([]byte("<?php "), bytes.Repeat([]byte("{"), shallow)...),
		"open.rb":     bytes.Repeat([]byte("begin\n"), shallow),
	}
	for path, content := range cases {
		started := time.Now()
		analysis := analyze(t, a, path, content)
		if elapsed := time.Since(started); elapsed > 2*syntaxanalysis.DefaultLimits().FileDeadline {
			t.Fatalf("%s took %v", path, elapsed)
		}
		if analysis.Path != path {
			t.Fatalf("%s: analysis for %s", path, analysis.Path)
		}
	}
	if got := analyze(t, a, "ok.rb", []byte("def f\nend\n")); len(got.Definitions) != 1 || !got.Complete() {
		t.Fatalf("analysis after hostile input = %+v", got)
	}
}
