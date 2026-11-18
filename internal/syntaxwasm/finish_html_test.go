package syntaxwasm

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

func TestScriptLanguageFollowsTheStartTag(t *testing.T) {
	cases := map[string]syntaxanalysis.Language{
		"<script>":                                 syntaxanalysis.LanguageJavaScript,
		`<script type="module">`:                   syntaxanalysis.LanguageJavaScript,
		`<script type='text/javascript' defer>`:    syntaxanalysis.LanguageJavaScript,
		"<SCRIPT TYPE=Module>":                     syntaxanalysis.LanguageJavaScript,
		`<script lang="ts">`:                       syntaxanalysis.LanguageTypeScript,
		`<script setup lang="tsx">`:                syntaxanalysis.LanguageTSX,
		`<script type="text/typescript">`:          syntaxanalysis.LanguageTypeScript,
		`<script lang="ts" type="module">`:         syntaxanalysis.LanguageTypeScript,
		`<script data-x="a>b" type="module">`:      syntaxanalysis.LanguageJavaScript,
		`<script type="module" type="importmap">`:  syntaxanalysis.LanguageJavaScript,
		`<script type="application/json">`:         "",
		`<script type="importmap">`:                "",
		`<script type="text/x-template" id="row">`: "",
		`<script lang="coffee">`:                   "",
	}
	for tag, want := range cases {
		got, ok := htmlScriptLanguage([]byte(tag))
		if got != want || ok != (want != "") {
			t.Errorf("%s: %q %v, want %q", tag, got, ok, want)
		}
	}
}

func TestInlineScriptsShareTheFileDeadline(t *testing.T) {
	a := testAnalyzer(t)
	content := []byte("<div id=\"a\"></div><script>function late() {}</script>")
	code := strings.Index(string(content), "function")
	tag := strings.Index(string(content), "<script>")
	e := embeddedCode{
		code: syntaxanalysis.Span{Start: code, End: strings.Index(string(content), "</script>")},
		tag:  syntaxanalysis.Span{Start: tag, End: tag + len("<script>")},
	}
	var raw syntaxanalysis.RawFile
	if err := a.addEmbedded(context.Background(), content, e, &raw, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(raw.Definitions) != 0 || len(raw.Gaps) != 1 || raw.Gaps[0].Reason != syntaxanalysis.GapDeadlineExceeded || raw.Gaps[0].Span != e.code {
		t.Fatalf("raw = %+v", raw)
	}
	raw = syntaxanalysis.RawFile{}
	if err := a.addEmbedded(context.Background(), content, e, &raw, time.Now()); err != nil {
		t.Fatal(err)
	}
	if len(raw.Definitions) != 1 || raw.Definitions[0].Name.Start != code+len("function ") {
		t.Fatalf("raw = %+v", raw)
	}
}
