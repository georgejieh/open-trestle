package semanticimpact

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestAnalyzeGoReportsDeclarationsReferencesTestsAndGaps(t *testing.T) {
	base := []File{mustFile(t, "lib/api.go", "package lib\nfunc Exported(v int) int { return v }\nfunc removed() {}\n"), mustFile(t, "lib/api_test.go", "package lib\nfunc TestExported(){ _ = Exported(1) }\n")}
	head := []File{mustFile(t, "lib/api.go", "package lib\ntype Public struct{ Value int }\nfunc Exported(v int) int { return v + 1 }\n"), mustFile(t, "lib/api_test.go", "package lib\nfunc TestExported(){ _ = Exported(1); _ = Public{} }\n"), mustFile(t, "lib/broken.go", "package lib\nfunc (")}
	changes := []ChangedPath{mustChangedPath(t, "lib/api.go"), mustChangedPath(t, "lib/broken.go"), mustChangedPath(t, "README.md")}
	input, err := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), changes, base, head)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := AnalyzeGo(input)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, d := range profile.Declarations() {
		got[d.Key()] = string(d.Change())
	}
	for key, want := range map[string]string{"func:Exported": "modified", "func:removed": "removed", "type:Public": "added"} {
		if got[key] != want {
			t.Errorf("%s=%q", key, got[key])
		}
	}
	if len(profile.PublicAPIChanges()) != 1 || profile.PublicAPIChanges()[0].Key() != "type:Public" {
		t.Fatalf("public=%#v", profile.PublicAPIChanges())
	}
	sawTest := false
	for _, r := range profile.References() {
		if r.DeclarationKey() == "func:Exported" && r.Path() == "lib/api_test.go" && r.AffectedTest() && r.Grade() == GradeSyntacticCandidate {
			sawTest = true
		}
	}
	if !sawTest {
		t.Fatal("missing affected test candidate")
	}
	reasons := map[GapReason]bool{}
	for _, g := range profile.Gaps() {
		reasons[g.Reason()] = true
	}
	if !reasons[GapUnsupportedLanguage] || !reasons[GapParseFailure] {
		t.Fatalf("gaps=%#v", profile.Gaps())
	}
	if profile.AdapterIdentity() == "" || profile.GraphSchema() != "open-trestle/semantic-impact/go-ast-graph/v1" || profile.Identity() == "" {
		t.Fatal("identity")
	}
}
func TestAnalyzeGoIsOrderIndependentAndBounded(t *testing.T) {
	f1 := mustFile(t, "a.go", "package p\nfunc A(){}\n")
	f2 := mustFile(t, "z.go", "package p\nfunc Z(){A()}\n")
	c1 := mustChangedPath(t, "a.go")
	one, _ := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []ChangedPath{c1}, nil, []File{f1, f2})
	two, _ := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []ChangedPath{c1}, nil, []File{f2, f1})
	p1, e1 := AnalyzeGo(one)
	p2, e2 := AnalyzeGo(two)
	if e1 != nil || e2 != nil || p1.Identity() != p2.Identity() {
		t.Fatalf("profiles=(%v,%v,%v,%v)", p1.Identity(), p2.Identity(), e1, e2)
	}
	_, err := NewFile("bad/../x.go", []byte("package x"))
	if !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("path err=%v", err)
	}
}

func TestGoPublicAPIDigestSeparatesBodyAndSignatureChanges(t *testing.T) {
	base := mustFile(t, "a.go", "package p\nfunc Exported(v int) int{return v}\n")
	body := mustFile(t, "a.go", "package p\nfunc Exported(v int) int{return v+1}\n")
	signature := mustFile(t, "a.go", "package p\nfunc Exported(v int, extra ...int) int{return v}\n")
	changed := []ChangedPath{mustChangedPath(t, "a.go")}
	makeProfile := func(head File) Profile {
		input, err := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), changed, []File{base}, []File{head})
		if err != nil {
			t.Fatal(err)
		}
		profile, err := AnalyzeGo(input)
		if err != nil {
			t.Fatal(err)
		}
		return profile
	}
	bodyProfile := makeProfile(body)
	signatureProfile := makeProfile(signature)
	if len(bodyProfile.Declarations()) != 1 || bodyProfile.Declarations()[0].PublicAPIChange() || len(bodyProfile.PublicAPIChanges()) != 0 {
		t.Fatal("body-only change classified as public API")
	}
	if len(signatureProfile.PublicAPIChanges()) != 1 || !signatureProfile.PublicAPIChanges()[0].PublicAPIChange() {
		t.Fatal("signature change omitted")
	}
}
func TestSemanticTypesRedactSource(t *testing.T) {
	file := mustFile(t, "secret.go", "package secret\nconst password=\"never-print\"\n")
	changed := mustChangedPath(t, "secret.go")
	input, _ := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []ChangedPath{changed}, nil, []File{file})
	profile, _ := AnalyzeGo(input)
	for _, value := range []string{fmt.Sprintf("%v", file), fmt.Sprintf("%#v", file), fmt.Sprintf("%v", input), fmt.Sprintf("%#v", profile)} {
		if strings.Contains(value, "never-print") || strings.Contains(value, "secret.go") {
			t.Fatalf("leaked %q", value)
		}
	}
}

func mustFile(t *testing.T, path, content string) File {
	t.Helper()
	f, err := NewFile(path, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func mustChangedPath(t *testing.T, path string) ChangedPath {
	t.Helper()
	c, err := NewChangedPath(path)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
