package semanticimpact

import (
	"errors"
	"strings"
	"testing"
)

func TestGoImpactPreservesChangesWithRepeatedInitAndBlankNames(t *testing.T) {
	prefix := "package p\nvar _ = 1\nvar _ = 2\ntype _ int\ntype _ string\nfunc _(){}\nfunc _(){}\n"
	base := mustFile(t, "a.go", prefix+"func init(){}\nfunc init(){ println(1) }\nfunc Exported(){}\n")
	head := mustFile(t, "a.go", prefix+"func init(){}\nfunc init(){ println(2) }\nfunc Exported(){ println(3) }\n")
	input, err := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []ChangedPath{mustChangedPath(t, "a.go")}, []File{base}, []File{head})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := AnalyzeGo(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(profile.Gaps()) != 0 {
		t.Fatalf("valid Go marked unsupported: %#v", profile.Gaps())
	}
	declarations := profile.Declarations()
	if len(declarations) != 2 {
		t.Fatalf("changed declarations=%#v", declarations)
	}
	seen := map[string]bool{}
	for _, d := range declarations {
		seen[d.Name()] = true
		if d.Change() != ChangeModified || d.PublicAPIChange() {
			t.Fatalf("body change misclassified: %#v", d)
		}
	}
	if !seen["init"] || !seen["Exported"] {
		t.Fatalf("missing changes: %#v", declarations)
	}
	if _, err := EncodeProfile(profile); err != nil {
		t.Fatal(err)
	}
}

func TestGoBlankVariablesChangedComparesOnlyBlankVarSpecs(t *testing.T) {
	const base = "package p\nvar _ = register(1)\nvar x, _ = f()\nconst _ = 1\n"
	for name, test := range map[string]struct {
		base, head []byte
		want       bool
	}{
		"unchanged":              {[]byte(base), []byte(base + "func g() {}\n"), false},
		"changed initializer":    {[]byte(base), []byte("package p\nvar _ = register(2)\nvar x, _ = f()\nconst _ = 1\n"), true},
		"named spec changed":     {[]byte(base), []byte("package p\nvar _ = register(1)\nvar x, _ = g()\nconst _ = 1\n"), false},
		"blank constant changed": {[]byte(base), []byte("package p\nvar _ = register(1)\nvar x, _ = f()\nconst _ = 2\n"), false},
		"added file":             {nil, []byte(base), true},
		"removed file":           {[]byte(base), nil, true},
		"added file without one": {nil, []byte("package p\nvar x = 1\n"), false},
		"unparsable head":        {[]byte(base), []byte("package p\nvar _ =\n"), true},
	} {
		if got := GoBlankVariablesChanged(test.base, test.head); got != test.want {
			t.Fatalf("%s: GoBlankVariablesChanged = %t", name, got)
		}
	}
}

func TestGoImpactDeclarationNameLimitProducesEncodableResults(t *testing.T) {
	for _, length := range []int{1024, 1025} {
		name := strings.Repeat("A", length)
		file := mustFile(t, "a.go", "package p\nfunc "+name+"(){}\n")
		input, err := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []ChangedPath{mustChangedPath(t, "a.go")}, nil, []File{file})
		if err != nil {
			t.Fatal(err)
		}
		profile, err := AnalyzeGo(input)
		if length > 1024 {
			if !errors.Is(err, ErrImpactLimit) || profile.Identity() != "" {
				t.Fatalf("oversized name returned successful/unbounded profile: %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := EncodeProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecodeProfile(encoded); err != nil {
			t.Fatal(err)
		}
	}
}
