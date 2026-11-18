package syntaxwasm

import (
	"slices"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

func TestCaptureRolesIncludeContainerOpaqueAndLocal(t *testing.T) {
	roles, err := captureRoles([]string{"container", "opaque", "name", "local"})
	if err != nil {
		t.Fatal(err)
	}
	if roles[0].kind != roleContainer || roles[1].kind != roleOpaque || roles[2].kind != roleName || roles[3].kind != roleLocal {
		t.Fatalf("roles = %+v", roles)
	}
}

func TestDropOpaqueRemovesOnlyTypeReferencesInsideTheSpans(t *testing.T) {
	ref := func(kind syntaxanalysis.ReferenceKind, start int) syntaxanalysis.RawReference {
		return syntaxanalysis.RawReference{Kind: kind, Name: syntaxanalysis.Span{Start: start, End: start + 1}}
	}
	spans := []syntaxanalysis.Span{{Start: 30, End: 40}, {Start: 10, End: 20}, {Start: 15, End: 25}}
	in := []syntaxanalysis.RawReference{
		ref(syntaxanalysis.ReferenceType, 5),
		ref(syntaxanalysis.ReferenceType, 10),
		ref(syntaxanalysis.ReferenceType, 22),
		ref(syntaxanalysis.ReferenceCall, 22),
		ref(syntaxanalysis.ReferenceType, 25),
		ref(syntaxanalysis.ReferenceType, 39),
		ref(syntaxanalysis.ReferenceType, 40),
	}
	got := dropOpaque(append([]syntaxanalysis.RawReference(nil), in...), mergeSpans(spans))
	var kept []int
	for _, r := range got {
		kept = append(kept, r.Name.Start)
	}
	want := []int{5, 22, 25, 40}
	if len(kept) != len(want) {
		t.Fatalf("kept %v, want %v", kept, want)
	}
	for i := range want {
		if kept[i] != want[i] {
			t.Fatalf("kept %v, want %v", kept, want)
		}
	}
	if got := dropOpaque(in, nil); len(got) != len(in) {
		t.Fatal("no spans must keep every reference")
	}
}

func TestDropLocalsRemovesVariablesAndDeclarationsInsideTheSpans(t *testing.T) {
	content := []byte("int g; void f() { int x; int h(void); struct S { void m() {} }; }")
	span := func(text string) syntaxanalysis.Span {
		at := strings.Index(string(content), text)
		return syntaxanalysis.Span{Start: at, End: at + len(text)}
	}
	name := func(text string) syntaxanalysis.Span {
		s := span(text)
		return syntaxanalysis.Span{Start: s.Start, End: s.Start + 1}
	}
	body := span("{ int x; int h(void); struct S { void m() {} }; }")
	definitions := []syntaxanalysis.RawDefinition{
		{Kind: syntaxanalysis.KindVariable, Name: name("g"), Node: span("int g;")},
		{Kind: syntaxanalysis.KindFunction, Name: name("f()"), Node: span("void f() " + string(content[body.Start:body.End]))},
		{Kind: syntaxanalysis.KindVariable, Name: name("x;"), Node: span("int x;")},
		{Kind: syntaxanalysis.KindFunction, Name: name("h(void)"), Node: span("int h(void);")},
		{Kind: syntaxanalysis.KindStruct, Name: name("S {"), Node: span("struct S { void m() {} }")},
		{Kind: syntaxanalysis.KindFunction, Name: name("m()"), Node: span("void m() {}")},
	}
	got := dropLocals(content, slices.Clone(definitions), mergeSpans([]syntaxanalysis.Span{body}))
	var names []string
	for _, d := range got {
		names = append(names, string(content[d.Name.Start:d.Name.End]))
	}
	if want := []string{"g", "f", "S", "m"}; !slices.Equal(names, want) {
		t.Fatalf("kept %v, want %v", names, want)
	}
	if got := dropLocals(content, definitions, nil); len(got) != len(definitions) {
		t.Fatal("no spans must keep every definition")
	}
}
