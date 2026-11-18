package syntaxwasm

import (
	"testing"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

func TestCaptureRolesIncludeContainerAndOpaque(t *testing.T) {
	roles, err := captureRoles([]string{"container", "opaque", "name"})
	if err != nil {
		t.Fatal(err)
	}
	if roles[0].kind != roleContainer || roles[1].kind != roleOpaque || roles[2].kind != roleName {
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
	got := dropOpaque(append([]syntaxanalysis.RawReference(nil), in...), spans)
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
