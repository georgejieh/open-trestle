package semanticimpact

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestGoImpactUsesPhysicalSourceCoordinates(t *testing.T) {
	for _, logicalLine := range []int{100, maximumSourcePosition + 100} {
		t.Run(fmt.Sprint(logicalLine), func(t *testing.T) {
			source := fmt.Sprintf("package p\n//line generated.go:%d\nfunc A(){ A() }\n//line generated.go:%d\nfunc B(){ A() }\n", logicalLine, logicalLine)
			file := mustFile(t, "a.go", source)
			input, err := NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []ChangedPath{mustChangedPath(t, "a.go")}, nil, []File{file})
			if err != nil {
				t.Fatal(err)
			}
			profile, err := AnalyzeGo(input)
			if err != nil {
				t.Fatal(err)
			}
			declarations := profile.Declarations()
			if len(declarations) != 2 || declarations[0].Path() != "a.go" || declarations[0].StartLine() != 3 || declarations[0].EndLine() != 3 || declarations[1].StartLine() != 5 || declarations[1].EndLine() != 5 {
				t.Fatalf("wrong physical declarations: %#v", declarations)
			}
			refs := profile.References()
			if len(refs) != 2 || refs[0].Line() != 3 || refs[1].Line() != 5 || refs[0].Column() != 11 || refs[1].Column() != 11 {
				t.Fatalf("wrong physical references: %#v", refs)
			}
			encoded, err := EncodeProfile(profile)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := DecodeProfile(encoded)
			if err != nil {
				t.Fatal(err)
			}
			roundtrip, err := EncodeProfile(decoded)
			if err != nil || !bytes.Equal(encoded, roundtrip) {
				t.Fatalf("roundtrip: %v", err)
			}
		})
	}
}
