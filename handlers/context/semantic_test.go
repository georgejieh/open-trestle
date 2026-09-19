package context

import (
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/semanticimpact"
	"strings"
	"testing"
)

func TestAppendSemanticCandidatesCountsEveryTruncatedReference(t *testing.T) {
	baseText := "package p\nfunc Target(){}\n"
	var b strings.Builder
	b.WriteString("package p\nfunc Target(){ _=1 }\nfunc Use(){\n")
	for range 300 {
		b.WriteString("Target()\n")
	}
	b.WriteString("}\n")
	base, _ := semanticimpact.NewFile("a.go", []byte(baseText))
	head, _ := semanticimpact.NewFile("a.go", []byte(b.String()))
	changed, _ := semanticimpact.NewChangedPath("a.go")
	input, _ := semanticimpact.NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []semanticimpact.ChangedPath{changed}, []semanticimpact.File{base}, []semanticimpact.File{head})
	profile, err := semanticimpact.AnalyzeGo(input)
	if err != nil || len(profile.References()) != 300 {
		t.Fatalf("refs=%d err=%v", len(profile.References()), err)
	}
	scope, _ := memorycore.NewScope("tenant", "repository", "actor", memorycore.RefVisibilityExact, strings.Repeat("d", 64), []string{"."})
	candidates, omissions, failure := appendSemanticCandidates(map[string][]byte{"a.go": []byte(b.String())}, scope, profile, nil, nil)
	if failure != 0 || len(candidates) != maximumContextCandidates || len(omissions) != 1 || omissions[0].Reason() != "semantic_candidate_limit" || omissions[0].Count() != 172 {
		t.Fatalf("result=(%d,%#v,%v)", len(candidates), omissions, failure)
	}
}
func TestAppendSemanticCandidatesDeduplicatesRangesBeforeAdmission(t *testing.T) {
	base, _ := semanticimpact.NewFile("a.go", []byte("package p\nfunc Target(){}\n"))
	headText := "package p\nfunc Target(){_=1}\nfunc Use(){Target();Target();Target()}\n"
	head, _ := semanticimpact.NewFile("a.go", []byte(headText))
	changed, _ := semanticimpact.NewChangedPath("a.go")
	input, _ := semanticimpact.NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []semanticimpact.ChangedPath{changed}, []semanticimpact.File{base}, []semanticimpact.File{head})
	profile, _ := semanticimpact.AnalyzeGo(input)
	scope, _ := memorycore.NewScope("tenant", "repository", "actor", memorycore.RefVisibilityExact, strings.Repeat("d", 64), []string{"."})
	candidates, omissions, failure := appendSemanticCandidates(map[string][]byte{"a.go": []byte(headText)}, scope, profile, nil, nil)
	if failure != 0 || len(candidates) != 1 || len(omissions) != 1 || omissions[0].Reason() != "semantic_duplicate_source" || omissions[0].Count() != 2 {
		t.Fatalf("result=(%d,%#v,%v)", len(candidates), omissions, failure)
	}
}
