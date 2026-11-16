package context

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/review"

	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

func TestAppendSemanticCandidatesAttributesCountedOmissionsToEachPath(t *testing.T) {
	targetBase := "package p\nfunc Target(){}\n"
	targetHeadText := "package p\nfunc Target(){ _=1 }\n"
	makeCalls := func(name string) string {
		var builder strings.Builder
		builder.WriteString("package p\nfunc " + name + "(){\n")
		for range 150 {
			builder.WriteString("Target()\n")
		}
		builder.WriteString("}\n")
		return builder.String()
	}
	firstText, secondText := makeCalls("First"), makeCalls("Second")
	base, _ := semanticimpact.NewFile("target.go", []byte(targetBase))
	targetHead, _ := semanticimpact.NewFile("target.go", []byte(targetHeadText))
	first, _ := semanticimpact.NewFile("a.go", []byte(firstText))
	second, _ := semanticimpact.NewFile("b.go", []byte(secondText))
	changedFirst, _ := semanticimpact.NewChangedPath("a.go")
	changedSecond, _ := semanticimpact.NewChangedPath("b.go")
	changedTarget, _ := semanticimpact.NewChangedPath("target.go")
	input, err := semanticimpact.NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []semanticimpact.ChangedPath{changedFirst, changedSecond, changedTarget}, []semanticimpact.File{base}, []semanticimpact.File{first, second, targetHead})
	if err != nil {
		t.Fatal(err)
	}
	profile, err := semanticimpact.AnalyzeGo(input)
	if err != nil || len(profile.References()) != 300 {
		t.Fatalf("references=%d err=%v", len(profile.References()), err)
	}
	scope, _ := memorycore.NewScope("tenant", "repository", "actor", memorycore.RefVisibilityExact, strings.Repeat("d", 64), []string{"."})
	candidates, omissions, failure := appendSemanticCandidates(map[string][]byte{"a.go": []byte(firstText), "b.go": []byte(secondText), "target.go": []byte(targetHeadText)}, scope, profile, nil, nil)
	if failure != 0 || len(candidates) != maximumContextCandidates || len(omissions) != 2 {
		t.Fatalf("candidates=%d omissions=%+v failure=%s", len(candidates), omissions, failure)
	}
	byPath := map[string]uint32{}
	for _, omission := range omissions {
		if omission.Reason() != "semantic_candidate_limit" || omission.StartLine() != 0 || omission.EndLine() != 0 {
			t.Fatalf("false precise location: %+v", omission)
		}
		byPath[omission.Path()] += omission.Count()
	}
	if byPath["a.go"] != 22 || byPath["b.go"] != 150 || len(byPath) != 2 {
		t.Fatalf("per-path omissions=%v", byPath)
	}
	omissionA, _ := review.NewCountedContextSourceOmission("existing-a.go", 0, 0, "candidate_limit", 32768)
	omissionB, _ := review.NewCountedContextSourceOmission("existing-b.go", 0, 0, "candidate_limit", 32768)
	_, _, overflow := appendSemanticCandidates(map[string][]byte{"a.go": []byte(firstText), "b.go": []byte(secondText), "target.go": []byte(targetHeadText)}, scope, profile, nil, []review.ContextSourceOmission{omissionA, omissionB})
	if overflow != controlplane.RunFailureResourceLimit {
		t.Fatalf("combined preselection+semantic count exceeded 65536: failure=%s", overflow)
	}
}
