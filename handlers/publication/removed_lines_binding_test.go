package publication

import (
	"context"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

// A deletion-only change supplies its removed base lines as removed_lines
// evidence. The route-granting context handler records them in the generation
// input outside the head snapshot ranges, and publication rebinds them to the
// exact base file instead of refusing them as unknown head evidence.
func TestBuildSourceBindingRebindsRemovedLinesToTheBaseFile(t *testing.T) {
	base := "package p\nfunc Changed(x int) int {\n\tif x == 0 {\n\t\treturn 0\n\t}\n\treturn 10 / x\n}\n"
	head := "package p\nfunc Changed(x int) int {\n\treturn 10 / x\n}\n"
	f := newSourceBindingFixtureFor(t, false, base, head)
	removed := f.analysis.RemovedLines()
	if f.analysis.SchemaVersion() != 7 || len(removed) != 1 || removed[0].StartLine() != 3 || removed[0].EndLine() != 5 {
		t.Fatalf("analysis did not bind the removed guard: version=%d removed=%d", f.analysis.SchemaVersion(), len(removed))
	}
	found := false
	for _, item := range f.input.EvidenceItems() {
		found = found || item.ID() == removed[0].EvidenceID()
	}
	if !found {
		t.Fatal("generation input lacks the removed_lines evidence")
	}
	for _, sourceRange := range f.input.Snapshot().Ranges() {
		if sourceRange.StartLine() == 3 && sourceRange.EndLine() == 5 {
			t.Fatal("removed base lines entered the head snapshot ranges")
		}
	}
	handler := &Handler{store: f.store}
	got, err := handler.buildSourceBinding(context.Background(), f.scope, f.target, nil, artifact.Artifact{}, f.inputArtifact, f.contextArtifact, time.UnixMilli(250))
	if err != nil || got.Validate() != nil {
		t.Fatalf("publication refused removed_lines evidence: %v", err)
	}
	bindings := make([]string, 0, len(f.input.EvidenceItems()))
	for _, item := range f.input.EvidenceItems() {
		if item.ID() == removed[0].EvidenceID() {
			bindings = append(bindings, removed[0].BindingIdentity())
			continue
		}
		content := f.contents[item.SourceRange().Path()]
		file, err := evidence.NewRepositoryFile(item.SourceRange().Path(), content)
		if err != nil {
			t.Fatal(err)
		}
		binding, err := evidence.BindSourceRange(file, content, item.SourceRange())
		if err != nil {
			t.Fatal(err)
		}
		bindings = append(bindings, binding.Identity())
	}
	want, err := review.NewProtectedSourceBinding(f.scope, f.change.Repository(), f.change.HeadRevision(), f.headArtifact.Identity(), f.head.Identity(), f.head.ManifestIdentity(), f.changeArtifact.Identity(), f.change.Identity(), f.analysisArtifact.Identity(), f.contextArtifact.Identity(), f.input.ContextIdentity(), f.input.Snapshot().Identity(), bindings)
	if err != nil || got.Identity() != want.Identity() {
		t.Fatalf("publication binding does not bind the removed lines to the base file: %v", err)
	}
}
