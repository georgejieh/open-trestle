package context

import (
	"context"
	"path"
	"sort"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/changecodec"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
	"github.com/georgejieh/open-trestle/repoindex"
	"github.com/georgejieh/open-trestle/reviewcontext"
	"github.com/georgejieh/open-trestle/semanticimpact"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
	"time"
)

// Bounds of the snapshot analysis, those the Go semantic-impact profile
// applied before the repository index existed.
const (
	maximumSnapshotGoFiles = 4096
	maximumSnapshotGoBytes = 64 << 20
)

// snapshotContextPlan plans index context from the snapshots the handler
// already loaded, analysing their Go files in process: the head's Go files
// and the base versions of the changed files; other languages need the
// repository index's worker processes. It serves a review without a
// repository index, or whose index could not be used.
func (h *Handler) snapshotContextPlan(ctx context.Context, scope audit.ReviewScope, at time.Time, base sourceoutput.Snapshot, change changecodec.Result, contents map[string][]byte, expires *time.Time) (review.ContextPlan, controlplane.RunFailure) {
	analyzer, err := semanticimpact.NewGoSyntaxAnalyzer(syntaxanalysis.DefaultLimits())
	if err != nil {
		return review.ContextPlan{}, controlplane.RunFailureInternal
	}
	paths := make([]string, 0, len(contents))
	for p := range contents {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	head, complete := map[string][]byte{}, true
	files, loaded := 0, 0
	for _, p := range paths {
		if content := contents[p]; path.Ext(p) == ".go" || path.Base(p) == "go.mod" {
			if files == maximumSnapshotGoFiles || loaded+len(content) > maximumSnapshotGoBytes {
				complete = false
				continue
			}
			files++
			loaded += len(content)
			head[p] = content
		}
	}
	baseContents, failure := h.changedBaseContents(ctx, scope, at, base, change, expires)
	if failure != 0 {
		return review.ContextPlan{}, failure
	}
	defer clearContents(baseContents)
	headGraph, err := repoindex.MemoryGraph(ctx, "head", head, analyzer)
	if err != nil {
		return review.ContextPlan{}, controlplane.RunFailureCanceled
	}
	baseGraph, err := repoindex.MemoryGraph(ctx, "base", baseContents, analyzer)
	if err != nil {
		return review.ContextPlan{}, controlplane.RunFailureCanceled
	}
	changes := []repoindex.Change{}
	for _, entry := range change.Entries() {
		p := entry.Path()
		headContent, inHead := contents[p]
		baseContent, inBase := baseContents[p]
		if path.Ext(p) != ".go" || !inHead && !inBase {
			continue
		}
		headPath, basePath := p, p
		if !inHead {
			headPath = ""
		}
		if !inBase {
			basePath = ""
		}
		changes = append(changes, repoindex.ChangeOf(headPath, basePath, baseContent, headContent))
	}
	repoindex.SortChanges(changes)
	plan, err := reviewcontext.Plan(ctx, headGraph, baseGraph, changes, reviewcontext.DefaultLimits())
	if err != nil {
		return review.ContextPlan{}, controlplane.RunFailureCanceled
	}
	plan.State = review.ContextIndexSnapshot
	plan.Complete = plan.Complete && complete
	return plan, 0
}

// changedBaseContents reads the base versions of the changed Go files.
func (h *Handler) changedBaseContents(ctx context.Context, scope audit.ReviewScope, at time.Time, base sourceoutput.Snapshot, change changecodec.Result, expires *time.Time) (map[string][]byte, controlplane.RunFailure) {
	changed := map[string]bool{}
	for _, entry := range change.Entries() {
		if path.Ext(entry.Path()) == ".go" {
			changed[entry.Path()] = true
		}
	}
	out := map[string][]byte{}
	loaded := 0
	for _, reference := range base.Files() {
		if !changed[reference.Path()] && path.Base(reference.Path()) != "go.mod" {
			continue
		}
		if loaded > maximumSnapshotGoBytes-reference.SizeBytes() {
			break
		}
		value, err := h.store.Get(ctx, scope, reference.ArtifactIdentity(), at)
		if err != nil {
			clearContents(out)
			return nil, readFailure(ctx, err)
		}
		file, err := sourceoutput.ParseFileArtifact(value, base, reference)
		if err != nil {
			clearContents(out)
			return nil, controlplane.RunFailureInvalidInput
		}
		out[reference.Path()] = file.Content()
		loaded += reference.SizeBytes()
		if value.ExpiresAt().Before(*expires) {
			*expires = value.ExpiresAt()
		}
	}
	return out, 0
}
