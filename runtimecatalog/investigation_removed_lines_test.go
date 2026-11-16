package runtimecatalog_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/memorycodec"
	"github.com/georgejieh/open-trestle/internal/review"
)

// bridgeLines returns the physical lines start..end of content, line endings
// included.
func bridgeLines(content []byte, start, end int) []byte {
	lines := strings.SplitAfter(string(content), "\n")
	return []byte(strings.Join(lines[start-1:end], ""))
}

// bridgeRemovedLinesAssembly rebuilds the context assembly of a removed-lines
// run from its stored upstream artifacts, with every removed_lines source's
// head line moved by shift. It stands in for a context assembler, so the
// pipeline's own assembly check is what admits or refuses it.
func (f *bridgeFixture) bridgeRemovedLinesAssembly(ctx context.Context, shift int) (modelhandler.InvestigationAssembly, error) {
	scope, now := f.prepared.Plan().Scope(), f.clock.Now()
	state, err := f.control.GetRun(ctx, scope)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	outputs := map[string]artifact.Artifact{}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory"} {
		task, ok := state.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeSucceeded {
			return modelhandler.InvestigationAssembly{}, fmt.Errorf("%s has no output", key)
		}
		if outputs[key], err = f.underlying.Get(ctx, scope, task.OutputIdentity(), now); err != nil {
			return modelhandler.InvestigationAssembly{}, err
		}
	}
	base, head, changed, analyzedArtifact, memoryArtifact := outputs["source-base"], outputs["source-head"], outputs["change"], outputs["analysis"], outputs["memory"]
	analyzed, err := analysishandler.ParseResultArtifact(analyzedArtifact, changed, base, head)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	recalled, err := memorycodec.ParseResultArtifact(memoryArtifact, changed, base, head)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	memoryScope, err := recalled.MemoryScope()
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	retrievals := []memory.LexicalRetrieval{}
	for _, query := range recalled.Queries() {
		retrieval, err := query.Retrieval(memoryScope, recalled.AsOf())
		if err != nil {
			return modelhandler.InvestigationAssembly{}, err
		}
		retrievals = append(retrievals, retrieval)
	}
	read := func(value artifact.Artifact) (map[string][]byte, []evidence.RepositoryFile, error) {
		snapshot, err := sourcehandler.ParseSnapshotArtifact(value)
		if err != nil {
			return nil, nil, err
		}
		contents, files := map[string][]byte{}, []evidence.RepositoryFile{}
		for _, reference := range snapshot.Files() {
			stored, err := f.underlying.Get(ctx, scope, reference.ArtifactIdentity(), now)
			if err != nil {
				return nil, nil, err
			}
			file, err := sourcehandler.ParseFileArtifact(stored, snapshot, reference)
			if err != nil {
				return nil, nil, err
			}
			contents[reference.Path()] = file.Content()
			repositoryFile, err := evidence.NewRepositoryFile(reference.Path(), file.Content())
			if err != nil {
				return nil, nil, err
			}
			files = append(files, repositoryFile)
		}
		return contents, files, nil
	}
	headContents, headFiles, err := read(head)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	baseContents, _, err := read(base)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	bind := func(contents map[string][]byte, path string, start, end int) ([]byte, evidence.SourceSliceBinding, error) {
		content := contents[path]
		file, err := evidence.NewRepositoryFile(path, content)
		if err != nil {
			return nil, evidence.SourceSliceBinding{}, err
		}
		span, err := evidence.NewSourceRange(path, start, end)
		if err != nil {
			return nil, evidence.SourceSliceBinding{}, err
		}
		slice := bridgeLines(content, start, end)
		binding, err := evidence.BindSourceSlice(file, content, span, slice)
		return slice, binding, err
	}
	sources, ranges := []review.ContextSource{}, []evidence.SourceRange{}
	for _, item := range analyzed.Items() {
		slice, binding, err := bind(headContents, item.Path(), item.StartLine(), item.EndLine())
		if err != nil {
			return modelhandler.InvestigationAssembly{}, err
		}
		evidenceItem, err := item.EvidenceItem()
		if err != nil {
			return modelhandler.InvestigationAssembly{}, err
		}
		source, err := review.NewBoundContextSource(review.ContextStageChangedHunk, memory.TaintRepositoryControlled, evidenceItem, slice, binding)
		if err != nil {
			return modelhandler.InvestigationAssembly{}, err
		}
		sources, ranges = append(sources, source), append(ranges, evidenceItem.SourceRange())
	}
	for _, item := range analyzed.RemovedLines() {
		slice, binding, err := bind(baseContents, item.Path(), item.StartLine(), item.EndLine())
		if err != nil {
			return modelhandler.InvestigationAssembly{}, err
		}
		evidenceItem, err := item.EvidenceItem()
		if err != nil {
			return modelhandler.InvestigationAssembly{}, err
		}
		source, err := review.NewRemovedLinesContextSource(evidenceItem, slice, binding, item.HeadLine()+shift)
		if err != nil {
			return modelhandler.InvestigationAssembly{}, err
		}
		sources = append(sources, source)
	}
	manifest, err := evidence.NewRepositoryManifest(headFiles)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	snapshot, err := review.NewAcquiredReviewPipelineSnapshot(scope.ReviewRunID(), manifest, ranges)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	limits, err := review.NewContextLimits(1<<20, 0)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	packet, err := review.NewContextPacketWithAccounting(scope, memoryScope, snapshot, review.ContextTaskCandidateGeneration, sources, retrievals, nil, limits)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	request, err := packet.ProviderRequest()
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	provenance := []string{analyzedArtifact.Identity(), memoryArtifact.Identity(), changed.Identity(), head.Identity(), analyzed.Identity(), recalled.Identity()}
	sort.Strings(provenance)
	expires := head.ExpiresAt()
	for _, value := range outputs {
		if value.ExpiresAt().Before(expires) {
			expires = value.ExpiresAt()
		}
	}
	initial, err := artifact.New(scope, artifact.KindContextPacket, "application/json", analyzedArtifact.Classification(), artifact.OriginHost, analyzedArtifact.Protection(), provenance, request.Payload(), now, expires)
	if err != nil {
		return modelhandler.InvestigationAssembly{}, err
	}
	return modelhandler.InvestigationAssembly{Packet: packet, Snapshot: snapshot, MemoryScope: memoryScope, InitialContextArtifact: initial, AnalysisArtifact: analyzedArtifact, MemoryArtifact: memoryArtifact, ChangeArtifact: changed, BaseSnapshotArtifact: base, HeadSnapshotArtifact: head}, nil
}

// bridgeAssembleContext replaces the context task: it hands the live pipeline
// the rebuilt assembly with removed_lines head lines moved by shift, and
// records what the pipeline returned.
func (f *bridgeFixture) bridgeAssembleContext(shift int, refused *error) {
	for _, observed := range f.observed {
		observed.replace["context"] = func(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
			failed, _ := controlplane.NewTaskFailure(controlplane.RunFailureInvalidInput)
			assembly, err := f.bridgeRemovedLinesAssembly(ctx, shift)
			if err != nil {
				f.t.Errorf("rebuild context assembly: %v", err)
				return failed
			}
			intent, err := f.bridge.PrepareContext(ctx, request, assembly)
			*refused = err
			if err != nil {
				return failed
			}
			completion, err := controlplane.NewTaskSuccess(intent.Identity())
			if err != nil {
				return failed
			}
			return completion
		}
	}
}

type bridgeContextSource struct {
	ID       string `json:"source_id"`
	Stage    string `json:"stage"`
	Digest   string `json:"evidence_digest"`
	Path     string `json:"path"`
	Start    int    `json:"start_line"`
	End      int    `json:"end_line"`
	HeadLine int    `json:"head_line"`
	Content  string `json:"content"`
}

// A live investigation of a change that removes a.go's zero guard assembles
// a removed_lines source for the removed base lines. At assembly the pipeline
// admits it because it matches its analysis record by evidence, binding, base
// file and head line; the run then completes with a verified finding on those
// base lines.
func TestInvestigationPipelineMatchesRemovedLinesToTheirAnalysisRecord(t *testing.T) {
	f := newBridgeFixture(t, "removed-lines")
	f.start()
	requiredCheck(t, f.runner.Run(f.ctx))
	requiredCheck(t, f.runner.Wait(f.ctx))
	state := f.settle()
	if state.Status() != controlplane.ReviewRunSucceeded {
		t.Fatalf("removed-lines investigation failed: %s", state.Failure())
	}
	view, err := f.bridge.ReadResult(f.ctx)
	requiredCheck(t, err)
	var packet struct {
		Sources []bridgeContextSource `json:"sources"`
	}
	requiredCheck(t, json.Unmarshal(view.InitialContextArtifact().Payload(), &packet))
	base, head, changed := f.output(state, "source-base"), f.output(state, "source-head"), f.output(state, "change")
	analyzed, err := analysishandler.ParseResultArtifact(f.output(state, "analysis"), changed, base, head)
	requiredCheck(t, err)
	records := analyzed.RemovedLines()
	if len(records) != 1 {
		t.Fatalf("analysis recorded %d deletion points, want 1", len(records))
	}
	baseFile, err := evidence.NewRepositoryFile("a.go", []byte(bridgeDeletionBase))
	requiredCheck(t, err)
	matched := 0
	for _, source := range packet.Sources {
		if source.Stage != "removed_lines" {
			continue
		}
		span, err := evidence.NewSourceRange(source.Path, source.Start, source.End)
		requiredCheck(t, err)
		binding, err := evidence.BindSourceSlice(baseFile, []byte(bridgeDeletionBase), span, []byte(source.Content))
		requiredCheck(t, err)
		record := records[0]
		if source.ID != record.EvidenceID() || binding.Identity() != record.BindingIdentity() || baseFile.Identity() != record.FileIdentity() || source.HeadLine != record.HeadLine() || source.HeadLine == 0 || source.Digest != binding.SliceDigest() {
			t.Fatalf("removed_lines source %+v does not match its analysis record", source)
		}
		matched++
	}
	if matched != 1 {
		t.Fatalf("initial context held %d removed_lines sources, want 1", matched)
	}
	captures := f.models.snapshot()
	if len(captures) != 5 {
		t.Fatalf("removed-lines investigation made %d model calls", len(captures))
	}
	set, err := f.diagnostics.GetDiagnosticSet(f.ctx, f.prepared.Plan().Scope())
	requiredCheck(t, err)
	findings := set.Findings()
	if set.VerifiedCount() != 1 || len(findings) != 1 || findings[0].Side() != diagnostics.LineSideBase || findings[0].Path() != "a.go" || findings[0].StartLine() != 3 || findings[0].EndLine() != 5 || int(findings[0].HeadLine()) != records[0].HeadLine() {
		t.Fatalf("verified removed-lines finding missing or misplaced: %d findings", len(findings))
	}
}

// The assembly check is the removed text's only custody, because removed base
// lines are not in the head snapshot. An assembly whose removed_lines source
// names another head line than its analysis record is refused before any
// model call; the same rebuilt assembly with the recorded head line is
// admitted, so the head line alone decides.
func TestInvestigationPipelineRefusesRemovedLinesThatMismatchTheirAnalysisRecord(t *testing.T) {
	for _, shift := range []int{0, 1} {
		t.Run(fmt.Sprintf("shift-%d", shift), func(t *testing.T) {
			f := newBridgeFixture(t, "removed-lines")
			var refused error
			f.bridgeAssembleContext(shift, &refused)
			f.start()
			_ = f.runner.Run(f.ctx)
			requiredCheck(t, f.runner.Wait(f.ctx))
			state := f.settle()
			contextTask, _ := state.Task("context")
			if shift == 0 {
				if refused != nil || contextTask.Status() != controlplane.TaskRuntimeSucceeded || state.Status() != controlplane.ReviewRunSucceeded {
					t.Fatalf("rebuilt assembly with the recorded head line was refused: %v (run %s)", refused, state.Status())
				}
				return
			}
			if !errors.Is(refused, modelhandler.ErrInvestigationPipeline) || contextTask.Status() != controlplane.TaskRuntimeFailed || state.Status() == controlplane.ReviewRunSucceeded {
				t.Fatalf("mismatched removed_lines head line was admitted: %v (context %s)", refused, contextTask.Status())
			}
			if len(f.models.snapshot()) != 0 {
				t.Fatal("refused assembly reached a model")
			}
			f.requireNoSuccessfulReadback()
		})
	}
}
