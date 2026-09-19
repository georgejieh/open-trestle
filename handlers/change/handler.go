package change

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

const maximumLoadedSourceBytes = 256 << 20

type Handler struct {
	identity string
	store    artifact.Store
	clock    artifact.Clock
}

func NewHandler(store artifact.Store, clock artifact.Clock) (*Handler, error) {
	if nilInterface(store) || nilInterface(clock) {
		return nil, ErrInvalidHandler
	}
	handler := &Handler{store: store, clock: clock}
	handler.identity = deriveHandlerIdentity()
	return handler, nil
}
func (h *Handler) HandlerIdentity() string {
	if h == nil {
		return ""
	}
	return h.identity
}
func (h *Handler) Kind() controlplane.TaskKind {
	if h == nil {
		return 0
	}
	return controlplane.TaskBuildChange
}
func (h *Handler) Validate() error {
	if h == nil || nilInterface(h.store) || nilInterface(h.clock) || h.identity != deriveHandlerIdentity() {
		return ErrInvalidHandler
	}
	return nil
}
func deriveHandlerIdentity() string {
	encoded, _ := json.Marshal(struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
	}{"open-trestle/change-model-handler", 2})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

type loadedSnapshot struct {
	artifact      artifact.Artifact
	snapshot      source.Snapshot
	inputArtifact artifact.Artifact
	input         source.Input
	manifest      evidence.RepositoryManifest
	contents      map[string][]byte
	bytes         int
}

func (h *Handler) Execute(ctx context.Context, request controlplane.TaskExecutionRequest) controlplane.TaskCompletion {
	if nilInterface(ctx) || h.Validate() != nil || request.Validate() != nil || request.Task().Kind() != controlplane.TaskBuildChange || request.Task().HandlerIdentity() != h.identity || !slicesEqual(request.Task().Dependencies(), []string{"source-base", "source-head"}) {
		return failure(controlplane.RunFailureInvalidInput)
	}
	if ctx.Err() != nil {
		return failure(controlplane.RunFailureCanceled)
	}
	at := h.clock.Now().UTC()
	if at.UnixMilli() <= 0 || at.After(request.Lease().ExpiresAt()) {
		return failure(controlplane.RunFailureCanceled)
	}
	base, err := h.load(ctx, request, "source-base", at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	defer clearContents(base.contents)
	head, err := h.load(ctx, request, "source-head", at)
	if err != nil {
		return failure(readFailure(ctx, err))
	}
	defer clearContents(head.contents)
	if base.bytes+head.bytes > maximumLoadedSourceBytes || base.input.Repository().Identity() != head.input.Repository().Identity() || base.input.SourceAdapterIdentity() != head.input.SourceAdapterIdentity() || base.artifact.Classification() != head.artifact.Classification() || base.artifact.Protection() != head.artifact.Protection() {
		return failure(controlplane.RunFailureInvalidInput)
	}
	delta, err := evidence.NewRepositoryManifestDelta(base.manifest, head.manifest)
	if err != nil || delta.Identity() == "" {
		return failure(controlplane.RunFailureInternal)
	}
	entries := delta.Entries()
	if len(entries) > maximumChangedEntries {
		return failure(controlplane.RunFailureResourceLimit)
	}
	executions := make([]evidence.RepositoryFileDeltaExecution, len(entries))
	extra := make(map[string][]evidence.SourceRange)
	for index, entry := range entries {
		if ctx.Err() != nil {
			return failure(controlplane.RunFailureCanceled)
		}
		baseContent := evidence.RepositoryFileDeltaContent{}
		headContent := evidence.RepositoryFileDeltaContent{}
		if content, ok := base.contents[entry.Path()]; ok {
			baseContent = evidence.RepositoryFileDeltaContent{Present: true, Content: content}
		}
		if content, ok := head.contents[entry.Path()]; ok {
			headContent = evidence.RepositoryFileDeltaContent{Present: true, Content: content}
		}
		execution, err := evidence.ExecuteRepositoryFileDelta(entry, baseContent, headContent)
		if err != nil {
			return failure(controlplane.RunFailureInternal)
		}
		executions[index] = execution
		if entry.Kind() == evidence.RepositoryFileDeltaAdded && execution.Status() == evidence.RepositoryFileDeltaExecutionStatusUnsupported {
			if sourceRange, ok := wholeTextRange(entry.Path(), headContent.Content); ok {
				extra[entry.Path()] = []evidence.SourceRange{sourceRange}
			}
		}
	}
	result, err := newResult(base.artifact, head.artifact, base.snapshot, head.snapshot, base.input.Repository(), base.input.Revision(), head.input.Revision(), delta, executions, extra)
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	payload, err := encodeResult(result)
	if err != nil {
		return failure(controlplane.RunFailureResourceLimit)
	}
	expires := base.artifact.ExpiresAt()
	if head.artifact.ExpiresAt().Before(expires) {
		expires = head.artifact.ExpiresAt()
	}
	provenance := []string{base.artifact.Identity(), head.artifact.Identity(), base.inputArtifact.Identity(), head.inputArtifact.Identity(), delta.Identity()}
	sort.Strings(provenance)
	output, err := artifact.New(request.Plan().Scope(), artifact.KindChangeModel, "application/json", base.artifact.Classification(), artifact.OriginDeterministicTool, base.artifact.Protection(), provenance, payload, at, expires)
	if err != nil {
		return failure(controlplane.RunFailureResourceLimit)
	}
	if _, err := h.store.Put(ctx, output, at); err != nil {
		return failure(writeFailure(ctx, err))
	}
	completion, err := controlplane.NewTaskSuccess(output.Identity())
	if err != nil {
		return failure(controlplane.RunFailureInternal)
	}
	return completion
}
func (h *Handler) load(ctx context.Context, request controlplane.TaskExecutionRequest, key string, at time.Time) (loadedSnapshot, error) {
	dependency, ok := request.DependencyOutput(key)
	if !ok || !dependency.Available() {
		return loadedSnapshot{}, ErrInvalidResult
	}
	task, ok := request.Plan().Task(key)
	if !ok || len(task.Dependencies()) != 0 {
		return loadedSnapshot{}, ErrInvalidResult
	}
	snapshotArtifact, err := h.store.Get(ctx, request.Plan().Scope(), dependency.OutputIdentity(), at)
	if err != nil {
		return loadedSnapshot{}, err
	}
	snapshot, err := source.ParseSnapshotArtifact(snapshotArtifact)
	if err != nil {
		return loadedSnapshot{}, ErrInvalidResult
	}
	inputArtifact, err := h.store.Get(ctx, request.Plan().Scope(), task.InputIdentity(), at)
	if err != nil {
		return loadedSnapshot{}, err
	}
	input, err := source.ParseInput(inputArtifact.Payload())
	if err != nil || inputArtifact.Kind() != artifact.KindTaskInput || inputArtifact.Origin() != artifact.OriginHost || inputArtifact.Classification() != snapshotArtifact.Classification() || inputArtifact.Protection() != snapshotArtifact.Protection() || input.Repository().Identity() != snapshot.RepositoryIdentity() || input.Revision().Identity() != snapshot.RevisionIdentity() || input.SourceAdapterIdentity() != snapshot.SourceAdapterIdentity() {
		return loadedSnapshot{}, ErrInvalidResult
	}
	files := make([]evidence.RepositoryFile, 0, snapshot.FileCount())
	contents := make(map[string][]byte, snapshot.FileCount())
	success := false
	defer func() {
		if !success {
			clearContents(contents)
		}
	}()
	total := 0
	for _, reference := range snapshot.Files() {
		value, err := h.store.Get(ctx, request.Plan().Scope(), reference.ArtifactIdentity(), at)
		if err != nil {
			return loadedSnapshot{}, err
		}
		file, err := source.ParseFileArtifact(value, snapshot, reference)
		if err != nil {
			return loadedSnapshot{}, ErrInvalidResult
		}
		content := file.Content()
		total += len(content)
		if total > maximumLoadedSourceBytes {
			return loadedSnapshot{}, artifact.ErrStoreCapacity
		}
		repositoryFile, err := evidence.NewRepositoryFile(file.Path(), content)
		if err != nil {
			return loadedSnapshot{}, ErrInvalidResult
		}
		files = append(files, repositoryFile)
		contents[file.Path()] = content
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	if err != nil || manifest.Identity() != snapshot.ManifestIdentity() {
		clearContents(contents)
		return loadedSnapshot{}, ErrInvalidResult
	}
	success = true
	return loadedSnapshot{snapshotArtifact, snapshot, inputArtifact, input, manifest, contents, total}, nil
}
func wholeTextRange(path string, content []byte) (evidence.SourceRange, bool) {
	if len(content) == 0 || len(content) > 4<<20 || !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 {
		return evidence.SourceRange{}, false
	}
	lines := bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		lines++
	}
	if lines <= 0 || lines > 1_000_000 {
		return evidence.SourceRange{}, false
	}
	value, err := evidence.NewSourceRange(path, 1, lines)
	return value, err == nil
}
func slicesEqual(first, second []string) bool {
	if len(first) != len(second) {
		return false
	}
	for i := range first {
		if first[i] != second[i] {
			return false
		}
	}
	return true
}
func readFailure(ctx context.Context, err error) controlplane.RunFailure {
	if ctx.Err() != nil {
		return controlplane.RunFailureCanceled
	}
	if errors.Is(err, artifact.ErrArtifactNotFound) || errors.Is(err, artifact.ErrArtifactExpired) || errors.Is(err, ErrInvalidResult) {
		return controlplane.RunFailureInvalidInput
	}
	if errors.Is(err, artifact.ErrStoreCapacity) {
		return controlplane.RunFailureResourceLimit
	}
	return controlplane.RunFailureInternal
}
func writeFailure(ctx context.Context, err error) controlplane.RunFailure {
	if ctx.Err() != nil {
		return controlplane.RunFailureCanceled
	}
	if errors.Is(err, artifact.ErrStoreCapacity) {
		return controlplane.RunFailureResourceLimit
	}
	return controlplane.RunFailureInternal
}
func failure(kind controlplane.RunFailure) controlplane.TaskCompletion {
	value, _ := controlplane.NewTaskFailure(kind)
	return value
}
func clearContents(contents map[string][]byte) {
	for _, content := range contents {
		clear(content)
	}
}
func nilInterface(value any) bool {
	if value == nil {
		return true
	}
	ref := reflect.ValueOf(value)
	switch ref.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return ref.IsNil()
	default:
		return false
	}
}
func (h *Handler) String() string   { return "change model task handler" }
func (h *Handler) GoString() string { return "change.Handler{<redacted>}" }
func (h *Handler) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "change model task handler", "change.Handler{<redacted>}")
}

var _ controlplane.TaskHandler = (*Handler)(nil)
