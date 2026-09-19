package source

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

var ErrSnapshotRead = errors.New("snapshot read unavailable or outside bounds")

// SnapshotArtifactReader grants protected reads, not source acquisition or writes.
type SnapshotArtifactReader interface {
	Get(context.Context, audit.ReviewScope, string, time.Time) (artifact.Artifact, error)
}

type SnapshotReadLimits struct {
	MaxFiles, MaxLines, MaxResultBytes, MaxMatches int
	MaxScannedBytes                                uint64
}

func (l SnapshotReadLimits) valid() bool {
	return l.MaxFiles > 0 && l.MaxFiles <= 64 && l.MaxLines > 0 && l.MaxLines <= 256 &&
		l.MaxResultBytes > 0 && l.MaxResultBytes <= 65536 && l.MaxMatches > 0 && l.MaxMatches <= 64 &&
		l.MaxScannedBytes > 0 && l.MaxScannedBytes <= 16777216
}

type SnapshotFileRef struct {
	ref  string
	file FileReference
}

func (r SnapshotFileRef) Ref() string              { return r.ref }
func (r SnapshotFileRef) Path() string             { return r.file.Path() }
func (r SnapshotFileRef) Digest() string           { return r.file.Digest() }
func (r SnapshotFileRef) SizeBytes() int           { return r.file.SizeBytes() }
func (r SnapshotFileRef) ArtifactIdentity() string { return r.file.ArtifactIdentity() }

type SnapshotListing struct {
	files           []SnapshotFileRef
	omitted         int
	serializedBytes uint64
}

func (l SnapshotListing) Files() []SnapshotFileRef { return append([]SnapshotFileRef(nil), l.files...) }
func (l SnapshotListing) OmittedCount() int        { return l.omitted }
func (l SnapshotListing) SerializedBytes() uint64  { return l.serializedBytes }

type SnapshotSlice struct {
	file                          SnapshotFileRef
	content                       string
	binding                       evidence.SourceSliceBinding
	scannedBytes, serializedBytes uint64
}

func (s SnapshotSlice) Content() []byte                      { return []byte(s.content) }
func (s SnapshotSlice) Binding() evidence.SourceSliceBinding { return s.binding }
func (s SnapshotSlice) File() SnapshotFileRef                { return s.file }
func (s SnapshotSlice) ScannedBytes() uint64                 { return s.scannedBytes }
func (s SnapshotSlice) SerializedBytes() uint64              { return s.serializedBytes }

type SnapshotSearchResult struct {
	matches                       []SnapshotSlice
	complete                      bool
	scannedBytes, serializedBytes uint64
}

func (r SnapshotSearchResult) Matches() []SnapshotSlice {
	return append([]SnapshotSlice(nil), r.matches...)
}
func (r SnapshotSearchResult) Complete() bool          { return r.complete }
func (r SnapshotSearchResult) ScannedBytes() uint64    { return r.scannedBytes }
func (r SnapshotSearchResult) SerializedBytes() uint64 { return r.serializedBytes }

// SnapshotReader resolves only its bounded, immutable snapshot reference set.
type SnapshotReader struct {
	store            SnapshotArtifactReader
	clock            artifact.Clock
	scope            audit.ReviewScope
	snapshot         Snapshot
	limits           SnapshotReadLimits
	files            []SnapshotFileRef
	byRef            map[string]SnapshotFileRef
	created, expires time.Time
}

func NewSnapshotReader(ctx context.Context, store SnapshotArtifactReader, clock artifact.Clock, scope audit.ReviewScope, snapshotArtifactIdentity, snapshotIdentity string, limits SnapshotReadLimits) (*SnapshotReader, error) {
	if nilInterface(ctx) || ctx.Err() != nil || nilInterface(store) || nilInterface(clock) || scope.Validate() != nil || !validDigest(snapshotArtifactIdentity) || !validDigest(snapshotIdentity) || !limits.valid() {
		return nil, ErrSnapshotRead
	}
	at := clock.Now()
	if at.UnixMilli() <= 0 {
		return nil, ErrSnapshotRead
	}
	value, err := store.Get(ctx, scope, snapshotArtifactIdentity, at)
	if err != nil || ctx.Err() != nil || !snapshotArtifactCurrent(value, scope, snapshotArtifactIdentity, clock.Now()) {
		return nil, ErrSnapshotRead
	}
	snapshot, err := ParseSnapshotArtifact(value)
	if err != nil || snapshot.Identity() != snapshotIdentity {
		return nil, ErrSnapshotRead
	}
	r := &SnapshotReader{store: store, clock: clock, scope: scope, snapshot: snapshot, limits: limits, byRef: make(map[string]SnapshotFileRef), created: value.CreatedAt(), expires: value.ExpiresAt()}
	files := snapshot.Files()
	for _, file := range files[:min(len(files), limits.MaxFiles)] {
		encoded, err := json.Marshal([]any{"open-trestle/snapshot-file-ref", 1, scope.Identity(), snapshot.ArtifactIdentity(), snapshot.Identity(), snapshot.AcquisitionExecutionIdentity(), file.ArtifactIdentity(), file.Path(), file.Digest(), file.SizeBytes()})
		if err != nil {
			return nil, ErrSnapshotRead
		}
		sum := sha256.Sum256(encoded)
		ref := SnapshotFileRef{ref: hex.EncodeToString(sum[:]), file: file}
		if _, exists := r.byRef[ref.ref]; exists {
			return nil, ErrSnapshotRead
		}
		r.byRef[ref.ref] = ref
		r.files = append(r.files, ref)
	}
	if r.check(ctx, r.expires) != nil {
		return nil, ErrSnapshotRead
	}
	return r, nil
}

func snapshotArtifactCurrent(value artifact.Artifact, scope audit.ReviewScope, identity string, at time.Time) bool {
	return value.Validate() == nil && value.Identity() == identity && value.Scope().Identity() == scope.Identity() &&
		at.UnixMilli() > 0 && !at.Before(value.CreatedAt()) && at.Before(value.ExpiresAt())
}

func (r *SnapshotReader) check(ctx context.Context, expires time.Time) error {
	if r == nil || nilInterface(ctx) || ctx.Err() != nil || nilInterface(r.clock) || nilInterface(r.store) || !r.limits.valid() {
		return ErrSnapshotRead
	}
	at := r.clock.Now()
	if at.UnixMilli() <= 0 || at.Before(r.created) || !at.Before(r.expires) || !at.Before(expires) {
		return ErrSnapshotRead
	}
	return nil
}

func (r *SnapshotReader) refresh(ctx context.Context) error {
	if r == nil || r.check(ctx, r.expires) != nil {
		return ErrSnapshotRead
	}
	value, err := r.store.Get(ctx, r.scope, r.snapshot.ArtifactIdentity(), r.clock.Now())
	if err != nil || r.check(ctx, value.ExpiresAt()) != nil || !snapshotArtifactCurrent(value, r.scope, r.snapshot.ArtifactIdentity(), r.clock.Now()) {
		return ErrSnapshotRead
	}
	snapshot, err := ParseSnapshotArtifact(value)
	if err != nil || snapshot.Identity() != r.snapshot.Identity() {
		return ErrSnapshotRead
	}
	return nil
}

type snapshotFileRefWire struct {
	Ref              string `json:"ref"`
	Path             string `json:"path"`
	Digest           string `json:"digest"`
	SizeBytes        int    `json:"size_bytes"`
	ArtifactIdentity string `json:"file_artifact_identity"`
}

func snapshotRefWire(ref SnapshotFileRef) snapshotFileRefWire {
	return snapshotFileRefWire{ref.Ref(), ref.Path(), ref.Digest(), ref.SizeBytes(), ref.ArtifactIdentity()}
}

type snapshotSliceWire struct {
	File            snapshotFileRefWire `json:"file"`
	StartLine       int                 `json:"start_line"`
	EndLine         int                 `json:"end_line"`
	BindingIdentity string              `json:"binding_identity"`
	Content         string              `json:"content"`
}

func snapshotReadWire(value SnapshotSlice) snapshotSliceWire {
	span := value.binding.SourceRange()
	return snapshotSliceWire{snapshotRefWire(value.file), span.StartLine(), span.EndLine(), value.binding.Identity(), value.content}
}

func (r *SnapshotReader) List(ctx context.Context) (SnapshotListing, error) {
	if r.refresh(ctx) != nil {
		return SnapshotListing{}, ErrSnapshotRead
	}
	files := make([]snapshotFileRefWire, len(r.files))
	for i, file := range r.files {
		files[i] = snapshotRefWire(file)
	}
	omitted := r.snapshot.FileCount() - len(files)
	encoded, err := json.Marshal(struct {
		Files   []snapshotFileRefWire `json:"files"`
		Omitted int                   `json:"omitted_file_count"`
	}{files, omitted})
	if err != nil || len(encoded) > r.limits.MaxResultBytes || r.check(ctx, r.expires) != nil {
		return SnapshotListing{}, ErrSnapshotRead
	}
	return SnapshotListing{files: append([]SnapshotFileRef(nil), r.files...), omitted: omitted, serializedBytes: uint64(len(encoded))}, nil
}

func (r *SnapshotReader) load(ctx context.Context, ref SnapshotFileRef) ([]byte, time.Time, error) {
	if r.check(ctx, r.expires) != nil || ref.SizeBytes() < 0 || uint64(ref.SizeBytes()) > r.limits.MaxScannedBytes {
		return nil, time.Time{}, ErrSnapshotRead
	}
	value, err := r.store.Get(ctx, r.scope, ref.ArtifactIdentity(), r.clock.Now())
	if err != nil || r.check(ctx, value.ExpiresAt()) != nil || !snapshotArtifactCurrent(value, r.scope, ref.ArtifactIdentity(), r.clock.Now()) {
		return nil, time.Time{}, ErrSnapshotRead
	}
	file, err := ParseFileArtifact(value, r.snapshot, ref.file)
	if err != nil {
		return nil, time.Time{}, ErrSnapshotRead
	}
	content := file.Content()
	if uint64(len(content)) > r.limits.MaxScannedBytes || !utf8.Valid(content) || bytes.IndexByte(content, 0) >= 0 || r.check(ctx, value.ExpiresAt()) != nil {
		clear(content)
		return nil, time.Time{}, ErrSnapshotRead
	}
	return content, value.ExpiresAt(), nil
}

func (r *SnapshotReader) slice(ctx context.Context, ref SnapshotFileRef, content []byte, start, end int, physical []byte) (SnapshotSlice, error) {
	if len(physical) == 0 || len(physical) > r.limits.MaxResultBytes || r.check(ctx, r.expires) != nil {
		return SnapshotSlice{}, ErrSnapshotRead
	}
	file, err := evidence.NewRepositoryFile(ref.Path(), content)
	if err != nil || file.Digest() != ref.Digest() || file.SizeBytes() != ref.SizeBytes() {
		return SnapshotSlice{}, ErrSnapshotRead
	}
	span, err := evidence.NewSourceRange(ref.Path(), start, end)
	if err != nil {
		return SnapshotSlice{}, ErrSnapshotRead
	}
	binding, err := evidence.BindSourceSlice(file, content, span, physical)
	if err != nil || r.check(ctx, r.expires) != nil {
		return SnapshotSlice{}, ErrSnapshotRead
	}
	result := SnapshotSlice{file: ref, content: string(physical), binding: binding, scannedBytes: uint64(len(content))}
	encoded, err := json.Marshal(struct {
		Source       snapshotSliceWire `json:"source"`
		ScannedBytes uint64            `json:"scanned_bytes"`
	}{snapshotReadWire(result), result.scannedBytes})
	if err != nil || len(encoded) > r.limits.MaxResultBytes {
		return SnapshotSlice{}, ErrSnapshotRead
	}
	result.serializedBytes = uint64(len(encoded))
	return result, nil
}

func (r *SnapshotReader) Read(ctx context.Context, opaqueRef string, start, end int) (SnapshotSlice, error) {
	if r == nil || r.check(ctx, r.expires) != nil || start < 1 || end < start || end > 1000000 || end-start >= r.limits.MaxLines {
		return SnapshotSlice{}, ErrSnapshotRead
	}
	ref, exists := r.byRef[opaqueRef]
	if !exists || ref.SizeBytes() < 0 || uint64(ref.SizeBytes()) > r.limits.MaxScannedBytes {
		return SnapshotSlice{}, ErrSnapshotRead
	}
	if r.refresh(ctx) != nil {
		return SnapshotSlice{}, ErrSnapshotRead
	}
	content, expires, err := r.load(ctx, ref)
	if err != nil {
		return SnapshotSlice{}, ErrSnapshotRead
	}
	defer clear(content)
	line, begin := 1, 0
	for offset := 0; offset < len(content); offset++ {
		if offset%4096 == 0 && r.check(ctx, expires) != nil {
			return SnapshotSlice{}, ErrSnapshotRead
		}
		if content[offset] != '\n' && offset != len(content)-1 {
			continue
		}
		if line == end {
			result, err := r.slice(ctx, ref, content, start, end, content[begin:offset+1])
			if err != nil {
				return SnapshotSlice{}, ErrSnapshotRead
			}
			if r.check(ctx, expires) != nil {
				return SnapshotSlice{}, ErrSnapshotRead
			}
			return result, nil
		}
		line++
		if line == start {
			begin = offset + 1
		}
	}
	return SnapshotSlice{}, ErrSnapshotRead
}

func (r *SnapshotReader) Search(ctx context.Context, refs []string, literal string) (SnapshotSearchResult, error) {
	if r == nil || r.check(ctx, r.expires) != nil || len(refs) == 0 || len(refs) > r.limits.MaxFiles || len(literal) == 0 || len(literal) > 256 || !utf8.ValidString(literal) || strings.ContainsAny(literal, "\x00\r\n") {
		return SnapshotSearchResult{}, ErrSnapshotRead
	}
	selected := make([]SnapshotFileRef, 0, len(refs))
	seen := make(map[string]bool, len(refs))
	var scanned uint64
	for _, id := range refs {
		ref, exists := r.byRef[id]
		if !exists || seen[id] || ref.SizeBytes() < 0 || uint64(ref.SizeBytes()) > r.limits.MaxScannedBytes-scanned {
			return SnapshotSearchResult{}, ErrSnapshotRead
		}
		seen[id] = true
		scanned += uint64(ref.SizeBytes())
		selected = append(selected, ref)
	}
	if r.refresh(ctx) != nil {
		return SnapshotSearchResult{}, ErrSnapshotRead
	}
	result := SnapshotSearchResult{matches: []SnapshotSlice{}, scannedBytes: scanned}
	wires := []snapshotSliceWire{}
	expires := r.expires
	for _, ref := range selected {
		content, fileExpires, err := r.load(ctx, ref)
		if err != nil {
			return SnapshotSearchResult{}, ErrSnapshotRead
		}
		if fileExpires.Before(expires) {
			expires = fileExpires
		}
		err = r.searchFile(ctx, ref, content, []byte(literal), expires, &result, &wires)
		clear(content)
		if err != nil {
			return SnapshotSearchResult{}, ErrSnapshotRead
		}
	}
	encoded, err := json.Marshal(struct {
		Matches      []snapshotSliceWire `json:"matches"`
		Complete     bool                `json:"complete"`
		ScannedBytes uint64              `json:"scanned_bytes"`
	}{wires, true, scanned})
	if err != nil || len(encoded) > r.limits.MaxResultBytes || r.check(ctx, expires) != nil {
		return SnapshotSearchResult{}, ErrSnapshotRead
	}
	result.complete = true
	result.serializedBytes = uint64(len(encoded))
	return result, nil
}

func (r *SnapshotReader) searchFile(ctx context.Context, ref SnapshotFileRef, content, literal []byte, expires time.Time, result *SnapshotSearchResult, wires *[]snapshotSliceWire) error {
	for start, line := 0, 1; start < len(content); line++ {
		if line > 1000000 || r.check(ctx, expires) != nil {
			return ErrSnapshotRead
		}
		end := len(content)
		if offset := bytes.IndexByte(content[start:], '\n'); offset >= 0 {
			end = start + offset + 1
		}
		physical := content[start:end]
		if bytes.Contains(physical, literal) {
			if len(result.matches) >= r.limits.MaxMatches {
				return ErrSnapshotRead
			}
			match, err := r.slice(ctx, ref, content, line, line, physical)
			if err != nil {
				return ErrSnapshotRead
			}
			result.matches = append(result.matches, match)
			*wires = append(*wires, snapshotReadWire(match))
			encoded, err := json.Marshal(*wires)
			if err != nil || len(encoded) > r.limits.MaxResultBytes {
				return ErrSnapshotRead
			}
		}
		start = end
	}
	return nil
}

func (v SnapshotFileRef) String() string   { return "snapshot file reference" }
func (v SnapshotFileRef) GoString() string { return "source.SnapshotFileRef{<redacted>}" }
func (v SnapshotFileRef) Format(state fmt.State, verb rune) {
	writeSourceRedacted(state, verb, "snapshot file reference", "source.SnapshotFileRef{<redacted>}")
}

func (v SnapshotListing) String() string   { return "snapshot file listing" }
func (v SnapshotListing) GoString() string { return "source.SnapshotListing{<redacted>}" }
func (v SnapshotListing) Format(state fmt.State, verb rune) {
	writeSourceRedacted(state, verb, "snapshot file listing", "source.SnapshotListing{<redacted>}")
}

func (v SnapshotSlice) String() string   { return "snapshot source slice" }
func (v SnapshotSlice) GoString() string { return "source.SnapshotSlice{<redacted>}" }
func (v SnapshotSlice) Format(state fmt.State, verb rune) {
	writeSourceRedacted(state, verb, "snapshot source slice", "source.SnapshotSlice{<redacted>}")
}

func (v SnapshotSearchResult) String() string   { return "snapshot search result" }
func (v SnapshotSearchResult) GoString() string { return "source.SnapshotSearchResult{<redacted>}" }
func (v SnapshotSearchResult) Format(state fmt.State, verb rune) {
	writeSourceRedacted(state, verb, "snapshot search result", "source.SnapshotSearchResult{<redacted>}")
}

func (r *SnapshotReader) String() string   { return "protected snapshot reader" }
func (r *SnapshotReader) GoString() string { return "source.SnapshotReader{<redacted>}" }
func (r *SnapshotReader) Format(state fmt.State, verb rune) {
	writeSourceRedacted(state, verb, "protected snapshot reader", "source.SnapshotReader{<redacted>}")
}
