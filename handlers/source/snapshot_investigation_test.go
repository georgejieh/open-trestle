package source

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

type investigationReadStore struct {
	artifact.Store
	gets    []string
	replace func(artifact.Artifact) artifact.Artifact
}

func (s *investigationReadStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	s.gets = append(s.gets, id)
	value, err := s.Store.Get(ctx, scope, id, at)
	if err == nil && s.replace != nil {
		value = s.replace(value)
	}
	return value, err
}

type investigationClock struct{ at time.Time }

func (c *investigationClock) Now() time.Time { return c.at }

func acquiredInvestigationSource(t *testing.T, scope audit.ReviewScope, revisionByte string, overrides ...map[string][]byte) (*artifact.MemoryStore, artifact.Artifact, Snapshot) {
	t.Helper()
	repository, _, adapter, result := sourceFixture(t)
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat(revisionByte, 40))
	if err != nil {
		t.Fatal(err)
	}
	result.Contents = map[string][]byte{"empty.txt": {}, "notes.txt": []byte("first\r\nneedle here\r\nlast"), "other.txt": []byte("needle elsewhere\n")}
	if len(overrides) == 1 {
		result.Contents = overrides[0]
	}
	files := []evidence.RepositoryFile{}
	for path, content := range result.Contents {
		file, err := evidence.NewRepositoryFile(path, content)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	result.Manifest, err = evidence.NewRepositoryManifest(files)
	if err != nil {
		t.Fatal(err)
	}
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 30)
	if err != nil {
		t.Fatal(err)
	}
	inner := &sourceAdapter{identity: adapter, result: result}
	handler, err := NewHandler(store, inner, fixedClock{at: time.UnixMilli(200)})
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewInput(repository, revision, adapter)
	if err != nil {
		t.Fatal(err)
	}
	inputArtifact, err := NewInputArtifact(scope, input, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, []string{strings.Repeat("d", 64)}, time.UnixMilli(100), time.UnixMilli(10000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Put(context.Background(), inputArtifact, time.UnixMilli(100)); err != nil {
		t.Fatal(err)
	}
	completion := handler.Execute(context.Background(), taskExecutionRequest(t, scope, inputArtifact.Identity(), handler.HandlerIdentity()))
	if completion.Status() != controlplane.TaskCompletionSucceeded || inner.calls != 1 {
		t.Fatal("real source acquisition did not complete")
	}
	value, err := store.Get(context.Background(), scope, completion.OutputIdentity(), time.UnixMilli(201))
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := ParseSnapshotArtifact(value)
	if err != nil {
		t.Fatal(err)
	}
	return store, value, snapshot
}

func TestSnapshotInvestigationReaderUsesProtectedPhysicalBytes(t *testing.T) {
	ctx := context.Background()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "investigation")
	store, value, snapshot := acquiredInvestigationSource(t, scope, "a")
	clock := &investigationClock{time.UnixMilli(201)}
	reader, err := NewSnapshotReader(context.Background(), store, clock, scope, value.Identity(), snapshot.Identity(), SnapshotReadLimits{MaxFiles: 3, MaxLines: 3, MaxScannedBytes: 4096, MaxResultBytes: 8192, MaxMatches: 2})
	if err != nil {
		t.Fatal(err)
	}
	listing, err := reader.List(ctx)
	if err != nil || len(listing.Files()) != 3 || listing.OmittedCount() != 0 {
		t.Fatal("bounded listing lost actual manifest entries")
	}
	var ref SnapshotFileRef
	for _, listed := range listing.Files() {
		if listed.Path() == "notes.txt" {
			ref = listed
		}
	}
	if ref.Ref() == "" || ref.Ref() == "notes.txt" {
		t.Fatal("model reference is not an opaque snapshot capability")
	}
	read, err := reader.Read(ctx, ref.Ref(), 2, 2)
	if err != nil || !bytes.Equal(read.Content(), []byte("needle here\r\n")) {
		t.Fatal("read normalized or mis-sliced physical bytes")
	}
	binding := read.Binding()
	if binding.Validate() != nil || binding.SourceRange().StartLine() != 2 || binding.SourceRange().EndLine() != 2 || binding.SourceRange().Path() != "notes.txt" || binding.RepositoryFileDigest() != ref.Digest() {
		t.Fatal("slice is not bound to real source file")
	}
	copy := read.Content()
	copy[0] = 'X'
	if bytes.Equal(copy, read.Content()) {
		t.Fatal("read bytes are mutable")
	}
	search, err := reader.Search(ctx, []string{ref.Ref()}, "needle")
	if err != nil || len(search.Matches()) != 1 || !search.Complete() || search.ScannedBytes() != uint64(len("first\r\nneedle here\r\nlast")) {
		t.Fatal("search ignored explicit bounded file set")
	}
	if search.Matches()[0].Binding().Identity() != binding.Identity() || !bytes.Equal(search.Matches()[0].Content(), read.Content()) {
		t.Fatal("literal search is not exact bound physical evidence")
	}
	last, err := reader.Read(ctx, ref.Ref(), 3, 3)
	if err != nil || string(last.Content()) != "last" {
		t.Fatal("unterminated final physical line changed")
	}
	for _, span := range [][2]int{{0, 1}, {2, 1}, {1, 4}, {4, 4}} {
		if _, err := reader.Read(ctx, ref.Ref(), span[0], span[1]); err == nil {
			t.Fatal("invalid physical range accepted")
		}
	}
	if _, err := reader.Search(ctx, []string{ref.Ref(), ref.Ref()}, "needle"); err == nil {
		t.Fatal("duplicate search reference admitted")
	}
	if _, err := reader.Search(ctx, nil, "needle"); err == nil {
		t.Fatal("unbounded implicit file-set search admitted")
	}
	if _, err := reader.Search(ctx, []string{ref.Ref()}, ""); err == nil {
		t.Fatal("empty literal admitted")
	}
	literal, err := reader.Search(ctx, []string{ref.Ref()}, ".*")
	if err != nil || len(literal.Matches()) != 0 {
		t.Fatal("literal was interpreted as regular expression")
	}
}

func TestSnapshotInvestigationReaderRefusesBeforeForeignStorageAccess(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "investigation")
	store, value, snapshot := acquiredInvestigationSource(t, scope, "a")
	_, otherValue, otherSnapshot := acquiredInvestigationSource(t, scope, "b")
	spy := &investigationReadStore{Store: store}
	clock := &investigationClock{time.UnixMilli(201)}
	limits := SnapshotReadLimits{MaxFiles: 3, MaxLines: 3, MaxScannedBytes: 4096, MaxResultBytes: 8192, MaxMatches: 2}
	reader, err := NewSnapshotReader(context.Background(), spy, clock, scope, value.Identity(), snapshot.Identity(), limits)
	if err != nil {
		t.Fatal(err)
	}
	for _, ref := range []string{"notes.txt", "../notes.txt", "/etc/passwd", `C:\private`, `notes.txt/../../secret`, strings.Repeat("f", 64), otherValue.Identity(), otherSnapshot.Files()[0].ArtifactIdentity()} {
		before := len(spy.gets)
		if _, err := reader.Read(context.Background(), ref, 1, 1); err == nil {
			t.Fatal("forged model reference admitted")
		}
		if len(spy.gets) != before {
			t.Fatal("forged reference accessed storage before admission")
		}
	}
	otherScope, _ := audit.NewReviewScope("tenant-b", "repo-a", "investigation")
	if _, err := NewSnapshotReader(context.Background(), spy, clock, otherScope, value.Identity(), snapshot.Identity(), limits); err == nil {
		t.Fatal("cross-scope snapshot admitted")
	}
	if _, err := NewSnapshotReader(context.Background(), spy, clock, scope, value.Identity(), otherSnapshot.Identity(), limits); err == nil {
		t.Fatal("cross-snapshot identity admitted")
	}
	if _, err := NewSnapshotReader(context.Background(), spy, clock, scope, otherValue.Identity(), snapshot.Identity(), limits); err == nil {
		t.Fatal("unavailable artifact paired with known snapshot")
	}
}

func TestSnapshotInvestigationReaderRejectsExpiryTamperAndOutputOverflow(t *testing.T) {
	for _, mode := range []string{"expired", "canceled", "tampered", "wrong origin", "wrong protection", "result limit", "scan limit", "match limit"} {
		t.Run(mode, func(t *testing.T) {
			scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "investigation")
			store, value, snapshot := acquiredInvestigationSource(t, scope, "a")
			spy := &investigationReadStore{Store: store}
			clock := &investigationClock{time.UnixMilli(201)}
			limits := SnapshotReadLimits{MaxFiles: 3, MaxLines: 3, MaxScannedBytes: 4096, MaxResultBytes: 8192, MaxMatches: 2}
			if mode == "result limit" {
				limits.MaxResultBytes = 1
			}
			if mode == "scan limit" {
				limits.MaxScannedBytes = 1
			}
			if mode == "match limit" {
				limits.MaxMatches = 1
			}
			reader, err := NewSnapshotReader(context.Background(), spy, clock, scope, value.Identity(), snapshot.Identity(), limits)
			if err != nil {
				t.Fatal(err)
			}
			listingReader, err := NewSnapshotReader(context.Background(), store, clock, scope, value.Identity(), snapshot.Identity(), SnapshotReadLimits{MaxFiles: 3, MaxLines: 3, MaxScannedBytes: 4096, MaxResultBytes: 8192, MaxMatches: 2})
			if err != nil {
				t.Fatal(err)
			}
			listing, err := listingReader.List(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var notes, other string
			for _, ref := range listing.Files() {
				if ref.Path() == "notes.txt" {
					notes = ref.Ref()
				}
				if ref.Path() == "other.txt" {
					other = ref.Ref()
				}
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if mode == "expired" {
				clock.at = time.UnixMilli(10000)
			}
			if mode == "canceled" {
				cancel()
			}
			if mode == "tampered" || mode == "wrong origin" || mode == "wrong protection" {
				spy.replace = func(a artifact.Artifact) artifact.Artifact {
					if a.Kind() != artifact.KindSourceFile {
						return a
					}
					payload := a.Payload()
					origin, protection := a.Origin(), a.Protection()
					if mode == "tampered" {
						payload[len(payload)/2] ^= 1
					}
					if mode == "wrong origin" {
						origin = artifact.OriginHost
					}
					if mode == "wrong protection" {
						protection = artifact.ProtectionEnvelopeEncrypted
					}
					replacement, err := artifact.New(a.Scope(), a.Kind(), a.MediaType(), a.Classification(), origin, protection, a.Provenance(), payload, a.CreatedAt(), a.ExpiresAt())
					if err != nil {
						t.Error(err)
						return artifact.Artifact{}
					}
					return replacement
				}
			}
			before := len(spy.gets)
			if _, err := reader.Search(ctx, []string{notes, other}, "needle"); err == nil {
				t.Fatal("unsafe or over-budget search returned admitted evidence")
			}
			if mode == "scan limit" {
				for _, id := range spy.gets[before:] {
					for _, file := range snapshot.Files() {
						if id == file.ArtifactIdentity() {
							t.Fatal("full-file size limit was checked after source Get")
						}
					}
				}
			}
		})
	}
}

type cancelingSnapshotStore struct {
	SnapshotArtifactReader
	cancel     context.CancelFunc
	called     bool
	contextKey any
}

func (s *cancelingSnapshotStore) Get(ctx context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	s.called = ctx.Value(s.contextKey) == "caller"
	value, err := s.SnapshotArtifactReader.Get(ctx, scope, id, at)
	s.cancel()
	return value, err
}
func TestSnapshotInvestigationConstructorUsesCallerCancellation(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "constructor-context")
	store, value, snapshot := acquiredInvestigationSource(t, scope, "a")
	clock := &investigationClock{time.UnixMilli(201)}
	limits := SnapshotReadLimits{MaxFiles: 3, MaxLines: 3, MaxScannedBytes: 4096, MaxResultBytes: 8192, MaxMatches: 2}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, stopped := range []context.Context{nil, ctx} {
		spy := &investigationReadStore{Store: store}
		reader, err := NewSnapshotReader(stopped, spy, clock, scope, value.Identity(), snapshot.Identity(), limits)
		if err == nil || reader != nil || len(spy.gets) != 0 {
			t.Fatal("invalid constructor context reached protected Get")
		}
	}
	type contextKey struct{}
	key := contextKey{}
	ctx, cancel = context.WithCancel(context.WithValue(context.Background(), key, "caller"))
	defer cancel()
	spy := &cancelingSnapshotStore{SnapshotArtifactReader: store, cancel: cancel, contextKey: key}
	reader, err := NewSnapshotReader(ctx, spy, clock, scope, value.Identity(), snapshot.Identity(), limits)
	if err == nil || reader != nil || !spy.called || ctx.Err() == nil {
		t.Fatal("constructor admitted protected bytes after in-Get caller cancellation")
	}
}

func TestSnapshotInvestigationReaderBoundsEmptyFilesAndResultValues(t *testing.T) {
	ctx := context.Background()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "bounded-values")
	store, value, snapshot := acquiredInvestigationSource(t, scope, "a")
	clock := &investigationClock{time.UnixMilli(201)}
	limits := SnapshotReadLimits{MaxFiles: 3, MaxLines: 3, MaxScannedBytes: 4096, MaxResultBytes: 8192, MaxMatches: 2}
	reader, err := NewSnapshotReader(ctx, store, clock, scope, value.Identity(), snapshot.Identity(), limits)
	if err != nil {
		t.Fatal(err)
	}
	listing, err := reader.List(ctx)
	if err != nil || listing.SerializedBytes() == 0 || listing.SerializedBytes() > 8192 {
		t.Fatal("listing did not bound serialized metadata")
	}
	var empty, notes SnapshotFileRef
	for _, ref := range listing.Files() {
		if ref.Path() == "empty.txt" {
			empty = ref
		}
		if ref.Path() == "notes.txt" {
			notes = ref
		}
	}
	if _, err := reader.Read(ctx, empty.Ref(), 1, 1); err == nil {
		t.Fatal("empty file invented a physical line")
	}
	search, err := reader.Search(ctx, []string{empty.Ref()}, "needle")
	if err != nil || !search.Complete() || len(search.Matches()) != 0 || search.ScannedBytes() != 0 || search.SerializedBytes() == 0 {
		t.Fatal("empty bounded search lost honest metadata")
	}
	read, err := reader.Read(ctx, notes.Ref(), 2, 2)
	if err != nil || read.ScannedBytes() != uint64(notes.SizeBytes()) || read.SerializedBytes() <= uint64(len(read.Content())) {
		t.Fatal("read accounted only selected source bytes")
	}
	search, err = reader.Search(ctx, []string{notes.Ref()}, "absent")
	if err != nil || len(search.Matches()) != 0 || search.ScannedBytes() != uint64(notes.SizeBytes()) {
		t.Fatal("no-match search skipped full-file charge")
	}
	for _, literal := range []string{"a\nb", "a\rb", "a\x00b", string([]byte{0xff}), strings.Repeat("x", 257)} {
		if _, err := reader.Search(ctx, []string{notes.Ref()}, literal); err == nil {
			t.Fatal("unsupported literal accepted")
		}
	}
	for _, v := range []any{reader, listing, notes, read, search} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%q"} {
			if rendered := fmt.Sprintf(verb, v); strings.Contains(rendered, "needle") || strings.Contains(rendered, "notes.txt") || strings.Contains(rendered, notes.Digest()) {
				t.Fatal("result formatting disclosed protected source")
			}
		}
	}
	limited := limits
	limited.MaxFiles = 1
	bounded, err := NewSnapshotReader(ctx, store, clock, scope, value.Identity(), snapshot.Identity(), limited)
	if err != nil {
		t.Fatal(err)
	}
	list, err := bounded.List(ctx)
	if err != nil || len(list.Files()) != 1 || list.OmittedCount() != 2 {
		t.Fatal("bounded listing claimed all files")
	}
	if _, err := bounded.Read(ctx, notes.Ref(), 1, 1); err == nil {
		t.Fatal("reference outside issued bounded set admitted")
	}
}

func TestSnapshotInvestigationReaderRefusesUnsupportedSourceText(t *testing.T) {
	for _, content := range [][]byte{{0xff, '\n'}, {'a', 0, '\n'}} {
		scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "unsupported-text")
		store, value, snapshot := acquiredInvestigationSource(t, scope, "a", map[string][]byte{"notes.txt": content})
		reader, err := NewSnapshotReader(context.Background(), store, &investigationClock{time.UnixMilli(201)}, scope, value.Identity(), snapshot.Identity(), SnapshotReadLimits{MaxFiles: 1, MaxLines: 1, MaxScannedBytes: 4096, MaxResultBytes: 8192, MaxMatches: 1})
		if err != nil {
			t.Fatal(err)
		}
		listing, err := reader.List(context.Background())
		if err != nil || len(listing.Files()) != 1 {
			t.Fatal("source metadata unavailable")
		}
		ref := listing.Files()[0].Ref()
		if _, err := reader.Read(context.Background(), ref, 1, 1); err == nil {
			t.Fatal("unsupported bytes normalized into admitted source")
		}
		if _, err := reader.Search(context.Background(), []string{ref}, "a"); err == nil {
			t.Fatal("unsupported bytes became a complete search result")
		}
	}
}

func TestSnapshotInvestigationConstructorRefusesInvalidLimitsBeforeGet(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "limits")
	store, value, snapshot := acquiredInvestigationSource(t, scope, "a")
	clock := &investigationClock{time.UnixMilli(201)}
	for _, limits := range []SnapshotReadLimits{
		{}, {MaxFiles: 65, MaxLines: 1, MaxScannedBytes: 1, MaxResultBytes: 1, MaxMatches: 1},
		{MaxFiles: 1, MaxLines: 257, MaxScannedBytes: 1, MaxResultBytes: 1, MaxMatches: 1},
		{MaxFiles: 1, MaxLines: 1, MaxScannedBytes: 16777217, MaxResultBytes: 1, MaxMatches: 1},
		{MaxFiles: 1, MaxLines: 1, MaxScannedBytes: 1, MaxResultBytes: 65537, MaxMatches: 1},
		{MaxFiles: 1, MaxLines: 1, MaxScannedBytes: 1, MaxResultBytes: 1, MaxMatches: 65},
	} {
		spy := &investigationReadStore{Store: store}
		reader, err := NewSnapshotReader(context.Background(), spy, clock, scope, value.Identity(), snapshot.Identity(), limits)
		if err == nil || reader != nil || len(spy.gets) != 0 {
			t.Fatal("invalid reader limits reached storage")
		}
	}
}
