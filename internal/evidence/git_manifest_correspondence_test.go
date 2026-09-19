package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"strings"
	"testing"
)

func TestVerifyGitManifestCorrespondenceEmpty(t *testing.T) {
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, nil, nil, nil)
	graph := mustVerifyGraphFixture(t, fixture)
	manifest := mustRepositoryManifestForTest(t)
	correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest)
	if err != nil {
		t.Fatalf("VerifyGitManifestCorrespondence() error = %v", err)
	}
	if len(correspondence.Identity()) != 64 || correspondence.GitTreeGraphIdentity() != graph.Identity() || correspondence.RepositoryManifestIdentity() != manifest.Identity() || correspondence.GitCommitIdentity() != fixture.commit.Identity() || correspondence.RevisionIdentity() != fixture.revision.Identity() || correspondence.FileCount() != 0 || correspondence.TotalSizeBytes() != 0 || correspondence.PathEncoding() != "utf8-exact-v1" {
		t.Fatalf("correspondence = %#v", correspondence)
	}
}

func TestVerifyGitManifestCorrespondenceMatchesRegularAndExecutableFiles(t *testing.T) {
	regular := []byte("regular")
	executable := []byte("#!/bin/sh\n")
	regularDigest := gitObjectDigestForTest("blob", regular, RevisionAlgorithmSHA1)
	executableDigest := gitObjectDigestForTest("blob", executable, RevisionAlgorithmSHA1)
	childContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{mode: GitTreeModeExecutable, name: []byte("run"), digest: executableDigest})
	childDigest := gitObjectDigestForTest("tree", childContent, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1,
		graphTestEntry{mode: GitTreeModeDirectory, name: []byte("dir"), digest: childDigest},
		graphTestEntry{mode: GitTreeModeRegular, name: []byte("file"), digest: regularDigest},
	)
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, map[string][]byte{childDigest: childContent}, map[string][]byte{regularDigest: regular, executableDigest: executable})
	graph := mustVerifyGraphFixture(t, fixture)
	manifest := mustRepositoryManifestForTest(t,
		manifestFileSpec{path: "file", content: regular},
		manifestFileSpec{path: "dir/run", content: executable},
	)
	correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest)
	if err != nil || correspondence.FileCount() != 2 || correspondence.TotalSizeBytes() != int64(len(regular)+len(executable)) {
		t.Fatalf("VerifyGitManifestCorrespondence() = (%#v, %v)", correspondence, err)
	}
}

func TestVerifyGitManifestCorrespondenceBindsSharedBlobAtEachPath(t *testing.T) {
	content := []byte("shared")
	digest := gitObjectDigestForTest("blob", content, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1,
		graphTestEntry{mode: GitTreeModeRegular, name: []byte("a"), digest: digest},
		graphTestEntry{mode: GitTreeModeRegular, name: []byte("b"), digest: digest},
	)
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{digest: content})
	graph := mustVerifyGraphFixture(t, fixture)
	manifest := mustRepositoryManifestForTest(t, manifestFileSpec{path: "a", content: content}, manifestFileSpec{path: "b", content: content})
	correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest)
	if err != nil || correspondence.FileCount() != 2 || manifest.Files()[0].Identity() == manifest.Files()[1].Identity() {
		t.Fatalf("shared correspondence = (%#v, %v)", correspondence, err)
	}
}

func TestVerifyGitManifestCorrespondenceMapsGitAlgorithmsToRawSHA256(t *testing.T) {
	for _, algorithm := range []RevisionAlgorithm{RevisionAlgorithmSHA1, RevisionAlgorithmSHA256} {
		t.Run(string(algorithm), func(t *testing.T) {
			content := []byte{0, 0xff, '\n'}
			gitDigest := gitObjectDigestForTest("blob", content, algorithm)
			rootContent := graphTreeContentForTest(t, algorithm, graphTestEntry{mode: GitTreeModeRegular, name: []byte("binary"), digest: gitDigest})
			fixture := mustGraphFixture(t, algorithm, rootContent, nil, map[string][]byte{gitDigest: content})
			graph := mustVerifyGraphFixture(t, fixture)
			manifest := mustRepositoryManifestForTest(t, manifestFileSpec{path: "binary", content: content})
			correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest)
			contentDigest := sha256.Sum256(content)
			if err != nil || manifest.Files()[0].Digest() != hex.EncodeToString(contentDigest[:]) || correspondence.FileCount() != 1 {
				t.Fatalf("correspondence = (%#v, %v)", correspondence, err)
			}
		})
	}
}

func TestVerifyGitManifestCorrespondenceRejectsManifestMismatch(t *testing.T) {
	first := []byte("first")
	second := []byte("second")
	firstDigest := gitObjectDigestForTest("blob", first, RevisionAlgorithmSHA1)
	secondDigest := gitObjectDigestForTest("blob", second, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1,
		graphTestEntry{mode: GitTreeModeRegular, name: []byte("a"), digest: firstDigest},
		graphTestEntry{mode: GitTreeModeRegular, name: []byte("b"), digest: secondDigest},
	)
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{firstDigest: first, secondDigest: second})
	graph := mustVerifyGraphFixture(t, fixture)
	testCases := []struct {
		name  string
		files []manifestFileSpec
	}{
		{name: "missing", files: []manifestFileSpec{{path: "a", content: first}}},
		{name: "extra", files: []manifestFileSpec{{path: "a", content: first}, {path: "b", content: second}, {path: "c", content: nil}}},
		{name: "renamed", files: []manifestFileSpec{{path: "a", content: first}, {path: "c", content: second}}},
		{name: "wrong content", files: []manifestFileSpec{{path: "a", content: []byte("changed")}, {path: "b", content: second}}},
		{name: "swapped content", files: []manifestFileSpec{{path: "a", content: second}, {path: "b", content: first}}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			manifest := mustRepositoryManifestForTest(t, testCase.files...)
			correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest)
			if err == nil || correspondence.Identity() != "" {
				t.Fatalf("VerifyGitManifestCorrespondence() = (%#v, %v), want zero result and error", correspondence, err)
			}
		})
	}
}

func TestSnapshotGitManifestInputsCopiesPayloads(t *testing.T) {
	commitContent := []byte("commit")
	rootContent := []byte("root")
	childTrees := map[string][]byte{"tree": []byte("child")}
	blobs := map[string][]byte{"blob": []byte("content")}
	snapshot, err := snapshotGitManifestInputs(commitContent, rootContent, childTrees, blobs)
	if err != nil {
		t.Fatalf("snapshotGitManifestInputs() error = %v", err)
	}
	commitContent[0] = 'X'
	rootContent[0] = 'X'
	childTrees["tree"][0] = 'X'
	blobs["blob"][0] = 'X'
	delete(childTrees, "tree")
	delete(blobs, "blob")
	if !bytes.Equal(snapshot.commitContent, []byte("commit")) || !bytes.Equal(snapshot.rootTreeContent, []byte("root")) || !bytes.Equal(snapshot.childTreeContents["tree"], []byte("child")) || !bytes.Equal(snapshot.blobContents["blob"], []byte("content")) {
		t.Fatalf("snapshot changed with caller inputs: %#v", snapshot)
	}
}

func TestGitGraphPathToRepositoryPathRejectsUnsafeBytes(t *testing.T) {
	testCases := [][]byte{
		{},
		{0xff},
		[]byte(`a\b`),
		{'a', 0},
		{'a', 1},
		[]byte("/absolute"),
		[]byte("a//b"),
		[]byte("a/./b"),
		[]byte("a/../b"),
		[]byte("."),
		[]byte(".."),
		[]byte("a/\u202e"),
		bytes.Repeat([]byte{'x'}, maxRepositoryFilePathBytes+1),
	}
	for _, raw := range testCases {
		if path, err := gitGraphPathToRepositoryPath(raw); err == nil || path != "" {
			t.Fatalf("gitGraphPathToRepositoryPath(%x) = (%q, %v)", raw, path, err)
		}
	}
}

func TestVerifyGitManifestCorrespondenceRejectsUnsafeGraphPaths(t *testing.T) {
	names := [][]byte{{0xff}, []byte(`a\b`), {'a', 1}, []byte("bidi-\u202e")}
	for _, name := range names {
		content := []byte("content")
		digest := gitObjectDigestForTest("blob", content, RevisionAlgorithmSHA1)
		rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{mode: GitTreeModeRegular, name: name, digest: digest})
		fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{digest: content})
		graph := mustVerifyGraphFixture(t, fixture)
		manifest := mustRepositoryManifestForTest(t)
		if correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest); err == nil || correspondence.Identity() != "" {
			t.Fatalf("unsafe graph path %x = (%#v, %v)", name, correspondence, err)
		}
	}
}

func TestVerifyGitManifestCorrespondencePreservesUnicodeBytes(t *testing.T) {
	content := []byte("same")
	digest := gitObjectDigestForTest("blob", content, RevisionAlgorithmSHA1)
	decomposed := "e\u0301"
	composed := "\u00e9"
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1,
		graphTestEntry{mode: GitTreeModeRegular, name: []byte(decomposed), digest: digest},
		graphTestEntry{mode: GitTreeModeRegular, name: []byte(composed), digest: digest},
	)
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{digest: content})
	graph := mustVerifyGraphFixture(t, fixture)
	manifest := mustRepositoryManifestForTest(t, manifestFileSpec{path: composed, content: content}, manifestFileSpec{path: decomposed, content: content})
	correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest)
	if err != nil || correspondence.FileCount() != 2 || bytes.Equal([]byte(composed), []byte(decomposed)) {
		t.Fatalf("unicode correspondence = (%#v, %v)", correspondence, err)
	}
}

func TestVerifyGitManifestCorrespondenceRejectsSymlinks(t *testing.T) {
	target := []byte("target")
	digest := gitObjectDigestForTest("blob", target, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{mode: GitTreeModeSymlink, name: []byte("link"), digest: digest})
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{digest: target})
	graph := mustVerifyGraphFixture(t, fixture)
	manifest := mustRepositoryManifestForTest(t, manifestFileSpec{path: "link", content: target})
	if correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest); err == nil || correspondence.Identity() != "" {
		t.Fatalf("symlink correspondence = (%#v, %v)", correspondence, err)
	}
}

func TestVerifyGitManifestCorrespondenceRebindsGraphAndManifest(t *testing.T) {
	content := []byte("content")
	digest := gitObjectDigestForTest("blob", content, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{mode: GitTreeModeRegular, name: []byte("file"), digest: digest})
	baseFixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{digest: content})
	baseGraph := mustVerifyGraphFixture(t, baseFixture)
	baseManifest := mustRepositoryManifestForTest(t, manifestFileSpec{path: "file", content: content})
	testCases := []struct {
		name   string
		mutate func(*graphFixture, *GitTreeGraph, *RepositoryManifest)
	}{
		{name: "revision", mutate: func(f *graphFixture, _ *GitTreeGraph, _ *RepositoryManifest) {
			f.revision.identity = strings.Repeat("0", 64)
		}},
		{name: "commit verification", mutate: func(f *graphFixture, _ *GitTreeGraph, _ *RepositoryManifest) {
			f.commitVerification.identity = strings.Repeat("0", 64)
		}},
		{name: "commit", mutate: func(f *graphFixture, _ *GitTreeGraph, _ *RepositoryManifest) {
			f.commit.identity = strings.Repeat("0", 64)
		}},
		{name: "root verification", mutate: func(f *graphFixture, _ *GitTreeGraph, _ *RepositoryManifest) {
			f.rootVerification.identity = strings.Repeat("0", 64)
		}},
		{name: "root tree", mutate: func(f *graphFixture, _ *GitTreeGraph, _ *RepositoryManifest) {
			f.rootTree.identity = strings.Repeat("0", 64)
		}},
		{name: "commit bytes", mutate: func(f *graphFixture, _ *GitTreeGraph, _ *RepositoryManifest) {
			f.commitContent[len(f.commitContent)-2] ^= 1
		}},
		{name: "root tree bytes", mutate: func(f *graphFixture, _ *GitTreeGraph, _ *RepositoryManifest) {
			f.rootContent[len(f.rootContent)-1] ^= 1
		}},
		{name: "blob bytes", mutate: func(f *graphFixture, _ *GitTreeGraph, _ *RepositoryManifest) { f.blobs[digest][0] ^= 1 }},
		{name: "graph identity", mutate: func(_ *graphFixture, g *GitTreeGraph, _ *RepositoryManifest) { g.identity = strings.Repeat("0", 64) }},
		{name: "graph entry", mutate: func(_ *graphFixture, g *GitTreeGraph, _ *RepositoryManifest) {
			g.entries = cloneGitTreeGraphEntries(g.entries)
			g.entries[0].path[0] = 'X'
		}},
		{name: "manifest identity", mutate: func(_ *graphFixture, _ *GitTreeGraph, m *RepositoryManifest) { m.identity = strings.Repeat("0", 64) }},
		{name: "manifest file", mutate: func(_ *graphFixture, _ *GitTreeGraph, m *RepositoryManifest) {
			m.files = append([]RepositoryFile{}, m.files...)
			m.files[0].digest = strings.Repeat("0", 64)
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := baseFixture.clone()
			graph := baseGraph
			manifest := baseManifest
			testCase.mutate(&fixture, &graph, &manifest)
			correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest)
			if err == nil || correspondence.Identity() != "" {
				t.Fatalf("VerifyGitManifestCorrespondence() = (%#v, %v)", correspondence, err)
			}
		})
	}
}

func TestVerifyGitManifestCorrespondenceAcceptsFileCountAndPathBoundaries(t *testing.T) {
	emptyDigest := gitObjectDigestForTest("blob", nil, RevisionAlgorithmSHA1)
	objectID, err := hex.DecodeString(emptyDigest)
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}
	rootContent := make([]byte, 0, maxRepositoryManifestFiles*32)
	files := make([]RepositoryFile, maxRepositoryManifestFiles)
	for i := 0; i < maxRepositoryManifestFiles; i++ {
		name := fmt.Sprintf("f%05d", i)
		rootContent = append(rootContent, encodeGitTreeEntryForTest(GitTreeModeRegular, []byte(name), objectID)...)
		files[i], err = NewRepositoryFile(name, nil)
		if err != nil {
			t.Fatalf("NewRepositoryFile(%q) error = %v", name, err)
		}
	}
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{emptyDigest: nil})
	graph := mustVerifyGraphFixture(t, fixture)
	manifest, err := NewRepositoryManifest(files)
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest)
	if err != nil || correspondence.FileCount() != maxRepositoryManifestFiles {
		t.Fatalf("file-count boundary = (%#v, %v)", correspondence, err)
	}

	maxPath := strings.Repeat("x", maxRepositoryFilePathBytes)
	rootContent = graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{mode: GitTreeModeRegular, name: []byte(maxPath), digest: emptyDigest})
	fixture = mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{emptyDigest: nil})
	graph = mustVerifyGraphFixture(t, fixture)
	manifest = mustRepositoryManifestForTest(t, manifestFileSpec{path: maxPath, content: nil})
	correspondence, err = verifyManifestCorrespondence(fixture, graph, manifest)
	if err != nil || correspondence.FileCount() != 1 {
		t.Fatalf("path boundary = (%#v, %v)", correspondence, err)
	}
}

func TestVerifyGitManifestCorrespondenceIgnoresManifestAndMapOrder(t *testing.T) {
	first := []byte("first")
	second := []byte("second")
	firstDigest := gitObjectDigestForTest("blob", first, RevisionAlgorithmSHA1)
	secondDigest := gitObjectDigestForTest("blob", second, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1,
		graphTestEntry{mode: GitTreeModeRegular, name: []byte("a"), digest: firstDigest},
		graphTestEntry{mode: GitTreeModeRegular, name: []byte("b"), digest: secondDigest},
	)
	one := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{firstDigest: first, secondDigest: second})
	two := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, nil)
	two.blobs[secondDigest] = second
	two.blobs[firstDigest] = first
	firstGraph := mustVerifyGraphFixture(t, one)
	secondGraph := mustVerifyGraphFixture(t, two)
	firstManifest := mustRepositoryManifestForTest(t, manifestFileSpec{path: "a", content: first}, manifestFileSpec{path: "b", content: second})
	secondManifest := mustRepositoryManifestForTest(t, manifestFileSpec{path: "b", content: second}, manifestFileSpec{path: "a", content: first})
	firstCorrespondence, firstErr := verifyManifestCorrespondence(one, firstGraph, firstManifest)
	secondCorrespondence, secondErr := verifyManifestCorrespondence(two, secondGraph, secondManifest)
	if firstErr != nil || secondErr != nil || firstCorrespondence.Identity() != secondCorrespondence.Identity() {
		t.Fatalf("correspondences differ: (%#v, %v) (%#v, %v)", firstCorrespondence, firstErr, secondCorrespondence, secondErr)
	}
}

func TestGitManifestCorrespondenceIdentityPreimage(t *testing.T) {
	content := []byte("content")
	digest := gitObjectDigestForTest("blob", content, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{mode: GitTreeModeRegular, name: []byte("file"), digest: digest})
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{digest: content})
	graph := mustVerifyGraphFixture(t, fixture)
	manifest := mustRepositoryManifestForTest(t, manifestFileSpec{path: "file", content: content})
	correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest)
	if err != nil {
		t.Fatalf("VerifyGitManifestCorrespondence() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/git-manifest-correspondence","schema_version":1,"revision_identity":"%s","git_commit_identity":"%s","git_tree_graph_identity":"%s","repository_manifest_identity":"%s","path_encoding":"utf8-exact-v1","included_modes":["100644","100755"],"file_count":1,"total_size_bytes":%d}`, fixture.revision.Identity(), fixture.commit.Identity(), graph.Identity(), manifest.Identity(), len(content))
	identityDigest := sha256.Sum256([]byte(preimage))
	if correspondence.Identity() != hex.EncodeToString(identityDigest[:]) {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", correspondence.Identity(), preimage)
	}
}

func TestCheckedCorrespondenceSizeAdd(t *testing.T) {
	if got, err := checkedCorrespondenceSizeAdd(0, math.MaxInt64); err != nil || got != math.MaxInt64 {
		t.Fatalf("checkedCorrespondenceSizeAdd() = (%d, %v)", got, err)
	}
	if got, err := checkedCorrespondenceSizeAdd(math.MaxInt64, 1); err == nil || got != math.MaxInt64 {
		t.Fatalf("overflow addition = (%d, %v)", got, err)
	}
	for _, values := range [][2]int64{{-1, 0}, {0, -1}} {
		if _, err := checkedCorrespondenceSizeAdd(values[0], values[1]); err == nil {
			t.Fatalf("checkedCorrespondenceSizeAdd(%v) succeeded", values)
		}
	}
}

func TestGitManifestCorrespondenceDoesNotRetainInputs(t *testing.T) {
	content := []byte("content")
	digest := gitObjectDigestForTest("blob", content, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{mode: GitTreeModeRegular, name: []byte("file"), digest: digest})
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{digest: content})
	graph := mustVerifyGraphFixture(t, fixture)
	manifest := mustRepositoryManifestForTest(t, manifestFileSpec{path: "file", content: content})
	correspondence, err := verifyManifestCorrespondence(fixture, graph, manifest)
	if err != nil {
		t.Fatalf("VerifyGitManifestCorrespondence() error = %v", err)
	}
	identity := correspondence.Identity()
	for i := range fixture.blobs[digest] {
		fixture.blobs[digest][i] = 0
	}
	graphEntries := graph.Entries()
	graphEntries[0].path[0] = 'X'
	manifestFiles := manifest.Files()
	manifestFiles[0].path = "changed"
	if correspondence.Identity() != identity || correspondence.FileCount() != 1 || correspondence.TotalSizeBytes() != int64(len(content)) {
		t.Fatal("input mutation changed GitManifestCorrespondence")
	}
}

func TestGitManifestCorrespondenceZeroValueIsEmpty(t *testing.T) {
	var correspondence GitManifestCorrespondence
	if correspondence.Identity() != "" || correspondence.GitTreeGraphIdentity() != "" || correspondence.RepositoryManifestIdentity() != "" || correspondence.GitCommitIdentity() != "" || correspondence.RevisionIdentity() != "" || correspondence.FileCount() != 0 || correspondence.TotalSizeBytes() != 0 || correspondence.PathEncoding() != "" {
		t.Fatalf("zero GitManifestCorrespondence = %#v", correspondence)
	}
}

type manifestFileSpec struct {
	path    string
	content []byte
}

func mustVerifyGraphFixture(t *testing.T, fixture graphFixture) GitTreeGraph {
	t.Helper()
	graph, err := fixture.verify()
	if err != nil {
		t.Fatalf("VerifyGitTreeGraph() error = %v", err)
	}
	return graph
}

func mustRepositoryManifestForTest(t *testing.T, specs ...manifestFileSpec) RepositoryManifest {
	t.Helper()
	files := make([]RepositoryFile, len(specs))
	for i, spec := range specs {
		file, err := NewRepositoryFile(spec.path, spec.content)
		if err != nil {
			t.Fatalf("NewRepositoryFile(%q) error = %v", spec.path, err)
		}
		files[i] = file
	}
	manifest, err := NewRepositoryManifest(files)
	if err != nil {
		t.Fatalf("NewRepositoryManifest() error = %v", err)
	}
	return manifest
}

func verifyManifestCorrespondence(fixture graphFixture, graph GitTreeGraph, manifest RepositoryManifest) (GitManifestCorrespondence, error) {
	return VerifyGitManifestCorrespondence(fixture.revision, fixture.commitVerification, fixture.commitContent, fixture.commit, fixture.rootVerification, fixture.rootContent, fixture.rootTree, fixture.childTrees, fixture.blobs, graph, manifest)
}
