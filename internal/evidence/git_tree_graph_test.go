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

func TestVerifyGitTreeGraphRootBlob(t *testing.T) {
	blob := []byte("hello\n")
	blobDigest := gitObjectDigestForTest("blob", blob, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("file"), blobDigest})
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{blobDigest: blob})
	graph, err := fixture.verify()
	if err != nil {
		t.Fatalf("VerifyGitTreeGraph() error = %v", err)
	}
	entries := graph.Entries()
	if len(graph.Identity()) != 64 || graph.GitCommitIdentity() != fixture.commit.Identity() || graph.RootTreeIdentity() != fixture.rootTree.Identity() || graph.RootTreeVerificationIdentity() != fixture.rootVerification.Identity() || graph.Algorithm() != RevisionAlgorithmSHA1 || graph.EntryCount() != 1 || graph.UniqueTreeObjectCount() != 1 || graph.UniqueBlobObjectCount() != 1 || graph.TotalObjectBytes() != int64(len(rootContent)+len(blob)) || graph.TraversalDigest() != "a9cfcf56de53a4d606f2a1a229ff1f4f6df1c14eceaa8aaef6670d74258ef9d0" {
		t.Fatalf("graph = %#v", graph)
	}
	if len(entries) != 1 || !bytes.Equal(entries[0].Path(), []byte("file")) || entries[0].PathHex() != "66696c65" || entries[0].Mode() != GitTreeModeRegular || entries[0].Kind() != GitTreeEntryKindBlob || entries[0].ObjectDigest() != blobDigest || entries[0].ContentSizeBytes() != len(blob) {
		t.Fatalf("entries = %#v", entries)
	}
}

func TestVerifyGitTreeGraphAcceptsEmptyRoot(t *testing.T) {
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, nil, nil, nil)
	graph, err := fixture.verify()
	if err != nil || graph.EntryCount() != 0 || graph.UniqueTreeObjectCount() != 1 || graph.UniqueBlobObjectCount() != 0 || graph.TotalObjectBytes() != 0 || graph.TraversalDigest() != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("VerifyGitTreeGraph(empty) = (%#v, %v)", graph, err)
	}
}

func TestVerifyGitTreeGraphCanonicalDepthFirstTraversal(t *testing.T) {
	deepBlob := []byte("deep")
	topBlob := []byte("top")
	deepDigest := gitObjectDigestForTest("blob", deepBlob, RevisionAlgorithmSHA256)
	topDigest := gitObjectDigestForTest("blob", topBlob, RevisionAlgorithmSHA256)
	childContent := graphTreeContentForTest(t, RevisionAlgorithmSHA256, graphTestEntry{GitTreeModeRegular, []byte("deep"), deepDigest})
	childDigest := gitObjectDigestForTest("tree", childContent, RevisionAlgorithmSHA256)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA256,
		graphTestEntry{GitTreeModeDirectory, []byte("dir"), childDigest},
		graphTestEntry{GitTreeModeExecutable, []byte("top"), topDigest},
	)
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA256, rootContent, map[string][]byte{childDigest: childContent}, map[string][]byte{deepDigest: deepBlob, topDigest: topBlob})
	graph, err := fixture.verify()
	if err != nil {
		t.Fatalf("VerifyGitTreeGraph() error = %v", err)
	}
	entries := graph.Entries()
	wantPaths := [][]byte{[]byte("dir"), []byte("dir/deep"), []byte("top")}
	wantKinds := []GitTreeEntryKind{GitTreeEntryKindTree, GitTreeEntryKindBlob, GitTreeEntryKindBlob}
	for i := range wantPaths {
		if !bytes.Equal(entries[i].Path(), wantPaths[i]) || entries[i].Kind() != wantKinds[i] {
			t.Fatalf("Entries()[%d] = %#v", i, entries[i])
		}
	}
	if graph.UniqueTreeObjectCount() != 2 || graph.UniqueBlobObjectCount() != 2 || graph.TotalObjectBytes() != int64(len(rootContent)+len(childContent)+len(deepBlob)+len(topBlob)) {
		t.Fatalf("graph stats = %#v", graph)
	}
}

func TestVerifyGitTreeGraphExpandsSharedObjects(t *testing.T) {
	blob := []byte("shared")
	blobDigest := gitObjectDigestForTest("blob", blob, RevisionAlgorithmSHA1)
	childContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("x"), blobDigest})
	childDigest := gitObjectDigestForTest("tree", childContent, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1,
		graphTestEntry{GitTreeModeDirectory, []byte("a"), childDigest},
		graphTestEntry{GitTreeModeDirectory, []byte("b"), childDigest},
	)
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, map[string][]byte{childDigest: childContent}, map[string][]byte{blobDigest: blob})
	graph, err := fixture.verify()
	if err != nil {
		t.Fatalf("VerifyGitTreeGraph() error = %v", err)
	}
	entries := graph.Entries()
	want := [][]byte{[]byte("a"), []byte("a/x"), []byte("b"), []byte("b/x")}
	for i := range want {
		if !bytes.Equal(entries[i].Path(), want[i]) {
			t.Fatalf("Entries()[%d].Path() = %x, want %x", i, entries[i].Path(), want[i])
		}
	}
	if graph.UniqueTreeObjectCount() != 2 || graph.UniqueBlobObjectCount() != 1 {
		t.Fatalf("unique counts = (%d, %d)", graph.UniqueTreeObjectCount(), graph.UniqueBlobObjectCount())
	}
}

func TestVerifyGitTreeGraphRejectsIncompleteOrAmbiguousMaps(t *testing.T) {
	blob := []byte("content")
	blobDigest := gitObjectDigestForTest("blob", blob, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("file"), blobDigest})
	base := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{blobDigest: blob})
	extra := []byte("extra")
	extraDigest := gitObjectDigestForTest("blob", extra, RevisionAlgorithmSHA1)
	extraTreeDigest := gitObjectDigestForTest("tree", nil, RevisionAlgorithmSHA1)
	testCases := []struct {
		name   string
		mutate func(*graphFixture)
	}{
		{name: "missing blob", mutate: func(f *graphFixture) { delete(f.blobs, blobDigest) }},
		{name: "extra blob", mutate: func(f *graphFixture) { f.blobs[extraDigest] = extra }},
		{name: "extra child tree", mutate: func(f *graphFixture) { f.childTrees[extraTreeDigest] = nil }},
		{name: "wrong blob bytes", mutate: func(f *graphFixture) { f.blobs[blobDigest] = []byte("changed") }},
		{name: "short key", mutate: func(f *graphFixture) { delete(f.blobs, blobDigest); f.blobs["abcd"] = blob }},
		{name: "uppercase key", mutate: func(f *graphFixture) { delete(f.blobs, blobDigest); f.blobs[strings.ToUpper(blobDigest)] = blob }},
		{name: "nonhex key", mutate: func(f *graphFixture) { delete(f.blobs, blobDigest); f.blobs[strings.Repeat("z", 40)] = blob }},
		{name: "kind ambiguity", mutate: func(f *graphFixture) { f.childTrees[blobDigest] = blob }},
		{name: "root repeated as child", mutate: func(f *graphFixture) { f.childTrees[f.rootTree.TreeDigest()] = f.rootContent }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := base.clone()
			testCase.mutate(&fixture)
			graph, err := fixture.verify()
			if err == nil || graph.Identity() != "" {
				t.Fatalf("VerifyGitTreeGraph() = (%#v, %v), want zero result and error", graph, err)
			}
		})
	}
}

func TestVerifyGitTreeGraphRejectsChildTreeMismatchAndMalformedTree(t *testing.T) {
	blob := []byte("leaf")
	blobDigest := gitObjectDigestForTest("blob", blob, RevisionAlgorithmSHA1)
	childContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("leaf"), blobDigest})
	childDigest := gitObjectDigestForTest("tree", childContent, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeDirectory, []byte("dir"), childDigest})
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, map[string][]byte{childDigest: childContent}, map[string][]byte{blobDigest: blob})
	missing := fixture.clone()
	delete(missing.childTrees, childDigest)
	if graph, err := missing.verify(); err == nil || graph.Identity() != "" {
		t.Fatalf("missing child tree = (%#v, %v)", graph, err)
	}
	fixture.childTrees[childDigest][0] ^= 1
	if graph, err := fixture.verify(); err == nil || graph.Identity() != "" {
		t.Fatalf("mutated child tree = (%#v, %v)", graph, err)
	}
	malformed := []byte("100644 no-terminator")
	malformedDigest := gitObjectDigestForTest("tree", malformed, RevisionAlgorithmSHA1)
	rootContent = graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeDirectory, []byte("dir"), malformedDigest})
	fixture = mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, map[string][]byte{malformedDigest: malformed}, nil)
	if graph, err := fixture.verify(); err == nil || graph.Identity() != "" {
		t.Fatalf("malformed child tree = (%#v, %v)", graph, err)
	}
}

func TestVerifyGitTreeGraphRejectsTypeConfusion(t *testing.T) {
	content := []byte("payload")
	for _, objectType := range []string{"tree", "commit", "tag"} {
		digest := gitObjectDigestForTest(objectType, content, RevisionAlgorithmSHA1)
		rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("file"), digest})
		fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{digest: content})
		if graph, err := fixture.verify(); err == nil || graph.Identity() != "" {
			t.Fatalf("VerifyGitTreeGraph(blob with %s framing) = (%#v, %v)", objectType, graph, err)
		}
	}
	for _, objectType := range []string{"blob", "commit", "tag"} {
		digest := gitObjectDigestForTest(objectType, content, RevisionAlgorithmSHA1)
		rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeDirectory, []byte("dir"), digest})
		fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, map[string][]byte{digest: content}, nil)
		if graph, err := fixture.verify(); err == nil || graph.Identity() != "" {
			t.Fatalf("VerifyGitTreeGraph(tree with %s framing) = (%#v, %v)", objectType, graph, err)
		}
	}
}

func TestVerifyGitTreeGraphRejectsGitlinkAndAcceptsOpaqueSymlink(t *testing.T) {
	gitlinkDigest := strings.Repeat("1", 40)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeGitlink, []byte("module"), gitlinkDigest})
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, nil)
	if graph, err := fixture.verify(); err == nil || graph.Identity() != "" {
		t.Fatalf("gitlink graph = (%#v, %v)", graph, err)
	}
	target := []byte("../outside")
	targetDigest := gitObjectDigestForTest("blob", target, RevisionAlgorithmSHA1)
	rootContent = graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeSymlink, []byte("link"), targetDigest})
	fixture = mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{targetDigest: target})
	graph, err := fixture.verify()
	if err != nil || graph.Entries()[0].Mode() != GitTreeModeSymlink || graph.Entries()[0].ContentSizeBytes() != len(target) {
		t.Fatalf("symlink graph = (%#v, %v)", graph, err)
	}
}

func TestVerifyGitTreeGraphPreservesRawPaths(t *testing.T) {
	blob := []byte{0, 0xff}
	blobDigest := gitObjectDigestForTest("blob", blob, RevisionAlgorithmSHA1)
	childName := []byte{' ', 'a', '\\', 0xfe, ' '}
	childContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, childName, blobDigest})
	childDigest := gitObjectDigestForTest("tree", childContent, RevisionAlgorithmSHA1)
	rootName := []byte{0xff}
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeDirectory, rootName, childDigest})
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, map[string][]byte{childDigest: childContent}, map[string][]byte{blobDigest: blob})
	graph, err := fixture.verify()
	if err != nil {
		t.Fatalf("VerifyGitTreeGraph() error = %v", err)
	}
	want := append(append(append([]byte{}, rootName...), '/'), childName...)
	if !bytes.Equal(graph.Entries()[1].Path(), want) || graph.Entries()[1].PathHex() != hex.EncodeToString(want) {
		t.Fatalf("raw path = %x, want %x", graph.Entries()[1].Path(), want)
	}
}

func TestVerifyGitTreeGraphEnforcesDepthAndPathBounds(t *testing.T) {
	atLimit := mustDepthGraphFixture(t, maxGitTreeGraphDepth)
	graph, err := atLimit.verify()
	if err != nil || graph.EntryCount() != maxGitTreeGraphDepth {
		t.Fatalf("VerifyGitTreeGraph(depth limit) = (%#v, %v)", graph, err)
	}
	overLimit := mustDepthGraphFixture(t, maxGitTreeGraphDepth+1)
	if graph, err := overLimit.verify(); err == nil || graph.Identity() != "" {
		t.Fatalf("VerifyGitTreeGraph(over depth) = (%#v, %v)", graph, err)
	}
	blobDigest := gitObjectDigestForTest("blob", nil, RevisionAlgorithmSHA1)
	name := bytes.Repeat([]byte{'x'}, maxGitTreeGraphPathBytes)
	root := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, name, blobDigest})
	pathLimit := mustGraphFixture(t, RevisionAlgorithmSHA1, root, nil, map[string][]byte{blobDigest: nil})
	graph, err = pathLimit.verify()
	if err != nil || len(graph.Entries()[0].Path()) != maxGitTreeGraphPathBytes {
		t.Fatalf("VerifyGitTreeGraph(path limit) = (%#v, %v)", graph, err)
	}
}

func TestVerifyGitTreeGraphRejectsOversizedChildObjects(t *testing.T) {
	t.Run("tree", func(t *testing.T) {
		digest := strings.Repeat("1", 40)
		root := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeDirectory, []byte("dir"), digest})
		fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, root, map[string][]byte{digest: make([]byte, maxGitTreeObjectBytes+1)}, nil)
		if graph, err := fixture.verify(); err == nil || graph.Identity() != "" {
			t.Fatalf("oversized tree = (%#v, %v)", graph, err)
		}
	})
	t.Run("blob", func(t *testing.T) {
		digest := strings.Repeat("1", 40)
		root := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("file"), digest})
		fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, root, nil, map[string][]byte{digest: make([]byte, maxGitBlobObjectBytes+1)})
		if graph, err := fixture.verify(); err == nil || graph.Identity() != "" {
			t.Fatalf("oversized blob = (%#v, %v)", graph, err)
		}
	})
}

func TestVerifyGitTreeGraphIgnoresMapInsertionOrder(t *testing.T) {
	first := []byte("first")
	second := []byte("second")
	firstDigest := gitObjectDigestForTest("blob", first, RevisionAlgorithmSHA1)
	secondDigest := gitObjectDigestForTest("blob", second, RevisionAlgorithmSHA1)
	firstTree := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("x"), firstDigest})
	secondTree := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("y"), secondDigest})
	firstTreeDigest := gitObjectDigestForTest("tree", firstTree, RevisionAlgorithmSHA1)
	secondTreeDigest := gitObjectDigestForTest("tree", secondTree, RevisionAlgorithmSHA1)
	root := graphTreeContentForTest(t, RevisionAlgorithmSHA1,
		graphTestEntry{GitTreeModeDirectory, []byte("a"), firstTreeDigest},
		graphTestEntry{GitTreeModeDirectory, []byte("b"), secondTreeDigest},
	)
	one := mustGraphFixture(t, RevisionAlgorithmSHA1, root, map[string][]byte{firstTreeDigest: firstTree, secondTreeDigest: secondTree}, map[string][]byte{firstDigest: first, secondDigest: second})
	two := mustGraphFixture(t, RevisionAlgorithmSHA1, root, nil, nil)
	two.childTrees[secondTreeDigest] = secondTree
	two.childTrees[firstTreeDigest] = firstTree
	two.blobs[secondDigest] = second
	two.blobs[firstDigest] = first
	firstGraph, firstErr := one.verify()
	secondGraph, secondErr := two.verify()
	if firstErr != nil || secondErr != nil || firstGraph.Identity() != secondGraph.Identity() || firstGraph.TraversalDigest() != secondGraph.TraversalDigest() {
		t.Fatalf("graphs differ: (%#v, %v) (%#v, %v)", firstGraph, firstErr, secondGraph, secondErr)
	}
}

func TestVerifyGitTreeGraphRebindsRootChain(t *testing.T) {
	blob := []byte("content")
	blobDigest := gitObjectDigestForTest("blob", blob, RevisionAlgorithmSHA1)
	root := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("file"), blobDigest})
	base := mustGraphFixture(t, RevisionAlgorithmSHA1, root, nil, map[string][]byte{blobDigest: blob})
	testCases := []struct {
		name   string
		mutate func(*graphFixture)
	}{
		{name: "revision", mutate: func(f *graphFixture) { f.revision.identity = strings.Repeat("0", 64) }},
		{name: "commit verification", mutate: func(f *graphFixture) { f.commitVerification.identity = strings.Repeat("0", 64) }},
		{name: "commit", mutate: func(f *graphFixture) { f.commit.identity = strings.Repeat("0", 64) }},
		{name: "root verification", mutate: func(f *graphFixture) { f.rootVerification.identity = strings.Repeat("0", 64) }},
		{name: "root tree", mutate: func(f *graphFixture) { f.rootTree.identity = strings.Repeat("0", 64) }},
		{name: "commit bytes", mutate: func(f *graphFixture) { f.commitContent[len(f.commitContent)-2] ^= 1 }},
		{name: "root bytes", mutate: func(f *graphFixture) { f.rootContent[len(f.rootContent)-1] ^= 1 }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			fixture := base.clone()
			testCase.mutate(&fixture)
			if graph, err := fixture.verify(); err == nil || graph.Identity() != "" {
				t.Fatalf("VerifyGitTreeGraph() = (%#v, %v)", graph, err)
			}
		})
	}
}

func TestVerifyGitTreeGraphDoesNotRetainInputs(t *testing.T) {
	blob := []byte("content")
	blobDigest := gitObjectDigestForTest("blob", blob, RevisionAlgorithmSHA1)
	root := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("file"), blobDigest})
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, root, nil, map[string][]byte{blobDigest: blob})
	graph, err := fixture.verify()
	if err != nil {
		t.Fatalf("VerifyGitTreeGraph() error = %v", err)
	}
	identity := graph.Identity()
	path := graph.Entries()[0].Path()
	path[0] = 'X'
	for i := range fixture.rootContent {
		fixture.rootContent[i] = 0
	}
	for i := range fixture.blobs[blobDigest] {
		fixture.blobs[blobDigest][i] = 0
	}
	if graph.Identity() != identity || !bytes.Equal(graph.Entries()[0].Path(), []byte("file")) || graph.Entries()[0].ObjectDigest() != blobDigest {
		t.Fatal("input or output mutation changed GitTreeGraph")
	}
}

func TestParseGitTreeEntriesMatchesPublicParser(t *testing.T) {
	blobDigest := strings.Repeat("1", 40)
	content := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("file"), blobDigest})
	revision, verification, commitContent, commit, treeVerification, tree := mustGitTreeInputs(t, RevisionAlgorithmSHA1, content)
	parsed, err := ParseVerifiedGitTree(revision, verification, commitContent, commit, treeVerification, content)
	if err != nil {
		t.Fatalf("ParseVerifiedGitTree() error = %v", err)
	}
	privateEntries, err := parseGitTreeEntries(content, RevisionAlgorithmSHA1)
	if err != nil || !gitTreeValuesEqual(tree, parsed) || len(privateEntries) != len(parsed.entries) {
		t.Fatalf("private/public parser mismatch: %v", err)
	}
	for i := range privateEntries {
		if !gitTreeEntryValuesEqual(privateEntries[i], parsed.entries[i]) {
			t.Fatalf("entry %d differs", i)
		}
	}
}

func TestTraverseVerifiedGitGraphDefensiveCycleAndDuplicateChecks(t *testing.T) {
	a := strings.Repeat("a", 40)
	b := strings.Repeat("b", 40)
	blob := strings.Repeat("c", 40)
	limits := standardGitTreeGraphLimits()
	cycle := verifiedGraphObjects{
		algorithm: RevisionAlgorithmSHA1,
		rootTree:  a,
		trees: map[string]verifiedGraphTree{
			a: {digest: a, entries: []verifiedGraphEntry{{name: []byte("b"), mode: GitTreeModeDirectory, kind: GitTreeEntryKindTree, objectDigest: b}}},
			b: {digest: b, entries: []verifiedGraphEntry{{name: []byte("a"), mode: GitTreeModeDirectory, kind: GitTreeEntryKindTree, objectDigest: a}}},
		},
		blobs: map[string]verifiedGraphBlob{},
	}
	if _, _, _, err := traverseVerifiedGitGraph(cycle, limits); err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("cycle error = %v", err)
	}
	duplicate := verifiedGraphObjects{
		algorithm: RevisionAlgorithmSHA1,
		rootTree:  a,
		trees: map[string]verifiedGraphTree{a: {digest: a, entries: []verifiedGraphEntry{
			{name: []byte("same"), mode: GitTreeModeRegular, kind: GitTreeEntryKindBlob, objectDigest: blob},
			{name: []byte("same"), mode: GitTreeModeRegular, kind: GitTreeEntryKindBlob, objectDigest: blob},
		}}},
		blobs: map[string]verifiedGraphBlob{blob: {digest: blob}},
	}
	if _, _, _, err := traverseVerifiedGitGraph(duplicate, limits); err == nil || !strings.Contains(err.Error(), "duplicate expanded path") {
		t.Fatalf("duplicate error = %v", err)
	}
}

func TestTraverseVerifiedGitGraphDefensiveRecordChecks(t *testing.T) {
	root := strings.Repeat("a", 40)
	child := strings.Repeat("b", 40)
	blob := strings.Repeat("c", 40)
	base := verifiedGraphObjects{
		algorithm: RevisionAlgorithmSHA1,
		rootTree:  root,
		trees:     map[string]verifiedGraphTree{root: {digest: root, entries: []verifiedGraphEntry{{name: []byte("entry"), mode: GitTreeModeDirectory, kind: GitTreeEntryKindTree, objectDigest: child}}}},
		blobs:     map[string]verifiedGraphBlob{},
	}
	if _, _, _, err := traverseVerifiedGitGraph(base, standardGitTreeGraphLimits()); err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing child error = %v", err)
	}
	mismatch := base
	mismatch.trees = map[string]verifiedGraphTree{root: {digest: root, entries: []verifiedGraphEntry{{name: []byte("entry"), mode: GitTreeModeDirectory, kind: GitTreeEntryKindBlob, objectDigest: blob}}}}
	mismatch.blobs = map[string]verifiedGraphBlob{blob: {digest: blob}}
	if _, _, _, err := traverseVerifiedGitGraph(mismatch, standardGitTreeGraphLimits()); err == nil || !strings.Contains(err.Error(), "non-tree kind") {
		t.Fatalf("kind mismatch error = %v", err)
	}
}

func TestCheckedGraphAddBoundaries(t *testing.T) {
	const objectLimit = int64(256 << 20)
	const pathLimit = int64(64 << 20)
	for _, limit := range []int64{objectLimit, pathLimit} {
		if got, err := checkedGraphAdd(0, limit, limit); err != nil || got != limit {
			t.Fatalf("checkedGraphAdd(0, %d, %d) = (%d, %v)", limit, limit, got, err)
		}
		first, err := checkedGraphAdd(0, limit/2, limit)
		if err != nil {
			t.Fatalf("first split addition error = %v", err)
		}
		if got, err := checkedGraphAdd(first, limit-limit/2, limit); err != nil || got != limit {
			t.Fatalf("split exact addition = (%d, %v)", got, err)
		}
		if got, err := checkedGraphAdd(limit, 1, limit); err == nil || got != limit {
			t.Fatalf("over-limit addition = (%d, %v)", got, err)
		}
	}
	invalid := [][3]int64{{-1, 0, 1}, {0, -1, 1}, {0, 0, -1}, {math.MaxInt64 - 1, 2, math.MaxInt64}}
	for _, values := range invalid {
		if _, err := checkedGraphAdd(values[0], values[1], values[2]); err == nil {
			t.Fatalf("checkedGraphAdd%v succeeded", values)
		}
	}
	budget := gitTreeGraphBudget{totalObjectBytes: 7, totalPathBytes: 8}
	if err := budget.addObjectBytes(4, 10); err == nil || budget.totalObjectBytes != 7 {
		t.Fatalf("object budget after rejection = %#v, %v", budget, err)
	}
	if err := budget.addPathBytes(3, 10); err == nil || budget.totalPathBytes != 8 {
		t.Fatalf("path budget after rejection = %#v, %v", budget, err)
	}
}

func TestTraverseVerifiedGitGraphEnforcesInjectedLimits(t *testing.T) {
	root := strings.Repeat("a", 40)
	blobOne := strings.Repeat("b", 40)
	blobTwo := strings.Repeat("c", 40)
	objects := verifiedGraphObjects{
		algorithm: RevisionAlgorithmSHA1,
		rootTree:  root,
		trees: map[string]verifiedGraphTree{root: {digest: root, contentSize: 2, entries: []verifiedGraphEntry{
			{name: []byte("a"), mode: GitTreeModeRegular, kind: GitTreeEntryKindBlob, objectDigest: blobOne},
			{name: []byte("b"), mode: GitTreeModeRegular, kind: GitTreeEntryKindBlob, objectDigest: blobTwo},
		}}},
		blobs: map[string]verifiedGraphBlob{blobOne: {digest: blobOne, contentSize: 3}, blobTwo: {digest: blobTwo, contentSize: 4}},
	}
	passing := standardGitTreeGraphLimits()
	passing.maxDepth = 1
	passing.maxEntries = 2
	passing.maxUniqueTrees = 1
	passing.maxUniqueBlobs = 2
	passing.maxPathBytes = 1
	passing.maxTotalPathBytes = 2
	passing.maxTotalObjectBytes = 9
	if _, stats, _, err := traverseVerifiedGitGraph(objects, passing); err != nil || stats.entryCount != 2 || stats.totalObjectBytes != 9 {
		t.Fatalf("exact limits = (%#v, %v)", stats, err)
	}
	testCases := []struct {
		name   string
		mutate func(*gitTreeGraphLimits)
	}{
		{name: "depth", mutate: func(l *gitTreeGraphLimits) { l.maxDepth = 0 }},
		{name: "entries", mutate: func(l *gitTreeGraphLimits) { l.maxEntries = 1 }},
		{name: "blobs", mutate: func(l *gitTreeGraphLimits) { l.maxUniqueBlobs = 1 }},
		{name: "path", mutate: func(l *gitTreeGraphLimits) { l.maxPathBytes = 0 }},
		{name: "total path", mutate: func(l *gitTreeGraphLimits) { l.maxTotalPathBytes = 1 }},
		{name: "object bytes", mutate: func(l *gitTreeGraphLimits) { l.maxTotalObjectBytes = 8 }},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			limits := passing
			testCase.mutate(&limits)
			if _, _, _, err := traverseVerifiedGitGraph(objects, limits); err == nil {
				t.Fatal("traversal unexpectedly passed")
			}
		})
	}
}

func TestGitTreeGraphIdentityPreimage(t *testing.T) {
	blob := []byte("hello\n")
	blobDigest := gitObjectDigestForTest("blob", blob, RevisionAlgorithmSHA1)
	rootContent := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("file"), blobDigest})
	fixture := mustGraphFixture(t, RevisionAlgorithmSHA1, rootContent, nil, map[string][]byte{blobDigest: blob})
	graph, err := fixture.verify()
	if err != nil {
		t.Fatalf("VerifyGitTreeGraph() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/git-tree-graph","schema_version":1,"git_commit_identity":"%s","root_tree_identity":"%s","root_tree_verification_identity":"%s","algorithm":"sha1","entry_count":1,"unique_tree_object_count":1,"unique_blob_object_count":1,"total_object_bytes":%d,"traversal_digest":"%s"}`, fixture.commit.Identity(), fixture.rootTree.Identity(), fixture.rootVerification.Identity(), len(rootContent)+len(blob), graph.TraversalDigest())
	digest := sha256.Sum256([]byte(preimage))
	if graph.Identity() != hex.EncodeToString(digest[:]) {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", graph.Identity(), preimage)
	}
}

func TestGitTreeGraphZeroValueIsEmpty(t *testing.T) {
	var graph GitTreeGraph
	var entry GitTreeGraphEntry
	if graph.Identity() != "" || graph.GitCommitIdentity() != "" || graph.RootTreeIdentity() != "" || graph.RootTreeVerificationIdentity() != "" || graph.Algorithm() != "" || graph.Entries() != nil || graph.EntryCount() != 0 || graph.UniqueTreeObjectCount() != 0 || graph.UniqueBlobObjectCount() != 0 || graph.TotalObjectBytes() != 0 || graph.TraversalDigest() != "" || entry.Path() != nil || entry.PathHex() != "" || entry.Mode() != "" || entry.Kind() != "" || entry.ObjectDigest() != "" || entry.ContentSizeBytes() != 0 {
		t.Fatalf("zero values = (%#v, %#v)", graph, entry)
	}
}

type graphTestEntry struct {
	mode   GitTreeMode
	name   []byte
	digest string
}

type graphFixture struct {
	revision           RevisionIdentity
	commitVerification GitCommitObjectVerification
	commitContent      []byte
	commit             GitCommit
	rootVerification   GitTreeObjectVerification
	rootContent        []byte
	rootTree           GitTree
	childTrees         map[string][]byte
	blobs              map[string][]byte
}

func graphTreeContentForTest(t *testing.T, algorithm RevisionAlgorithm, entries ...graphTestEntry) []byte {
	t.Helper()
	var content []byte
	for _, entry := range entries {
		objectID, err := hex.DecodeString(entry.digest)
		if err != nil {
			t.Fatalf("hex.DecodeString(%q) error = %v", entry.digest, err)
		}
		content = append(content, encodeGitTreeEntryForTest(entry.mode, entry.name, objectID)...)
	}
	return content
}

func mustDepthGraphFixture(t *testing.T, depth int) graphFixture {
	t.Helper()
	blobDigest := gitObjectDigestForTest("blob", nil, RevisionAlgorithmSHA1)
	content := graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeRegular, []byte("leaf"), blobDigest})
	childTrees := make(map[string][]byte)
	for level := 1; level < depth; level++ {
		digest := gitObjectDigestForTest("tree", content, RevisionAlgorithmSHA1)
		childTrees[digest] = content
		content = graphTreeContentForTest(t, RevisionAlgorithmSHA1, graphTestEntry{GitTreeModeDirectory, []byte("d"), digest})
	}
	return mustGraphFixture(t, RevisionAlgorithmSHA1, content, childTrees, map[string][]byte{blobDigest: nil})
}

func mustGraphFixture(t *testing.T, algorithm RevisionAlgorithm, rootContent []byte, childTrees, blobs map[string][]byte) graphFixture {
	t.Helper()
	revision, commitVerification, commitContent, commit, rootVerification, rootTree := mustGitTreeInputs(t, algorithm, rootContent)
	fixture := graphFixture{
		revision:           revision,
		commitVerification: commitVerification,
		commitContent:      append([]byte{}, commitContent...),
		commit:             commit,
		rootVerification:   rootVerification,
		rootContent:        append([]byte{}, rootContent...),
		rootTree:           rootTree,
		childTrees:         make(map[string][]byte),
		blobs:              make(map[string][]byte),
	}
	for digest, content := range childTrees {
		fixture.childTrees[digest] = append([]byte{}, content...)
	}
	for digest, content := range blobs {
		fixture.blobs[digest] = append([]byte{}, content...)
	}
	return fixture
}

func (f graphFixture) verify() (GitTreeGraph, error) {
	return VerifyGitTreeGraph(f.revision, f.commitVerification, f.commitContent, f.commit, f.rootVerification, f.rootContent, f.rootTree, f.childTrees, f.blobs)
}

func (f graphFixture) clone() graphFixture {
	result := f
	result.commitContent = append([]byte{}, f.commitContent...)
	result.rootContent = append([]byte{}, f.rootContent...)
	result.childTrees = make(map[string][]byte, len(f.childTrees))
	for digest, content := range f.childTrees {
		result.childTrees[digest] = append([]byte{}, content...)
	}
	result.blobs = make(map[string][]byte, len(f.blobs))
	for digest, content := range f.blobs {
		result.blobs[digest] = append([]byte{}, content...)
	}
	return result
}
