package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestParseVerifiedGitTreeAcceptsEmptyTrees(t *testing.T) {
	for _, algorithm := range []RevisionAlgorithm{RevisionAlgorithmSHA1, RevisionAlgorithmSHA256} {
		tree := mustParseGitTree(t, algorithm, nil)
		if len(tree.Identity()) != 64 || tree.TreeAlgorithm() != algorithm || tree.EntryCount() != 0 || tree.Entries() == nil || len(tree.Entries()) != 0 {
			t.Fatalf("tree = %#v", tree)
		}
	}
}

func TestParseVerifiedGitTreeDerivesModesAndKinds(t *testing.T) {
	algorithm := RevisionAlgorithmSHA1
	entries := []struct {
		mode GitTreeMode
		kind GitTreeEntryKind
		name []byte
		id   byte
	}{
		{mode: GitTreeModeRegular, kind: GitTreeEntryKindBlob, name: []byte("a"), id: 1},
		{mode: GitTreeModeExecutable, kind: GitTreeEntryKindBlob, name: []byte("b"), id: 2},
		{mode: GitTreeModeSymlink, kind: GitTreeEntryKindBlob, name: []byte("c"), id: 3},
		{mode: GitTreeModeDirectory, kind: GitTreeEntryKindTree, name: []byte("d"), id: 4},
		{mode: GitTreeModeGitlink, kind: GitTreeEntryKindCommit, name: []byte("e"), id: 5},
	}
	var content []byte
	for _, entry := range entries {
		content = append(content, encodeGitTreeEntryForTest(entry.mode, entry.name, bytes.Repeat([]byte{entry.id}, 20))...)
	}
	tree := mustParseGitTree(t, algorithm, content)
	got := tree.Entries()
	if len(got) != len(entries) || tree.EntryCount() != len(entries) {
		t.Fatalf("entries = %d, want %d", len(got), len(entries))
	}
	for i, entry := range entries {
		if got[i].Mode() != entry.mode || got[i].Kind() != entry.kind || !bytes.Equal(got[i].Name(), entry.name) || got[i].NameHex() != hex.EncodeToString(entry.name) || got[i].ObjectAlgorithm() != algorithm || got[i].ObjectDigest() != strings.Repeat(fmt.Sprintf("%02x", entry.id), 20) {
			t.Fatalf("entry %d = %#v", i, got[i])
		}
	}
}

func TestParseVerifiedGitTreeUsesRawObjectIDs(t *testing.T) {
	for _, testCase := range []struct {
		algorithm RevisionAlgorithm
		idBytes   int
	}{
		{algorithm: RevisionAlgorithmSHA1, idBytes: 20},
		{algorithm: RevisionAlgorithmSHA256, idBytes: 32},
	} {
		objectID := make([]byte, testCase.idBytes)
		for i := range objectID {
			objectID[i] = byte(i + 1)
		}
		content := encodeGitTreeEntryForTest(GitTreeModeRegular, []byte("file"), objectID)
		entry := mustParseGitTree(t, testCase.algorithm, content).Entries()[0]
		if entry.ObjectDigest() != hex.EncodeToString(objectID) || len(entry.ObjectDigest()) != testCase.idBytes*2 {
			t.Fatalf("ObjectDigest() = %q", entry.ObjectDigest())
		}
	}
}

func TestGitTreeUsesCanonicalPreimage(t *testing.T) {
	content := encodeGitTreeEntryForTest(GitTreeModeRegular, []byte("file"), bytes.Repeat([]byte{1}, 20))
	revision, _, _, commit, treeVerification, tree := mustGitTreeInputs(t, RevisionAlgorithmSHA1, content)
	preimage := fmt.Sprintf(`{"contract":"open-trestle/git-tree","schema_version":1,"git_commit_identity":"%s","tree_verification_identity":"%s","tree_algorithm":"sha1","tree_digest":"%s","entry_count":1}`, commit.Identity(), treeVerification.Identity(), treeVerification.ComputedTreeDigest())
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); tree.Identity() != want || tree.GitCommitIdentity() != commit.Identity() || tree.TreeVerificationIdentity() != treeVerification.Identity() || tree.TreeDigest() != treeVerification.ComputedTreeDigest() || tree.TreeAlgorithm() != revision.Algorithm() {
		t.Fatalf("tree = %#v, want SHA-256 of %s", tree, preimage)
	}
}

func TestParseVerifiedGitTreeRejectsInvalidModes(t *testing.T) {
	invalid := []string{"", "040000", "0100644", "100664", "1006440", "100 644", "+100644", "-100644", "ABCDEF", " 100644"}
	for _, mode := range invalid {
		content := append([]byte(mode+" file\x00"), bytes.Repeat([]byte{1}, 20)...)
		assertGitTreeParseError(t, RevisionAlgorithmSHA1, content)
	}
	for _, mode := range []GitTreeMode{GitTreeModeRegular, GitTreeModeExecutable, GitTreeModeSymlink, GitTreeModeDirectory, GitTreeModeGitlink} {
		mutations := []string{"0" + string(mode), string(mode) + "0"}
		for _, mutation := range mutations {
			content := append([]byte(mutation+" file\x00"), bytes.Repeat([]byte{1}, 20)...)
			assertGitTreeParseError(t, RevisionAlgorithmSHA1, content)
		}
	}
}

func TestParseVerifiedGitTreePreservesRawNames(t *testing.T) {
	names := [][]byte{
		[]byte(" file"),
		[]byte("file "),
		[]byte("  "),
		[]byte(".hidden."),
		[]byte(`a\b`),
		[]byte{0xff, 0xfe},
		bytes.Repeat([]byte{' '}, 4096),
	}
	for _, name := range names {
		content := encodeGitTreeEntryForTest(GitTreeModeRegular, name, bytes.Repeat([]byte{1}, 20))
		entry := mustParseGitTree(t, RevisionAlgorithmSHA1, content).Entries()[0]
		if !bytes.Equal(entry.Name(), name) || entry.NameHex() != hex.EncodeToString(name) {
			t.Fatalf("name = %x, entry = %#v", name, entry)
		}
	}
	invalid := [][]byte{nil, []byte("."), []byte(".."), []byte("a/b"), bytes.Repeat([]byte{'a'}, 4097)}
	for _, name := range invalid {
		content := encodeGitTreeEntryForTest(GitTreeModeRegular, name, bytes.Repeat([]byte{1}, 20))
		assertGitTreeParseError(t, RevisionAlgorithmSHA1, content)
	}
}

func TestParseVerifiedGitTreeRejectsMalformedRecords(t *testing.T) {
	objectID := bytes.Repeat([]byte{1}, 20)
	valid := encodeGitTreeEntryForTest(GitTreeModeRegular, []byte("file"), objectID)
	testCases := [][]byte{
		[]byte("100644"),
		append([]byte("100644 file"), objectID...),
		[]byte("100644 \x00"),
		append([]byte("100644 file\x00"), objectID[:19]...),
		append(append([]byte{}, valid...), 1),
		append([]byte("100644 a\x00b"), objectID...),
		append([]byte("100644 file\x00"), []byte(strings.Repeat("a", 40))...),
	}
	for _, content := range testCases {
		assertGitTreeParseError(t, RevisionAlgorithmSHA1, content)
	}
}

func TestParseVerifiedGitTreeRejectsDuplicateNames(t *testing.T) {
	first := encodeGitTreeEntryForTest(GitTreeModeRegular, []byte("same"), bytes.Repeat([]byte{1}, 20))
	second := encodeGitTreeEntryForTest(GitTreeModeDirectory, []byte("same"), bytes.Repeat([]byte{2}, 20))
	assertGitTreeParseError(t, RevisionAlgorithmSHA1, append(first, second...))
}

func TestParseVerifiedGitTreeEnforcesCanonicalOrdering(t *testing.T) {
	testCases := []struct {
		firstMode  GitTreeMode
		firstName  []byte
		secondMode GitTreeMode
		secondName []byte
	}{
		{firstMode: GitTreeModeRegular, firstName: []byte("a"), secondMode: GitTreeModeRegular, secondName: []byte("a.b")},
		{firstMode: GitTreeModeRegular, firstName: []byte("a.b"), secondMode: GitTreeModeDirectory, secondName: []byte("a")},
		{firstMode: GitTreeModeDirectory, firstName: []byte("a"), secondMode: GitTreeModeRegular, secondName: []byte("a0")},
		{firstMode: GitTreeModeRegular, firstName: []byte(" a"), secondMode: GitTreeModeRegular, secondName: []byte("a")},
		{firstMode: GitTreeModeRegular, firstName: []byte{0x7f}, secondMode: GitTreeModeRegular, secondName: []byte{0x80}},
	}
	for _, testCase := range testCases {
		first := encodeGitTreeEntryForTest(testCase.firstMode, testCase.firstName, bytes.Repeat([]byte{1}, 20))
		second := encodeGitTreeEntryForTest(testCase.secondMode, testCase.secondName, bytes.Repeat([]byte{2}, 20))
		mustParseGitTree(t, RevisionAlgorithmSHA1, append(append([]byte{}, first...), second...))
		assertGitTreeParseError(t, RevisionAlgorithmSHA1, append(append([]byte{}, second...), first...))
	}
}

func TestParseVerifiedGitTreeRebindsVerificationChain(t *testing.T) {
	content := encodeGitTreeEntryForTest(GitTreeModeRegular, []byte("file"), bytes.Repeat([]byte{1}, 20))
	revision, commitVerification, commitContent, commit, treeVerification, _ := mustGitTreeInputs(t, RevisionAlgorithmSHA1, content)
	mutated := append([]byte{}, content...)
	mutated[len(mutated)-1] = 2
	if tree, err := ParseVerifiedGitTree(revision, commitVerification, commitContent, commit, treeVerification, mutated); err == nil || tree.Identity() != "" {
		t.Fatalf("mutated tree = (%#v, %v)", tree, err)
	}
	mutatedCommit := append([]byte{}, commitContent...)
	mutatedCommit[len(mutatedCommit)-2] = 'X'
	if tree, err := ParseVerifiedGitTree(revision, commitVerification, mutatedCommit, commit, treeVerification, content); err == nil || tree.Identity() != "" {
		t.Fatalf("mutated commit = (%#v, %v)", tree, err)
	}
	forgedCommitVerification := commitVerification
	forgedCommitVerification.identity = strings.Repeat("0", 64)
	if tree, err := ParseVerifiedGitTree(revision, forgedCommitVerification, commitContent, commit, treeVerification, content); err == nil || tree.Identity() != "" {
		t.Fatalf("forged commit verification = (%#v, %v)", tree, err)
	}
	forged := treeVerification
	forged.identity = strings.Repeat("0", 64)
	if tree, err := ParseVerifiedGitTree(revision, commitVerification, commitContent, commit, forged, content); err == nil || tree.Identity() != "" {
		t.Fatalf("forged verification = (%#v, %v)", tree, err)
	}
	forged = treeVerification
	forged.computedTreeDigest = strings.Repeat("0", 40)
	if tree, err := ParseVerifiedGitTree(revision, commitVerification, commitContent, commit, forged, content); err == nil || tree.Identity() != "" {
		t.Fatalf("stale verification = (%#v, %v)", tree, err)
	}
	forgedCommit := commit
	forgedCommit.treeDigest = strings.Repeat("0", 40)
	if tree, err := ParseVerifiedGitTree(revision, commitVerification, commitContent, forgedCommit, treeVerification, content); err == nil || tree.Identity() != "" {
		t.Fatalf("forged commit = (%#v, %v)", tree, err)
	}
	forgedRevision := revision
	forgedRevision.identity = strings.Repeat("0", 64)
	if tree, err := ParseVerifiedGitTree(forgedRevision, commitVerification, commitContent, commit, treeVerification, content); err == nil || tree.Identity() != "" {
		t.Fatalf("forged revision = (%#v, %v)", tree, err)
	}
}

func TestParseVerifiedGitTreeEnforcesEntryBound(t *testing.T) {
	build := func(count int) []byte {
		content := make([]byte, 0, count*33)
		for i := 0; i < count; i++ {
			name := []byte(fmt.Sprintf("%05d", i))
			content = append(content, encodeGitTreeEntryForTest(GitTreeModeRegular, name, bytes.Repeat([]byte{1}, 20))...)
		}
		return content
	}
	if tree := mustParseGitTree(t, RevisionAlgorithmSHA1, build(65_536)); tree.EntryCount() != 65_536 {
		t.Fatalf("EntryCount() = %d", tree.EntryCount())
	}
	assertGitTreeParseError(t, RevisionAlgorithmSHA1, build(65_537))
}

func TestGitTreeIsImmutableAndDoesNotRetainContent(t *testing.T) {
	content := encodeGitTreeEntryForTest(GitTreeModeRegular, []byte("file"), bytes.Repeat([]byte{1}, 20))
	tree := mustParseGitTree(t, RevisionAlgorithmSHA1, content)
	identity := tree.Identity()
	entries := tree.Entries()
	name := entries[0].Name()
	name[0] = 'X'
	entries[0].name[0] = 'Y'
	for i := range content {
		content[i] = 0
	}
	if tree.Identity() != identity || !bytes.Equal(tree.Entries()[0].Name(), []byte("file")) {
		t.Fatal("caller mutation changed GitTree")
	}
}

func TestGitTreeZeroValuesAreEmpty(t *testing.T) {
	var tree GitTree
	if tree.Identity() != "" || tree.GitCommitIdentity() != "" || tree.TreeVerificationIdentity() != "" || tree.TreeAlgorithm() != "" || tree.TreeDigest() != "" || len(tree.Entries()) != 0 || tree.EntryCount() != 0 {
		t.Fatalf("zero GitTree = %#v", tree)
	}
	var entry GitTreeEntry
	if entry.Mode() != "" || entry.Kind() != "" || len(entry.Name()) != 0 || entry.NameHex() != "" || entry.ObjectAlgorithm() != "" || entry.ObjectDigest() != "" {
		t.Fatalf("zero GitTreeEntry = %#v", entry)
	}
}

func mustParseGitTree(t *testing.T, algorithm RevisionAlgorithm, content []byte) GitTree {
	t.Helper()
	_, _, _, _, _, tree := mustGitTreeInputs(t, algorithm, content)
	return tree
}

func mustGitTreeInputs(t *testing.T, algorithm RevisionAlgorithm, treeContent []byte) (RevisionIdentity, GitCommitObjectVerification, []byte, GitCommit, GitTreeObjectVerification, GitTree) {
	t.Helper()
	treeDigest := gitObjectDigestForTest("tree", treeContent, algorithm)
	commitContent := commitContentForTree(treeDigest)
	revision, commitVerification, commit := mustGitCommitInputs(t, algorithm, commitContent)
	treeVerification, err := VerifyGitTreeObject(revision, commitVerification, commitContent, commit, treeContent)
	if err != nil {
		t.Fatalf("VerifyGitTreeObject() error = %v", err)
	}
	tree, err := ParseVerifiedGitTree(revision, commitVerification, commitContent, commit, treeVerification, treeContent)
	if err != nil {
		t.Fatalf("ParseVerifiedGitTree() error = %v", err)
	}
	return revision, commitVerification, commitContent, commit, treeVerification, tree
}

func assertGitTreeParseError(t *testing.T, algorithm RevisionAlgorithm, content []byte) {
	t.Helper()
	treeDigest := gitObjectDigestForTest("tree", content, algorithm)
	commitContent := commitContentForTree(treeDigest)
	revision, commitVerification, commit := mustGitCommitInputs(t, algorithm, commitContent)
	treeVerification, err := VerifyGitTreeObject(revision, commitVerification, commitContent, commit, content)
	if err != nil {
		t.Fatalf("VerifyGitTreeObject() error = %v", err)
	}
	tree, err := ParseVerifiedGitTree(revision, commitVerification, commitContent, commit, treeVerification, content)
	if err == nil || tree.Identity() != "" {
		t.Fatalf("ParseVerifiedGitTree() = (%#v, %v), want zero error result", tree, err)
	}
}

func encodeGitTreeEntryForTest(mode GitTreeMode, name, objectID []byte) []byte {
	result := make([]byte, 0, len(mode)+1+len(name)+1+len(objectID))
	result = append(result, []byte(mode)...)
	result = append(result, ' ')
	result = append(result, name...)
	result = append(result, 0)
	result = append(result, objectID...)
	return result
}
