package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestVerifyGitBlobObjectKnownVectors(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm RevisionAlgorithm
		mode      GitTreeMode
		digest    string
	}{
		{name: "SHA-1 regular", algorithm: RevisionAlgorithmSHA1, mode: GitTreeModeRegular, digest: "ce013625030ba8dba906f756967f9e9ca394464a"},
		{name: "SHA-256 executable", algorithm: RevisionAlgorithmSHA256, mode: GitTreeModeExecutable, digest: "2cf8d83d9ee29543b34a87727421fdecb7e3f3a183d337639025de576db9ebb4"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			chain := mustBlobChain(t, testCase.algorithm, testCase.mode, []byte("file"), testCase.digest)
			verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, []byte("hello\n"))
			if err != nil {
				t.Fatalf("VerifyGitBlobObject() error = %v", err)
			}
			if len(verification.Identity()) != 64 || verification.GitCommitIdentity() != chain.commit.Identity() || verification.GitTreeIdentity() != chain.tree.Identity() || verification.TreeVerificationIdentity() != chain.treeVerification.Identity() || verification.EntryIndex() != 0 || verification.EntryMode() != testCase.mode || !bytes.Equal(verification.EntryName(), []byte("file")) || verification.EntryNameHex() != "66696c65" || verification.Algorithm() != testCase.algorithm || verification.DeclaredBlobDigest() != testCase.digest || verification.ComputedBlobDigest() != testCase.digest || verification.ContentSizeBytes() != 6 || verification.ObjectType() != "blob" || verification.FramingVersion() != "git-object-v1" {
				t.Fatalf("verification = %#v", verification)
			}
		})
	}
}

func TestVerifyGitBlobObjectAcceptsEmptyBlobs(t *testing.T) {
	testCases := []struct {
		algorithm RevisionAlgorithm
		digest    string
	}{
		{algorithm: RevisionAlgorithmSHA1, digest: "e69de29bb2d1d6434b8b29ae775ad8c2e48c5391"},
		{algorithm: RevisionAlgorithmSHA256, digest: "473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749120a303721813"},
	}
	for _, testCase := range testCases {
		chain := mustBlobChain(t, testCase.algorithm, GitTreeModeRegular, []byte("empty"), testCase.digest)
		verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, nil)
		if err != nil || verification.ComputedBlobDigest() != testCase.digest || verification.ContentSizeBytes() != 0 {
			t.Fatalf("VerifyGitBlobObject() = (%#v, %v)", verification, err)
		}
	}
}

func TestVerifyGitBlobObjectAcceptsSymlinkOpaqueBytes(t *testing.T) {
	content := []byte("target/path")
	digest := "d0f12b94eeb3c5301ed4468f5c26e689c113ae10"
	chain := mustBlobChain(t, RevisionAlgorithmSHA1, GitTreeModeSymlink, []byte("link"), digest)
	verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, content)
	if err != nil || verification.EntryMode() != GitTreeModeSymlink || verification.ComputedBlobDigest() != digest {
		t.Fatalf("VerifyGitBlobObject() = (%#v, %v)", verification, err)
	}
}

func TestGitBlobObjectVerificationUsesCanonicalPreimage(t *testing.T) {
	digest := "ce013625030ba8dba906f756967f9e9ca394464a"
	chain := mustBlobChain(t, RevisionAlgorithmSHA1, GitTreeModeRegular, []byte("file"), digest)
	verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, []byte("hello\n"))
	if err != nil {
		t.Fatalf("VerifyGitBlobObject() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/git-blob-object-verification","schema_version":1,"git_commit_identity":"%s","git_tree_identity":"%s","tree_verification_identity":"%s","entry_index":0,"entry_mode":"100644","entry_name_hex":"66696c65","algorithm":"sha1","declared_blob_digest":"%s","computed_blob_digest":"%s","content_size_bytes":6,"object_type":"blob","framing_version":"git-object-v1"}`, chain.commit.Identity(), chain.tree.Identity(), chain.treeVerification.Identity(), digest, digest)
	identityDigest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(identityDigest[:]); verification.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", verification.Identity(), preimage)
	}
}

func TestVerifyGitBlobObjectRejectsNonBlobModes(t *testing.T) {
	for _, mode := range []GitTreeMode{GitTreeModeDirectory, GitTreeModeGitlink} {
		digest := strings.Repeat("1", 40)
		chain := mustBlobChain(t, RevisionAlgorithmSHA1, mode, []byte("entry"), digest)
		verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, nil)
		if err == nil || verification.Identity() != "" {
			t.Fatalf("VerifyGitBlobObject(%s) = (%#v, %v), want zero error result", mode, verification, err)
		}
	}
}

func TestVerifyGitBlobObjectRejectsInvalidIndex(t *testing.T) {
	digest := gitObjectDigestForTest("blob", nil, RevisionAlgorithmSHA1)
	chain := mustBlobChain(t, RevisionAlgorithmSHA1, GitTreeModeRegular, []byte("file"), digest)
	for _, index := range []int{-1, 1, 1 << 30} {
		verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, index, nil)
		if err == nil || verification.Identity() != "" {
			t.Fatalf("VerifyGitBlobObject(index %d) = (%#v, %v), want zero error result", index, verification, err)
		}
	}
}

func TestVerifyGitBlobObjectRejectsMismatchAndTypeConfusion(t *testing.T) {
	content := []byte("hello\n")
	digest := gitObjectDigestForTest("blob", content, RevisionAlgorithmSHA1)
	chain := mustBlobChain(t, RevisionAlgorithmSHA1, GitTreeModeRegular, []byte("file"), digest)
	if verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, []byte("Hello\n")); err == nil || verification.Identity() != "" {
		t.Fatalf("mutated blob = (%#v, %v)", verification, err)
	}
	for _, objectType := range []string{"tree", "commit", "tag"} {
		wrongDigest := gitObjectDigestForTest(objectType, content, RevisionAlgorithmSHA1)
		chain := mustBlobChain(t, RevisionAlgorithmSHA1, GitTreeModeRegular, []byte("file"), wrongDigest)
		if verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, content); err == nil || verification.Identity() != "" {
			t.Fatalf("VerifyGitBlobObject(%s digest) = (%#v, %v)", objectType, verification, err)
		}
	}
}

func TestVerifyGitBlobObjectRebindsFullChain(t *testing.T) {
	content := []byte("hello\n")
	digest := gitObjectDigestForTest("blob", content, RevisionAlgorithmSHA1)
	chain := mustBlobChain(t, RevisionAlgorithmSHA1, GitTreeModeRegular, []byte("file"), digest)
	mutatedCommit := append([]byte{}, chain.commitContent...)
	mutatedCommit[len(mutatedCommit)-2] = 'X'
	if verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, mutatedCommit, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, content); err == nil || verification.Identity() != "" {
		t.Fatalf("mutated commit = (%#v, %v)", verification, err)
	}
	mutatedTree := append([]byte{}, chain.treeContent...)
	mutatedTree[len(mutatedTree)-1] ^= 1
	if verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, mutatedTree, chain.tree, 0, content); err == nil || verification.Identity() != "" {
		t.Fatalf("mutated tree = (%#v, %v)", verification, err)
	}
	forgedCommitVerification := chain.commitVerification
	forgedCommitVerification.identity = strings.Repeat("0", 64)
	if verification, err := VerifyGitBlobObject(chain.revision, forgedCommitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, content); err == nil || verification.Identity() != "" {
		t.Fatalf("forged commit verification = (%#v, %v)", verification, err)
	}
	forgedTree := chain.tree
	forgedTree.identity = strings.Repeat("0", 64)
	if verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, forgedTree, 0, content); err == nil || verification.Identity() != "" {
		t.Fatalf("forged tree = (%#v, %v)", verification, err)
	}
	forgedTree = chain.tree
	forgedTree.entries = cloneGitTreeEntries(chain.tree.entries)
	forgedTree.entries[0].name[0] = 'X'
	if verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, forgedTree, 0, content); err == nil || verification.Identity() != "" {
		t.Fatalf("forged tree entry = (%#v, %v)", verification, err)
	}
	forgedTreeVerification := chain.treeVerification
	forgedTreeVerification.identity = strings.Repeat("0", 64)
	if verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, forgedTreeVerification, chain.treeContent, chain.tree, 0, content); err == nil || verification.Identity() != "" {
		t.Fatalf("forged tree verification = (%#v, %v)", verification, err)
	}
	forgedCommit := chain.commit
	forgedCommit.identity = strings.Repeat("0", 64)
	if verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, forgedCommit, chain.treeVerification, chain.treeContent, chain.tree, 0, content); err == nil || verification.Identity() != "" {
		t.Fatalf("forged commit = (%#v, %v)", verification, err)
	}
	forgedRevision := chain.revision
	forgedRevision.identity = strings.Repeat("0", 64)
	if verification, err := VerifyGitBlobObject(forgedRevision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, content); err == nil || verification.Identity() != "" {
		t.Fatalf("forged revision = (%#v, %v)", verification, err)
	}
}

func TestVerifyGitBlobObjectPreservesRawEntryNames(t *testing.T) {
	names := [][]byte{[]byte(" file"), []byte(`a\b`), {0xff, 0xfe}}
	for _, name := range names {
		content := []byte{0, 0xff, '\n'}
		digest := gitObjectDigestForTest("blob", content, RevisionAlgorithmSHA1)
		chain := mustBlobChain(t, RevisionAlgorithmSHA1, GitTreeModeRegular, name, digest)
		verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, content)
		if err != nil || !bytes.Equal(verification.EntryName(), name) || verification.EntryNameHex() != hex.EncodeToString(name) {
			t.Fatalf("VerifyGitBlobObject(%x) = (%#v, %v)", name, verification, err)
		}
	}
}

func TestVerifyGitBlobObjectBindsEntryIndex(t *testing.T) {
	firstContent := []byte("first")
	secondContent := []byte("second")
	firstDigest := gitObjectDigestForTest("blob", firstContent, RevisionAlgorithmSHA1)
	secondDigest := gitObjectDigestForTest("blob", secondContent, RevisionAlgorithmSHA1)
	firstID, _ := hex.DecodeString(firstDigest)
	secondID, _ := hex.DecodeString(secondDigest)
	treeContent := append(encodeGitTreeEntryForTest(GitTreeModeRegular, []byte("a"), firstID), encodeGitTreeEntryForTest(GitTreeModeRegular, []byte("b"), secondID)...)
	chain := mustBlobTreeChain(t, RevisionAlgorithmSHA1, treeContent)
	first, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, firstContent)
	if err != nil {
		t.Fatalf("VerifyGitBlobObject(first) error = %v", err)
	}
	second, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 1, secondContent)
	if err != nil || first.Identity() == second.Identity() || first.EntryIndex() != 0 || second.EntryIndex() != 1 {
		t.Fatalf("verifications = (%#v, %#v, %v)", first, second, err)
	}
}

func TestVerifyGitBlobObjectEnforcesPayloadBound(t *testing.T) {
	content := make([]byte, 64<<20)
	digest := gitObjectDigestForTest("blob", content, RevisionAlgorithmSHA256)
	chain := mustBlobChain(t, RevisionAlgorithmSHA256, GitTreeModeRegular, []byte("large"), digest)
	verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, content)
	if err != nil || verification.ContentSizeBytes() != len(content) {
		t.Fatalf("VerifyGitBlobObject(max) = (%#v, %v)", verification, err)
	}
	tooLarge := make([]byte, (64<<20)+1)
	if verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, tooLarge); err == nil || verification.Identity() != "" {
		t.Fatalf("VerifyGitBlobObject(over max) = (%#v, %v)", verification, err)
	}
}

func TestGitBlobObjectVerificationDoesNotRetainBuffers(t *testing.T) {
	content := []byte("hello\n")
	digest := gitObjectDigestForTest("blob", content, RevisionAlgorithmSHA1)
	chain := mustBlobChain(t, RevisionAlgorithmSHA1, GitTreeModeRegular, []byte("file"), digest)
	verification, err := VerifyGitBlobObject(chain.revision, chain.commitVerification, chain.commitContent, chain.commit, chain.treeVerification, chain.treeContent, chain.tree, 0, content)
	if err != nil {
		t.Fatalf("VerifyGitBlobObject() error = %v", err)
	}
	identity := verification.Identity()
	name := verification.EntryName()
	name[0] = 'X'
	for i := range content {
		content[i] = 0
	}
	for i := range chain.commitContent {
		chain.commitContent[i] = 0
	}
	for i := range chain.treeContent {
		chain.treeContent[i] = 0
	}
	if verification.Identity() != identity || !bytes.Equal(verification.EntryName(), []byte("file")) || verification.ComputedBlobDigest() != digest {
		t.Fatal("caller mutation changed GitBlobObjectVerification")
	}
}

func TestGitBlobObjectVerificationZeroValueIsEmpty(t *testing.T) {
	var verification GitBlobObjectVerification
	if verification.Identity() != "" || verification.GitCommitIdentity() != "" || verification.GitTreeIdentity() != "" || verification.TreeVerificationIdentity() != "" || verification.EntryIndex() != 0 || verification.EntryMode() != "" || len(verification.EntryName()) != 0 || verification.EntryNameHex() != "" || verification.Algorithm() != "" || verification.DeclaredBlobDigest() != "" || verification.ComputedBlobDigest() != "" || verification.ContentSizeBytes() != 0 || verification.ObjectType() != "" || verification.FramingVersion() != "" {
		t.Fatalf("zero GitBlobObjectVerification = %#v", verification)
	}
}

type blobTreeChain struct {
	revision           RevisionIdentity
	commitVerification GitCommitObjectVerification
	commitContent      []byte
	commit             GitCommit
	treeVerification   GitTreeObjectVerification
	treeContent        []byte
	tree               GitTree
}

func mustBlobChain(t *testing.T, algorithm RevisionAlgorithm, mode GitTreeMode, name []byte, digest string) blobTreeChain {
	t.Helper()
	objectID, err := hex.DecodeString(digest)
	if err != nil {
		t.Fatalf("hex.DecodeString() error = %v", err)
	}
	return mustBlobTreeChain(t, algorithm, encodeGitTreeEntryForTest(mode, name, objectID))
}

func mustBlobTreeChain(t *testing.T, algorithm RevisionAlgorithm, treeContent []byte) blobTreeChain {
	t.Helper()
	revision, commitVerification, commitContent, commit, treeVerification, tree := mustGitTreeInputs(t, algorithm, treeContent)
	return blobTreeChain{
		revision:           revision,
		commitVerification: commitVerification,
		commitContent:      commitContent,
		commit:             commit,
		treeVerification:   treeVerification,
		treeContent:        treeContent,
		tree:               tree,
	}
}
