package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestVerifyGitTreeObjectKnownVectors(t *testing.T) {
	treeContent := []byte("hello\n")
	testCases := []struct {
		name      string
		algorithm RevisionAlgorithm
		digest    string
	}{
		{name: "SHA-1", algorithm: RevisionAlgorithmSHA1, digest: "149e5b19a5281f340f976d2ba38d4f02d8a6e967"},
		{name: "SHA-256", algorithm: RevisionAlgorithmSHA256, digest: "ae1e4b5e47ccab8d4387bf290e90c0d2d633e15d9a929cb082d628942ddcaa51"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			revision, commitVerification, commit := mustTreeCommitInputs(t, testCase.algorithm, testCase.digest)
			verification, err := VerifyGitTreeObject(revision, commitVerification, commitContentForTree(testCase.digest), commit, treeContent)
			if err != nil {
				t.Fatalf("VerifyGitTreeObject() error = %v", err)
			}
			if len(verification.Identity()) != 64 || verification.GitCommitIdentity() != commit.Identity() || verification.RevisionIdentity() != revision.Identity() || verification.TreeAlgorithm() != testCase.algorithm || verification.DeclaredTreeDigest() != testCase.digest || verification.ComputedTreeDigest() != testCase.digest || verification.ContentSizeBytes() != len(treeContent) || verification.ObjectType() != "tree" || verification.FramingVersion() != "git-object-v1" {
				t.Fatalf("verification = %#v", verification)
			}
			repeated, err := VerifyGitTreeObject(revision, commitVerification, commitContentForTree(testCase.digest), commit, treeContent)
			if err != nil || repeated != verification {
				t.Fatalf("repeated = (%#v, %v), want %#v", repeated, err, verification)
			}
		})
	}
}

func TestVerifyGitTreeObjectEmptyVectors(t *testing.T) {
	testCases := []struct {
		algorithm RevisionAlgorithm
		digest    string
	}{
		{algorithm: RevisionAlgorithmSHA1, digest: "4b825dc642cb6eb9a060e54bf8d69288fbee4904"},
		{algorithm: RevisionAlgorithmSHA256, digest: "6ef19b41225c5369f1c104d45d8d85efa9b057b53b14b4b9b939dd74decc5321"},
	}
	for _, testCase := range testCases {
		revision, commitVerification, commit := mustTreeCommitInputs(t, testCase.algorithm, testCase.digest)
		verification, err := VerifyGitTreeObject(revision, commitVerification, commitContentForTree(testCase.digest), commit, nil)
		if err != nil || verification.ComputedTreeDigest() != testCase.digest || verification.ContentSizeBytes() != 0 {
			t.Fatalf("VerifyGitTreeObject() = (%#v, %v)", verification, err)
		}
	}
}

func TestGitTreeObjectVerificationUsesCanonicalPreimage(t *testing.T) {
	treeDigest := "149e5b19a5281f340f976d2ba38d4f02d8a6e967"
	revision, commitVerification, commit := mustTreeCommitInputs(t, RevisionAlgorithmSHA1, treeDigest)
	verification, err := VerifyGitTreeObject(revision, commitVerification, commitContentForTree(treeDigest), commit, []byte("hello\n"))
	if err != nil {
		t.Fatalf("VerifyGitTreeObject() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/git-tree-object-verification","schema_version":1,"git_commit_identity":"%s","revision_identity":"%s","tree_algorithm":"sha1","declared_tree_digest":"%s","computed_tree_digest":"%s","content_size_bytes":6,"object_type":"tree","framing_version":"git-object-v1"}`, commit.Identity(), revision.Identity(), treeDigest, treeDigest)
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); verification.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", verification.Identity(), preimage)
	}
}

func TestVerifyGitTreeObjectRejectsTreeMismatchAndTypeConfusion(t *testing.T) {
	treeContent := []byte("hello\n")
	declared := gitObjectDigestForTest("tree", treeContent, RevisionAlgorithmSHA1)
	revision, commitVerification, commit := mustTreeCommitInputs(t, RevisionAlgorithmSHA1, declared)
	mutated := []byte("Hello\n")
	if verification, err := VerifyGitTreeObject(revision, commitVerification, commitContentForTree(declared), commit, mutated); err == nil || verification.Identity() != "" {
		t.Fatalf("VerifyGitTreeObject(mutated) = (%#v, %v)", verification, err)
	}
	for _, objectType := range []string{"blob", "commit", "tag"} {
		wrongDigest := gitObjectDigestForTest(objectType, treeContent, RevisionAlgorithmSHA1)
		revision, commitVerification, commit := mustTreeCommitInputs(t, RevisionAlgorithmSHA1, wrongDigest)
		if verification, err := VerifyGitTreeObject(revision, commitVerification, commitContentForTree(wrongDigest), commit, treeContent); err == nil || verification.Identity() != "" {
			t.Fatalf("VerifyGitTreeObject(%s digest) = (%#v, %v)", objectType, verification, err)
		}
	}
}

func TestVerifyGitTreeObjectRebindsCommitChain(t *testing.T) {
	treeContent := []byte("hello\n")
	treeDigest := gitObjectDigestForTest("tree", treeContent, RevisionAlgorithmSHA1)
	commitContent := commitContentForTree(treeDigest)
	revision, commitVerification, commit := mustTreeCommitInputs(t, RevisionAlgorithmSHA1, treeDigest)
	mutatedCommitContent := append([]byte{}, commitContent...)
	mutatedCommitContent[len(mutatedCommitContent)-2] = 'X'
	if verification, err := VerifyGitTreeObject(revision, commitVerification, mutatedCommitContent, commit, treeContent); err == nil || verification.Identity() != "" {
		t.Fatalf("mutated commit = (%#v, %v)", verification, err)
	}
	forgedVerification := commitVerification
	forgedVerification.identity = strings.Repeat("0", 64)
	if verification, err := VerifyGitTreeObject(revision, forgedVerification, commitContent, commit, treeContent); err == nil || verification.Identity() != "" {
		t.Fatalf("forged verification = (%#v, %v)", verification, err)
	}
	forgeries := []GitCommit{}
	forged := commit
	forged.identity = strings.Repeat("0", 64)
	forgeries = append(forgeries, forged)
	forged = commit
	forged.treeDigest = strings.Repeat("2", 40)
	forgeries = append(forgeries, forged)
	forged = commit
	forged.treeAlgorithm = RevisionAlgorithmSHA256
	forgeries = append(forgeries, forged)
	forged = commit
	forged.revisionIdentity = strings.Repeat("0", 64)
	forgeries = append(forgeries, forged)
	forged = commit
	forged.objectVerificationIdentity = strings.Repeat("0", 64)
	forgeries = append(forgeries, forged)
	forged = commit
	forged.parents = nil
	forgeries = append(forgeries, forged)
	forged = commit
	forged.encoding = "UTF-8"
	forgeries = append(forgeries, forged)
	forged = commit
	forged.headerCount++
	forgeries = append(forgeries, forged)
	forged = commit
	forged.messageSizeBytes++
	forgeries = append(forgeries, forged)
	forged = commit
	forged.messageDigest = strings.Repeat("0", 64)
	forgeries = append(forgeries, forged)
	for _, forgedCommit := range forgeries {
		if verification, err := VerifyGitTreeObject(revision, commitVerification, commitContent, forgedCommit, treeContent); err == nil || verification.Identity() != "" {
			t.Fatalf("forged commit = (%#v, %v)", verification, err)
		}
	}
	forgedRevision := revision
	forgedRevision.identity = strings.Repeat("0", 64)
	if verification, err := VerifyGitTreeObject(forgedRevision, commitVerification, commitContent, commit, treeContent); err == nil || verification.Identity() != "" {
		t.Fatalf("forged revision = (%#v, %v)", verification, err)
	}
}

func TestVerifyGitTreeObjectAcceptsArbitraryPayloadBytes(t *testing.T) {
	treeContent := []byte{0, 0xff, '\n'}
	testCases := []struct {
		algorithm RevisionAlgorithm
		digest    string
	}{
		{algorithm: RevisionAlgorithmSHA1, digest: "0a7a40b3766d0efb371b206b6720d17d9fa8b0ba"},
		{algorithm: RevisionAlgorithmSHA256, digest: "3f19b2eb8dfbee3afab9898a1183081a48c09769065b062fce267df9814227d8"},
	}
	for _, testCase := range testCases {
		revision, commitVerification, commit := mustTreeCommitInputs(t, testCase.algorithm, testCase.digest)
		verification, err := VerifyGitTreeObject(revision, commitVerification, commitContentForTree(testCase.digest), commit, treeContent)
		if err != nil || verification.ComputedTreeDigest() != testCase.digest {
			t.Fatalf("VerifyGitTreeObject() = (%#v, %v)", verification, err)
		}
	}
}

func TestVerifyGitTreeObjectEnforcesPayloadBound(t *testing.T) {
	treeContent := make([]byte, 16<<20)
	treeDigest := gitObjectDigestForTest("tree", treeContent, RevisionAlgorithmSHA256)
	revision, commitVerification, commit := mustTreeCommitInputs(t, RevisionAlgorithmSHA256, treeDigest)
	verification, err := VerifyGitTreeObject(revision, commitVerification, commitContentForTree(treeDigest), commit, treeContent)
	if err != nil || verification.ContentSizeBytes() != len(treeContent) {
		t.Fatalf("VerifyGitTreeObject(max) = (%#v, %v)", verification, err)
	}
	tooLarge := make([]byte, (16<<20)+1)
	if verification, err := VerifyGitTreeObject(revision, commitVerification, commitContentForTree(treeDigest), commit, tooLarge); err == nil || verification.Identity() != "" {
		t.Fatalf("VerifyGitTreeObject(over max) = (%#v, %v)", verification, err)
	}
}

func TestGitTreeObjectVerificationDoesNotRetainContent(t *testing.T) {
	treeContent := []byte("hello\n")
	treeDigest := gitObjectDigestForTest("tree", treeContent, RevisionAlgorithmSHA1)
	commitContent := commitContentForTree(treeDigest)
	revision, commitVerification, commit := mustTreeCommitInputs(t, RevisionAlgorithmSHA1, treeDigest)
	verification, err := VerifyGitTreeObject(revision, commitVerification, commitContent, commit, treeContent)
	if err != nil {
		t.Fatalf("VerifyGitTreeObject() error = %v", err)
	}
	identity := verification.Identity()
	for i := range treeContent {
		treeContent[i] = 0
	}
	for i := range commitContent {
		commitContent[i] = 0
	}
	if verification.Identity() != identity || verification.ComputedTreeDigest() != treeDigest {
		t.Fatal("content mutation changed GitTreeObjectVerification")
	}
}

func TestGitTreeObjectVerificationZeroValueIsEmpty(t *testing.T) {
	var verification GitTreeObjectVerification
	if verification.Identity() != "" || verification.GitCommitIdentity() != "" || verification.RevisionIdentity() != "" || verification.TreeAlgorithm() != "" || verification.DeclaredTreeDigest() != "" || verification.ComputedTreeDigest() != "" || verification.ContentSizeBytes() != 0 || verification.ObjectType() != "" || verification.FramingVersion() != "" {
		t.Fatalf("zero GitTreeObjectVerification = %#v", verification)
	}
}

func mustTreeCommitInputs(t *testing.T, algorithm RevisionAlgorithm, treeDigest string) (RevisionIdentity, GitCommitObjectVerification, GitCommit) {
	t.Helper()
	content := commitContentForTree(treeDigest)
	return mustGitCommitInputs(t, algorithm, content)
}

func commitContentForTree(treeDigest string) []byte {
	return []byte("tree " + treeDigest + "\nauthor A\ncommitter C\n\n")
}
