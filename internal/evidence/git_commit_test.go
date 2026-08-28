package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestParseVerifiedGitCommitMinimalSHA1(t *testing.T) {
	content := []byte("tree 1111111111111111111111111111111111111111\nauthor A\ncommitter C\n\n")
	commit := mustParseGitCommit(t, RevisionAlgorithmSHA1, content)
	if len(commit.Identity()) != 64 || commit.TreeAlgorithm() != RevisionAlgorithmSHA1 || commit.TreeDigest() != strings.Repeat("1", 40) || len(commit.Parents()) != 0 || commit.Encoding() != "" || commit.HeaderCount() != 3 || commit.MessageSizeBytes() != 0 || commit.MessageDigest() != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("commit = %#v", commit)
	}
}

func TestParseVerifiedGitCommitSHA256TreeAndParents(t *testing.T) {
	tree := strings.Repeat("a", 64)
	parent := strings.Repeat("b", 64)
	content := []byte("tree " + tree + "\nparent " + parent + "\nauthor A\ncommitter C\n\nhello\n")
	commit := mustParseGitCommit(t, RevisionAlgorithmSHA256, content)
	parents := commit.Parents()
	if commit.TreeAlgorithm() != RevisionAlgorithmSHA256 || commit.TreeDigest() != tree || len(parents) != 1 || parents[0].Algorithm() != RevisionAlgorithmSHA256 || parents[0].Digest() != parent || commit.MessageSizeBytes() != 6 || commit.MessageDigest() != "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" {
		t.Fatalf("commit = %#v, parents = %#v", commit, parents)
	}
	mixed := []byte("tree " + strings.Repeat("a", 40) + "\nauthor A\ncommitter C\n\n")
	assertGitCommitParseError(t, RevisionAlgorithmSHA256, mixed)
}

func TestGitCommitUsesCanonicalPreimage(t *testing.T) {
	parentDigest := strings.Repeat("2", 40)
	content := []byte("tree " + strings.Repeat("1", 40) + "\nparent " + parentDigest + "\nauthor A\ncommitter C\n\nhello\n")
	revision, verification, commit := mustGitCommitInputs(t, RevisionAlgorithmSHA1, content)
	parent := commit.Parents()[0]
	preimage := fmt.Sprintf(`{"contract":"open-trestle/git-commit","schema_version":1,"revision_identity":"%s","object_verification_identity":"%s","tree_algorithm":"sha1","tree_digest":"%s","parent_revision_identities":["%s"],"encoding":"","header_count":4,"message_size_bytes":6,"message_digest":"5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"}`, revision.Identity(), verification.Identity(), strings.Repeat("1", 40), parent.Identity())
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); commit.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", commit.Identity(), preimage)
	}
}

func TestGitCommitIdentityChangesWithParsedStructure(t *testing.T) {
	tree := strings.Repeat("1", 40)
	otherTree := strings.Repeat("3", 40)
	firstParent := strings.Repeat("4", 40)
	secondParent := strings.Repeat("5", 40)
	baseHeaders := "tree " + tree + "\nparent " + firstParent + "\nparent " + secondParent + "\nauthor A\ncommitter C\n"
	contents := [][]byte{
		[]byte(baseHeaders + "\nmessage"),
		[]byte("tree " + otherTree + "\nparent " + firstParent + "\nparent " + secondParent + "\nauthor A\ncommitter C\n\nmessage"),
		[]byte("tree " + tree + "\nparent " + secondParent + "\nparent " + firstParent + "\nauthor A\ncommitter C\n\nmessage"),
		[]byte(baseHeaders + "encoding UTF-8\n\nmessage"),
		[]byte(baseHeaders + "\nMessage"),
	}
	identities := make(map[string]struct{}, len(contents))
	for _, content := range contents {
		commit := mustParseGitCommit(t, RevisionAlgorithmSHA1, content)
		identities[commit.Identity()] = struct{}{}
	}
	if len(identities) != len(contents) {
		t.Fatalf("%d commit variants produced %d identities", len(contents), len(identities))
	}
}

func TestParseVerifiedGitCommitRebindsExactContent(t *testing.T) {
	content := []byte("tree 1111111111111111111111111111111111111111\nauthor A\ncommitter C\n\n")
	revision, verification, _ := mustGitCommitInputs(t, RevisionAlgorithmSHA1, content)
	mutated := append([]byte{}, content...)
	mutated[len(mutated)-2] = 'X'
	if commit, err := ParseVerifiedGitCommit(revision, verification, mutated); err == nil || commit.Identity() != "" {
		t.Fatalf("ParseVerifiedGitCommit(mutated) = (%#v, %v), want zero error result", commit, err)
	}
	forged := verification
	forged.identity = strings.Repeat("0", 64)
	if commit, err := ParseVerifiedGitCommit(revision, forged, content); err == nil || commit.Identity() != "" {
		t.Fatalf("ParseVerifiedGitCommit(forged) = (%#v, %v), want zero error result", commit, err)
	}
	forged = verification
	forged.contentSizeBytes++
	if commit, err := ParseVerifiedGitCommit(revision, forged, content); err == nil || commit.Identity() != "" {
		t.Fatalf("ParseVerifiedGitCommit(stale) = (%#v, %v), want zero error result", commit, err)
	}
}

func TestParseVerifiedGitCommitEnforcesRequiredOrder(t *testing.T) {
	tree := strings.Repeat("1", 40)
	parent := strings.Repeat("2", 40)
	testCases := map[string]string{
		"missing tree":           "author A\ncommitter C\n\n",
		"tree not first":         "x y\ntree " + tree + "\nauthor A\ncommitter C\n\n",
		"duplicate tree":         "tree " + tree + "\ntree " + tree + "\nauthor A\ncommitter C\n\n",
		"missing author":         "tree " + tree + "\ncommitter C\n\n",
		"duplicate author":       "tree " + tree + "\nauthor A\nauthor B\ncommitter C\n\n",
		"missing committer":      "tree " + tree + "\nauthor A\n\n",
		"committer first":        "tree " + tree + "\ncommitter C\nauthor A\n\n",
		"duplicate committer":    "tree " + tree + "\nauthor A\ncommitter C\ncommitter D\n\n",
		"parent after author":    "tree " + tree + "\nauthor A\nparent " + parent + "\ncommitter C\n\n",
		"optional before author": "tree " + tree + "\nx y\nauthor A\ncommitter C\n\n",
		"missing separator":      "tree " + tree + "\nauthor A\ncommitter C\n",
	}
	for name, content := range testCases {
		t.Run(name, func(t *testing.T) {
			assertGitCommitParseError(t, RevisionAlgorithmSHA1, []byte(content))
		})
	}
}

func TestParseVerifiedGitCommitValidatesTreeAndParents(t *testing.T) {
	tree := strings.Repeat("1", 40)
	valid := "tree " + tree + "\nauthor A\ncommitter C\n\n"
	invalidTrees := []string{"", strings.Repeat("0", 40), strings.Repeat("a", 39), strings.Repeat("a", 41), strings.Repeat("A", 40), "g" + strings.Repeat("a", 39), "sha1:" + strings.Repeat("a", 40)}
	for _, invalid := range invalidTrees {
		assertGitCommitParseError(t, RevisionAlgorithmSHA1, []byte("tree "+invalid+"\nauthor A\ncommitter C\n\n"))
	}
	invalidParents := []string{strings.Repeat("0", 40), strings.Repeat("a", 12), strings.Repeat("A", 40), "g" + strings.Repeat("a", 39)}
	for _, invalid := range invalidParents {
		assertGitCommitParseError(t, RevisionAlgorithmSHA1, []byte("tree "+tree+"\nparent "+invalid+"\nauthor A\ncommitter C\n\n"))
	}
	duplicate := "tree " + tree + "\nparent " + strings.Repeat("2", 40) + "\nparent " + strings.Repeat("2", 40) + "\nauthor A\ncommitter C\n\n"
	assertGitCommitParseError(t, RevisionAlgorithmSHA1, []byte(duplicate))
	if commit := mustParseGitCommit(t, RevisionAlgorithmSHA1, []byte(valid)); commit.TreeDigest() != tree {
		t.Fatalf("TreeDigest() = %q", commit.TreeDigest())
	}
}

func TestParseVerifiedGitCommitEnforcesParentBound(t *testing.T) {
	build := func(count int) []byte {
		var content strings.Builder
		content.WriteString("tree " + strings.Repeat("1", 40) + "\n")
		for i := 1; i <= count; i++ {
			content.WriteString(fmt.Sprintf("parent %040x\n", i))
		}
		content.WriteString("author A\ncommitter C\n\n")
		return []byte(content.String())
	}
	commit := mustParseGitCommit(t, RevisionAlgorithmSHA1, build(1024))
	if len(commit.Parents()) != 1024 {
		t.Fatalf("len(Parents()) = %d, want 1024", len(commit.Parents()))
	}
	assertGitCommitParseError(t, RevisionAlgorithmSHA1, build(1025))
}

func TestParseVerifiedGitCommitValidatesHeaderGrammar(t *testing.T) {
	tree := strings.Repeat("1", 40)
	testCases := []string{
		"Tree " + tree + "\nauthor A\ncommitter C\n\n",
		"tree\nauthor A\ncommitter C\n\n",
		"tree \nauthor A\ncommitter C\n\n",
		"tree " + tree + "\nauthor\ncommitter C\n\n",
		"tree " + tree + "\nauthor A\ncommitter \n\n",
		"tree " + tree + "\nauthor A\ncommitter C\n-bad value\n\n",
		"tree " + tree + "\nauthor A\ncommitter C\nbad--key value\n\n",
		"tree " + tree + "\nauthor A\ncommitter C\nbad- value\n\n",
		"tree " + tree + "\nauthor A\ncommitter C\n" + strings.Repeat("a", 65) + " value\n\n",
		"tree " + tree + "\nauthor A\r\ncommitter C\n\n",
		"tree " + tree + "\nauthor A\x00B\ncommitter C\n\n",
		"tree " + tree + "\nauthor A\ncommitter C\n\tbad\n\n",
	}
	for _, content := range testCases {
		assertGitCommitParseError(t, RevisionAlgorithmSHA1, []byte(content))
	}
}

func TestParseVerifiedGitCommitHandlesOpaqueContinuations(t *testing.T) {
	tree := strings.Repeat("1", 40)
	for _, key := range []string{"gpgsig", "gpgsig-sha256", "mergetag", "x-extension"} {
		content := []byte("tree " + tree + "\nauthor A\ncommitter C\n" + key + " value\n \n  data\n   data\n\n")
		commit := mustParseGitCommit(t, RevisionAlgorithmSHA1, content)
		if commit.HeaderCount() != 7 {
			t.Fatalf("HeaderCount(%s) = %d, want 7", key, commit.HeaderCount())
		}
	}
	invalid := []string{
		" tree continuation\ntree " + tree + "\nauthor A\ncommitter C\n\n",
		"tree " + tree + "\n continuation\nauthor A\ncommitter C\n\n",
		"tree " + tree + "\nparent " + strings.Repeat("2", 40) + "\n continuation\nauthor A\ncommitter C\n\n",
		"tree " + tree + "\nauthor A\n continuation\ncommitter C\n\n",
		"tree " + tree + "\nauthor A\ncommitter C\n continuation\n\n",
		"tree " + tree + "\nauthor A\ncommitter C\nencoding UTF-8\n continuation\n\n",
		"tree " + tree + "\nauthor A\ncommitter C\nx value\n \r\n\n",
		"tree " + tree + "\nauthor A\ncommitter C\nx value\n \x00\n\n",
	}
	for _, content := range invalid {
		assertGitCommitParseError(t, RevisionAlgorithmSHA1, []byte(content))
	}
}

func TestParseVerifiedGitCommitValidatesEncoding(t *testing.T) {
	tree := strings.Repeat("1", 40)
	valid := []string{"UTF-8", "ISO-8859-1", strings.Repeat("a", 128)}
	for _, encoding := range valid {
		content := []byte("tree " + tree + "\nauthor A\ncommitter C\nencoding " + encoding + "\n\n")
		if got := mustParseGitCommit(t, RevisionAlgorithmSHA1, content).Encoding(); got != encoding {
			t.Fatalf("Encoding() = %q, want %q", got, encoding)
		}
	}
	invalid := []string{"", "UTF 8", strings.Repeat("a", 129), "UTF\t8", "UTF\x7f8"}
	for _, encoding := range invalid {
		assertGitCommitParseError(t, RevisionAlgorithmSHA1, []byte("tree "+tree+"\nauthor A\ncommitter C\nencoding "+encoding+"\n\n"))
	}
	assertGitCommitParseError(t, RevisionAlgorithmSHA1, []byte("tree "+tree+"\nauthor A\ncommitter C\nencoding UTF-8\nencoding UTF-8\n\n"))
}

func TestParseVerifiedGitCommitUsesFirstSeparator(t *testing.T) {
	tree := strings.Repeat("1", 40)
	messages := [][]byte{
		[]byte(" data\n"),
		[]byte("  data\n"),
		[]byte("\tdata\n"),
		[]byte("gpgsig looks-like-header\n"),
		[]byte{'x', 0, '\r', 0xff, '\n'},
		[]byte("\n\n"),
	}
	for _, message := range messages {
		content := append([]byte("tree "+tree+"\nauthor A\ncommitter C\n\n"), message...)
		commit := mustParseGitCommit(t, RevisionAlgorithmSHA1, content)
		digest := sha256.Sum256(message)
		if commit.HeaderCount() != 3 || commit.MessageSizeBytes() != len(message) || commit.MessageDigest() != hex.EncodeToString(digest[:]) {
			t.Fatalf("message %q -> %#v", message, commit)
		}
	}
}

func TestParseVerifiedGitCommitEnforcesLineAndHeaderBounds(t *testing.T) {
	tree := strings.Repeat("1", 40)
	prefix := "tree " + tree + "\nauthor A\ncommitter C\n"
	topPass := []byte(prefix + "x " + strings.Repeat("v", (64<<10)-2) + "\n\n")
	mustParseGitCommit(t, RevisionAlgorithmSHA1, topPass)
	topFail := []byte(prefix + "x " + strings.Repeat("v", (64<<10)-1) + "\n\n")
	assertGitCommitParseError(t, RevisionAlgorithmSHA1, topFail)
	continuationPass := []byte(prefix + "x v\n " + strings.Repeat("v", (64<<10)-1) + "\n\n")
	mustParseGitCommit(t, RevisionAlgorithmSHA1, continuationPass)
	continuationFail := []byte(prefix + "x v\n " + strings.Repeat("v", 64<<10) + "\n\n")
	assertGitCommitParseError(t, RevisionAlgorithmSHA1, continuationFail)
	var headers strings.Builder
	headers.WriteString(prefix)
	for i := 3; i < 4096; i++ {
		headers.WriteString("x v\n")
	}
	headers.WriteString("\n")
	if commit := mustParseGitCommit(t, RevisionAlgorithmSHA1, []byte(headers.String())); commit.HeaderCount() != 4096 {
		t.Fatalf("HeaderCount() = %d", commit.HeaderCount())
	}
	overHeaders := strings.TrimSuffix(headers.String(), "\n") + "x v\n\n"
	assertGitCommitParseError(t, RevisionAlgorithmSHA1, []byte(overHeaders))
}

func TestGitCommitIsImmutableAndDoesNotRetainContent(t *testing.T) {
	content := []byte("tree " + strings.Repeat("1", 40) + "\nparent " + strings.Repeat("2", 40) + "\nauthor A\ncommitter C\n\nhello\n")
	commit := mustParseGitCommit(t, RevisionAlgorithmSHA1, content)
	identity := commit.Identity()
	parents := commit.Parents()
	parents[0] = RevisionIdentity{}
	for i := range content {
		content[i] = 0
	}
	if commit.Identity() != identity || commit.Parents()[0].Identity() == "" || commit.MessageDigest() != "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03" {
		t.Fatal("caller mutation changed GitCommit")
	}
}

func TestGitCommitZeroValueIsEmpty(t *testing.T) {
	var commit GitCommit
	if commit.Identity() != "" || commit.RevisionIdentity() != "" || commit.ObjectVerificationIdentity() != "" || commit.TreeAlgorithm() != "" || commit.TreeDigest() != "" || len(commit.Parents()) != 0 || commit.Encoding() != "" || commit.HeaderCount() != 0 || commit.MessageSizeBytes() != 0 || commit.MessageDigest() != "" {
		t.Fatalf("zero GitCommit = %#v", commit)
	}
}

func mustParseGitCommit(t *testing.T, algorithm RevisionAlgorithm, content []byte) GitCommit {
	t.Helper()
	_, _, commit := mustGitCommitInputs(t, algorithm, content)
	return commit
}

func mustGitCommitInputs(t *testing.T, algorithm RevisionAlgorithm, content []byte) (RevisionIdentity, GitCommitObjectVerification, GitCommit) {
	t.Helper()
	digest := gitObjectDigestForTest("commit", content, algorithm)
	revision := mustGitCommitRevision(t, algorithm, digest)
	verification, err := VerifyGitCommitObject(revision, content)
	if err != nil {
		t.Fatalf("VerifyGitCommitObject() error = %v", err)
	}
	commit, err := ParseVerifiedGitCommit(revision, verification, content)
	if err != nil {
		t.Fatalf("ParseVerifiedGitCommit() error = %v", err)
	}
	return revision, verification, commit
}

func assertGitCommitParseError(t *testing.T, algorithm RevisionAlgorithm, content []byte) {
	t.Helper()
	digest := gitObjectDigestForTest("commit", content, algorithm)
	revision := mustGitCommitRevision(t, algorithm, digest)
	verification, err := VerifyGitCommitObject(revision, content)
	if err != nil {
		t.Fatalf("VerifyGitCommitObject() error = %v", err)
	}
	commit, err := ParseVerifiedGitCommit(revision, verification, content)
	if err == nil || commit.Identity() != "" {
		t.Fatalf("ParseVerifiedGitCommit() = (%#v, %v), want zero error result", commit, err)
	}
}
