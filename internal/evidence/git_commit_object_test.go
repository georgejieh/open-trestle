package evidence

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"testing"
)

func TestVerifyGitCommitObjectKnownVectors(t *testing.T) {
	content := []byte("hello\n")
	testCases := []struct {
		name      string
		algorithm RevisionAlgorithm
		digest    string
	}{
		{name: "SHA-1", algorithm: RevisionAlgorithmSHA1, digest: "656d88de433ec9f9c5d4ed9b2c643844127a0fb4"},
		{name: "SHA-256", algorithm: RevisionAlgorithmSHA256, digest: "0dc599b3b0ab7db2ef28ab7bcd9a37ac991827a78d0d53a1ae438f3731f374d7"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			revision := mustGitCommitRevision(t, testCase.algorithm, testCase.digest)
			verification, err := VerifyGitCommitObject(revision, content)
			if err != nil {
				t.Fatalf("VerifyGitCommitObject() error = %v", err)
			}
			if len(verification.Identity()) != 64 || verification.RevisionIdentity() != revision.Identity() || verification.Algorithm() != testCase.algorithm || verification.ObjectType() != "commit" || verification.ComputedDigest() != testCase.digest || verification.ContentSizeBytes() != len(content) || verification.FramingVersion() != "git-object-v1" {
				t.Fatalf("verification = %#v", verification)
			}
			repeated, err := VerifyGitCommitObject(revision, content)
			if err != nil || repeated != verification {
				t.Fatalf("repeated = (%#v, %v), want %#v", repeated, err, verification)
			}
		})
	}
}

func TestVerifyGitCommitObjectEmptyPayloadVectors(t *testing.T) {
	testCases := []struct {
		algorithm RevisionAlgorithm
		digest    string
	}{
		{algorithm: RevisionAlgorithmSHA1, digest: "dcf5b16e76cce7425d0beaef62d79a7d10fce1f5"},
		{algorithm: RevisionAlgorithmSHA256, digest: "9f2a7f3b00f22334f6adc2721fb1f89cd969f02264d37cf6a2c32ba09beb6822"},
	}
	for _, testCase := range testCases {
		verification, err := VerifyGitCommitObject(mustGitCommitRevision(t, testCase.algorithm, testCase.digest), nil)
		if err != nil || verification.ComputedDigest() != testCase.digest || verification.ContentSizeBytes() != 0 {
			t.Fatalf("VerifyGitCommitObject() = (%#v, %v)", verification, err)
		}
	}
}

func TestGitCommitObjectVerificationUsesCanonicalPreimage(t *testing.T) {
	revision := mustGitCommitRevision(t, RevisionAlgorithmSHA1, "656d88de433ec9f9c5d4ed9b2c643844127a0fb4")
	verification, err := VerifyGitCommitObject(revision, []byte("hello\n"))
	if err != nil {
		t.Fatalf("VerifyGitCommitObject() error = %v", err)
	}
	preimage := fmt.Sprintf(`{"contract":"open-trestle/git-commit-object-verification","schema_version":1,"revision_identity":"%s","object_type":"commit","algorithm":"sha1","computed_digest":"656d88de433ec9f9c5d4ed9b2c643844127a0fb4","content_size_bytes":6,"framing_version":"git-object-v1"}`, revision.Identity())
	digest := sha256.Sum256([]byte(preimage))
	if want := hex.EncodeToString(digest[:]); verification.Identity() != want {
		t.Fatalf("Identity() = %q, want SHA-256 of %s", verification.Identity(), preimage)
	}
}

func TestVerifyGitCommitObjectRejectsPayloadMismatch(t *testing.T) {
	revision := mustGitCommitRevision(t, RevisionAlgorithmSHA1, "656d88de433ec9f9c5d4ed9b2c643844127a0fb4")
	testCases := [][]byte{
		[]byte("Hello\n"),
		[]byte("hello"),
		[]byte("commit 6\x00hello\n"),
		[]byte{0x78, 0x9c, 0x01, 0x02},
	}
	for _, content := range testCases {
		verification, err := VerifyGitCommitObject(revision, content)
		if err == nil || verification.Identity() != "" {
			t.Fatalf("VerifyGitCommitObject(%q) = (%#v, %v), want zero error result", content, verification, err)
		}
	}
}

func TestVerifyGitCommitObjectUsesCommitFramingOnly(t *testing.T) {
	content := []byte("hello\n")
	for _, objectType := range []string{"blob", "tree", "tag"} {
		digest := gitObjectDigestForTest(objectType, content, RevisionAlgorithmSHA1)
		revision := mustGitCommitRevision(t, RevisionAlgorithmSHA1, digest)
		verification, err := VerifyGitCommitObject(revision, content)
		if err == nil || verification.Identity() != "" {
			t.Fatalf("VerifyGitCommitObject(%s digest) = (%#v, %v), want zero error result", objectType, verification, err)
		}
	}
}

func TestVerifyGitCommitObjectAcceptsArbitraryPayloadBytes(t *testing.T) {
	content := []byte{0, '\r', '\n', 0xff, 0xfe, 'A'}
	testCases := []struct {
		algorithm RevisionAlgorithm
		digest    string
	}{
		{algorithm: RevisionAlgorithmSHA1, digest: "5520e01a6c35a02e7393b77c5531ec54525a8621"},
		{algorithm: RevisionAlgorithmSHA256, digest: "b837a4ae50acdf64754c9db1babaace34b43cfc67952de0152132c49003ba2d9"},
	}
	for _, testCase := range testCases {
		verification, err := VerifyGitCommitObject(mustGitCommitRevision(t, testCase.algorithm, testCase.digest), content)
		if err != nil || verification.ComputedDigest() != testCase.digest {
			t.Fatalf("VerifyGitCommitObject() = (%#v, %v)", verification, err)
		}
	}
}

func TestVerifyGitCommitObjectRejectsForgedRevision(t *testing.T) {
	valid := mustGitCommitRevision(t, RevisionAlgorithmSHA1, "656d88de433ec9f9c5d4ed9b2c643844127a0fb4")
	forgeries := []RevisionIdentity{}
	forged := valid
	forged.identity = strings.Repeat("0", 64)
	forgeries = append(forgeries, forged)
	forged = valid
	forged.kind = RevisionKind("git_tag")
	forgeries = append(forgeries, forged)
	forged = valid
	forged.algorithm = RevisionAlgorithmSHA256
	forgeries = append(forgeries, forged)
	forged = valid
	forged.digest = strings.ToUpper(forged.digest)
	forgeries = append(forgeries, forged)
	forged = valid
	forged.digest = forged.digest[:12]
	forgeries = append(forgeries, forged)
	forged = valid
	forged.digest = "g" + forged.digest[1:]
	forgeries = append(forgeries, forged)
	forged = valid
	forged.digest = strings.Repeat("0", 40)
	forgeries = append(forgeries, forged)
	for _, revision := range forgeries {
		verification, err := VerifyGitCommitObject(revision, []byte("hello\n"))
		if err == nil || verification.Identity() != "" {
			t.Fatalf("VerifyGitCommitObject() = (%#v, %v), want zero error result", verification, err)
		}
	}
	if verification, err := VerifyGitCommitObject(RevisionIdentity{}, []byte("hello\n")); err == nil || verification.Identity() != "" {
		t.Fatalf("VerifyGitCommitObject(zero) = (%#v, %v)", verification, err)
	}
}

func TestVerifyGitCommitObjectEnforcesPayloadBound(t *testing.T) {
	content := make([]byte, 4<<20)
	digest := gitObjectDigestForTest("commit", content, RevisionAlgorithmSHA256)
	verification, err := VerifyGitCommitObject(mustGitCommitRevision(t, RevisionAlgorithmSHA256, digest), content)
	if err != nil || verification.ContentSizeBytes() != len(content) {
		t.Fatalf("VerifyGitCommitObject(max) = (%#v, %v)", verification, err)
	}
	tooLarge := make([]byte, (4<<20)+1)
	verification, err = VerifyGitCommitObject(mustGitCommitRevision(t, RevisionAlgorithmSHA256, digest), tooLarge)
	if err == nil || verification.Identity() != "" {
		t.Fatalf("VerifyGitCommitObject(over max) = (%#v, %v), want zero error result", verification, err)
	}
}

func TestGitCommitObjectVerificationDoesNotRetainContent(t *testing.T) {
	content := []byte("hello\n")
	revision := mustGitCommitRevision(t, RevisionAlgorithmSHA1, "656d88de433ec9f9c5d4ed9b2c643844127a0fb4")
	verification, err := VerifyGitCommitObject(revision, content)
	if err != nil {
		t.Fatalf("VerifyGitCommitObject() error = %v", err)
	}
	identity := verification.Identity()
	for i := range content {
		content[i] = 0
	}
	if verification.Identity() != identity || verification.ComputedDigest() != revision.Digest() {
		t.Fatal("content mutation changed GitCommitObjectVerification")
	}
}

func TestGitCommitObjectVerificationZeroValueIsEmpty(t *testing.T) {
	var verification GitCommitObjectVerification
	if verification.Identity() != "" || verification.RevisionIdentity() != "" || verification.Algorithm() != "" || verification.ObjectType() != "" || verification.ComputedDigest() != "" || verification.ContentSizeBytes() != 0 || verification.FramingVersion() != "" {
		t.Fatalf("zero GitCommitObjectVerification = %#v", verification)
	}
}

func mustGitCommitRevision(t *testing.T, algorithm RevisionAlgorithm, digest string) RevisionIdentity {
	t.Helper()
	revision, err := NewRevisionIdentity(RevisionKindGitCommit, algorithm, digest)
	if err != nil {
		t.Fatalf("NewRevisionIdentity() error = %v", err)
	}
	return revision
}

func gitObjectDigestForTest(objectType string, content []byte, algorithm RevisionAlgorithm) string {
	var digest hash.Hash
	if algorithm == RevisionAlgorithmSHA1 {
		digest = sha1.New()
	} else {
		digest = sha256.New()
	}
	digest.Write([]byte(objectType))
	digest.Write([]byte(" "))
	digest.Write([]byte(strconv.Itoa(len(content))))
	digest.Write([]byte{0})
	digest.Write(content)
	return hex.EncodeToString(digest.Sum(nil))
}
