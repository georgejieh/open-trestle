package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func TestNewRevisionIdentityAcceptsFullGitCommitDigests(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm RevisionAlgorithm
		digest    string
	}{
		{name: "SHA-1", algorithm: RevisionAlgorithmSHA1, digest: "0123456789abcdef0123456789abcdef01234567"},
		{name: "SHA-256", algorithm: RevisionAlgorithmSHA256, digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			revision, err := NewRevisionIdentity(RevisionKindGitCommit, testCase.algorithm, testCase.digest)
			if err != nil {
				t.Fatalf("NewRevisionIdentity() error = %v", err)
			}
			if len(revision.Identity()) != 64 || revision.Kind() != RevisionKindGitCommit || revision.Algorithm() != testCase.algorithm || revision.Digest() != testCase.digest {
				t.Fatalf("revision = (%q, %q, %q, %q)", revision.Identity(), revision.Kind(), revision.Algorithm(), revision.Digest())
			}
			repeated, err := NewRevisionIdentity(RevisionKindGitCommit, testCase.algorithm, testCase.digest)
			if err != nil || repeated != revision {
				t.Fatalf("repeated = (%#v, %v), want %#v", repeated, err, revision)
			}
		})
	}
}

func TestRevisionIdentityUsesCanonicalPreimage(t *testing.T) {
	testCases := []struct {
		name      string
		algorithm RevisionAlgorithm
		digest    string
	}{
		{name: "SHA-1", algorithm: RevisionAlgorithmSHA1, digest: "0123456789abcdef0123456789abcdef01234567"},
		{name: "SHA-256", algorithm: RevisionAlgorithmSHA256, digest: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			revision, err := NewRevisionIdentity(RevisionKindGitCommit, testCase.algorithm, testCase.digest)
			if err != nil {
				t.Fatalf("NewRevisionIdentity() error = %v", err)
			}
			preimage := fmt.Sprintf(`{"contract":"open-trestle/revision-identity","schema_version":1,"kind":"git_commit","algorithm":"%s","digest":"%s"}`, testCase.algorithm, testCase.digest)
			digest := sha256.Sum256([]byte(preimage))
			if want := hex.EncodeToString(digest[:]); revision.Identity() != want {
				t.Fatalf("Identity() = %q, want SHA-256 of %s", revision.Identity(), preimage)
			}
		})
	}
}

func TestRevisionIdentityChangesWithDigestAndAlgorithm(t *testing.T) {
	first, err := NewRevisionIdentity(RevisionKindGitCommit, RevisionAlgorithmSHA1, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("NewRevisionIdentity(first) error = %v", err)
	}
	changed, err := NewRevisionIdentity(RevisionKindGitCommit, RevisionAlgorithmSHA1, "baaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("NewRevisionIdentity(changed) error = %v", err)
	}
	longer, err := NewRevisionIdentity(RevisionKindGitCommit, RevisionAlgorithmSHA256, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("NewRevisionIdentity(longer) error = %v", err)
	}
	if first.Identity() == changed.Identity() || first.Identity() == longer.Identity() || first.Digest() == longer.Digest() {
		t.Fatalf("revision identities = (%q, %q, %q)", first.Identity(), changed.Identity(), longer.Identity())
	}
}

func TestNewRevisionIdentityRejectsInvalidDigest(t *testing.T) {
	validSHA1 := "0123456789abcdef0123456789abcdef01234567"
	testCases := []struct {
		name      string
		algorithm RevisionAlgorithm
		digest    string
	}{
		{name: "empty", algorithm: RevisionAlgorithmSHA1},
		{name: "abbreviated", algorithm: RevisionAlgorithmSHA1, digest: validSHA1[:12]},
		{name: "short", algorithm: RevisionAlgorithmSHA1, digest: validSHA1[:39]},
		{name: "long", algorithm: RevisionAlgorithmSHA1, digest: validSHA1 + "0"},
		{name: "uppercase", algorithm: RevisionAlgorithmSHA1, digest: "A" + validSHA1[1:]},
		{name: "non-hex", algorithm: RevisionAlgorithmSHA1, digest: "g" + validSHA1[1:]},
		{name: "leading whitespace", algorithm: RevisionAlgorithmSHA1, digest: " " + validSHA1[:39]},
		{name: "trailing whitespace", algorithm: RevisionAlgorithmSHA1, digest: validSHA1[:39] + " "},
		{name: "internal whitespace", algorithm: RevisionAlgorithmSHA1, digest: validSHA1[:20] + " " + validSHA1[21:]},
		{name: "prefixed", algorithm: RevisionAlgorithmSHA1, digest: "sha1:" + validSHA1},
		{name: "separated", algorithm: RevisionAlgorithmSHA1, digest: validSHA1[:20] + "-" + validSHA1[21:]},
		{name: "all-zero SHA-1", algorithm: RevisionAlgorithmSHA1, digest: strings.Repeat("0", 40)},
		{name: "all-zero SHA-256", algorithm: RevisionAlgorithmSHA256, digest: strings.Repeat("0", 64)},
		{name: "SHA-1 digest with SHA-256 algorithm", algorithm: RevisionAlgorithmSHA256, digest: validSHA1},
		{name: "SHA-256 digest with SHA-1 algorithm", algorithm: RevisionAlgorithmSHA1, digest: strings.Repeat("a", 64)},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			revision, err := NewRevisionIdentity(RevisionKindGitCommit, testCase.algorithm, testCase.digest)
			if err == nil || revision.Identity() != "" {
				t.Fatalf("NewRevisionIdentity() = (%#v, %v), want zero error result", revision, err)
			}
		})
	}
}

func TestNewRevisionIdentityRejectsUnknownKindAndAlgorithm(t *testing.T) {
	validSHA1 := "0123456789abcdef0123456789abcdef01234567"
	testCases := []struct {
		name      string
		kind      RevisionKind
		algorithm RevisionAlgorithm
	}{
		{name: "empty kind", algorithm: RevisionAlgorithmSHA1},
		{name: "unknown kind", kind: RevisionKind("git_tag"), algorithm: RevisionAlgorithmSHA1},
		{name: "empty algorithm", kind: RevisionKindGitCommit},
		{name: "uppercase alias", kind: RevisionKindGitCommit, algorithm: RevisionAlgorithm("SHA1")},
		{name: "hyphenated alias", kind: RevisionKindGitCommit, algorithm: RevisionAlgorithm("sha-1")},
		{name: "prefixed alias", kind: RevisionKindGitCommit, algorithm: RevisionAlgorithm("git-sha1")},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			revision, err := NewRevisionIdentity(testCase.kind, testCase.algorithm, validSHA1)
			if err == nil || revision.Identity() != "" {
				t.Fatalf("NewRevisionIdentity() = (%#v, %v), want zero error result", revision, err)
			}
		})
	}
}
