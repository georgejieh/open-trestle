package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

const (
	maxGitCommitHeaderLineBytes = 64 << 10
	maxGitCommitHeaderLines     = 4096
	maxGitCommitParents         = 1024
	maxGitCommitHeaderKeyBytes  = 64
	maxGitCommitEncodingBytes   = 128
)

// GitCommit records bounded structure parsed from an identity-verified commit object.
type GitCommit struct {
	identity                   string
	revisionIdentity           string
	objectVerificationIdentity string
	treeAlgorithm              RevisionAlgorithm
	treeDigest                 string
	parents                    []RevisionIdentity
	encoding                   string
	headerCount                int
	messageSizeBytes           int
	messageDigest              string
}

type gitCommitParseStage uint8

const (
	gitCommitExpectTree gitCommitParseStage = iota
	gitCommitExpectParentsOrAuthor
	gitCommitExpectCommitter
	gitCommitExpectOptional
)

// ParseVerifiedGitCommit parses bounded structure from exact identity-verified payload bytes.
func ParseVerifiedGitCommit(revision RevisionIdentity, verification GitCommitObjectVerification, content []byte) (GitCommit, error) {
	canonicalRevision, err := NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || revision != canonicalRevision {
		return GitCommit{}, fmt.Errorf("revision identity is not canonical")
	}
	canonicalVerification, err := VerifyGitCommitObject(canonicalRevision, content)
	if err != nil || verification != canonicalVerification {
		return GitCommit{}, fmt.Errorf("git commit object verification does not match content")
	}
	stage := gitCommitExpectTree
	position := 0
	headerCount := 0
	separatorFound := false
	previousHeader := false
	continuationAllowed := false
	treeDigest := ""
	parents := make([]RevisionIdentity, 0)
	parentDigests := make(map[string]struct{})
	encoding := ""
	for position < len(content) {
		lineEnd := bytes.IndexByte(content[position:], '\n')
		if lineEnd < 0 {
			return GitCommit{}, fmt.Errorf("git commit header region is missing a terminating LF")
		}
		line := content[position : position+lineEnd]
		position += lineEnd + 1
		if len(line) == 0 {
			separatorFound = true
			break
		}
		if len(line) > maxGitCommitHeaderLineBytes {
			return GitCommit{}, fmt.Errorf("git commit header line has %d bytes, want at most %d", len(line), maxGitCommitHeaderLineBytes)
		}
		headerCount++
		if headerCount > maxGitCommitHeaderLines {
			return GitCommit{}, fmt.Errorf("git commit has more than %d header lines", maxGitCommitHeaderLines)
		}
		if bytes.IndexByte(line, 0) >= 0 || bytes.IndexByte(line, '\r') >= 0 {
			return GitCommit{}, fmt.Errorf("git commit header line contains a forbidden byte")
		}
		if line[0] == ' ' {
			if !previousHeader || !continuationAllowed {
				return GitCommit{}, fmt.Errorf("git commit header continuation is not allowed")
			}
			continue
		}
		separator := bytes.IndexByte(line, ' ')
		if separator <= 0 || separator == len(line)-1 {
			return GitCommit{}, fmt.Errorf("git commit top-level header must contain a key and value")
		}
		key := line[:separator]
		value := line[separator+1:]
		if err := validateGitCommitHeaderKey(key); err != nil {
			return GitCommit{}, err
		}
		previousHeader = true
		continuationAllowed = false
		switch stage {
		case gitCommitExpectTree:
			if string(key) != "tree" {
				return GitCommit{}, fmt.Errorf("git commit first header must be tree")
			}
			if err := validateGitObjectDigest(value, canonicalRevision.Algorithm()); err != nil {
				return GitCommit{}, fmt.Errorf("git commit tree: %w", err)
			}
			treeDigest = string(value)
			stage = gitCommitExpectParentsOrAuthor
		case gitCommitExpectParentsOrAuthor:
			switch string(key) {
			case "parent":
				if len(parents) >= maxGitCommitParents {
					return GitCommit{}, fmt.Errorf("git commit has more than %d parents", maxGitCommitParents)
				}
				if err := validateGitObjectDigest(value, canonicalRevision.Algorithm()); err != nil {
					return GitCommit{}, fmt.Errorf("git commit parent: %w", err)
				}
				parentDigest := string(value)
				if _, exists := parentDigests[parentDigest]; exists {
					return GitCommit{}, fmt.Errorf("git commit contains duplicate parent %q", parentDigest)
				}
				parent, err := NewRevisionIdentity(RevisionKindGitCommit, canonicalRevision.Algorithm(), parentDigest)
				if err != nil {
					return GitCommit{}, fmt.Errorf("construct git commit parent: %w", err)
				}
				parentDigests[parentDigest] = struct{}{}
				parents = append(parents, parent)
			case "author":
				stage = gitCommitExpectCommitter
			default:
				return GitCommit{}, fmt.Errorf("git commit requires contiguous parent headers followed by author")
			}
		case gitCommitExpectCommitter:
			if string(key) != "committer" {
				return GitCommit{}, fmt.Errorf("git commit author must be followed by committer")
			}
			stage = gitCommitExpectOptional
		case gitCommitExpectOptional:
			switch string(key) {
			case "tree", "parent", "author", "committer":
				return GitCommit{}, fmt.Errorf("git commit required header %q is duplicated or out of order", key)
			case "encoding":
				if encoding != "" {
					return GitCommit{}, fmt.Errorf("git commit contains duplicate encoding header")
				}
				if err := validateGitCommitEncoding(value); err != nil {
					return GitCommit{}, err
				}
				encoding = string(value)
			default:
				continuationAllowed = true
			}
		}
	}
	if !separatorFound {
		return GitCommit{}, fmt.Errorf("git commit is missing the header and message separator")
	}
	if stage != gitCommitExpectOptional {
		return GitCommit{}, fmt.Errorf("git commit is missing required headers")
	}
	message := content[position:]
	messageHash := sha256.Sum256(message)
	messageDigest := hex.EncodeToString(messageHash[:])
	parentIdentities := make([]string, len(parents))
	for i, parent := range parents {
		parentIdentities[i] = parent.Identity()
	}
	preimage := struct {
		Contract                   string            `json:"contract"`
		SchemaVersion              int               `json:"schema_version"`
		RevisionIdentity           string            `json:"revision_identity"`
		ObjectVerificationIdentity string            `json:"object_verification_identity"`
		TreeAlgorithm              RevisionAlgorithm `json:"tree_algorithm"`
		TreeDigest                 string            `json:"tree_digest"`
		ParentRevisionIdentities   []string          `json:"parent_revision_identities"`
		Encoding                   string            `json:"encoding"`
		HeaderCount                int               `json:"header_count"`
		MessageSizeBytes           int               `json:"message_size_bytes"`
		MessageDigest              string            `json:"message_digest"`
	}{
		Contract:                   "open-trestle/git-commit",
		SchemaVersion:              1,
		RevisionIdentity:           canonicalRevision.Identity(),
		ObjectVerificationIdentity: canonicalVerification.Identity(),
		TreeAlgorithm:              canonicalRevision.Algorithm(),
		TreeDigest:                 treeDigest,
		ParentRevisionIdentities:   parentIdentities,
		Encoding:                   encoding,
		HeaderCount:                headerCount,
		MessageSizeBytes:           len(message),
		MessageDigest:              messageDigest,
	}
	encoded, err := json.Marshal(preimage)
	if err != nil {
		return GitCommit{}, fmt.Errorf("encode git commit identity: %w", err)
	}
	identityDigest := sha256.Sum256(encoded)
	return GitCommit{
		identity:                   hex.EncodeToString(identityDigest[:]),
		revisionIdentity:           canonicalRevision.Identity(),
		objectVerificationIdentity: canonicalVerification.Identity(),
		treeAlgorithm:              canonicalRevision.Algorithm(),
		treeDigest:                 treeDigest,
		parents:                    append([]RevisionIdentity{}, parents...),
		encoding:                   encoding,
		headerCount:                headerCount,
		messageSizeBytes:           len(message),
		messageDigest:              messageDigest,
	}, nil
}

func validateGitCommitHeaderKey(key []byte) error {
	if len(key) == 0 || len(key) > maxGitCommitHeaderKeyBytes || key[0] < 'a' || key[0] > 'z' {
		return fmt.Errorf("git commit header key is not canonical")
	}
	previousHyphen := false
	for _, candidate := range key {
		if candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9' {
			previousHyphen = false
			continue
		}
		if candidate != '-' || previousHyphen {
			return fmt.Errorf("git commit header key is not canonical")
		}
		previousHyphen = true
	}
	if previousHyphen {
		return fmt.Errorf("git commit header key is not canonical")
	}
	return nil
}

func validateGitObjectDigest(digest []byte, algorithm RevisionAlgorithm) error {
	expectedLength := sha1HexLength
	if algorithm == RevisionAlgorithmSHA256 {
		expectedLength = sha256.Size * 2
	}
	if len(digest) != expectedLength {
		return fmt.Errorf("object ID has %d characters, want %d", len(digest), expectedLength)
	}
	allZero := true
	for _, candidate := range digest {
		if candidate >= 'A' && candidate <= 'F' {
			return fmt.Errorf("object ID must use lowercase hexadecimal")
		}
		if !(candidate >= '0' && candidate <= '9' || candidate >= 'a' && candidate <= 'f') {
			return fmt.Errorf("object ID is not hexadecimal")
		}
		if candidate != '0' {
			allZero = false
		}
	}
	if allZero {
		return fmt.Errorf("object ID must not be all zero")
	}
	return nil
}

func validateGitCommitEncoding(encoding []byte) error {
	if len(encoding) == 0 || len(encoding) > maxGitCommitEncodingBytes {
		return fmt.Errorf("git commit encoding has %d bytes, want 1 to %d", len(encoding), maxGitCommitEncodingBytes)
	}
	for _, candidate := range encoding {
		if candidate < 0x21 || candidate > 0x7e {
			return fmt.Errorf("git commit encoding must use non-space printable ASCII")
		}
	}
	return nil
}

// Identity returns the versioned canonical SHA-256 identity.
func (c GitCommit) Identity() string {
	return c.identity
}

// RevisionIdentity returns the exact commit revision identity.
func (c GitCommit) RevisionIdentity() string {
	return c.revisionIdentity
}

// ObjectVerificationIdentity returns the exact object verification identity.
func (c GitCommit) ObjectVerificationIdentity() string {
	return c.objectVerificationIdentity
}

// TreeAlgorithm returns the tree object ID algorithm.
func (c GitCommit) TreeAlgorithm() RevisionAlgorithm {
	return c.treeAlgorithm
}

// TreeDigest returns the declared full lowercase tree object ID.
func (c GitCommit) TreeDigest() string {
	return c.treeDigest
}

// Parents returns the ordered parent revision identities.
func (c GitCommit) Parents() []RevisionIdentity {
	return append([]RevisionIdentity{}, c.parents...)
}

// Encoding returns the exact declared message encoding, if present.
func (c GitCommit) Encoding() string {
	return c.encoding
}

// HeaderCount returns the number of header and continuation lines.
func (c GitCommit) HeaderCount() int {
	return c.headerCount
}

// MessageSizeBytes returns the exact message byte size.
func (c GitCommit) MessageSizeBytes() int {
	return c.messageSizeBytes
}

// MessageDigest returns the SHA-256 digest of the exact message bytes.
func (c GitCommit) MessageDigest() string {
	return c.messageDigest
}
