package scm

import (
	"bufio"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	maxLooseObjectCompressedBytes = 65 << 20
	maxLooseObjectHeaderBytes     = 128
	maxGitCommitPayloadBytes      = 4 << 20
	maxGitTreePayloadBytes        = 16 << 20
	maxGitBlobPayloadBytes        = 64 << 20
)

// LocalGitObjectStore reads verified loose objects beneath one supplied object root.
type LocalGitObjectStore struct {
	objectsRoot        *os.Root
	repositoryIdentity string
}

// NewLocalGitObjectStore uses objectsRoot as the exact authorized Git objects directory.
// The caller owns its lifetime; repository labels scope without proving origin.
func NewLocalGitObjectStore(objectsRoot *os.Root, repository evidence.RepositoryIdentity) (*LocalGitObjectStore, error) {
	if objectsRoot == nil {
		return nil, fmt.Errorf("Git object root is nil")
	}
	if !confinedRootOpenSupported() {
		return nil, fmt.Errorf("confined Git object reads are unsupported on this platform")
	}
	canonicalRepository, err := evidence.NewRepositoryIdentity(repository.Authority(), repository.Namespace(), repository.Name())
	if err != nil || !repositoryIdentityValuesEqual(repository, canonicalRepository) {
		return nil, fmt.Errorf("repository identity is not canonical")
	}
	rootInfo, err := objectsRoot.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("inspect Git object root: %w", err)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("Git object root is not a directory")
	}
	return &LocalGitObjectStore{objectsRoot: objectsRoot, repositoryIdentity: canonicalRepository.Identity()}, nil
}

// RepositoryIdentity returns the canonical repository scope label.
func (s *LocalGitObjectStore) RepositoryIdentity() string {
	if s == nil {
		return ""
	}
	return s.repositoryIdentity
}

// ReadCommit returns an exact verified loose commit payload.
func (s *LocalGitObjectStore) ReadCommit(ctx context.Context, revision evidence.RevisionIdentity) ([]byte, error) {
	canonicalRevision, err := evidence.NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || !revisionIdentityValuesEqual(revision, canonicalRevision) {
		return nil, fmt.Errorf("revision identity is not canonical")
	}
	return s.readLooseObject(ctx, canonicalRevision.Algorithm(), canonicalRevision.Digest(), "commit", maxGitCommitPayloadBytes)
}

// ReadTree returns an exact verified loose tree payload.
func (s *LocalGitObjectStore) ReadTree(ctx context.Context, algorithm evidence.RevisionAlgorithm, digest string) ([]byte, error) {
	return s.readLooseObject(ctx, algorithm, digest, "tree", maxGitTreePayloadBytes)
}

// ReadBlob returns an exact verified loose blob payload.
func (s *LocalGitObjectStore) ReadBlob(ctx context.Context, algorithm evidence.RevisionAlgorithm, digest string) ([]byte, error) {
	return s.readLooseObject(ctx, algorithm, digest, "blob", maxGitBlobPayloadBytes)
}

func (s *LocalGitObjectStore) readLooseObject(ctx context.Context, algorithm evidence.RevisionAlgorithm, digest, expectedType string, maxPayloadBytes int64) ([]byte, error) {
	if s == nil || s.objectsRoot == nil {
		return nil, fmt.Errorf("local Git object store is nil")
	}
	if isNilInterface(ctx) {
		return nil, fmt.Errorf("Git object read context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expectedDigest, err := decodeGitObjectDigest(algorithm, digest)
	if err != nil {
		return nil, err
	}
	objectPath := digest[:2] + "/" + digest[2:]
	objectFile, err := s.objectsRoot.OpenFile(objectPath, regularFileOpenFlags(), 0)
	if err != nil {
		return nil, fmt.Errorf("open loose Git object %q: %w", objectPath, err)
	}
	payload, readErr := readOpenedLooseObject(ctx, objectFile, objectPath, expectedType, maxPayloadBytes, algorithm, expectedDigest)
	closeErr := objectFile.Close()
	if readErr != nil {
		return nil, readErr
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close loose Git object %q: %w", objectPath, closeErr)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return payload, nil
}

func readOpenedLooseObject(ctx context.Context, objectFile *os.File, objectPath, expectedType string, maxPayloadBytes int64, algorithm evidence.RevisionAlgorithm, expectedDigest []byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	info, err := objectFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect loose Git object %q: %w", objectPath, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%q is not a regular file", objectPath)
	}
	if err := validateLooseObjectCompressedSize(info.Size()); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	limited := &io.LimitedReader{R: &contextCheckingReader{ctx: ctx, reader: objectFile}, N: maxLooseObjectCompressedBytes + 1}
	buffered := bufio.NewReader(limited)
	compressed, err := zlib.NewReader(buffered)
	if err != nil {
		return nil, fmt.Errorf("decode loose Git object %q: %w", objectPath, err)
	}
	decoded := &contextCheckingReader{ctx: ctx, reader: compressed}
	header, payload, readErr := readLooseObjectPayload(decoded, expectedType, maxPayloadBytes)
	closeErr := compressed.Close()
	if readErr != nil {
		return nil, fmt.Errorf("decode loose Git object %q: %w", objectPath, readErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("close loose Git object decoder %q: %w", objectPath, closeErr)
	}
	if limited.N == 0 {
		return nil, fmt.Errorf("loose Git object exceeds %d compressed bytes", maxLooseObjectCompressedBytes)
	}
	if trailing, err := buffered.Peek(1); len(trailing) != 0 || err == nil {
		return nil, fmt.Errorf("loose Git object %q has trailing compressed data", objectPath)
	} else if err != io.EOF {
		return nil, fmt.Errorf("read loose Git object %q trailer: %w", objectPath, err)
	}
	if err := verifyLooseObjectDigest(algorithm, expectedDigest, header, payload); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return payload, nil
}

func readLooseObjectPayload(reader io.Reader, expectedType string, maxPayloadBytes int64) ([]byte, []byte, error) {
	header := make([]byte, 0, maxLooseObjectHeaderBytes)
	var next [1]byte
	for {
		if _, err := io.ReadFull(reader, next[:]); err != nil {
			return nil, nil, fmt.Errorf("read loose object header: %w", err)
		}
		if next[0] == 0 {
			break
		}
		if len(header) == maxLooseObjectHeaderBytes {
			return nil, nil, fmt.Errorf("loose object header exceeds %d bytes", maxLooseObjectHeaderBytes)
		}
		header = append(header, next[0])
	}
	objectType, sizeText, found := strings.Cut(string(header), " ")
	if !found || objectType != expectedType {
		return nil, nil, fmt.Errorf("loose object type %q does not match %q", objectType, expectedType)
	}
	payloadSize, err := parseCanonicalLooseObjectSize(sizeText, maxPayloadBytes)
	if err != nil {
		return nil, nil, err
	}
	payload := make([]byte, int(payloadSize))
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, nil, fmt.Errorf("read loose object payload: %w", err)
	}
	if _, err := io.ReadFull(reader, next[:]); err == nil {
		return nil, nil, fmt.Errorf("loose object has trailing decompressed data")
	} else if err != io.EOF {
		return nil, nil, fmt.Errorf("finish loose object payload: %w", err)
	}
	return header, payload, nil
}

func parseCanonicalLooseObjectSize(text string, limit int64) (int64, error) {
	if limit < 0 {
		return 0, fmt.Errorf("loose object payload limit is negative")
	}
	if len(text) == 0 || len(text) > 1 && text[0] == '0' {
		return 0, fmt.Errorf("loose object size is not canonical decimal")
	}
	var size int64
	for i := 0; i < len(text); i++ {
		if text[i] < '0' || text[i] > '9' {
			return 0, fmt.Errorf("loose object size is not canonical decimal")
		}
		digit := int64(text[i] - '0')
		if digit > limit || size > (limit-digit)/10 {
			return 0, fmt.Errorf("loose object payload exceeds %d bytes", limit)
		}
		size = size*10 + digit
	}
	return size, nil
}

func validateLooseObjectCompressedSize(size int64) error {
	if size < 0 || size > maxLooseObjectCompressedBytes {
		return fmt.Errorf("loose Git object exceeds %d compressed bytes", maxLooseObjectCompressedBytes)
	}
	return nil
}

func decodeGitObjectDigest(algorithm evidence.RevisionAlgorithm, digest string) ([]byte, error) {
	expectedLength := 0
	switch algorithm {
	case evidence.RevisionAlgorithmSHA1:
		expectedLength = sha1.Size * 2
	case evidence.RevisionAlgorithmSHA256:
		expectedLength = sha256.Size * 2
	default:
		return nil, fmt.Errorf("unsupported Git object algorithm %q", algorithm)
	}
	if len(digest) != expectedLength {
		return nil, fmt.Errorf("%s Git object digest has %d characters, want %d", algorithm, len(digest), expectedLength)
	}
	if digest != strings.ToLower(digest) {
		return nil, fmt.Errorf("Git object digest must use lowercase hexadecimal")
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil {
		return nil, fmt.Errorf("Git object digest is not hexadecimal: %w", err)
	}
	if strings.Trim(digest, "0") == "" {
		return nil, fmt.Errorf("Git object digest must not be all zero")
	}
	return decoded, nil
}

func verifyLooseObjectDigest(algorithm evidence.RevisionAlgorithm, expected, header, payload []byte) error {
	var hasher hash.Hash
	switch algorithm {
	case evidence.RevisionAlgorithmSHA1:
		hasher = sha1.New()
	case evidence.RevisionAlgorithmSHA256:
		hasher = sha256.New()
	default:
		return fmt.Errorf("unsupported Git object algorithm %q", algorithm)
	}
	_, _ = hasher.Write(header)
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(payload)
	if subtle.ConstantTimeCompare(hasher.Sum(nil), expected) != 1 {
		return fmt.Errorf("loose Git object identity does not match requested digest")
	}
	return nil
}

func repositoryIdentityValuesEqual(first, second evidence.RepositoryIdentity) bool {
	return first.Identity() == second.Identity() && first.Authority() == second.Authority() && slices.Equal(first.Namespace(), second.Namespace()) && first.Name() == second.Name()
}

func revisionIdentityValuesEqual(first, second evidence.RevisionIdentity) bool {
	return first.Identity() == second.Identity() && first.Kind() == second.Kind() && first.Algorithm() == second.Algorithm() && first.Digest() == second.Digest()
}

type contextCheckingReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextCheckingReader) Read(buffer []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	read, err := r.reader.Read(buffer)
	if contextErr := r.ctx.Err(); contextErr != nil {
		return read, contextErr
	}
	return read, err
}
