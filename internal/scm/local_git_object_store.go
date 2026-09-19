package scm

import (
	"bufio"
	"compress/zlib"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	maxLooseObjectCompressedBytes = 65 << 20
	maxLooseObjectHeaderBytes     = 128
	maxGitCommitPayloadBytes      = 4 << 20
	maxGitTreePayloadBytes        = 16 << 20
	maxGitBlobPayloadBytes        = 64 << 20
)

type LocalGitObjectStoreProfile string

const (
	LocalGitObjectStoreProfileLooseOnly           LocalGitObjectStoreProfile = "loose-only"
	LocalGitObjectStoreProfileLooseAndPackIndexV1 LocalGitObjectStoreProfile = "loose-and-pack-index-v1"
)

const localGitObjectStorePackedProfileIdentity = "de5515d7a1782495bbb622dc483331d6382fc1502fe498cf989e298296eb1697"

type LocalGitObjectStoreOptions struct {
	ObjectsRoot     *os.Root
	Repository      evidence.RepositoryIdentity
	Profile         LocalGitObjectStoreProfile
	ObjectAlgorithm evidence.RevisionAlgorithm
}

// LocalGitObjectStoreProfileIdentity returns the reviewed identity for supported store profiles.
func LocalGitObjectStoreProfileIdentity(profile LocalGitObjectStoreProfile) (string, error) {
	switch profile {
	case "", LocalGitObjectStoreProfileLooseOnly:
		return "", nil
	case LocalGitObjectStoreProfileLooseAndPackIndexV1:
		return localGitObjectStorePackedProfileIdentity, nil
	default:
		return "", fmt.Errorf("unsupported local Git object store profile %q", profile)
	}
}

// LocalGitObjectStore reads verified Git objects beneath one supplied object root.
type LocalGitObjectStore struct {
	objectsRoot        *os.Root
	repositoryIdentity string
	profile            LocalGitObjectStoreProfile
	profileIdentity    string
	objectAlgorithm    evidence.RevisionAlgorithm
	packLimits         localGitPackLimits

	mu      sync.Mutex
	closing bool
	closed  bool
	active  int
	idle    chan struct{}
	gate    chan struct{}
	catalog *localGitPackIndexCatalog
}

// NewLocalGitObjectStore uses objectsRoot as the exact authorized Git objects directory.
// The caller owns its lifetime; repository labels scope without proving origin.
func NewLocalGitObjectStore(objectsRoot *os.Root, repository evidence.RepositoryIdentity) (*LocalGitObjectStore, error) {
	return NewLocalGitObjectStoreWithOptions(LocalGitObjectStoreOptions{ObjectsRoot: objectsRoot, Repository: repository, Profile: LocalGitObjectStoreProfileLooseOnly})
}

// NewLocalGitObjectStoreWithOptions constructs a local Git object store without opening pack contents.
func NewLocalGitObjectStoreWithOptions(options LocalGitObjectStoreOptions) (*LocalGitObjectStore, error) {
	if options.ObjectsRoot == nil {
		return nil, fmt.Errorf("Git object root is nil")
	}
	if !confinedRootOpenSupported() {
		return nil, fmt.Errorf("confined Git object reads are unsupported on this platform")
	}
	canonicalRepository, err := evidence.NewRepositoryIdentity(options.Repository.Authority(), options.Repository.Namespace(), options.Repository.Name())
	if err != nil || !repositoryIdentityValuesEqual(options.Repository, canonicalRepository) {
		return nil, fmt.Errorf("repository identity is not canonical")
	}
	rootInfo, err := options.ObjectsRoot.Stat(".")
	if err != nil {
		return nil, fmt.Errorf("inspect Git object root: %w", err)
	}
	if !rootInfo.IsDir() {
		return nil, fmt.Errorf("Git object root is not a directory")
	}
	profile := options.Profile
	if profile == "" {
		profile = LocalGitObjectStoreProfileLooseOnly
	}
	profileIdentity, err := LocalGitObjectStoreProfileIdentity(profile)
	if err != nil {
		return nil, err
	}
	store := &LocalGitObjectStore{
		objectsRoot:        options.ObjectsRoot,
		repositoryIdentity: canonicalRepository.Identity(),
		profile:            profile,
		profileIdentity:    profileIdentity,
		objectAlgorithm:    options.ObjectAlgorithm,
		packLimits:         standardLocalGitPackLimits(),
		idle:               closedLocalGitIdleChan(),
	}
	if profile == LocalGitObjectStoreProfileLooseAndPackIndexV1 {
		if !nonblockingRegularFileOpenSupported() {
			return nil, fmt.Errorf("nonblocking regular file opens are unsupported for packed Git object reads")
		}
		if options.ObjectAlgorithm != evidence.RevisionAlgorithmSHA1 && options.ObjectAlgorithm != evidence.RevisionAlgorithmSHA256 {
			return nil, fmt.Errorf("unsupported packed Git object algorithm %q", options.ObjectAlgorithm)
		}
		if err := ValidateLocalGitPackedLayout(options.ObjectsRoot); err != nil {
			return nil, err
		}
		store.gate = make(chan struct{}, 1)
	}
	return store, nil
}

// RepositoryIdentity returns the canonical repository scope label.
func (s *LocalGitObjectStore) RepositoryIdentity() string {
	if s == nil {
		return ""
	}
	return s.repositoryIdentity
}

func (s *LocalGitObjectStore) Profile() LocalGitObjectStoreProfile {
	if s == nil || s.profile == "" {
		return LocalGitObjectStoreProfileLooseOnly
	}
	return s.profile
}

func (s *LocalGitObjectStore) ProfileIdentity() string {
	if s == nil {
		return ""
	}
	return s.profileIdentity
}

func (s *LocalGitObjectStore) Close(ctx context.Context) error {
	if s == nil || s.Profile() == LocalGitObjectStoreProfileLooseOnly {
		return nil
	}
	if isNilInterface(ctx) {
		return fmt.Errorf("Git object store close context is nil")
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closing = true
	for s.active > 0 {
		idle := s.idle
		s.mu.Unlock()
		select {
		case <-idle:
		case <-ctx.Done():
			return ctx.Err()
		}
		s.mu.Lock()
	}
	catalog := s.catalog
	s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if catalog != nil {
		if err := catalog.close(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	s.catalog = nil
	s.closed = true
	s.mu.Unlock()
	return ctx.Err()
}

func (s *LocalGitObjectStore) ValidateStable(ctx context.Context) error {
	if s == nil || s.objectsRoot == nil {
		return fmt.Errorf("local Git object store is nil")
	}
	if isNilInterface(ctx) {
		return fmt.Errorf("Git object store validation context is nil")
	}
	if s.Profile() == LocalGitObjectStoreProfileLooseOnly {
		return ctx.Err()
	}
	return s.withPackScope(ctx, func(scope *localGitPackScope) error {
		return nil
	})
}

// ReadCommit returns an exact verified commit payload.
func (s *LocalGitObjectStore) ReadCommit(ctx context.Context, revision evidence.RevisionIdentity) ([]byte, error) {
	canonicalRevision, err := evidence.NewRevisionIdentity(revision.Kind(), revision.Algorithm(), revision.Digest())
	if err != nil || !revisionIdentityValuesEqual(revision, canonicalRevision) {
		return nil, fmt.Errorf("revision identity is not canonical")
	}
	return s.readGitObject(ctx, canonicalRevision.Algorithm(), canonicalRevision.Digest(), "commit", maxGitCommitPayloadBytes)
}

// ReadTree returns an exact verified tree payload.
func (s *LocalGitObjectStore) ReadTree(ctx context.Context, algorithm evidence.RevisionAlgorithm, digest string) ([]byte, error) {
	return s.readGitObject(ctx, algorithm, digest, "tree", maxGitTreePayloadBytes)
}

// ReadBlob returns an exact verified blob payload.
func (s *LocalGitObjectStore) ReadBlob(ctx context.Context, algorithm evidence.RevisionAlgorithm, digest string) ([]byte, error) {
	return s.readGitObject(ctx, algorithm, digest, "blob", maxGitBlobPayloadBytes)
}

func (s *LocalGitObjectStore) readGitObject(ctx context.Context, algorithm evidence.RevisionAlgorithm, digest, expectedType string, maxPayloadBytes int64) ([]byte, error) {
	if s == nil || s.objectsRoot == nil {
		return nil, fmt.Errorf("local Git object store is nil")
	}
	if s.Profile() == LocalGitObjectStoreProfileLooseOnly {
		return s.readLooseObject(ctx, algorithm, digest, expectedType, maxPayloadBytes)
	}
	var payload []byte
	err := s.withPackScope(ctx, func(scope *localGitPackScope) error {
		var readErr error
		payload, readErr = scope.readGitObject(ctx, algorithm, digest, expectedType, maxPayloadBytes)
		return readErr
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
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

func (s *LocalGitObjectStore) readLooseThenPackObject(ctx context.Context, catalog *localGitPackIndexCatalog, scope *localGitPackScope, algorithm evidence.RevisionAlgorithm, digest, expectedType string, maxPayloadBytes int64) ([]byte, error) {
	payload, err := s.readLooseObject(ctx, algorithm, digest, expectedType, maxPayloadBytes)
	if err == nil {
		return payload, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return catalog.readObjectWithScope(ctx, digest, expectedType, maxPayloadBytes, scope)
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

func verifyGitObjectPayloadDigest(algorithm evidence.RevisionAlgorithm, expected []byte, objectType string, payload []byte) error {
	var hasher hash.Hash
	switch algorithm {
	case evidence.RevisionAlgorithmSHA1:
		hasher = sha1.New()
	case evidence.RevisionAlgorithmSHA256:
		hasher = sha256.New()
	default:
		return fmt.Errorf("unsupported Git object algorithm %q", algorithm)
	}
	_, _ = hasher.Write([]byte(objectType))
	_, _ = hasher.Write([]byte{' '})
	_, _ = hasher.Write([]byte(fmt.Sprintf("%d", len(payload))))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write(payload)
	if subtle.ConstantTimeCompare(hasher.Sum(nil), expected) != 1 {
		return fmt.Errorf("Git object identity does not match requested digest")
	}
	return nil
}

func bytesIndexByteOrEnd(buffer []byte, target byte) int {
	for i, b := range buffer {
		if b == target {
			return i
		}
	}
	return len(buffer)
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

func closedLocalGitIdleChan() chan struct{} {
	idle := make(chan struct{})
	close(idle)
	return idle
}
