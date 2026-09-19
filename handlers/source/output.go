package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	maximumSourceFileContentBytes = 10 << 20
	maximumSourceFilePayloadBytes = 16 << 20
	maximumSnapshotPayloadBytes   = 16 << 20
	maximumSnapshotFiles          = 1 << 16
)

// FileReference binds one manifest entry to its protected source-file artifact.
type FileReference struct {
	path, digest, artifactIdentity string
	sizeBytes                      int
}

func (r FileReference) Path() string             { return r.path }
func (r FileReference) Digest() string           { return r.digest }
func (r FileReference) SizeBytes() int           { return r.sizeBytes }
func (r FileReference) ArtifactIdentity() string { return r.artifactIdentity }
func (r FileReference) String() string           { return "source file reference" }
func (r FileReference) GoString() string         { return "source.FileReference{<redacted>}" }
func (r FileReference) Format(state fmt.State, verb rune) {
	writeSourceRedacted(state, verb, "source file reference", "source.FileReference{<redacted>}")
}

// Snapshot is the immutable source-snapshot index used by downstream tasks.
type Snapshot struct {
	identity, artifactIdentity, scopeIdentity               string
	classification                                          artifact.Classification
	protection                                              artifact.Protection
	acquisitionRequest, acquisitionReceipt, acquisitionExec string
	repositoryIdentity, revisionIdentity                    string
	sourceAdapterIdentity, manifestIdentity                 string
	files                                                   []FileReference
}

func (s Snapshot) Identity() string                        { return s.identity }
func (s Snapshot) ArtifactIdentity() string                { return s.artifactIdentity }
func (s Snapshot) ScopeIdentity() string                   { return s.scopeIdentity }
func (s Snapshot) Classification() artifact.Classification { return s.classification }
func (s Snapshot) Protection() artifact.Protection         { return s.protection }
func (s Snapshot) AcquisitionRequestIdentity() string      { return s.acquisitionRequest }
func (s Snapshot) AcquisitionReceiptIdentity() string      { return s.acquisitionReceipt }
func (s Snapshot) AcquisitionExecutionIdentity() string    { return s.acquisitionExec }
func (s Snapshot) RepositoryIdentity() string              { return s.repositoryIdentity }
func (s Snapshot) RevisionIdentity() string                { return s.revisionIdentity }
func (s Snapshot) SourceAdapterIdentity() string           { return s.sourceAdapterIdentity }
func (s Snapshot) ManifestIdentity() string                { return s.manifestIdentity }
func (s Snapshot) FileCount() int                          { return len(s.files) }
func (s Snapshot) Files() []FileReference                  { return append([]FileReference(nil), s.files...) }
func (s Snapshot) String() string                          { return "source snapshot" }
func (s Snapshot) GoString() string                        { return "source.Snapshot{<redacted>}" }
func (s Snapshot) Format(state fmt.State, verb rune) {
	writeSourceRedacted(state, verb, "source snapshot", "source.Snapshot{<redacted>}")
}

// File is one exact repository file decoded from a protected artifact.
type File struct {
	artifactIdentity, acquisitionExecution string
	path, digest                           string
	sizeBytes                              int
	content                                []byte
}

func (f File) ArtifactIdentity() string             { return f.artifactIdentity }
func (f File) AcquisitionExecutionIdentity() string { return f.acquisitionExecution }
func (f File) Path() string                         { return f.path }
func (f File) Digest() string                       { return f.digest }
func (f File) SizeBytes() int                       { return f.sizeBytes }
func (f File) Content() []byte                      { return append([]byte(nil), f.content...) }
func (f File) String() string                       { return "source file" }
func (f File) GoString() string                     { return "source.File{<redacted>}" }
func (f File) Format(state fmt.State, verb rune) {
	writeSourceRedacted(state, verb, "source file", "source.File{<redacted>}")
}

type fileWire struct {
	Contract                     string `json:"contract"`
	SchemaVersion                int    `json:"schema_version"`
	AcquisitionExecutionIdentity string `json:"acquisition_execution_identity"`
	Path                         string `json:"path"`
	Digest                       string `json:"digest"`
	SizeBytes                    int    `json:"size_bytes"`
	Content                      []byte `json:"content"`
}

type snapshotWire struct {
	Contract                     string              `json:"contract"`
	SchemaVersion                int                 `json:"schema_version"`
	Identity                     string              `json:"identity"`
	AcquisitionRequestIdentity   string              `json:"acquisition_request_identity"`
	AcquisitionReceiptIdentity   string              `json:"acquisition_receipt_identity"`
	AcquisitionExecutionIdentity string              `json:"acquisition_execution_identity"`
	RepositoryIdentity           string              `json:"repository_identity"`
	RevisionIdentity             string              `json:"revision_identity"`
	SourceAdapterIdentity        string              `json:"source_adapter_identity"`
	ManifestIdentity             string              `json:"manifest_identity"`
	Files                        []fileReferenceWire `json:"files"`
}

type fileReferenceWire struct {
	Path             string `json:"path"`
	Digest           string `json:"digest"`
	SizeBytes        int    `json:"size_bytes"`
	ArtifactIdentity string `json:"artifact_identity"`
}

func encodeFile(
	acquisitionExecutionIdentity string,
	file evidence.RepositoryFile,
	content []byte,
) ([]byte, error) {
	actual, err := evidence.NewRepositoryFile(file.Path(), content)
	if len(content) > maximumSourceFileContentBytes || err != nil || actual.Identity() != file.Identity() || !validDigest(acquisitionExecutionIdentity) {
		return nil, ErrInvalidOutput
	}
	encoded, err := json.Marshal(fileWire{
		Contract: "open-trestle/source-file", SchemaVersion: 1,
		AcquisitionExecutionIdentity: acquisitionExecutionIdentity,
		Path:                         file.Path(), Digest: file.Digest(), SizeBytes: file.SizeBytes(), Content: content,
	})
	if err != nil || len(encoded) == 0 || len(encoded) > maximumSourceFilePayloadBytes {
		return nil, ErrInvalidOutput
	}
	return encoded, nil
}

// ParseFileArtifact validates and decodes one exact source-file artifact.
func ParseFileArtifact(value artifact.Artifact, snapshot Snapshot, reference FileReference) (File, error) {
	if snapshot.validateFields(true) != nil || !snapshotContainsReference(snapshot, reference) ||
		value.Validate() != nil || value.Identity() != reference.ArtifactIdentity() ||
		value.Scope().Identity() != snapshot.ScopeIdentity() || value.Classification() != snapshot.Classification() ||
		value.Protection() != snapshot.Protection() || value.Kind() != artifact.KindSourceFile ||
		value.MediaType() != "application/json" || value.Origin() != artifact.OriginRepository ||
		!hasProvenance(value.Provenance(), snapshot.AcquisitionExecutionIdentity()) {
		return File{}, ErrInvalidOutput
	}
	expectedAcquisitionExecution := snapshot.AcquisitionExecutionIdentity()
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumSourceFilePayloadBytes {
		return File{}, ErrInvalidOutput
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire fileWire
	if err := decoder.Decode(&wire); err != nil {
		return File{}, ErrInvalidOutput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return File{}, ErrInvalidOutput
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/source-file" ||
		wire.SchemaVersion != 1 || wire.AcquisitionExecutionIdentity != expectedAcquisitionExecution ||
		wire.SizeBytes < 0 || wire.SizeBytes > maximumSourceFileContentBytes || wire.SizeBytes != len(wire.Content) {
		return File{}, ErrInvalidOutput
	}
	file, err := evidence.NewRepositoryFile(wire.Path, wire.Content)
	if err != nil || file.Digest() != wire.Digest || file.SizeBytes() != wire.SizeBytes ||
		wire.Path != reference.Path() || wire.Digest != reference.Digest() || wire.SizeBytes != reference.SizeBytes() {
		return File{}, ErrInvalidOutput
	}
	return File{
		artifactIdentity: value.Identity(), acquisitionExecution: wire.AcquisitionExecutionIdentity,
		path: wire.Path, digest: wire.Digest, sizeBytes: wire.SizeBytes,
		content: append([]byte(nil), wire.Content...),
	}, nil
}

func snapshotContainsReference(snapshot Snapshot, reference FileReference) bool {
	index := sort.Search(len(snapshot.files), func(index int) bool {
		return snapshot.files[index].path >= reference.path
	})
	return index < len(snapshot.files) && snapshot.files[index] == reference
}

func newSnapshot(
	artifactIdentity string,
	acquisitionRequest, acquisitionReceipt, acquisitionExecution string,
	repositoryIdentity, revisionIdentity, sourceAdapterIdentity, manifestIdentity string,
	files []FileReference,
) (Snapshot, error) {
	snapshot := Snapshot{
		artifactIdentity:   artifactIdentity,
		acquisitionRequest: acquisitionRequest, acquisitionReceipt: acquisitionReceipt,
		acquisitionExec: acquisitionExecution, repositoryIdentity: repositoryIdentity,
		revisionIdentity: revisionIdentity, sourceAdapterIdentity: sourceAdapterIdentity,
		manifestIdentity: manifestIdentity, files: append([]FileReference(nil), files...),
	}
	if err := snapshot.validateFields(false); err != nil {
		return Snapshot{}, err
	}
	snapshot.identity = deriveSnapshotIdentity(snapshot)
	return snapshot, nil
}

func (s Snapshot) validateFields(requireArtifact bool) error {
	identities := []string{
		s.acquisitionRequest, s.acquisitionReceipt, s.acquisitionExec,
		s.repositoryIdentity, s.revisionIdentity, s.sourceAdapterIdentity, s.manifestIdentity,
	}
	for _, identity := range identities {
		if !validDigest(identity) {
			return ErrInvalidOutput
		}
	}
	if requireArtifact && (!validDigest(s.artifactIdentity) || !validDigest(s.scopeIdentity) ||
		s.classification.String() == "" || s.protection.String() == "") || len(s.files) > maximumSnapshotFiles {
		return ErrInvalidOutput
	}
	previous := ""
	for _, file := range s.files {
		if file.path <= previous || !validDigest(file.digest) || !validDigest(file.artifactIdentity) || file.sizeBytes < 0 {
			return ErrInvalidOutput
		}
		if _, err := evidence.NewRepositoryFile(file.path, nil); err != nil {
			return ErrInvalidOutput
		}
		previous = file.path
	}
	return nil
}

func encodeSnapshot(snapshot Snapshot) ([]byte, error) {
	if err := snapshot.validateFields(false); err != nil || snapshot.identity != deriveSnapshotIdentity(snapshot) {
		return nil, ErrInvalidOutput
	}
	encoded, err := json.Marshal(snapshotWireValue(snapshot))
	if err != nil || len(encoded) == 0 || len(encoded) > maximumSnapshotPayloadBytes {
		return nil, ErrInvalidOutput
	}
	return encoded, nil
}

// ParseSnapshotArtifact validates and decodes one source-snapshot index.
func ParseSnapshotArtifact(value artifact.Artifact) (Snapshot, error) {
	if value.Validate() != nil || value.Kind() != artifact.KindSourceSnapshot || value.MediaType() != "application/json" ||
		value.Origin() != artifact.OriginRepository {
		return Snapshot{}, ErrInvalidOutput
	}
	payload := value.Payload()
	if len(payload) == 0 || len(payload) > maximumSnapshotPayloadBytes {
		return Snapshot{}, ErrInvalidOutput
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	var wire snapshotWire
	if err := decoder.Decode(&wire); err != nil {
		return Snapshot{}, ErrInvalidOutput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Snapshot{}, ErrInvalidOutput
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, payload) || wire.Contract != "open-trestle/source-snapshot" || wire.SchemaVersion != 1 ||
		!hasProvenance(value.Provenance(), wire.AcquisitionExecutionIdentity) {
		return Snapshot{}, ErrInvalidOutput
	}
	files := make([]FileReference, len(wire.Files))
	for index, file := range wire.Files {
		files[index] = FileReference{
			path: file.Path, digest: file.Digest, sizeBytes: file.SizeBytes,
			artifactIdentity: file.ArtifactIdentity,
		}
	}
	snapshot, err := newSnapshot(
		value.Identity(), wire.AcquisitionRequestIdentity, wire.AcquisitionReceiptIdentity,
		wire.AcquisitionExecutionIdentity, wire.RepositoryIdentity, wire.RevisionIdentity,
		wire.SourceAdapterIdentity, wire.ManifestIdentity, files,
	)
	if err != nil || snapshot.identity != wire.Identity {
		return Snapshot{}, ErrInvalidOutput
	}
	snapshot.scopeIdentity = value.Scope().Identity()
	snapshot.classification = value.Classification()
	snapshot.protection = value.Protection()
	if snapshot.validateFields(true) != nil {
		return Snapshot{}, ErrInvalidOutput
	}
	reencoded, _ := encodeSnapshot(snapshot)
	if !bytes.Equal(reencoded, payload) {
		return Snapshot{}, ErrInvalidOutput
	}
	return snapshot, nil
}

func snapshotWireValue(snapshot Snapshot) snapshotWire {
	files := make([]fileReferenceWire, len(snapshot.files))
	for index, file := range snapshot.files {
		files[index] = fileReferenceWire{
			Path: file.path, Digest: file.digest, SizeBytes: file.sizeBytes,
			ArtifactIdentity: file.artifactIdentity,
		}
	}
	return snapshotWire{
		Contract: "open-trestle/source-snapshot", SchemaVersion: 1, Identity: snapshot.identity,
		AcquisitionRequestIdentity:   snapshot.acquisitionRequest,
		AcquisitionReceiptIdentity:   snapshot.acquisitionReceipt,
		AcquisitionExecutionIdentity: snapshot.acquisitionExec,
		RepositoryIdentity:           snapshot.repositoryIdentity, RevisionIdentity: snapshot.revisionIdentity,
		SourceAdapterIdentity: snapshot.sourceAdapterIdentity, ManifestIdentity: snapshot.manifestIdentity,
		Files: files,
	}
}

func deriveSnapshotIdentity(snapshot Snapshot) string {
	wire := snapshotWireValue(snapshot)
	wire.Identity = ""
	encoded, err := json.Marshal(wire)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func validDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) || strings.Trim(value, "0") == "" {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func hasProvenance(values []string, expected string) bool {
	index := sort.SearchStrings(values, expected)
	return index < len(values) && values[index] == expected
}
