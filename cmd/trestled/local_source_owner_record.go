package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/georgejieh/open-trestle/internal/localownerroot"
	"github.com/georgejieh/open-trestle/internal/scm"
)

const (
	localSourceOwnerRecordContract = "open-trestle/local-source-owner-record"
	localSourceOwnerRecordVersion  = 1
	maxLocalSourceOwnerRecordBytes = 16 << 10
	localSourceOwnerChecksumDomain = "open-trestle/local-source-owner-record/checksum/v1\x00"
)

var (
	ErrLocalSourceOwnerMissing   = errors.New("local source owner record missing")
	ErrLocalSourceOwnerMismatch  = errors.New("local source owner record owner mismatch")
	ErrLocalSourceOwnerMalformed = errors.New("local source owner record malformed")
	ErrLocalSourceOwnerVersion   = errors.New("local source owner record unsupported version")
	ErrLocalSourceOwnerChecksum  = errors.New("local source owner record checksum mismatch")
)

// localSourceDirectoryIdentity is a Linux directory device/inode pair, not a pathname proof.
type localSourceDirectoryIdentity = localownerroot.DirectoryIdentity

type localSourceOwnerRecord struct {
	StatePath          string                       `json:"state_path"`
	ArtifactPath       string                       `json:"artifact_path"`
	GitObjectsPath     string                       `json:"git_objects_path"`
	TenantID           string                       `json:"tenant_id"`
	RepositoryID       string                       `json:"repository_id"`
	RepositoryIdentity string                       `json:"repository_identity"`
	AdapterIdentity    string                       `json:"adapter_identity"`
	Profile            string                       `json:"profile"`
	SourcePathDigest   string                       `json:"source_path_digest"`
	Git                localSourceDirectoryIdentity `json:"git"`
	State              localSourceDirectoryIdentity `json:"state"`
	Artifact           localSourceDirectoryIdentity `json:"artifact"`
}

type localSourceOwnerPayload struct {
	Contract string `json:"contract"`
	Version  int    `json:"version"`
	localSourceOwnerRecord
}

type localSourceOwnerEnvelope struct {
	localSourceOwnerPayload
	ChecksumSHA256 string `json:"checksum_sha256"`
}

func validLocalOwnerPath(path string) bool {
	return localownerroot.ValidPath(path)
}

func validLocalOwnerLabel(label string) bool {
	if len(label) == 0 || len(label) > 4096 {
		return false
	}
	for i := 0; i < len(label); i++ {
		if label[i] < ' ' || label[i] > '~' {
			return false
		}
	}
	return true
}

func (r localSourceOwnerRecord) validate() error {
	if !validLocalOwnerPath(r.StatePath) || !validLocalOwnerPath(r.ArtifactPath) || !validLocalOwnerPath(r.GitObjectsPath) || r.ArtifactPath != filepath.Join(r.StatePath, "artifacts") ||
		!validLocalOwnerLabel(r.TenantID) || !validLocalOwnerLabel(r.RepositoryID) ||
		!daemonNonzeroDigest(r.RepositoryIdentity) || !daemonNonzeroDigest(r.AdapterIdentity) || !daemonNonzeroDigest(r.SourcePathDigest) ||
		r.Profile != string(scm.LocalGitObjectStoreProfileLooseOnly) ||
		r.Git.Device == 0 || r.Git.Inode == 0 || r.State.Device == 0 || r.State.Inode == 0 || r.Artifact.Device == 0 || r.Artifact.Inode == 0 {
		return ErrLocalSourceOwnerMalformed
	}
	return nil
}

func localSourceOwnerChecksum(payload []byte) string {
	input := make([]byte, 0, len(localSourceOwnerChecksumDomain)+len(payload))
	input = append(input, localSourceOwnerChecksumDomain...)
	input = append(input, payload...)
	sum := sha256.Sum256(input)
	return hex.EncodeToString(sum[:])
}

// encodeLocalSourceOwnerRecord creates bytes only; it does not publish or validate a file.
func encodeLocalSourceOwnerRecord(record localSourceOwnerRecord) ([]byte, error) {
	if err := record.validate(); err != nil {
		return nil, err
	}
	payload := localSourceOwnerPayload{Contract: localSourceOwnerRecordContract, Version: localSourceOwnerRecordVersion, localSourceOwnerRecord: record}
	raw, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: encode payload: %v", ErrLocalSourceOwnerMalformed, err)
	}
	encoded, err := json.Marshal(localSourceOwnerEnvelope{localSourceOwnerPayload: payload, ChecksumSHA256: localSourceOwnerChecksum(raw)})
	if err != nil {
		return nil, fmt.Errorf("%w: encode envelope: %v", ErrLocalSourceOwnerMalformed, err)
	}
	encoded = append(encoded, '\n')
	if len(encoded) > maxLocalSourceOwnerRecordBytes {
		return nil, ErrLocalSourceOwnerMalformed
	}
	return encoded, nil
}

// decodeLocalSourceOwnerRecord accepts only the exact v1 canonical bytes.
func decodeLocalSourceOwnerRecord(encoded []byte) (localSourceOwnerRecord, error) {
	if encoded == nil {
		return localSourceOwnerRecord{}, ErrLocalSourceOwnerMissing
	}
	if len(encoded) == 0 || len(encoded) > maxLocalSourceOwnerRecordBytes || encoded[len(encoded)-1] != '\n' {
		return localSourceOwnerRecord{}, ErrLocalSourceOwnerMalformed
	}
	var envelope localSourceOwnerEnvelope
	if err := json.Unmarshal(encoded[:len(encoded)-1], &envelope); err != nil {
		return localSourceOwnerRecord{}, ErrLocalSourceOwnerMalformed
	}
	if envelope.Contract != localSourceOwnerRecordContract {
		return localSourceOwnerRecord{}, ErrLocalSourceOwnerMalformed
	}
	if err := envelope.localSourceOwnerRecord.validate(); err != nil {
		return localSourceOwnerRecord{}, err
	}
	if len(envelope.ChecksumSHA256) != sha256.Size*2 || envelope.ChecksumSHA256 != string(bytes.ToLower([]byte(envelope.ChecksumSHA256))) {
		return localSourceOwnerRecord{}, ErrLocalSourceOwnerMalformed
	}
	if _, err := hex.DecodeString(envelope.ChecksumSHA256); err != nil {
		return localSourceOwnerRecord{}, ErrLocalSourceOwnerMalformed
	}
	canonical, err := json.Marshal(envelope)
	if err != nil || !bytes.Equal(encoded[:len(encoded)-1], canonical) {
		return localSourceOwnerRecord{}, ErrLocalSourceOwnerMalformed
	}
	// A structurally valid, canonical future envelope is unsupported. Duplicate
	// or case-variant version keys and incomplete records are malformed first.
	if envelope.Version != localSourceOwnerRecordVersion {
		return localSourceOwnerRecord{}, ErrLocalSourceOwnerVersion
	}
	payload, err := json.Marshal(envelope.localSourceOwnerPayload)
	if err != nil {
		return localSourceOwnerRecord{}, ErrLocalSourceOwnerMalformed
	}
	if envelope.ChecksumSHA256 != localSourceOwnerChecksum(payload) {
		return localSourceOwnerRecord{}, ErrLocalSourceOwnerChecksum
	}
	return envelope.localSourceOwnerRecord, nil
}

// matchLocalSourceOwnerRecord compares validated decoded bytes with a separately observed owner.
// This comparison does not authenticate the record or its checksum.
func matchLocalSourceOwnerRecord(record, observed localSourceOwnerRecord) error {
	if err := record.validate(); err != nil {
		return err
	}
	if err := observed.validate(); err != nil {
		return err
	}
	if record != observed {
		return ErrLocalSourceOwnerMismatch
	}
	return nil
}
