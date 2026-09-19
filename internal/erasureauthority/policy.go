// Package erasureauthority loads immutable, configured-local erasure policy
// snapshots. A snapshot does not prove provider configuration, bucket class, or
// continuous versioning, and does not by itself authorize an external effect.
// Effect callers must check the policy at effect time and bind the exact storage
// namespace and database authority.
package erasureauthority

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
)

// ErrProtectedAuthority deliberately discloses neither paths nor underlying causes.
var ErrProtectedAuthority = errors.New("protected erasure authority unavailable or unstable")

const (
	policyContract              = "open-trestle/protected-artifact-erasure-policy"
	namespaceContract           = "open-trestle/artifact-storage-namespace"
	maxDocumentBytes            = 16384
	maxPathBytes                = 4096
	maxPolicyMilliseconds int64 = 253402300799999
)

// Policy is a protected local policy snapshot. Its zero value is invalid.
// Copies retain the same immutable snapshot, not continuing pathname authority.
type Policy struct {
	witness *protectedRead
	record  policyRecord
}

// Document is a protected raw byte snapshot, not a policy grant.
// Its zero value is invalid. JSON decoding cannot mint either snapshot type.
type Document struct {
	witness *protectedRead
}

// Only readProtected mints this content-bound witness after two protected reads.
// Strings keep its contents immutable even when a snapshot is copied.
type protectedRead struct {
	content string
	digest  [sha256.Size]byte
}

type policyRecord struct {
	Contract                      string `json:"contract"`
	SchemaVersion                 int    `json:"schema_version"`
	Identity                      string `json:"identity"`
	NamespaceIdentity             string `json:"namespace_identity"`
	BackendConfigurationIdentity  string `json:"backend_configuration_identity"`
	Prefix                        string `json:"prefix"`
	NamespaceEpochIdentity        string `json:"namespace_epoch_identity"`
	BackendKind                   string `json:"backend_kind"`
	DatabaseAuthorityIdentity     string `json:"database_authority_identity"`
	NamespaceMode                 string `json:"namespace_mode"`
	Protocol                      string `json:"protocol"`
	Ownership                     string `json:"ownership"`
	FenceRetentionPolicyIdentity  string `json:"fence_retention_policy_identity"`
	ErasurePolicyIdentity         string `json:"erasure_policy_identity"`
	RecoveryPolicyIdentity        string `json:"recovery_policy_identity"`
	ConfigurationEvidenceIdentity string `json:"configuration_evidence_identity"`
	NotBeforeMilliseconds         int64  `json:"not_before_milliseconds"`
	NotAfterMilliseconds          int64  `json:"not_after_milliseconds"`
}

type unsignedPolicyRecord struct {
	Contract                      string `json:"contract"`
	SchemaVersion                 int    `json:"schema_version"`
	NamespaceIdentity             string `json:"namespace_identity"`
	BackendConfigurationIdentity  string `json:"backend_configuration_identity"`
	Prefix                        string `json:"prefix"`
	NamespaceEpochIdentity        string `json:"namespace_epoch_identity"`
	BackendKind                   string `json:"backend_kind"`
	DatabaseAuthorityIdentity     string `json:"database_authority_identity"`
	NamespaceMode                 string `json:"namespace_mode"`
	Protocol                      string `json:"protocol"`
	Ownership                     string `json:"ownership"`
	FenceRetentionPolicyIdentity  string `json:"fence_retention_policy_identity"`
	ErasurePolicyIdentity         string `json:"erasure_policy_identity"`
	RecoveryPolicyIdentity        string `json:"recovery_policy_identity"`
	ConfigurationEvidenceIdentity string `json:"configuration_evidence_identity"`
	NotBeforeMilliseconds         int64  `json:"not_before_milliseconds"`
	NotAfterMilliseconds          int64  `json:"not_after_milliseconds"`
}

type unsignedNamespaceRecord struct {
	Contract                     string `json:"contract"`
	SchemaVersion                int    `json:"schema_version"`
	BackendConfigurationIdentity string `json:"backend_configuration_identity"`
	Prefix                       string `json:"prefix"`
	NamespaceEpochIdentity       string `json:"namespace_epoch_identity"`
}

// LoadPolicy reads a strict canonical policy from an explicit protected path.
// Loading and validation check structure, not whether the wall clock is in range.
func LoadPolicy(ctx context.Context, path string) (Policy, error) {
	witness, err := readProtected(ctx, path)
	if err != nil {
		return Policy{}, ErrProtectedAuthority
	}
	record, err := parsePolicy(witness.content)
	if err != nil || ctx.Err() != nil {
		return Policy{}, ErrProtectedAuthority
	}
	return Policy{witness: witness, record: record}, nil
}

// LoadDocument accepts any nonempty protected content up to 16384 bytes,
// including NUL and invalid UTF-8. Its digest is SHA256 of those exact bytes.
func LoadDocument(ctx context.Context, path string) (Document, error) {
	witness, err := readProtected(ctx, path)
	if err != nil || ctx.Err() != nil {
		return Document{}, ErrProtectedAuthority
	}
	return Document{witness: witness}, nil
}

// Validate checks the protected-read witness and its exact canonical binding.
// It does not re-open a path or sample the wall clock.
func (p Policy) Validate() error {
	if !p.witness.valid() {
		return ErrProtectedAuthority
	}
	record, err := parsePolicy(p.witness.content)
	if err != nil || record != p.record {
		return ErrProtectedAuthority
	}
	return nil
}

// Validate checks the protected-read witness and raw content digest.
func (d Document) Validate() error {
	if !d.witness.valid() {
		return ErrProtectedAuthority
	}
	return nil
}

func (w *protectedRead) valid() bool {
	return w != nil && len(w.content) > 0 && len(w.content) <= maxDocumentBytes &&
		sha256.Sum256([]byte(w.content)) == w.digest
}

// AllowsAt tests the caller's instant against [NotBefore, NotAfter).
// It is a local policy predicate, not authorization to perform an effect.
func (p Policy) AllowsAt(instant time.Time) bool {
	return p.Validate() == nil && !instant.Before(p.NotBefore()) && instant.Before(p.NotAfter())
}

// Bytes returns an independent copy of the canonical policy bytes.
func (p Policy) Bytes() []byte {
	if p.witness == nil {
		return nil
	}
	return []byte(p.witness.content)
}

// Bytes returns an independent copy of the protected raw bytes.
func (d Document) Bytes() []byte {
	if d.witness == nil {
		return nil
	}
	return []byte(d.witness.content)
}

func (d Document) Digest() string {
	if d.witness == nil {
		return ""
	}
	return hex.EncodeToString(d.witness.digest[:])
}

func (p Policy) Identity() string {
	return p.record.Identity
}

func (p Policy) NamespaceIdentity() string {
	return p.record.NamespaceIdentity
}

func (p Policy) BackendConfigurationIdentity() string {
	return p.record.BackendConfigurationIdentity
}

func (p Policy) Prefix() string {
	return p.record.Prefix
}

func (p Policy) NamespaceEpochIdentity() string {
	return p.record.NamespaceEpochIdentity
}

func (p Policy) BackendKind() string {
	return p.record.BackendKind
}

func (p Policy) DatabaseAuthorityIdentity() string {
	return p.record.DatabaseAuthorityIdentity
}

func (p Policy) NamespaceMode() string {
	return p.record.NamespaceMode
}

func (p Policy) Protocol() string {
	return p.record.Protocol
}

func (p Policy) Ownership() string {
	return p.record.Ownership
}

func (p Policy) FenceRetentionPolicyIdentity() string {
	return p.record.FenceRetentionPolicyIdentity
}

func (p Policy) ErasurePolicyIdentity() string {
	return p.record.ErasurePolicyIdentity
}

func (p Policy) RecoveryPolicyIdentity() string {
	return p.record.RecoveryPolicyIdentity
}

func (p Policy) ConfigurationEvidenceIdentity() string {
	return p.record.ConfigurationEvidenceIdentity
}

func (p Policy) NotBefore() time.Time {
	if p.witness == nil {
		return time.Time{}
	}
	return time.UnixMilli(p.record.NotBeforeMilliseconds).UTC()
}

func (p Policy) NotAfter() time.Time {
	if p.witness == nil {
		return time.Time{}
	}
	return time.UnixMilli(p.record.NotAfterMilliseconds).UTC()
}

func (Policy) String() string     { return "erasureauthority.Policy{redacted}" }
func (Policy) GoString() string   { return "erasureauthority.Policy{redacted}" }
func (Document) String() string   { return "erasureauthority.Document{redacted}" }
func (Document) GoString() string { return "erasureauthority.Document{redacted}" }

func (p Policy) Format(state fmt.State, verb rune) {
	formatRedacted(state, verb, p.String())
}

func (d Document) Format(state fmt.State, verb rune) {
	formatRedacted(state, verb, d.String())
}

func formatRedacted(state fmt.State, verb rune, value string) {
	if verb == 'q' {
		value = `"` + value + `"`
	}
	_, _ = state.Write([]byte(value))
}

func parsePolicy(content string) (policyRecord, error) {
	if len(content) == 0 || len(content) > maxDocumentBytes || !utf8.ValidString(content) {
		return policyRecord{}, ErrProtectedAuthority
	}
	var record policyRecord
	if err := json.Unmarshal([]byte(content), &record); err != nil {
		return policyRecord{}, ErrProtectedAuthority
	}
	// Exact re-encoding rejects duplicates, aliases, unknown or missing fields,
	// nulls, escapes, alternate number syntax, field reordering and whitespace.
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, []byte(content)) || !record.valid() {
		return policyRecord{}, ErrProtectedAuthority
	}
	return record, nil
}

func (r policyRecord) valid() bool {
	if r.Contract != policyContract || r.SchemaVersion != 1 ||
		r.BackendKind != "aws_s3_general_purpose" || r.NamespaceMode != "protected_new_nonnull" ||
		r.Protocol != "same-key-fence-v2" || r.Ownership != "all_versions_at_exact_key" ||
		!validPrefix(r.Prefix) || r.NotBeforeMilliseconds <= 0 ||
		r.NotAfterMilliseconds <= r.NotBeforeMilliseconds || r.NotAfterMilliseconds > maxPolicyMilliseconds {
		return false
	}
	for _, identity := range [...]string{
		r.Identity, r.NamespaceIdentity, r.BackendConfigurationIdentity, r.NamespaceEpochIdentity,
		r.DatabaseAuthorityIdentity, r.FenceRetentionPolicyIdentity, r.ErasurePolicyIdentity,
		r.RecoveryPolicyIdentity, r.ConfigurationEvidenceIdentity,
	} {
		if !validIdentity(identity) {
			return false
		}
	}
	namespace, err := json.Marshal(unsignedNamespaceRecord{
		Contract:                     namespaceContract,
		SchemaVersion:                1,
		BackendConfigurationIdentity: r.BackendConfigurationIdentity,
		Prefix:                       r.Prefix,
		NamespaceEpochIdentity:       r.NamespaceEpochIdentity,
	})
	if err != nil || domainIdentity(namespaceContract, namespace) != r.NamespaceIdentity {
		return false
	}
	unsigned, err := json.Marshal(unsignedPolicyRecord{
		Contract:                      r.Contract,
		SchemaVersion:                 r.SchemaVersion,
		NamespaceIdentity:             r.NamespaceIdentity,
		BackendConfigurationIdentity:  r.BackendConfigurationIdentity,
		Prefix:                        r.Prefix,
		NamespaceEpochIdentity:        r.NamespaceEpochIdentity,
		BackendKind:                   r.BackendKind,
		DatabaseAuthorityIdentity:     r.DatabaseAuthorityIdentity,
		NamespaceMode:                 r.NamespaceMode,
		Protocol:                      r.Protocol,
		Ownership:                     r.Ownership,
		FenceRetentionPolicyIdentity:  r.FenceRetentionPolicyIdentity,
		ErasurePolicyIdentity:         r.ErasurePolicyIdentity,
		RecoveryPolicyIdentity:        r.RecoveryPolicyIdentity,
		ConfigurationEvidenceIdentity: r.ConfigurationEvidenceIdentity,
		NotBeforeMilliseconds:         r.NotBeforeMilliseconds,
		NotAfterMilliseconds:          r.NotAfterMilliseconds,
	})
	return err == nil && domainIdentity(policyContract, unsigned) == r.Identity
}

func domainIdentity(contract string, unsigned []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte(contract + "/v1\x00"))
	_, _ = digest.Write(unsigned)
	return hex.EncodeToString(digest.Sum(nil))
}

func validIdentity(identity string) bool {
	if len(identity) != sha256.Size*2 {
		return false
	}
	nonzero := false
	for i := 0; i < len(identity); i++ {
		c := identity[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
		nonzero = nonzero || c != '0'
	}
	return nonzero
}

func validPrefix(prefix string) bool {
	if len(prefix) == 0 || len(prefix) > 128 || prefix[0] == '/' || prefix[len(prefix)-1] == '/' {
		return false
	}
	for i := 0; i < len(prefix); i++ {
		c := prefix[i]
		if c == '/' {
			if i > 0 && prefix[i-1] == '/' {
				return false
			}
		} else if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func readProtected(ctx context.Context, path string) (*protectedRead, error) {
	if ctx == nil || ctx.Err() != nil || len(path) == 0 || len(path) > maxPathBytes ||
		strings.IndexByte(path, 0) >= 0 || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrProtectedAuthority
	}
	var original os.FileInfo
	var content []byte
	for pass := 0; pass < 2; pass++ {
		if ctx.Err() != nil {
			return nil, ErrProtectedAuthority
		}
		file, err := fileauthority.OpenReadOnly(path)
		if err != nil || file == nil {
			if file != nil {
				_ = file.Close()
			}
			return nil, ErrProtectedAuthority
		}
		before, beforeErr := file.Stat()
		var value []byte
		if beforeErr == nil && before != nil && before.Mode().IsRegular() &&
			fileauthority.TrustedOwner(before) && before.Size() > 0 && before.Size() <= maxDocumentBytes {
			value, err = io.ReadAll(io.LimitReader(protectedContextReader{ctx: ctx, file: file}, maxDocumentBytes+1))
		} else {
			err = ErrProtectedAuthority
		}
		after, afterErr := file.Stat()
		closeErr := file.Close()
		if err != nil || beforeErr != nil || afterErr != nil || closeErr != nil || ctx.Err() != nil ||
			len(value) == 0 || len(value) > maxDocumentBytes || !stableInfo(before, after) ||
			int64(len(value)) != before.Size() {
			return nil, ErrProtectedAuthority
		}
		if pass == 0 {
			original, content = before, value
		} else if !stableInfo(original, before) || !bytes.Equal(content, value) {
			return nil, ErrProtectedAuthority
		}
	}
	witness := &protectedRead{content: string(content), digest: sha256.Sum256(content)}
	if ctx.Err() != nil {
		return nil, ErrProtectedAuthority
	}
	return witness, nil
}

func stableInfo(a, b os.FileInfo) bool {
	return a != nil && b != nil && a.Mode().IsRegular() && b.Mode().IsRegular() &&
		fileauthority.TrustedOwner(a) && fileauthority.TrustedOwner(b) &&
		os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime())
}

type protectedContextReader struct {
	ctx  context.Context
	file *os.File
}

func (r protectedContextReader) Read(p []byte) (int, error) {
	if r.ctx.Err() != nil {
		return 0, ErrProtectedAuthority
	}
	n, err := r.file.Read(p)
	if r.ctx.Err() != nil {
		return n, ErrProtectedAuthority
	}
	return n, err
}
