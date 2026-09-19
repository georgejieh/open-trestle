package postgres

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/artifact"
)

// This record is historical metadata only. Parsing SQL bytes must never mint
// erasureauthority.Policy or Document, or call their protected file loaders.
const persistedPolicyContract = "open-trestle/protected-artifact-erasure-policy"
const erasureMaxMilliseconds int64 = 253402300799999

type persistedErasurePolicy struct {
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

type unsignedPersistedErasurePolicy struct {
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

func parsePersistedErasurePolicy(content []byte) (persistedErasurePolicy, error) {
	var r persistedErasurePolicy
	if len(content) == 0 || len(content) > 16384 || !utf8.Valid(content) {
		return r, ErrCorruptRecord
	}
	if json.Unmarshal(content, &r) != nil {
		return persistedErasurePolicy{}, ErrCorruptRecord
	}
	canonical, err := json.Marshal(r)
	if err != nil || !bytes.Equal(canonical, content) || !r.valid() {
		return persistedErasurePolicy{}, ErrCorruptRecord
	}
	return r, nil
}
func (r persistedErasurePolicy) valid() bool {
	if r.Contract != persistedPolicyContract || r.SchemaVersion != 1 ||
		r.BackendKind != "aws_s3_general_purpose" || r.NamespaceMode != "protected_new_nonnull" ||
		r.Protocol != "same-key-fence-v2" || r.Ownership != "all_versions_at_exact_key" ||
		r.NotBeforeMilliseconds <= 0 || r.NotAfterMilliseconds <= r.NotBeforeMilliseconds || r.NotAfterMilliseconds > erasureMaxMilliseconds {
		return false
	}
	for _, identity := range []string{r.Identity, r.NamespaceIdentity, r.BackendConfigurationIdentity,
		r.NamespaceEpochIdentity, r.DatabaseAuthorityIdentity, r.FenceRetentionPolicyIdentity,
		r.ErasurePolicyIdentity, r.RecoveryPolicyIdentity, r.ConfigurationEvidenceIdentity} {
		if !validDigest(identity) {
			return false
		}
	}
	namespace, err := artifact.NewStorageNamespace(r.BackendConfigurationIdentity, r.Prefix, r.NamespaceEpochIdentity)
	if err != nil || namespace.Identity() != r.NamespaceIdentity {
		return false
	}
	unsigned, err := json.Marshal(unsignedPersistedErasurePolicy{
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
	return err == nil && persistedPolicyIdentity(unsigned) == r.Identity
}

func persistedPolicyIdentity(unsigned []byte) string {
	h := sha256.New()
	_, _ = h.Write([]byte(persistedPolicyContract + "/v1\x00"))
	_, _ = h.Write(unsigned)
	return hex.EncodeToString(h.Sum(nil))
}
func (r persistedErasurePolicy) allows(at time.Time) bool {
	return validErasureInstant(at) && at.UnixMilli() >= r.NotBeforeMilliseconds && at.UnixMilli() < r.NotAfterMilliseconds
}
func validErasureInstant(at time.Time) bool {
	_, offset := at.Zone()
	return offset == 0 && at.Year() >= 1970 && at.Year() <= 9999 && at.Nanosecond()%int(time.Millisecond) == 0 && at.UnixMilli() > 0 && at.UnixMilli() <= erasureMaxMilliseconds
}
func (r persistedErasurePolicy) matchesNamespace(n artifact.StorageNamespace, authority string) bool {
	return r.NamespaceIdentity == n.Identity() && r.BackendConfigurationIdentity == n.BackendConfigurationIdentity() &&
		r.Prefix == n.Prefix() && r.NamespaceEpochIdentity == n.NamespaceEpochIdentity() && r.DatabaseAuthorityIdentity == authority
}
func (r persistedErasurePolicy) matchesGrant(g artifact.ErasureAuthorizationV2) bool {
	return g.Validate() == nil && g.NamespaceIdentity() == r.NamespaceIdentity && g.PolicyIdentity() == r.ErasurePolicyIdentity &&
		g.FenceRetentionPolicyIdentity() == r.FenceRetentionPolicyIdentity && g.Ownership() == r.Ownership && g.LegacyReceiptIdentity() == ""
}

func (persistedErasurePolicy) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("persisted erasure policy{redacted}"))
}
func (unsignedPersistedErasurePolicy) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("unsigned persisted erasure policy{redacted}"))
}
