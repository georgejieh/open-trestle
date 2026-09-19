package artifact

import (
	"encoding/json"
	"fmt"
	"time"
)

const erasurePolicySnapshotContract = "open-trestle/protected-artifact-erasure-policy"

// Historical bytes carry no protected-file witness.
type erasurePolicySnapshot struct {
	Contract                      string `json:"contract"`
	SchemaVersion                 int    `json:"schema_version"`
	Identity                      string `json:"identity,omitempty"`
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

func parseErasurePolicySnapshot(encoded []byte) (erasurePolicySnapshot, error) {
	var p erasurePolicySnapshot
	if !erasureMetadataDecode(encoded, 16384, &p) {
		return erasurePolicySnapshot{}, ErrInvalidErasureContract
	}
	if p.Contract != erasurePolicySnapshotContract || p.SchemaVersion != 1 ||
		p.BackendKind != "aws_s3_general_purpose" || p.NamespaceMode != "protected_new_nonnull" ||
		p.Protocol != erasureOperationProtocol || p.Ownership != erasureAuthorizationV2Ownership ||
		!erasureMetadataMillis(p.NotBeforeMilliseconds) || !erasureMetadataMillis(p.NotAfterMilliseconds) ||
		p.NotAfterMilliseconds <= p.NotBeforeMilliseconds {
		return erasurePolicySnapshot{}, ErrInvalidErasureContract
	}
	for _, id := range [...]string{p.Identity, p.NamespaceIdentity, p.BackendConfigurationIdentity,
		p.NamespaceEpochIdentity, p.DatabaseAuthorityIdentity, p.FenceRetentionPolicyIdentity,
		p.ErasurePolicyIdentity, p.RecoveryPolicyIdentity, p.ConfigurationEvidenceIdentity} {
		if !validDigest(id) {
			return erasurePolicySnapshot{}, ErrInvalidErasureContract
		}
	}
	ns, err := NewStorageNamespace(p.BackendConfigurationIdentity, p.Prefix, p.NamespaceEpochIdentity)
	if err != nil {
		return erasurePolicySnapshot{}, err
	}
	unsigned := p
	unsigned.Identity = ""
	raw, err := json.Marshal(unsigned)
	if err != nil {
		return erasurePolicySnapshot{}, ErrInvalidErasureContract
	}
	if p.Identity != hashBytes(append([]byte(erasurePolicySnapshotContract+"/v1\x00"), raw...)) {
		return erasurePolicySnapshot{}, ErrErasureIdentityMismatch
	}
	if p.NamespaceIdentity != ns.Identity() {
		return erasurePolicySnapshot{}, ErrErasureBindingMismatch
	}
	return p, nil
}

func (p erasurePolicySnapshot) allows(at time.Time) bool {
	return validErasureAuthorizationV2Time(at) && at.UnixMilli() >= p.NotBeforeMilliseconds && at.UnixMilli() < p.NotAfterMilliseconds
}

func (p erasurePolicySnapshot) matchesNamespace(n StorageNamespace) bool {
	return p.NamespaceIdentity == n.Identity() && p.BackendConfigurationIdentity == n.BackendConfigurationIdentity() &&
		p.Prefix == n.Prefix() && p.NamespaceEpochIdentity == n.NamespaceEpochIdentity()
}

func (p erasurePolicySnapshot) stableEqual(other erasurePolicySnapshot) bool {
	p.Identity, other.Identity = "", ""
	p.ConfigurationEvidenceIdentity, other.ConfigurationEvidenceIdentity = "", ""
	p.NotBeforeMilliseconds, other.NotBeforeMilliseconds = 0, 0
	p.NotAfterMilliseconds, other.NotAfterMilliseconds = 0, 0
	return p == other
}

func (erasurePolicySnapshot) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("erasure policy snapshot{redacted}"))
}
