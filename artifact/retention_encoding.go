package artifact

import (
	"bytes"
	"encoding/json"
	"github.com/georgejieh/open-trestle/audit"
	"io"
	"time"
)

const maxEncodedRetentionContractBytes = 4096

type deletionAuthorizationRecord struct {
	Contract              string `json:"contract"`
	SchemaVersion         int    `json:"schema_version"`
	Identity              string `json:"identity"`
	TenantID              string `json:"tenant_id"`
	RepositoryID          string `json:"repository_id"`
	ReviewRunID           string `json:"review_run_id"`
	ArtifactIdentity      string `json:"artifact_identity"`
	PolicyIdentity        string `json:"policy_identity"`
	PrincipalIdentity     string `json:"principal_identity"`
	HoldClearanceIdentity string `json:"hold_clearance_identity"`
	Reason                string `json:"reason"`
	IssuedAtMilliseconds  int64  `json:"issued_at_milliseconds"`
	ExpiresAtMilliseconds int64  `json:"expires_at_milliseconds"`
}

func EncodeDeletionAuthorization(value DeletionAuthorization) ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrInvalidDeletionAuthorization
	}
	record := deletionAuthorizationRecord{
		Contract: "open-trestle/artifact-deletion-authorization", SchemaVersion: 1,
		Identity: value.identity, TenantID: value.scope.TenantID(),
		RepositoryID: value.scope.RepositoryID(), ReviewRunID: value.scope.ReviewRunID(),
		ArtifactIdentity: value.artifactIdentity, PolicyIdentity: value.policyIdentity,
		PrincipalIdentity: value.principalIdentity, HoldClearanceIdentity: value.holdClearanceIdentity,
		Reason: value.reason.String(), IssuedAtMilliseconds: value.issuedAtMillis,
		ExpiresAtMilliseconds: value.expiresAtMillis,
	}
	return json.Marshal(record)
}
func ParseDeletionAuthorization(encoded []byte) (DeletionAuthorization, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedRetentionContractBytes {
		return DeletionAuthorization{}, ErrInvalidDeletionAuthorization
	}
	var record deletionAuthorizationRecord
	if decodeRetention(encoded, &record) != nil || record.Contract != "open-trestle/artifact-deletion-authorization" || record.SchemaVersion != 1 {
		return DeletionAuthorization{}, ErrInvalidDeletionAuthorization
	}
	scope, err := audit.NewReviewScope(record.TenantID, record.RepositoryID, record.ReviewRunID)
	if err != nil {
		return DeletionAuthorization{}, ErrInvalidDeletionAuthorization
	}
	reason := parseDeletionReason(record.Reason)
	value, err := NewDeletionAuthorization(
		scope, record.ArtifactIdentity, record.PolicyIdentity,
		record.PrincipalIdentity, record.HoldClearanceIdentity, reason,
		time.UnixMilli(record.IssuedAtMilliseconds), time.UnixMilli(record.ExpiresAtMilliseconds),
	)
	if err != nil || value.Identity() != record.Identity {
		return DeletionAuthorization{}, ErrInvalidDeletionAuthorizationIdentity
	}
	return value, nil
}

type deletionReceiptRecord struct {
	Contract              string `json:"contract"`
	SchemaVersion         int    `json:"schema_version"`
	Identity              string `json:"identity"`
	TenantID              string `json:"tenant_id"`
	RepositoryID          string `json:"repository_id"`
	ReviewRunID           string `json:"review_run_id"`
	ArtifactIdentity      string `json:"artifact_identity"`
	PayloadDigest         string `json:"payload_digest"`
	AuthorizationIdentity string `json:"authorization_identity"`
	DeletedAtMilliseconds int64  `json:"deleted_at_milliseconds"`
	Physical              bool   `json:"physical"`
}

func EncodeDeletionReceipt(value DeletionReceipt) ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrInvalidDeletionReceipt
	}
	record := deletionReceiptRecord{
		Contract: "open-trestle/artifact-deletion-receipt", SchemaVersion: 1,
		Identity: value.identity, TenantID: value.scope.TenantID(),
		RepositoryID: value.scope.RepositoryID(), ReviewRunID: value.scope.ReviewRunID(),
		ArtifactIdentity: value.artifactIdentity, PayloadDigest: value.payloadDigest,
		AuthorizationIdentity: value.authorizationIdentity,
		DeletedAtMilliseconds: value.deletedAtMillis, Physical: true,
	}
	return json.Marshal(record)
}
func ParseDeletionReceipt(encoded []byte) (DeletionReceipt, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedRetentionContractBytes {
		return DeletionReceipt{}, ErrInvalidDeletionReceipt
	}
	var record deletionReceiptRecord
	if decodeRetention(encoded, &record) != nil || record.Contract != "open-trestle/artifact-deletion-receipt" || record.SchemaVersion != 1 || !record.Physical {
		return DeletionReceipt{}, ErrInvalidDeletionReceipt
	}
	scope, err := audit.NewReviewScope(record.TenantID, record.RepositoryID, record.ReviewRunID)
	if err != nil {
		return DeletionReceipt{}, ErrInvalidDeletionReceipt
	}
	value := DeletionReceipt{
		identity: record.Identity, scope: scope, artifactIdentity: record.ArtifactIdentity,
		payloadDigest: record.PayloadDigest, authorizationIdentity: record.AuthorizationIdentity,
		deletedAtMillis: record.DeletedAtMilliseconds,
	}
	if value.Validate() != nil {
		return DeletionReceipt{}, ErrInvalidDeletionReceiptIdentity
	}
	return value, nil
}
func decodeRetention(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidEncoding
	}
	canonical, _ := json.Marshal(target)
	if !bytes.Equal(canonical, encoded) {
		return ErrInvalidEncoding
	}
	return nil
}
func parseDeletionReason(value string) DeletionReason {
	for reason := DeletionExpired; reason <= DeletionRepositoryErasure; reason++ {
		if reason.String() == value {
			return reason
		}
	}
	return 0
}
