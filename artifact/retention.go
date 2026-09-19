package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"io"
	"strings"
	"time"
	"unicode/utf8"
)

const maxDeletionAuthorizationLifetime = 15 * time.Minute

var (
	// ErrInvalidDeletionAuthorization identifies malformed retention or legal-hold clearance authority.
	ErrInvalidDeletionAuthorization = errors.New("invalid artifact deletion authorization")
	// ErrInvalidDeletionAuthorizationIdentity identifies authorization content inconsistent with its identity.
	ErrInvalidDeletionAuthorizationIdentity = errors.New("invalid artifact deletion authorization identity")
	// ErrDeletionNotAllowed identifies premature, expired, foreign, or held deletion.
	ErrDeletionNotAllowed = errors.New("artifact deletion not allowed")
	// ErrArtifactDeleted identifies attempted reintroduction of physically deleted data.
	ErrArtifactDeleted = errors.New("runtime artifact already deleted")
	// ErrInvalidDeletionReceipt identifies malformed physical deletion evidence.
	ErrInvalidDeletionReceipt = errors.New("invalid artifact deletion receipt")
	// ErrInvalidDeletionReceiptIdentity identifies receipt content inconsistent with its identity.
	ErrInvalidDeletionReceiptIdentity = errors.New("invalid artifact deletion receipt identity")
)

// DeletionReason is a closed retention-policy disposition.
type DeletionReason uint8

const (
	DeletionExpired DeletionReason = iota + 1
	DeletionTenantErasure
	DeletionRepositoryErasure
)

func (r DeletionReason) String() string {
	switch r {
	case DeletionExpired:
		return "expired"
	case DeletionTenantErasure:
		return "tenant_erasure"
	case DeletionRepositoryErasure:
		return "repository_erasure"
	default:
		return ""
	}
}

// DeletionAuthorization binds policy and legal-hold clearance to one exact artifact.
type DeletionAuthorization struct {
	identity, artifactIdentity, policyIdentity, principalIdentity, holdClearanceIdentity string
	scope                                                                                audit.ReviewScope
	reason                                                                               DeletionReason
	issuedAtMillis, expiresAtMillis                                                      int64
}

func NewDeletionAuthorization(
	scope audit.ReviewScope,
	artifactIdentity, policyIdentity, principalIdentity, holdClearanceIdentity string,
	reason DeletionReason,
	issuedAt, expiresAt time.Time,
) (DeletionAuthorization, error) {
	issuedMillis, expiresMillis := issuedAt.UnixMilli(), expiresAt.UnixMilli()
	validAuthority := scope.Validate() == nil && validDigest(artifactIdentity) && validDigest(policyIdentity) && validPrincipal(principalIdentity) && validDigest(holdClearanceIdentity)
	validTime := issuedMillis > 0 && expiresMillis > issuedMillis && expiresAt.Sub(issuedAt) <= maxDeletionAuthorizationLifetime && expiresMillis <= maxArtifactUnixMilliseconds
	valid := validAuthority && reason.String() != "" && validTime
	if !valid {
		return DeletionAuthorization{}, ErrInvalidDeletionAuthorization
	}
	authorization := DeletionAuthorization{
		scope: scope, artifactIdentity: artifactIdentity, policyIdentity: policyIdentity,
		principalIdentity: strings.Clone(principalIdentity), holdClearanceIdentity: holdClearanceIdentity,
		reason: reason, issuedAtMillis: issuedMillis, expiresAtMillis: expiresMillis,
	}
	authorization.identity = deriveDeletionAuthorizationIdentity(authorization)
	return authorization, nil
}
func (a DeletionAuthorization) Identity() string              { return a.identity }
func (a DeletionAuthorization) Scope() audit.ReviewScope      { return a.scope }
func (a DeletionAuthorization) ArtifactIdentity() string      { return a.artifactIdentity }
func (a DeletionAuthorization) PolicyIdentity() string        { return a.policyIdentity }
func (a DeletionAuthorization) PrincipalIdentity() string     { return a.principalIdentity }
func (a DeletionAuthorization) HoldClearanceIdentity() string { return a.holdClearanceIdentity }
func (a DeletionAuthorization) Reason() DeletionReason        { return a.reason }
func (a DeletionAuthorization) IssuedAt() time.Time           { return time.UnixMilli(a.issuedAtMillis).UTC() }
func (a DeletionAuthorization) ExpiresAt() time.Time          { return time.UnixMilli(a.expiresAtMillis).UTC() }
func (a DeletionAuthorization) Validate() error {
	rebuilt, err := NewDeletionAuthorization(
		a.scope, a.artifactIdentity, a.policyIdentity, a.principalIdentity,
		a.holdClearanceIdentity, a.reason,
		time.UnixMilli(a.issuedAtMillis), time.UnixMilli(a.expiresAtMillis),
	)
	if err != nil {
		return err
	}
	if rebuilt.identity != a.identity {
		return ErrInvalidDeletionAuthorizationIdentity
	}
	return nil
}
func (a DeletionAuthorization) Allows(value Artifact, at time.Time) bool {
	if a.Validate() != nil || value.Validate() != nil || a.scope.Identity() != value.Scope().Identity() || a.artifactIdentity != value.Identity() {
		return false
	}
	atMillis := at.UnixMilli()
	if atMillis < a.issuedAtMillis || atMillis >= a.expiresAtMillis {
		return false
	}
	return a.reason != DeletionExpired || atMillis >= value.expiresAtMillis
}
func (a DeletionAuthorization) String() string   { return "artifact deletion authorization" }
func (a DeletionAuthorization) GoString() string { return "artifact.DeletionAuthorization{<redacted>}" }
func (a DeletionAuthorization) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "artifact deletion authorization", "artifact.DeletionAuthorization{<redacted>}")
}

// DeletionReceipt is content-free evidence of completed physical removal.
type DeletionReceipt struct {
	identity, artifactIdentity, payloadDigest, authorizationIdentity string
	scope                                                            audit.ReviewScope
	deletedAtMillis                                                  int64
}

func newDeletionReceipt(value Artifact, authorization DeletionAuthorization, at time.Time) DeletionReceipt {
	receipt := DeletionReceipt{
		scope: value.Scope(), artifactIdentity: value.Identity(), payloadDigest: value.PayloadDigest(),
		authorizationIdentity: authorization.Identity(), deletedAtMillis: at.UnixMilli(),
	}
	receipt.identity = deriveDeletionReceiptIdentity(receipt)
	return receipt
}
func (r DeletionReceipt) Identity() string              { return r.identity }
func (r DeletionReceipt) Scope() audit.ReviewScope      { return r.scope }
func (r DeletionReceipt) ArtifactIdentity() string      { return r.artifactIdentity }
func (r DeletionReceipt) PayloadDigest() string         { return r.payloadDigest }
func (r DeletionReceipt) AuthorizationIdentity() string { return r.authorizationIdentity }
func (r DeletionReceipt) DeletedAt() time.Time          { return time.UnixMilli(r.deletedAtMillis).UTC() }
func (r DeletionReceipt) Validate() error {
	validIdentities := validDigest(r.artifactIdentity) && validDigest(r.payloadDigest) && validDigest(r.authorizationIdentity)
	validTime := r.deletedAtMillis > 0 && r.deletedAtMillis <= maxArtifactUnixMilliseconds
	if r.scope.Validate() != nil || !validIdentities || !validTime {
		return ErrInvalidDeletionReceipt
	}
	if r.identity != deriveDeletionReceiptIdentity(r) {
		return ErrInvalidDeletionReceiptIdentity
	}
	return nil
}
func (r DeletionReceipt) String() string   { return "artifact deletion receipt" }
func (r DeletionReceipt) GoString() string { return "artifact.DeletionReceipt{<redacted>}" }
func (r DeletionReceipt) Format(state fmt.State, verb rune) {
	writeRedacted(state, verb, "artifact deletion receipt", "artifact.DeletionReceipt{<redacted>}")
}
func deriveDeletionAuthorizationIdentity(a DeletionAuthorization) string {
	return hashValue(struct {
		ScopeIdentity         string `json:"scope_identity"`
		ArtifactIdentity      string `json:"artifact_identity"`
		PolicyIdentity        string `json:"policy_identity"`
		PrincipalIdentity     string `json:"principal_identity"`
		HoldClearanceIdentity string `json:"hold_clearance_identity"`
		Reason                string `json:"reason"`
		IssuedAtMilliseconds  int64  `json:"issued_at_milliseconds"`
		ExpiresAtMilliseconds int64  `json:"expires_at_milliseconds"`
	}{a.scope.Identity(), a.artifactIdentity, a.policyIdentity, a.principalIdentity, a.holdClearanceIdentity, a.reason.String(), a.issuedAtMillis, a.expiresAtMillis})
}
func deriveDeletionReceiptIdentity(r DeletionReceipt) string {
	return hashValue(struct {
		ScopeIdentity         string `json:"scope_identity"`
		ArtifactIdentity      string `json:"artifact_identity"`
		PayloadDigest         string `json:"payload_digest"`
		AuthorizationIdentity string `json:"authorization_identity"`
		DeletedAtMilliseconds int64  `json:"deleted_at_milliseconds"`
		Physical              bool   `json:"physical"`
	}{r.scope.Identity(), r.artifactIdentity, r.payloadDigest, r.authorizationIdentity, r.deletedAtMillis, true})
}
func validPrincipal(value string) bool {
	if len(value) == 0 || len(value) > 128 || !utf8.ValidString(value) {
		return false
	}
	for index, candidate := range value {
		alphaNumeric := candidate >= 'a' && candidate <= 'z' || candidate >= 'A' && candidate <= 'Z' || candidate >= '0' && candidate <= '9'
		separator := strings.ContainsRune("._:@/-", candidate)
		if !alphaNumeric && !(separator && index > 0 && index < len(value)-1) {
			return false
		}
	}
	return true
}
func writeRedacted(state fmt.State, verb rune, plain, syntax string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = syntax
	}
	_, _ = state.Write([]byte(value))
}

const maxEncodedDeletionRecordBytes = 4096

type deletionRecord struct {
	Contract              string `json:"contract"`
	SchemaVersion         int    `json:"schema_version"`
	Completed             bool   `json:"completed"`
	Identity              string `json:"identity"`
	TenantID              string `json:"tenant_id"`
	RepositoryID          string `json:"repository_id"`
	ReviewRunID           string `json:"review_run_id"`
	ArtifactIdentity      string `json:"artifact_identity"`
	PayloadDigest         string `json:"payload_digest"`
	AuthorizationIdentity string `json:"authorization_identity"`
	DeletedAtMilliseconds int64  `json:"deleted_at_milliseconds"`
}

func encodeDeletionRecord(receipt DeletionReceipt, completed bool) ([]byte, error) {
	if receipt.Validate() != nil {
		return nil, ErrInvalidDeletionReceipt
	}
	record := deletionRecord{
		Contract: "open-trestle/artifact-deletion", SchemaVersion: 1, Completed: completed,
		Identity: receipt.Identity(), TenantID: receipt.Scope().TenantID(),
		RepositoryID: receipt.Scope().RepositoryID(), ReviewRunID: receipt.Scope().ReviewRunID(),
		ArtifactIdentity: receipt.ArtifactIdentity(), PayloadDigest: receipt.PayloadDigest(),
		AuthorizationIdentity: receipt.AuthorizationIdentity(), DeletedAtMilliseconds: receipt.deletedAtMillis,
	}
	return json.Marshal(record)
}
func parseDeletionRecord(encoded []byte) (DeletionReceipt, bool, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedDeletionRecordBytes {
		return DeletionReceipt{}, false, ErrInvalidDeletionReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record deletionRecord
	if err := decoder.Decode(&record); err != nil {
		return DeletionReceipt{}, false, ErrInvalidDeletionReceipt
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return DeletionReceipt{}, false, ErrInvalidDeletionReceipt
	}
	canonical, _ := json.Marshal(record)
	if !bytes.Equal(canonical, encoded) || record.Contract != "open-trestle/artifact-deletion" || record.SchemaVersion != 1 {
		return DeletionReceipt{}, false, ErrInvalidDeletionReceipt
	}
	scope, err := audit.NewReviewScope(record.TenantID, record.RepositoryID, record.ReviewRunID)
	if err != nil {
		return DeletionReceipt{}, false, ErrInvalidDeletionReceipt
	}
	receipt := DeletionReceipt{
		identity: record.Identity, scope: scope, artifactIdentity: record.ArtifactIdentity,
		payloadDigest: record.PayloadDigest, authorizationIdentity: record.AuthorizationIdentity,
		deletedAtMillis: record.DeletedAtMilliseconds,
	}
	if receipt.Validate() != nil {
		return DeletionReceipt{}, false, ErrInvalidDeletionReceipt
	}
	return receipt, record.Completed, nil
}
