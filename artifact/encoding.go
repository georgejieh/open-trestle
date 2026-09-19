package artifact

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"io"
	"time"
)

const maxEncodedArtifactBytes = (22 << 20)

var ErrInvalidEncoding = errors.New("invalid runtime artifact encoding")

type record struct {
	Contract              string   `json:"contract"`
	SchemaVersion         int      `json:"schema_version"`
	Identity              string   `json:"identity"`
	TenantID              string   `json:"tenant_id"`
	RepositoryID          string   `json:"repository_id"`
	ReviewRunID           string   `json:"review_run_id"`
	Kind                  string   `json:"kind"`
	MediaType             string   `json:"media_type"`
	Classification        string   `json:"classification"`
	Origin                string   `json:"origin"`
	Protection            string   `json:"protection"`
	Provenance            []string `json:"provenance"`
	PayloadDigest         string   `json:"payload_digest"`
	Payload               []byte   `json:"payload"`
	CreatedAtMilliseconds int64    `json:"created_at_milliseconds"`
	ExpiresAtMilliseconds int64    `json:"expires_at_milliseconds"`
}

func Encode(value Artifact) ([]byte, error) {
	if err := value.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(toRecord(value))
	if err != nil || len(encoded) > maxEncodedArtifactBytes {
		return nil, ErrInvalidEncoding
	}
	return encoded, nil
}
func Parse(encoded []byte) (Artifact, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedArtifactBytes {
		return Artifact{}, ErrInvalidEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var value record
	if err := decoder.Decode(&value); err != nil {
		return Artifact{}, ErrInvalidEncoding
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return Artifact{}, ErrInvalidEncoding
	}
	canonical, _ := json.Marshal(value)
	if !bytes.Equal(canonical, encoded) || value.Contract != "open-trestle/runtime-artifact" || value.SchemaVersion != 1 {
		return Artifact{}, ErrInvalidEncoding
	}
	scope, err := audit.NewReviewScope(value.TenantID, value.RepositoryID, value.ReviewRunID)
	if err != nil {
		return Artifact{}, ErrInvalidEncoding
	}
	kind, classification, origin, protection, err := parseEnums(value.Kind, value.Classification, value.Origin, value.Protection)
	if err != nil {
		return Artifact{}, err
	}
	artifact, err := New(
		scope, kind, value.MediaType, classification, origin, protection,
		value.Provenance, value.Payload,
		time.UnixMilli(value.CreatedAtMilliseconds), time.UnixMilli(value.ExpiresAtMilliseconds),
	)
	if err != nil {
		return Artifact{}, err
	}
	if artifact.identity != value.Identity || artifact.payloadDigest != value.PayloadDigest {
		return Artifact{}, ErrInvalidArtifactIdentity
	}
	reencoded, _ := Encode(artifact)
	if !bytes.Equal(reencoded, encoded) {
		return Artifact{}, ErrInvalidEncoding
	}
	return artifact, nil
}
func toRecord(value Artifact) record {
	return record{
		Contract: "open-trestle/runtime-artifact", SchemaVersion: 1,
		Identity: value.identity, TenantID: value.scope.TenantID(),
		RepositoryID: value.scope.RepositoryID(), ReviewRunID: value.scope.ReviewRunID(),
		Kind: value.kind.String(), MediaType: value.mediaType,
		Classification: value.classification.String(), Origin: value.origin.String(),
		Protection: value.protection.String(), Provenance: value.Provenance(),
		PayloadDigest: value.payloadDigest, Payload: value.Payload(),
		CreatedAtMilliseconds: value.createdAtMillis, ExpiresAtMilliseconds: value.expiresAtMillis,
	}
}
func parseEnums(kindValue, classificationValue, originValue, protectionValue string) (Kind, Classification, Origin, Protection, error) {
	var kind Kind
	for candidate := KindSourceSnapshot; candidate <= KindInvestigationToolResult; candidate++ {
		if candidate.String() == kindValue {
			kind = candidate
		}
	}
	var classification Classification
	for candidate := ClassificationPublic; candidate <= ClassificationRestricted; candidate++ {
		if candidate.String() == classificationValue {
			classification = candidate
		}
	}
	var origin Origin
	for candidate := OriginHost; candidate <= OriginMemory; candidate++ {
		if candidate.String() == originValue {
			origin = candidate
		}
	}
	var protection Protection
	for candidate := ProtectionProcessPrivate; candidate <= ProtectionEnvelopeEncrypted; candidate++ {
		if candidate.String() == protectionValue {
			protection = candidate
		}
	}
	if kind == 0 || classification == 0 || origin == 0 || protection == 0 {
		return 0, 0, 0, 0, ErrInvalidEncoding
	}
	return kind, classification, origin, protection, nil
}
