package webhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const maxEncodedVerifiedDeliveryBytes = 2 << 20

var ErrInvalidVerifiedDeliveryEncoding = errors.New("invalid verified webhook delivery encoding")

type verifiedDeliveryRecord struct {
	Contract               string `json:"contract"`
	SchemaVersion          int    `json:"schema_version"`
	Identity               string `json:"identity"`
	DeduplicationKey       string `json:"deduplication_key"`
	TenantID               string `json:"tenant_id"`
	RepositoryID           string `json:"repository_id"`
	Source                 string `json:"source"`
	DeliveryID             string `json:"delivery_id"`
	EventType              string `json:"event_type"`
	Action                 string `json:"action"`
	VerifierIdentity       string `json:"verifier_identity"`
	BodyDigest             string `json:"body_digest"`
	Payload                []byte `json:"payload"`
	ReceivedAtMilliseconds int64  `json:"received_at_milliseconds"`
}

func EncodeVerifiedDelivery(delivery VerifiedDelivery) ([]byte, error) {
	if err := delivery.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(deliveryToRecord(delivery))
	if err != nil || len(encoded) > maxEncodedVerifiedDeliveryBytes {
		return nil, ErrInvalidVerifiedDeliveryEncoding
	}
	return encoded, nil
}
func ParseVerifiedDelivery(encoded []byte) (VerifiedDelivery, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedVerifiedDeliveryBytes {
		return VerifiedDelivery{}, ErrInvalidVerifiedDeliveryEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record verifiedDeliveryRecord
	if err := decoder.Decode(&record); err != nil {
		return VerifiedDelivery{}, ErrInvalidVerifiedDeliveryEncoding
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return VerifiedDelivery{}, ErrInvalidVerifiedDeliveryEncoding
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) || record.Contract != "open-trestle/verified-webhook-delivery" || record.SchemaVersion != 1 {
		return VerifiedDelivery{}, ErrInvalidVerifiedDeliveryEncoding
	}
	scope, err := NewRepositoryScope(record.TenantID, record.RepositoryID)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	source, err := parseSource(record.Source)
	if err != nil {
		return VerifiedDelivery{}, err
	}
	delivery, err := NewVerifiedDelivery(scope, source, record.DeliveryID, record.EventType, record.Action, record.VerifierIdentity, record.Payload, time.UnixMilli(record.ReceivedAtMilliseconds))
	if err != nil {
		return VerifiedDelivery{}, err
	}
	if delivery.identity != record.Identity || delivery.deduplicationKey != record.DeduplicationKey || delivery.bodyDigest != record.BodyDigest {
		return VerifiedDelivery{}, ErrInvalidVerifiedDeliveryIdentity
	}
	return delivery, nil
}
func deliveryToRecord(delivery VerifiedDelivery) verifiedDeliveryRecord {
	return verifiedDeliveryRecord{
		Contract: "open-trestle/verified-webhook-delivery", SchemaVersion: 1,
		Identity: delivery.identity, DeduplicationKey: delivery.deduplicationKey,
		TenantID: delivery.scope.TenantID(), RepositoryID: delivery.scope.RepositoryID(),
		Source: delivery.source.String(), DeliveryID: delivery.deliveryID,
		EventType: delivery.eventType, Action: delivery.action,
		VerifierIdentity: delivery.verifierIdentity, BodyDigest: delivery.bodyDigest,
		Payload: delivery.Payload(), ReceivedAtMilliseconds: delivery.receivedAtMillis,
	}
}
func parseSource(value string) (Source, error) {
	for source := SourceGitHub; source <= SourceForgejo; source++ {
		if source.String() == value {
			return source, nil
		}
	}
	return 0, ErrInvalidVerifiedDeliveryEncoding
}
