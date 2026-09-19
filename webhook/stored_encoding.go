package webhook

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const maxEncodedStoredDeliveryBytes = (2 << 20) + 4096

var ErrInvalidStoredDeliveryEncoding = errors.New("invalid stored webhook delivery encoding")

type storedDeliveryRecord struct {
	Contract               string          `json:"contract"`
	SchemaVersion          int             `json:"schema_version"`
	AcceptanceIdentity     string          `json:"acceptance_identity"`
	AcceptedAtMilliseconds int64           `json:"accepted_at_milliseconds"`
	Delivery               json.RawMessage `json:"delivery"`
}

// EncodeStoredDelivery returns the bounded canonical durable inbox representation.
func EncodeStoredDelivery(stored StoredDelivery) ([]byte, error) {
	if err := stored.Validate(); err != nil {
		return nil, err
	}
	delivery, err := EncodeVerifiedDelivery(stored.delivery)
	if err != nil {
		return nil, err
	}
	record := storedDeliveryRecord{
		Contract: "open-trestle/stored-webhook-delivery", SchemaVersion: 1,
		AcceptanceIdentity:     stored.receipt.Identity(),
		AcceptedAtMilliseconds: stored.receipt.acceptedAtMillis, Delivery: delivery,
	}
	encoded, err := json.Marshal(record)
	if err != nil || len(encoded) > maxEncodedStoredDeliveryBytes {
		return nil, ErrInvalidStoredDeliveryEncoding
	}
	return encoded, nil
}

// ParseStoredDelivery verifies and reconstructs the canonical durable inbox representation.
func ParseStoredDelivery(encoded []byte) (StoredDelivery, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedStoredDeliveryBytes {
		return StoredDelivery{}, ErrInvalidStoredDeliveryEncoding
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record storedDeliveryRecord
	if err := decoder.Decode(&record); err != nil {
		return StoredDelivery{}, ErrInvalidStoredDeliveryEncoding
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return StoredDelivery{}, ErrInvalidStoredDeliveryEncoding
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, encoded) || record.Contract != "open-trestle/stored-webhook-delivery" || record.SchemaVersion != 1 {
		return StoredDelivery{}, ErrInvalidStoredDeliveryEncoding
	}
	delivery, err := ParseVerifiedDelivery(record.Delivery)
	if err != nil {
		return StoredDelivery{}, err
	}
	receipt, err := newAcceptanceReceipt(delivery, time.UnixMilli(record.AcceptedAtMilliseconds))
	if err != nil || receipt.Identity() != record.AcceptanceIdentity {
		return StoredDelivery{}, ErrInvalidStoredDeliveryEncoding
	}
	stored := StoredDelivery{delivery: delivery, receipt: receipt}
	if err := stored.Validate(); err != nil {
		return StoredDelivery{}, err
	}
	return stored, nil
}
