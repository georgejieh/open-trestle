package artifact

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/georgejieh/open-trestle/audit"
)

// Delete performs an authorized, intent-first physical deletion in object storage.
func (s *EnvelopeStore) Delete(ctx context.Context, authorization DeletionAuthorization, at time.Time) (DeletionReceipt, error) {
	if err := validateContext(ctx); err != nil {
		return DeletionReceipt{}, err
	}
	if authorization.Validate() != nil {
		return DeletionReceipt{}, ErrInvalidDeletionAuthorization
	}
	if s == nil || nilInterface(s.backend) || nilInterface(s.keys) {
		return DeletionReceipt{}, ErrInvalidRemoteStore
	}
	if s.admission != nil {
		return DeletionReceipt{}, ErrErasureAuthorizationV2Required
	}
	scope, identity := authorization.Scope(), authorization.ArtifactIdentity()
	if receipt, found, err := s.readRemoteDeletion(ctx, s.deletionReceiptObjectKey(scope, identity), scope, identity, true); err != nil {
		return DeletionReceipt{}, err
	} else if found {
		if receipt.AuthorizationIdentity() != authorization.Identity() {
			return DeletionReceipt{}, ErrArtifactDeleted
		}
		return receipt, nil
	}
	if receipt, found, err := s.readRemoteDeletion(ctx, s.deletionIntentObjectKey(scope, identity), scope, identity, false); err != nil {
		return DeletionReceipt{}, err
	} else if found {
		if err := s.completeRemoteDeletion(ctx, receipt); err != nil {
			return DeletionReceipt{}, err
		}
		if receipt.AuthorizationIdentity() != authorization.Identity() {
			return DeletionReceipt{}, ErrArtifactDeleted
		}
		return receipt, nil
	}
	value, found, err := s.readArtifact(ctx, scope, identity)
	if err != nil {
		return DeletionReceipt{}, err
	}
	if !found {
		return DeletionReceipt{}, ErrArtifactNotFound
	}
	if !authorization.Allows(value, at) {
		return DeletionReceipt{}, ErrDeletionNotAllowed
	}
	receipt := newDeletionReceipt(value, authorization, at)
	intent, _ := encodeRemoteDeletion(receipt, false)
	created, err := s.backend.Create(ctx, s.deletionIntentObjectKey(scope, identity), intent, hashBytes(intent))
	if err != nil {
		return DeletionReceipt{}, mapRemoteMutationError(err)
	}
	existing, found, verifyErr := s.readRemoteDeletion(ctx, s.deletionIntentObjectKey(scope, identity), scope, identity, false)
	if verifyErr != nil {
		return DeletionReceipt{}, verifyErr
	}
	if !found {
		return DeletionReceipt{}, ErrRemoteStoreConflict
	}
	if !created {
		receipt = existing
	} else if existing.Identity() != receipt.Identity() {
		return DeletionReceipt{}, ErrRemoteStoreConflict
	}
	if err := s.completeRemoteDeletion(ctx, receipt); err != nil {
		return DeletionReceipt{}, err
	}
	if receipt.AuthorizationIdentity() != authorization.Identity() {
		return DeletionReceipt{}, ErrArtifactDeleted
	}
	return receipt, nil
}

// RecoverDeletion completes one known prepared deletion without requiring the expired authority again.
func (s *EnvelopeStore) RecoverDeletion(ctx context.Context, scope audit.ReviewScope, identity string) (DeletionReceipt, bool, error) {
	if err := validateContext(ctx); err != nil {
		return DeletionReceipt{}, false, err
	}
	if scope.Validate() != nil || !validDigest(identity) {
		return DeletionReceipt{}, false, ErrInvalidStore
	}
	if s == nil || nilInterface(s.backend) || nilInterface(s.keys) {
		return DeletionReceipt{}, false, ErrInvalidRemoteStore
	}
	if s.admission != nil {
		return DeletionReceipt{}, false, ErrErasureCertificationAPIRequired
	}
	if receipt, found, err := s.readRemoteDeletion(ctx, s.deletionReceiptObjectKey(scope, identity), scope, identity, true); err != nil || found {
		return receipt, found, err
	}
	receipt, found, err := s.readRemoteDeletion(ctx, s.deletionIntentObjectKey(scope, identity), scope, identity, false)
	if err != nil || !found {
		return DeletionReceipt{}, found, err
	}
	if err := s.completeRemoteDeletion(ctx, receipt); err != nil {
		return DeletionReceipt{}, false, err
	}
	return receipt, true, nil
}

func (s *EnvelopeStore) completeRemoteDeletion(ctx context.Context, receipt DeletionReceipt) error {
	key := s.artifactObjectKey(receipt.Scope(), receipt.ArtifactIdentity())
	object, err := s.backend.Read(ctx, key, maxRemoteArtifactBytes)
	if err == nil {
		if object.validate(maxRemoteArtifactBytes) != nil {
			return ErrCorruptArtifact
		}
		value, decryptErr := s.decryptRemoteObject(ctx, receipt.Scope(), receipt.ArtifactIdentity(), object)
		if decryptErr != nil {
			return decryptErr
		}
		if value.PayloadDigest() != receipt.PayloadDigest() {
			return ErrCorruptArtifact
		}
		if _, deleteErr := s.backend.Delete(ctx, key, object.Version); deleteErr != nil {
			return mapRemoteMutationError(deleteErr)
		}
		if _, verifyErr := s.backend.Read(ctx, key, maxRemoteArtifactBytes); verifyErr == nil {
			return ErrRemoteStoreConflict
		} else if !errors.Is(verifyErr, ErrRemoteObjectNotFound) {
			return mapRemoteReadError(verifyErr)
		}
	} else if !errors.Is(err, ErrRemoteObjectNotFound) {
		return mapRemoteReadError(err)
	}
	completed, _ := encodeRemoteDeletion(receipt, true)
	_, err = s.backend.Create(ctx, s.deletionReceiptObjectKey(receipt.Scope(), receipt.ArtifactIdentity()), completed, hashBytes(completed))
	if err != nil {
		return mapRemoteMutationError(err)
	}
	existing, found, err := s.readRemoteDeletion(
		ctx, s.deletionReceiptObjectKey(receipt.Scope(), receipt.ArtifactIdentity()),
		receipt.Scope(), receipt.ArtifactIdentity(), true,
	)
	if err != nil {
		return err
	}
	if !found || existing.Identity() != receipt.Identity() {
		return ErrRemoteStoreConflict
	}
	return nil
}

func (s *EnvelopeStore) deletionExists(ctx context.Context, scope audit.ReviewScope, identity string) (bool, error) {
	if _, found, err := s.readRemoteDeletion(ctx, s.deletionReceiptObjectKey(scope, identity), scope, identity, true); err != nil || found {
		return found, err
	}
	_, found, err := s.readRemoteDeletion(ctx, s.deletionIntentObjectKey(scope, identity), scope, identity, false)
	return found, err
}

func (s *EnvelopeStore) readRemoteDeletion(
	ctx context.Context,
	key string,
	scope audit.ReviewScope,
	identity string,
	wantCompleted bool,
) (DeletionReceipt, bool, error) {
	object, err := s.backend.Read(ctx, key, maxEncodedDeletionRecordBytes)
	if errors.Is(err, ErrRemoteObjectNotFound) {
		return DeletionReceipt{}, false, nil
	}
	if err != nil {
		return DeletionReceipt{}, false, mapRemoteReadError(err)
	}
	if object.validate(maxEncodedDeletionRecordBytes) != nil {
		return DeletionReceipt{}, false, ErrCorruptArtifact
	}
	receipt, completed, err := parseRemoteDeletion(object.Content, scope)
	if err != nil || completed != wantCompleted || receipt.ArtifactIdentity() != identity {
		return DeletionReceipt{}, false, ErrCorruptArtifact
	}
	return receipt, true, nil
}

type remoteDeletionRecord struct {
	Contract              string `json:"contract"`
	SchemaVersion         int    `json:"schema_version"`
	Completed             bool   `json:"completed"`
	Identity              string `json:"identity"`
	ScopeIdentity         string `json:"scope_identity"`
	ArtifactIdentity      string `json:"artifact_identity"`
	PayloadDigest         string `json:"payload_digest"`
	AuthorizationIdentity string `json:"authorization_identity"`
	DeletedAtMilliseconds int64  `json:"deleted_at_milliseconds"`
}

func encodeRemoteDeletion(receipt DeletionReceipt, completed bool) ([]byte, error) {
	if receipt.Validate() != nil {
		return nil, ErrInvalidDeletionReceipt
	}
	return json.Marshal(remoteDeletionRecord{
		Contract: "open-trestle/remote-artifact-deletion", SchemaVersion: 1, Completed: completed,
		Identity: receipt.Identity(), ScopeIdentity: receipt.Scope().Identity(),
		ArtifactIdentity: receipt.ArtifactIdentity(), PayloadDigest: receipt.PayloadDigest(),
		AuthorizationIdentity: receipt.AuthorizationIdentity(), DeletedAtMilliseconds: receipt.deletedAtMillis,
	})
}

func parseRemoteDeletion(encoded []byte, scope audit.ReviewScope) (DeletionReceipt, bool, error) {
	if len(encoded) == 0 || len(encoded) > maxEncodedDeletionRecordBytes || scope.Validate() != nil {
		return DeletionReceipt{}, false, ErrInvalidDeletionReceipt
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var record remoteDeletionRecord
	if err := decoder.Decode(&record); err != nil {
		return DeletionReceipt{}, false, ErrInvalidDeletionReceipt
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return DeletionReceipt{}, false, ErrInvalidDeletionReceipt
	}
	canonical, _ := json.Marshal(record)
	if !bytes.Equal(canonical, encoded) || record.Contract != "open-trestle/remote-artifact-deletion" || record.SchemaVersion != 1 || record.ScopeIdentity != scope.Identity() {
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
