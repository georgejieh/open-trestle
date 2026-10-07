package runtimecatalog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

var (
	ErrInvalidLocalFullReview  = errors.New("invalid local full review")
	ErrLocalFullReviewConflict = errors.New("local full review conflict")
	ErrLocalFullReviewExpired  = errors.New("local full review expired")
)

// LocalFullReviewIntent binds expected policy identities without conveying source, route, or credential authority.
type LocalFullReviewIntent struct {
	base                                                                     LocalDeterministicReviewIntent
	reviewPolicyIdentity, inventoryIdentity, runtimePolicyIdentity, identity string
}

func NewLocalFullReviewIntent(scope audit.ReviewScope, repository evidence.RepositoryIdentity, base, head evidence.RevisionIdentity, reviewPolicyIdentity, inventoryIdentity, runtimePolicyIdentity string, createdAt time.Time) (LocalFullReviewIntent, error) {
	canonical, err := NewLocalDeterministicReviewIntent(scope, repository, base, head, createdAt)
	if err != nil || controlplane.ValidateHandlerIdentity(reviewPolicyIdentity) != nil || controlplane.ValidateHandlerIdentity(inventoryIdentity) != nil || controlplane.ValidateHandlerIdentity(runtimePolicyIdentity) != nil {
		return LocalFullReviewIntent{}, ErrInvalidLocalFullReview
	}
	value := LocalFullReviewIntent{base: canonical, reviewPolicyIdentity: reviewPolicyIdentity, inventoryIdentity: inventoryIdentity, runtimePolicyIdentity: runtimePolicyIdentity}
	value.identity = fullReviewIntentIdentity(value)
	return value, nil
}
func (i LocalFullReviewIntent) Identity() string                        { return i.identity }
func (i LocalFullReviewIntent) Scope() audit.ReviewScope                { return i.base.Scope() }
func (i LocalFullReviewIntent) Repository() evidence.RepositoryIdentity { return i.base.Repository() }
func (i LocalFullReviewIntent) BaseRevision() evidence.RevisionIdentity { return i.base.BaseRevision() }
func (i LocalFullReviewIntent) HeadRevision() evidence.RevisionIdentity { return i.base.HeadRevision() }
func (i LocalFullReviewIntent) CreatedAt() time.Time                    { return i.base.CreatedAt() }
func (i LocalFullReviewIntent) ReviewPolicyIdentity() string            { return i.reviewPolicyIdentity }
func (i LocalFullReviewIntent) InventoryIdentity() string               { return i.inventoryIdentity }
func (i LocalFullReviewIntent) RuntimePolicyIdentity() string           { return i.runtimePolicyIdentity }
func (i LocalFullReviewIntent) String() string                          { return "local full review intent" }
func (i LocalFullReviewIntent) GoString() string {
	return "runtimecatalog.LocalFullReviewIntent{<redacted>}"
}
func (i LocalFullReviewIntent) Validate() error {
	rebuilt, err := NewLocalFullReviewIntent(i.Scope(), i.Repository(), i.BaseRevision(), i.HeadRevision(), i.reviewPolicyIdentity, i.inventoryIdentity, i.runtimePolicyIdentity, i.CreatedAt())
	if err != nil || rebuilt.identity != i.identity {
		return ErrInvalidLocalFullReview
	}
	return nil
}

type localFullReviewIntentWire struct {
	localDeterministicIntentWire
	ReviewPolicyIdentity  string `json:"review_policy_identity"`
	InventoryIdentity     string `json:"inventory_identity"`
	RuntimePolicyIdentity string `json:"runtime_policy_identity"`
}

func fullReviewIntentWireValue(i LocalFullReviewIntent) localFullReviewIntentWire {
	base := localDeterministicIntentWireValue(i.base)
	base.Contract = "open-trestle/local-full-review-intent"
	base.Identity = i.identity
	return localFullReviewIntentWire{base, i.reviewPolicyIdentity, i.inventoryIdentity, i.runtimePolicyIdentity}
}
func fullReviewIntentIdentity(i LocalFullReviewIntent) string {
	wire := fullReviewIntentWireValue(i)
	wire.Identity = ""
	encoded, _ := json.Marshal(wire)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func EncodeLocalFullReviewIntent(i LocalFullReviewIntent) ([]byte, error) {
	if i.Validate() != nil {
		return nil, ErrInvalidLocalFullReview
	}
	encoded, err := json.Marshal(fullReviewIntentWireValue(i))
	if err != nil || len(encoded) > maximumLocalDeterministicIntentBytes {
		return nil, ErrInvalidLocalFullReview
	}
	return encoded, nil
}
func ParseLocalFullReviewIntent(encoded []byte) (LocalFullReviewIntent, error) {
	if len(encoded) == 0 || len(encoded) > maximumLocalDeterministicIntentBytes {
		return LocalFullReviewIntent{}, ErrInvalidLocalFullReview
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire localFullReviewIntentWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF || wire.Contract != "open-trestle/local-full-review-intent" || wire.SchemaVersion != 1 {
		return LocalFullReviewIntent{}, ErrInvalidLocalFullReview
	}
	scope, err := audit.NewReviewScope(wire.TenantID, wire.RepositoryID, wire.ReviewRunID)
	if err != nil {
		return LocalFullReviewIntent{}, ErrInvalidLocalFullReview
	}
	repository, err := evidence.NewRepositoryIdentity(wire.RepositoryAuthority, wire.RepositoryNamespace, wire.RepositoryName)
	if err != nil {
		return LocalFullReviewIntent{}, ErrInvalidLocalFullReview
	}
	base, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, wire.RevisionAlgorithm, wire.BaseRevisionDigest)
	if err != nil {
		return LocalFullReviewIntent{}, ErrInvalidLocalFullReview
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, wire.RevisionAlgorithm, wire.HeadRevisionDigest)
	if err != nil {
		return LocalFullReviewIntent{}, ErrInvalidLocalFullReview
	}
	intent, err := NewLocalFullReviewIntent(scope, repository, base, head, wire.ReviewPolicyIdentity, wire.InventoryIdentity, wire.RuntimePolicyIdentity, time.UnixMilli(wire.CreatedAtUnixMilliseconds))
	if err != nil || intent.Identity() != wire.Identity {
		return LocalFullReviewIntent{}, ErrInvalidLocalFullReview
	}
	canonical, _ := EncodeLocalFullReviewIntent(intent)
	if !bytes.Equal(canonical, encoded) {
		return LocalFullReviewIntent{}, ErrInvalidLocalFullReview
	}
	return intent, nil
}
