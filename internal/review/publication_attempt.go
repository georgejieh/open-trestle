package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	// ErrInvalidPublicationAttempt identifies malformed operation lineage.
	ErrInvalidPublicationAttempt = errors.New("invalid publication attempt authorization")
	// ErrInvalidPublicationAttemptIdentity identifies attempt content inconsistent with its identity.
	ErrInvalidPublicationAttemptIdentity = errors.New("invalid publication attempt authorization identity")
)

// PublicationAttemptAuthorization binds the single dispatch of a publication operation to its claim.
type PublicationAttemptAuthorization struct {
	identity              string
	authorizationIdentity string
	claimIdentity         string
}

func NewInitialPublicationAttemptAuthorization(authorization PublicationAuthorization, claim PublicationClaim) (PublicationAttemptAuthorization, error) {
	if err := validatePublicationOperationBinding(authorization, claim); err != nil {
		return PublicationAttemptAuthorization{}, err
	}
	attempt := PublicationAttemptAuthorization{authorizationIdentity: authorization.Identity(), claimIdentity: claim.Identity()}
	attempt.identity = derivePublicationAttemptIdentity(attempt)
	return attempt, nil
}
func (a PublicationAttemptAuthorization) Identity() string { return a.identity }
func (a PublicationAttemptAuthorization) AuthorizationIdentity() string {
	return a.authorizationIdentity
}
func (a PublicationAttemptAuthorization) ClaimIdentity() string { return a.claimIdentity }
func (a PublicationAttemptAuthorization) Validate() error {
	if !validCandidateDigest(a.authorizationIdentity) || !validCandidateDigest(a.claimIdentity) {
		return ErrInvalidPublicationAttempt
	}
	if a.identity != derivePublicationAttemptIdentity(a) {
		return ErrInvalidPublicationAttemptIdentity
	}
	return nil
}
func (a PublicationAttemptAuthorization) String() string { return "publication attempt authorization" }
func (a PublicationAttemptAuthorization) GoString() string {
	return "review.PublicationAttemptAuthorization{<redacted>}"
}
func (a PublicationAttemptAuthorization) Format(state fmt.State, verb rune) {
	writeRedactedReviewFormat(state, verb, "publication attempt authorization", "review.PublicationAttemptAuthorization{<redacted>}")
}

func validatePublicationOperationBinding(authorization PublicationAuthorization, claim PublicationClaim) error {
	if err := authorization.Validate(); err != nil {
		return err
	}
	if err := claim.Validate(); err != nil {
		return err
	}
	matchingAuthorization := claim.AuthorizationIdentity() == authorization.Identity()
	matchingPlan := claim.PlanIdentity() == authorization.PlanIdentity()
	matchingTarget := claim.TargetIdentity() == authorization.TargetIdentity()
	matchingKey := claim.IdempotencyKey() == authorization.IdempotencyKey()
	if !matchingAuthorization || !matchingPlan || !matchingTarget || !matchingKey {
		return ErrInvalidPublicationAttempt
	}
	return nil
}

// derivePublicationAttemptIdentity keeps the original preimage layout so identities already
// recorded in run journals and audit ledgers still verify.
func derivePublicationAttemptIdentity(attempt PublicationAttemptAuthorization) string {
	preimage := struct {
		Contract      string `json:"contract"`
		Version       int    `json:"version"`
		Kind          string `json:"kind"`
		Authorization string `json:"authorization"`
		Claim         string `json:"claim"`
		Number        uint8  `json:"number"`
		Prior         string `json:"prior"`
		Gate          string `json:"gate"`
		NotBefore     int64  `json:"not_before"`
	}{
		Contract: "open-trestle/publication-attempt-authorization", Version: 1, Kind: "initial",
		Authorization: attempt.authorizationIdentity, Claim: attempt.claimIdentity, Number: 1,
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
