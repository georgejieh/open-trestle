package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	maxPublisherIDBytes         = 64
	maxPublicationChangeIDBytes = 128
)

var (
	// ErrInvalidPublisherID identifies a malformed publisher implementation ID.
	ErrInvalidPublisherID = errors.New("invalid source-control publisher ID")
	// ErrInvalidPublicationRepository identifies a malformed repository identity.
	ErrInvalidPublicationRepository = errors.New("invalid publication repository")
	// ErrInvalidPublicationChangeID identifies an unsafe or malformed change ID.
	ErrInvalidPublicationChangeID = errors.New("invalid publication change ID")
	// ErrInvalidPublicationRevision identifies a malformed immutable head revision.
	ErrInvalidPublicationRevision = errors.New("invalid publication revision")
	// ErrInvalidPublicationTargetIdentity identifies target content inconsistent with its identity.
	ErrInvalidPublicationTargetIdentity = errors.New("invalid publication target identity")
)

// ValidatePublisherID verifies one stable publisher implementation identifier.
func ValidatePublisherID(value string) error {
	if !validPublicationToken(value, maxPublisherIDBytes) {
		return ErrInvalidPublisherID
	}
	return nil
}

// PublicationTarget identifies one exact source-control change and immutable head revision.
type PublicationTarget struct {
	identity     string
	publisherID  string
	repository   evidence.RepositoryIdentity
	changeID     string
	headRevision evidence.RevisionIdentity
}

// NewPublicationTarget creates a content-addressed source-control write target.
func NewPublicationTarget(publisherID string, repository evidence.RepositoryIdentity, changeID string, headRevision evidence.RevisionIdentity) (PublicationTarget, error) {
	target := PublicationTarget{
		publisherID: strings.Clone(publisherID), repository: repository,
		changeID: strings.Clone(changeID), headRevision: headRevision,
	}
	if err := target.validateFields(); err != nil {
		return PublicationTarget{}, err
	}
	target.identity = derivePublicationTargetIdentity(target)
	return target, nil
}

func (t PublicationTarget) Identity() string                                { return t.identity }
func (t PublicationTarget) PublisherID() string                             { return t.publisherID }
func (t PublicationTarget) RepositoryIdentity() evidence.RepositoryIdentity { return t.repository }
func (t PublicationTarget) ChangeID() string                                { return t.changeID }
func (t PublicationTarget) HeadRevision() evidence.RevisionIdentity         { return t.headRevision }
func (t PublicationTarget) String() string                                  { return "source-control publication target" }
func (t PublicationTarget) GoString() string                                { return "review.PublicationTarget{<redacted>}" }
func (t PublicationTarget) Format(state fmt.State, verb rune) {
	formatted := "source-control publication target"
	if verb == 'q' {
		formatted = `"source-control publication target"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = "review.PublicationTarget{<redacted>}"
	}
	_, _ = state.Write([]byte(formatted))
}

// Validate verifies component identities, stable labels, and content identity.
func (t PublicationTarget) Validate() error {
	if err := t.validateFields(); err != nil {
		return err
	}
	if t.identity != derivePublicationTargetIdentity(t) {
		return ErrInvalidPublicationTargetIdentity
	}
	return nil
}

func (t PublicationTarget) validateFields() error {
	if !validPublicationToken(t.publisherID, maxPublisherIDBytes) {
		return ErrInvalidPublisherID
	}
	repository, err := evidence.NewRepositoryIdentity(t.repository.Authority(), t.repository.Namespace(), t.repository.Name())
	if err != nil || repository.Identity() != t.repository.Identity() {
		return ErrInvalidPublicationRepository
	}
	if !validPublicationToken(t.changeID, maxPublicationChangeIDBytes) {
		return ErrInvalidPublicationChangeID
	}
	revision, err := evidence.NewRevisionIdentity(t.headRevision.Kind(), t.headRevision.Algorithm(), t.headRevision.Digest())
	if err != nil || revision.Identity() != t.headRevision.Identity() {
		return ErrInvalidPublicationRevision
	}
	return nil
}

func validPublicationToken(value string, maximum int) bool {
	if len(value) == 0 || len(value) > maximum || !isPublicationAlphaNumeric(value[0]) || !isPublicationAlphaNumeric(value[len(value)-1]) {
		return false
	}
	for index := 1; index < len(value)-1; index++ {
		character := value[index]
		if isPublicationAlphaNumeric(character) || character == '-' || character == '_' || character == '.' || character == ':' {
			continue
		}
		return false
	}
	return true
}

func isPublicationAlphaNumeric(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= '0' && value <= '9'
}

func derivePublicationTargetIdentity(target PublicationTarget) string {
	preimage := struct {
		Contract   string `json:"contract"`
		Version    int    `json:"version"`
		Publisher  string `json:"publisher"`
		Repository string `json:"repository"`
		Change     string `json:"change"`
		Head       string `json:"head"`
	}{
		Contract: "open-trestle/publication-target", Version: 1,
		Publisher: target.publisherID, Repository: target.repository.Identity(),
		Change: target.changeID, Head: target.headRevision.Identity(),
	}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
