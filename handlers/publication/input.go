package publication

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"io"
	"sort"
	"time"
)

var ErrInvalidPublicationInput = errors.New("invalid publication input")

type Input struct {
	identity, publisherID, changeID string
	repository                      evidence.RepositoryIdentity
	head                            evidence.RevisionIdentity
}

func NewInput(publisherID string, repository evidence.RepositoryIdentity, changeID string, head evidence.RevisionIdentity) (Input, error) {
	target, err := review.NewPublicationTarget(publisherID, repository, changeID, head)
	if err != nil {
		return Input{}, ErrInvalidPublicationInput
	}
	input := Input{publisherID: publisherID, repository: repository, changeID: changeID, head: head}
	input.identity = deriveInputIdentity(input)
	if input.identity == "" || target.Identity() == "" {
		return Input{}, ErrInvalidPublicationInput
	}
	return input, nil
}
func (i Input) Identity() string { return i.identity }
func (i Input) Target() (review.PublicationTarget, error) {
	return review.NewPublicationTarget(i.publisherID, i.repository, i.changeID, i.head)
}

type inputWire struct {
	Contract            string   `json:"contract"`
	SchemaVersion       int      `json:"schema_version"`
	Identity            string   `json:"identity"`
	PublisherID         string   `json:"publisher_id"`
	RepositoryAuthority string   `json:"repository_authority"`
	RepositoryNamespace []string `json:"repository_namespace"`
	RepositoryName      string   `json:"repository_name"`
	RepositoryIdentity  string   `json:"repository_identity"`
	ChangeID            string   `json:"change_id"`
	HeadKind            string   `json:"head_kind"`
	HeadAlgorithm       string   `json:"head_algorithm"`
	HeadDigest          string   `json:"head_digest"`
	HeadIdentity        string   `json:"head_identity"`
}

func toInputWire(i Input) inputWire {
	return inputWire{"open-trestle/publication-input", 1, i.identity, i.publisherID, i.repository.Authority(), i.repository.Namespace(), i.repository.Name(), i.repository.Identity(), i.changeID, string(i.head.Kind()), string(i.head.Algorithm()), i.head.Digest(), i.head.Identity()}
}
func deriveInputIdentity(i Input) string {
	wire := toInputWire(i)
	wire.Identity = ""
	encoded, _ := json.Marshal(wire)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func EncodeInput(i Input) ([]byte, error) {
	target, err := i.Target()
	if err != nil || target.Validate() != nil || i.identity != deriveInputIdentity(i) {
		return nil, ErrInvalidPublicationInput
	}
	return json.Marshal(toInputWire(i))
}
func ParseInput(encoded []byte) (Input, error) {
	if len(encoded) == 0 || len(encoded) > 64<<10 {
		return Input{}, ErrInvalidPublicationInput
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire inputWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return Input{}, ErrInvalidPublicationInput
	}
	canonical, _ := json.Marshal(wire)
	if !bytes.Equal(canonical, encoded) || wire.Contract != "open-trestle/publication-input" || wire.SchemaVersion != 1 {
		return Input{}, ErrInvalidPublicationInput
	}
	repository, err := evidence.NewRepositoryIdentity(wire.RepositoryAuthority, wire.RepositoryNamespace, wire.RepositoryName)
	if err != nil || repository.Identity() != wire.RepositoryIdentity {
		return Input{}, ErrInvalidPublicationInput
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKind(wire.HeadKind), evidence.RevisionAlgorithm(wire.HeadAlgorithm), wire.HeadDigest)
	if err != nil || head.Identity() != wire.HeadIdentity {
		return Input{}, ErrInvalidPublicationInput
	}
	input, err := NewInput(wire.PublisherID, repository, wire.ChangeID, head)
	if err != nil || input.Identity() != wire.Identity {
		return Input{}, ErrInvalidPublicationInput
	}
	return input, nil
}
func NewInputArtifact(scope audit.ReviewScope, input Input, classification artifact.Classification, protection artifact.Protection, provenance []string, created, expires time.Time) (artifact.Artifact, error) {
	payload, err := EncodeInput(input)
	if err != nil {
		return artifact.Artifact{}, err
	}
	canonical := append([]string(nil), provenance...)
	sort.Strings(canonical)
	return artifact.New(scope, artifact.KindTaskInput, "application/json", classification, artifact.OriginHost, protection, canonical, payload, created, expires)
}
