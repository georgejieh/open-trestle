package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

const maximumInputBytes = 16 << 10

var (
	// ErrInvalidInput identifies malformed or cross-wired source acquisition authority.
	ErrInvalidInput = errors.New("invalid source acquisition input")
	// ErrInvalidOutput identifies malformed source snapshot or file output.
	ErrInvalidOutput = errors.New("invalid source acquisition output")
	// ErrInvalidHandler identifies incomplete handler dependencies or identity.
	ErrInvalidHandler = errors.New("invalid source acquisition handler")
)

// Input authorizes one exact read-only complete-content acquisition.
type Input struct {
	identity   string
	repository evidence.RepositoryIdentity
	revision   evidence.RevisionIdentity
	adapter    evidence.SourceAdapterIdentity
}

// NewInput creates an immutable acquisition input for an exact repository revision and adapter.
func NewInput(
	repository evidence.RepositoryIdentity,
	revision evidence.RevisionIdentity,
	adapter evidence.SourceAdapterIdentity,
) (Input, error) {
	input := Input{repository: repository, revision: revision, adapter: adapter}
	if err := input.validateFields(); err != nil {
		return Input{}, err
	}
	input.identity = deriveInputIdentity(input)
	return input, nil
}

func (i Input) Identity() string                        { return i.identity }
func (i Input) Repository() evidence.RepositoryIdentity { return i.repository }
func (i Input) Revision() evidence.RevisionIdentity     { return i.revision }
func (i Input) Adapter() evidence.SourceAdapterIdentity { return i.adapter }
func (i Input) SourceAdapterIdentity() string           { return i.adapter.Identity() }
func (i Input) String() string                          { return "source acquisition input" }
func (i Input) GoString() string                        { return "source.Input{<redacted>}" }
func (i Input) Format(state fmt.State, verb rune) {
	writeSourceRedacted(state, verb, "source acquisition input", "source.Input{<redacted>}")
}
func (i Input) Validate() error {
	if err := i.validateFields(); err != nil {
		return err
	}
	if i.identity != deriveInputIdentity(i) {
		return ErrInvalidInput
	}
	return nil
}

func (i Input) validateFields() error {
	repository, err := evidence.NewRepositoryIdentity(i.repository.Authority(), i.repository.Namespace(), i.repository.Name())
	if err != nil || repository.Identity() != i.repository.Identity() {
		return ErrInvalidInput
	}
	revision, err := evidence.NewRevisionIdentity(i.revision.Kind(), i.revision.Algorithm(), i.revision.Digest())
	if err != nil || revision != i.revision {
		return ErrInvalidInput
	}
	adapter, err := evidence.NewSourceAdapterIdentity(i.adapter.Kind(), i.adapter.Name(), i.adapter.Version(), i.adapter.Capabilities())
	if err != nil || !sameAdapterIdentity(adapter, i.adapter) ||
		!adapter.HasCapability(evidence.SourceCapabilityReadManifest) ||
		!adapter.HasCapability(evidence.SourceCapabilityReadContent) {
		return ErrInvalidInput
	}
	return nil
}

func sameAdapterIdentity(first, second evidence.SourceAdapterIdentity) bool {
	return first.Identity() == second.Identity() && first.Kind() == second.Kind() &&
		first.Name() == second.Name() && first.Version() == second.Version() &&
		first.MajorVersion() == second.MajorVersion() && slices.Equal(first.Capabilities(), second.Capabilities())
}

type inputWire struct {
	Contract              string                             `json:"contract"`
	SchemaVersion         int                                `json:"schema_version"`
	Identity              string                             `json:"identity"`
	RepositoryAuthority   string                             `json:"repository_authority"`
	RepositoryNamespace   []string                           `json:"repository_namespace"`
	RepositoryName        string                             `json:"repository_name"`
	RevisionKind          evidence.RevisionKind              `json:"revision_kind"`
	RevisionAlgorithm     evidence.RevisionAlgorithm         `json:"revision_algorithm"`
	RevisionDigest        string                             `json:"revision_digest"`
	SourceAdapterIdentity string                             `json:"source_adapter_identity"`
	SourceAdapterKind     evidence.SourceAdapterKind         `json:"source_adapter_kind"`
	SourceAdapterName     string                             `json:"source_adapter_name"`
	SourceAdapterVersion  string                             `json:"source_adapter_version"`
	SourceCapabilities    []evidence.SourceAdapterCapability `json:"source_capabilities"`
	Artifact              string                             `json:"artifact"`
	Effect                string                             `json:"effect"`
}

// EncodeInput returns the one canonical JSON representation.
func EncodeInput(input Input) ([]byte, error) {
	if err := input.Validate(); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(inputWireValue(input))
	if err != nil || len(encoded) > maximumInputBytes {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

// ParseInput accepts only the canonical complete-content input representation.
func ParseInput(encoded []byte) (Input, error) {
	if len(encoded) == 0 || len(encoded) > maximumInputBytes {
		return Input{}, ErrInvalidInput
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire inputWire
	if err := decoder.Decode(&wire); err != nil {
		return Input{}, ErrInvalidInput
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Input{}, ErrInvalidInput
	}
	canonical, err := json.Marshal(wire)
	if err != nil || !bytes.Equal(canonical, encoded) || wire.Contract != "open-trestle/source-acquisition-input" ||
		wire.SchemaVersion != 1 || wire.Artifact != string(evidence.AcquisitionArtifactManifestAndContent) ||
		wire.Effect != string(evidence.AcquisitionEffectReadOnly) {
		return Input{}, ErrInvalidInput
	}
	repository, err := evidence.NewRepositoryIdentity(wire.RepositoryAuthority, wire.RepositoryNamespace, wire.RepositoryName)
	if err != nil {
		return Input{}, ErrInvalidInput
	}
	revision, err := evidence.NewRevisionIdentity(wire.RevisionKind, wire.RevisionAlgorithm, wire.RevisionDigest)
	if err != nil {
		return Input{}, ErrInvalidInput
	}
	adapter, err := evidence.NewSourceAdapterIdentity(
		wire.SourceAdapterKind,
		wire.SourceAdapterName,
		wire.SourceAdapterVersion,
		wire.SourceCapabilities,
	)
	if err != nil || adapter.Identity() != wire.SourceAdapterIdentity {
		return Input{}, ErrInvalidInput
	}
	input, err := NewInput(repository, revision, adapter)
	if err != nil || input.Identity() != wire.Identity {
		return Input{}, ErrInvalidInput
	}
	reencoded, _ := EncodeInput(input)
	if !bytes.Equal(reencoded, encoded) {
		return Input{}, ErrInvalidInput
	}
	return input, nil
}

func inputWireValue(input Input) inputWire {
	return inputWire{
		Contract: "open-trestle/source-acquisition-input", SchemaVersion: 1, Identity: input.Identity(),
		RepositoryAuthority: input.repository.Authority(), RepositoryNamespace: input.repository.Namespace(),
		RepositoryName: input.repository.Name(), RevisionKind: input.revision.Kind(),
		RevisionAlgorithm: input.revision.Algorithm(), RevisionDigest: input.revision.Digest(),
		SourceAdapterIdentity: input.adapter.Identity(), SourceAdapterKind: input.adapter.Kind(),
		SourceAdapterName: input.adapter.Name(), SourceAdapterVersion: input.adapter.Version(),
		SourceCapabilities: input.adapter.Capabilities(),
		Artifact:           string(evidence.AcquisitionArtifactManifestAndContent), Effect: string(evidence.AcquisitionEffectReadOnly),
	}
}

func deriveInputIdentity(input Input) string {
	wire := inputWireValue(input)
	wire.Identity = ""
	encoded, err := json.Marshal(wire)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// NewInputArtifact wraps exact source authority for durable scoped task exchange.
func NewInputArtifact(
	scope audit.ReviewScope,
	input Input,
	classification artifact.Classification,
	protection artifact.Protection,
	provenance []string,
	createdAt, expiresAt time.Time,
) (artifact.Artifact, error) {
	encoded, err := EncodeInput(input)
	if err != nil {
		return artifact.Artifact{}, err
	}
	return artifact.New(
		scope,
		artifact.KindTaskInput,
		"application/json",
		classification,
		artifact.OriginHost,
		protection,
		provenance,
		encoded,
		createdAt,
		expiresAt,
	)
}

func writeSourceRedacted(state fmt.State, verb rune, plain, detailed string) {
	value := plain
	if verb == 'q' {
		value = fmt.Sprintf("%q", plain)
	} else if verb == 'v' && state.Flag('#') {
		value = detailed
	}
	_, _ = state.Write([]byte(value))
}
