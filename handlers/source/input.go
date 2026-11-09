package source

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/sourceinput"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

// Input authorizes one exact read-only complete-content acquisition.
type Input = sourceinput.Input

var (
	// ErrInvalidInput identifies malformed or cross-wired source acquisition authority.
	// This variable initially shares the lower sentinel; reassignment does not alter codec errors.
	ErrInvalidInput = sourceinput.ErrInvalidInput
	// ErrInvalidOutput identifies malformed source snapshot or file output.
	// This initially shares the lower sentinel. Reassigning either exported variable does not synchronize them.
	ErrInvalidOutput = sourceoutput.ErrInvalidOutput
	// ErrInvalidHandler identifies incomplete handler dependencies or identity.
	ErrInvalidHandler = errors.New("invalid source acquisition handler")
)

// NewInput creates an immutable acquisition input for an exact repository revision and adapter.
func NewInput(repository evidence.RepositoryIdentity, revision evidence.RevisionIdentity, adapter evidence.SourceAdapterIdentity) (Input, error) {
	return sourceinput.NewInput(repository, revision, adapter)
}

// NewBoundInput binds acquisition to one daemon-retained source-root authority.
func NewBoundInput(repository evidence.RepositoryIdentity, revision evidence.RevisionIdentity, adapter evidence.SourceAdapterIdentity, sourceRootIdentity string) (Input, error) {
	return sourceinput.NewBoundInput(repository, revision, adapter, sourceRootIdentity)
}

// NewMergeBaseInput authorizes acquisition of the merge base of the requested base and the head.
func NewMergeBaseInput(repository evidence.RepositoryIdentity, requestedBase, head evidence.RevisionIdentity, adapter evidence.SourceAdapterIdentity) (Input, error) {
	return sourceinput.NewMergeBaseInput(repository, requestedBase, head, adapter)
}

// EncodeInput returns the one canonical JSON representation.
func EncodeInput(input Input) ([]byte, error) { return sourceinput.EncodeInput(input) }

// ParseInput accepts only the canonical complete-content input representation.
func ParseInput(encoded []byte) (Input, error) { return sourceinput.ParseInput(encoded) }

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

func sameAdapterIdentity(first, second evidence.SourceAdapterIdentity) bool {
	return first.Identity() == second.Identity() && first.Kind() == second.Kind() &&
		first.Name() == second.Name() && first.Version() == second.Version() &&
		first.MajorVersion() == second.MajorVersion() && slices.Equal(first.Capabilities(), second.Capabilities())
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
