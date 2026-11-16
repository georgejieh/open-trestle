package change

import (
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/changecodec"
)

type Range = changecodec.Range
type Entry = changecodec.Entry
type Result = changecodec.Result

// ErrInvalidResult initially shares the codec sentinel. Reassigning either exported var breaks that identity.
var ErrInvalidResult = changecodec.ErrInvalidResult

func ResultArtifactReferences(value artifact.Artifact) (string, string, error) {
	return changecodec.ResultArtifactReferences(value)
}

func ParseResultArtifact(value, baseArtifact, headArtifact artifact.Artifact) (Result, error) {
	return changecodec.ParseResultArtifact(value, baseArtifact, headArtifact)
}
