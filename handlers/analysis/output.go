package analysis

import (
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/analysiscodec"
)

type Item = analysiscodec.Item
type Gap = analysiscodec.Gap
type Result = analysiscodec.Result
type Observation = analysiscodec.Observation
type DeterministicCheck = analysiscodec.DeterministicCheck
type DeterministicCheckState = analysiscodec.DeterministicCheckState

const (
	CheckPassed          = analysiscodec.CheckPassed
	CheckFailed          = analysiscodec.CheckFailed
	CheckIncomplete      = analysiscodec.CheckIncomplete
	CheckNotApplicable   = analysiscodec.CheckNotApplicable
	maximumEvidenceItems = analysiscodec.MaxEvidenceItems
)

var (
	ErrInvalidResult             = analysiscodec.ErrInvalidResult
	ErrInvalidDeterministicCheck = analysiscodec.ErrInvalidDeterministicCheck
)

func NewDeterministicCheck(changeIdentity string, state DeterministicCheckState, applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches uint32) (DeterministicCheck, error) {
	return analysiscodec.NewDeterministicCheck(changeIdentity, state, applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches)
}
func ParseResultArtifact(value, changeArtifact, baseArtifact, headArtifact artifact.Artifact) (Result, error) {
	return analysiscodec.ParseResultArtifact(value, changeArtifact, baseArtifact, headArtifact)
}
