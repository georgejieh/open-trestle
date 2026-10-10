package source

import (
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

// These aliases retain ordinary assignment compatibility. Reflected type names
// and defining package are sourceoutput, not source.
type File = sourceoutput.File
type Snapshot = sourceoutput.Snapshot
type FileReference = sourceoutput.FileReference

func ParseFileArtifact(value artifact.Artifact, snapshot Snapshot, reference FileReference) (File, error) {
	return sourceoutput.ParseFileArtifact(value, snapshot, reference)
}

func ParseSnapshotArtifact(value artifact.Artifact) (Snapshot, error) {
	return sourceoutput.ParseSnapshotArtifact(value)
}
