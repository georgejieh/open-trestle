package source

import (
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

// The frozen golden uses these wire fields only to build mutation fixtures.
type snapshotWire struct {
	Contract                     string              `json:"contract"`
	SchemaVersion                int                 `json:"schema_version"`
	Identity                     string              `json:"identity"`
	AcquisitionRequestIdentity   string              `json:"acquisition_request_identity"`
	AcquisitionReceiptIdentity   string              `json:"acquisition_receipt_identity"`
	AcquisitionExecutionIdentity string              `json:"acquisition_execution_identity"`
	RepositoryIdentity           string              `json:"repository_identity"`
	RevisionIdentity             string              `json:"revision_identity"`
	SourceAdapterIdentity        string              `json:"source_adapter_identity"`
	ManifestIdentity             string              `json:"manifest_identity"`
	Files                        []fileReferenceWire `json:"files"`
}

type fileReferenceWire struct {
	Path             string `json:"path"`
	Digest           string `json:"digest"`
	SizeBytes        int    `json:"size_bytes"`
	ArtifactIdentity string `json:"artifact_identity"`
}

func encodeFile(acquisitionExecutionIdentity string, file evidence.RepositoryFile, content []byte) ([]byte, error) {
	return sourceoutput.EncodeFile(acquisitionExecutionIdentity, file, content)
}

func newSnapshot(artifactIdentity, acquisitionRequest, acquisitionReceipt, acquisitionExecution,
	repositoryIdentity, revisionIdentity, sourceAdapterIdentity, manifestIdentity string,
	files []FileReference,
) (Snapshot, error) {
	return sourceoutput.NewSnapshot(artifactIdentity, acquisitionRequest, acquisitionReceipt, acquisitionExecution,
		repositoryIdentity, revisionIdentity, sourceAdapterIdentity, manifestIdentity, files)
}

func encodeSnapshot(snapshot Snapshot) ([]byte, error) { return sourceoutput.EncodeSnapshot(snapshot) }
