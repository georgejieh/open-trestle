package contextpacket

import (
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/review"
)

// Assembly carries the packet and validated source artifacts into investigation.
type Assembly struct {
	Packet                                           review.ContextPacket
	Snapshot                                         review.ReviewSnapshot
	MemoryScope                                      memory.Scope
	InitialContextArtifact                           artifact.Artifact
	AnalysisArtifact, MemoryArtifact, ChangeArtifact artifact.Artifact
	BaseSnapshotArtifact, HeadSnapshotArtifact       artifact.Artifact
}
