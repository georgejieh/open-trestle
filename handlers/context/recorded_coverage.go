package context

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/analysiscodec"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
)

var ErrRecordedSourceCoverage = errors.New("recorded source coverage unavailable")

type RecordedSourceCoverage struct {
	packet   artifact.Artifact
	input    modelhandler.GenerationInput
	recorded review.RecordedContext
}

func (r RecordedSourceCoverage) ArtifactIdentity() string                      { return r.packet.Identity() }
func (r RecordedSourceCoverage) PacketArtifact() artifact.Artifact             { return r.packet }
func (r RecordedSourceCoverage) GenerationInput() modelhandler.GenerationInput { return r.input }
func (r RecordedSourceCoverage) Analyzed() int                                 { return r.recorded.Analyzed() }
func (r RecordedSourceCoverage) Selected() int                                 { return r.recorded.Selected() }
func (r RecordedSourceCoverage) Omitted() int                                  { return r.recorded.Omitted() }

// ReadRecordedSourceCoverage follows at most one exact scoped packet reference.
// Callers supply outputs from completed context, analysis, change and source tasks.
func ReadRecordedSourceCoverage(ctx context.Context, reader artifact.Reader, at time.Time, output, analysisArtifact, changeArtifact, baseArtifact, headArtifact artifact.Artifact) (RecordedSourceCoverage, error) {
	if nilInterface(ctx) || ctx.Err() != nil || at.UnixMilli() <= 0 {
		return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
	}
	scope := output.Scope()
	for _, value := range []artifact.Artifact{output, analysisArtifact, changeArtifact, baseArtifact, headArtifact} {
		if value.Validate() != nil || value.Scope().Identity() != scope.Identity() || !at.Before(value.ExpiresAt()) || at.Before(value.CreatedAt()) {
			return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
		}
	}
	analysis, err := analysiscodec.ParseResultArtifact(analysisArtifact, changeArtifact, baseArtifact, headArtifact)
	if err != nil {
		return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
	}
	head, err := sourceoutput.ParseSnapshotArtifact(headArtifact)
	if err != nil || analysis.HeadSnapshotIdentity() != head.Identity() || analysis.HeadManifestIdentity() != head.ManifestIdentity() {
		return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
	}
	packet := output
	var input modelhandler.GenerationInput
	switch output.Kind() {
	case artifact.KindTaskInput:
		if nilInterface(reader) || output.Origin() != artifact.OriginHost || output.MediaType() != "application/json" {
			return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
		}
		input, err = modelhandler.ParseGenerationInput(output.Payload())
		if err != nil || input.ReviewScopeIdentity() != scope.Identity() || !coverageProvenance(output, input.ContextArtifactIdentity(), input.Authorization().Identity()) {
			return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
		}
		if input.IsSanitized() && !coverageProvenance(output, input.SanitizedRequestArtifactIdentity(), input.SanitizedEgressReceiptArtifactIdentity()) {
			return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
		}
		packet, err = reader.Get(ctx, scope, input.ContextArtifactIdentity(), at)
		if err != nil || packet.Identity() != input.ContextArtifactIdentity() || packet.Classification() != output.Classification() || packet.Protection() != output.Protection() {
			return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
		}
	case artifact.KindContextPacket:
	default:
		return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
	}
	if ctx.Err() != nil || packet.Validate() != nil || packet.Kind() != artifact.KindContextPacket || packet.Origin() != artifact.OriginHost || packet.MediaType() != "application/json" || packet.Scope().Identity() != scope.Identity() || !at.Before(packet.ExpiresAt()) || at.Before(packet.CreatedAt()) || packet.Classification() != analysisArtifact.Classification() || packet.Protection() != analysisArtifact.Protection() || !coverageProvenance(packet, analysisArtifact.Identity(), analysis.Identity(), changeArtifact.Identity(), headArtifact.Identity()) {
		return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
	}
	recorded, err := review.ParseRecordedContext(packet.Payload(), scope, head)
	if err != nil {
		return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
	}
	if output.Kind() == artifact.KindTaskInput && (input.ContextIdentity() != recorded.Identity() || input.MemoryScopeIdentity() != recorded.MemoryScopeIdentity() || input.MemoryIdentity() != recorded.MemoryIdentity() || input.Snapshot().Identity() != recorded.Snapshot().Identity() || !reflect.DeepEqual(input.EvidenceItems(), recorded.EvidenceItems())) {
		return RecordedSourceCoverage{}, ErrRecordedSourceCoverage
	}
	return RecordedSourceCoverage{packet: packet, input: input, recorded: recorded}, nil
}

func coverageProvenance(value artifact.Artifact, identities ...string) bool {
	for _, identity := range identities {
		found := false
		for _, actual := range value.Provenance() {
			found = found || identity == actual
		}
		if !found {
			return false
		}
	}
	return true
}
