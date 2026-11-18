package context

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/review"
)

type coverageReader struct {
	value    artifact.Artifact
	expected string
	scope    audit.ReviewScope
	at       time.Time
	gets     int
}

func (r *coverageReader) Get(_ context.Context, scope audit.ReviewScope, id string, at time.Time) (artifact.Artifact, error) {
	r.gets++
	if id != r.expected || scope.Identity() != r.scope.Identity() || !at.Equal(r.at) {
		return artifact.Artifact{}, errors.New("unexpected indexed read")
	}
	return r.value, nil
}

type recordedCoverageFixture struct {
	output, sanitizedOutput, packet, analysis, change, base, head artifact.Artifact
	input                                                         modelhandler.GenerationInput
	at                                                            time.Time
}

func newRecordedCoverageFixture(t *testing.T) recordedCoverageFixture {
	t.Helper()
	authority, request, coordinator, store, _, cleanup, _ := newPacketWriterFixture(t, false, false, false, false, false)
	t.Cleanup(cleanup)
	at := time.UnixMilli(230)
	assembly, providerRequest, abstention, failure := (&Handler{store: store, clock: authority.clock, packetOnly: true}).assembleAt(context.Background(), request, at, at)
	if failure != 0 || abstention != nil {
		t.Fatalf("assemble: %v", failure)
	}
	authorization, err := routeAuthorization(request.Plan().Scope(), providerRequest, "test-provider", "test-model", "primary/test", "test-model", "1", strings.Repeat("c", 64), strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	input, err := modelhandler.NewGenerationInput(assembly.InitialContextArtifact, assembly.Packet, assembly.Snapshot, authorization)
	if err != nil {
		t.Fatal(err)
	}
	output, err := modelhandler.NewGenerationInputArtifact(input, assembly.InitialContextArtifact, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	sanitizer := contextTestSanitizer{}
	sanitized, receipt, err := sanitizer.SanitizeGeneration(context.Background(), providerRequest, request.Plan().Scope().Identity())
	if err != nil {
		t.Fatal(err)
	}
	requestArtifact, receiptArtifact, err := review.NewSanitizedEgressArtifacts(assembly.InitialContextArtifact, sanitized, receipt, sanitizer.ExpectedBinaryDigests(), at)
	if err != nil {
		t.Fatal(err)
	}
	dispatch, err := sanitized.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	sanitizedAuthorization, err := routeAuthorization(request.Plan().Scope(), dispatch, "test-provider", "test-model", "primary/test", "test-model", "1", strings.Repeat("c", 64), strings.Repeat("d", 64))
	if err != nil {
		t.Fatal(err)
	}
	sanitizedInput, err := modelhandler.NewSanitizedGenerationInput(assembly.InitialContextArtifact, assembly.Packet, assembly.Snapshot, requestArtifact, receiptArtifact, sanitizer.ExpectedBinaryDigests(), sanitizedAuthorization)
	if err != nil {
		t.Fatal(err)
	}
	sanitizedOutput, err := modelhandler.NewGenerationInputArtifact(sanitizedInput, assembly.InitialContextArtifact, nil, at)
	if err != nil {
		t.Fatal(err)
	}
	// No candidate task has executed when the context artifacts are inspected.
	_, state, err := coordinator.Resume(context.Background(), request.Plan().Scope())
	if err != nil {
		t.Fatal(err)
	}
	runtime, _ := state.Task("context")
	if runtime.Status() != controlplane.TaskRuntimeLeased {
		t.Fatal("context fixture advanced unexpectedly")
	}
	return recordedCoverageFixture{output: output, sanitizedOutput: sanitizedOutput, packet: assembly.InitialContextArtifact, analysis: assembly.AnalysisArtifact, change: assembly.ChangeArtifact, base: assembly.BaseSnapshotArtifact, head: assembly.HeadSnapshotArtifact, input: input, at: at}
}
func (f recordedCoverageFixture) read(ctx context.Context, reader artifact.Reader, output artifact.Artifact, at time.Time) (RecordedSourceCoverage, error) {
	return ReadRecordedSourceCoverage(ctx, reader, at, output, f.analysis, f.change, f.base, f.head)
}
func TestReadRecordedSourceCoverageBeforeCandidates(t *testing.T) {
	f := newRecordedCoverageFixture(t)
	reader := &coverageReader{value: f.packet, expected: f.packet.Identity(), scope: f.packet.Scope(), at: f.at}
	result, err := f.read(context.Background(), reader, f.output, f.at)
	if err != nil || result.ArtifactIdentity() != f.packet.Identity() || result.Selected() != 2 || result.Analyzed() != result.Selected()+result.Omitted() || reader.gets != 1 || result.GenerationInput().Identity() != f.input.Identity() {
		t.Fatalf("result=%#v gets=%d err=%v", result, reader.gets, err)
	}
	reader.gets = 0
	sanitizedResult, err := f.read(context.Background(), reader, f.sanitizedOutput, f.at)
	if err != nil || !sanitizedResult.GenerationInput().IsSanitized() || sanitizedResult.ArtifactIdentity() != f.packet.Identity() || reader.gets != 1 {
		t.Fatalf("sanitized result=%#v gets=%d err=%v", sanitizedResult, reader.gets, err)
	}
	reader.gets = 0
	packetResult, err := f.read(context.Background(), reader, f.packet, f.at)
	if err != nil || packetResult.Analyzed() != result.Analyzed() || packetResult.Selected() != result.Selected() || packetResult.Omitted() != result.Omitted() || reader.gets != 0 {
		t.Fatalf("packet result=%#v gets=%d err=%v", packetResult, reader.gets, err)
	}
	benchmark := testing.Benchmark(func(b *testing.B) {
		b.ReportAllocs()
		for range b.N {
			if _, err := f.read(context.Background(), reader, f.output, f.at); err != nil {
				b.Fatal(err)
			}
		}
	})
	t.Logf("task_input coverage: %s, %s; exactly one indexed Get per invocation", benchmark.String(), benchmark.MemString())
}
func TestReadRecordedSourceCoverageFailsClosed(t *testing.T) {
	f := newRecordedCoverageFixture(t)
	rewrap := func(value artifact.Artifact, scope audit.ReviewScope, provenance []string, payload []byte) artifact.Artifact {
		t.Helper()
		result, err := artifact.New(scope, value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), provenance, payload, value.CreatedAt(), value.ExpiresAt())
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	foreign, _ := audit.NewReviewScope("tenant", "repository", "other-run")
	tests := []struct {
		name             string
		output, returned artifact.Artifact
		at               time.Time
	}{
		{"wrong exact packet", f.output, rewrap(f.packet, f.packet.Scope(), f.packet.Provenance(), append(f.packet.Payload(), ' ')), f.at},
		{"cross scope packet", f.output, rewrap(f.packet, foreign, f.packet.Provenance(), f.packet.Payload()), f.at},
		{"missing input provenance", rewrap(f.output, f.output.Scope(), []string{strings.Repeat("a", 64)}, f.output.Payload()), f.packet, f.at},
		{"missing packet lineage", rewrap(f.packet, f.packet.Scope(), []string{strings.Repeat("a", 64)}, f.packet.Payload()), f.packet, f.at},
		{"corrupt packet", rewrap(f.packet, f.packet.Scope(), f.packet.Provenance(), []byte(`{}`)), f.packet, f.at},
		{"expired input", f.output, f.packet, f.output.ExpiresAt()},
		{"future artifact", f.output, f.packet, f.output.CreatedAt().Add(-time.Millisecond)},
		{"unknown output", f.analysis, f.packet, f.at},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reader := &coverageReader{value: tc.returned, expected: f.packet.Identity(), scope: f.packet.Scope(), at: tc.at}
			result, err := f.read(context.Background(), reader, tc.output, tc.at)
			if !errors.Is(err, ErrRecordedSourceCoverage) || result.ArtifactIdentity() != "" || result.Selected() != 0 || reader.gets > 1 {
				t.Fatalf("result=%#v gets=%d err=%v", result, reader.gets, err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	reader := &coverageReader{}
	if _, err := f.read(ctx, reader, f.output, f.at); err == nil || reader.gets != 0 {
		t.Fatal("cancellation did not fail before reads")
	}
	if _, err := f.read(context.Background(), (*coverageReader)(nil), f.output, f.at); err == nil {
		t.Fatal("typed nil reader accepted")
	}
	bad := f
	bad.analysis = f.packet
	if _, err := bad.read(context.Background(), reader, f.output, f.at); err == nil || reader.gets != 0 {
		t.Fatal("cross-wired analysis accepted")
	}
}
