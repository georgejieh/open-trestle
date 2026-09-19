package review

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/policy"
	"github.com/georgejieh/open-trestle/internal/provider"
	reviewschema "github.com/georgejieh/open-trestle/schemas/review"
)

func v4Check(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func v4Hash(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func v4JSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	v4Check(t, err)
	return b
}
func v4Claim(label string) string { return v4Hash([]byte("syntax-only-claim:" + label)) }

type v4Fixture struct {
	binding                           InvestigationContextBindingOptions
	initial, expanded                 ContextPacket
	initialSnapshot, expandedSnapshot ReviewSnapshot
	changed, extra                    ContextSource
	memoryScope                       memory.Scope
	retrieval                         memory.LexicalRetrieval
	manifest                          evidence.RepositoryManifest
}

func v4Route(t *testing.T, name, version string) (InvestigationRouteContextClaim, provider.RoutePerformanceObservation) {
	t.Helper()
	ref, err := provider.NewRouteReference(provider.ProviderZoneLocal, "provider-"+name, "adapter-"+name, "connection-"+name, "model-"+name, version)
	v4Check(t, err)
	caps, err := provider.NewModelCapabilities(128000, 8192, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	v4Check(t, err)
	declaration, err := provider.NewRouteCapabilityDeclaration(ref, caps)
	v4Check(t, err)
	pricing, err := provider.NewRoutePricing(1000000, 1000000)
	v4Check(t, err)
	candidate, err := provider.NewRouteCandidateDeclaration(declaration, provider.ContentLoggingDisabled, pricing, provider.RouteQualityTier3)
	v4Check(t, err)
	record, err := provider.NewRouteRegistryRecord(1, candidate, provider.RouteRegistryApproved, v4Claim("manifest"))
	v4Check(t, err)
	operational, err := provider.NewRouteOperationalState(record.Identity(), 1, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
	v4Check(t, err)
	performance, err := provider.NewKnownRoutePerformanceObservation(record.Identity(), 1, 10, 20)
	v4Check(t, err)
	return InvestigationRouteContextClaim{Record: record, ManifestSizeBytes: 10, Operational: operational}, performance
}
func newV4Fixture(t *testing.T) v4Fixture {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant", "repository", "context-only")
	v4Check(t, err)
	memoryScope, err := memory.NewScope("tenant", "repository", "actor", memory.RefVisibilityExact, v4Claim("policy"), []string{"."})
	v4Check(t, err)
	query, err := memory.NewLexicalQuery(memoryScope, "a.go", nil, nil, time.UnixMilli(1000), 1)
	v4Check(t, err)
	retrieval, err := memory.NewLexicalIndex().Search(context.Background(), memoryScope, query)
	v4Check(t, err)
	contents := []struct {
		path, text string
		stage      ContextStage
	}{{"a.go", "func Changed(x int) int { return 10 / x }\n", ContextStageChangedHunk}, {"notes.txt", "zero<&> requests enabled\n", ContextStageRepositoryContext}}
	files := []evidence.RepositoryFile{}
	sources := []ContextSource{}
	ranges := []evidence.SourceRange{}
	for _, value := range contents {
		file, err := evidence.NewRepositoryFile(value.path, []byte(value.text))
		v4Check(t, err)
		files = append(files, file)
		span, err := evidence.NewSourceRange(value.path, 1, 1)
		v4Check(t, err)
		ranges = append(ranges, span)
		binding, err := evidence.BindSourceSlice(file, []byte(value.text), span, []byte(value.text))
		v4Check(t, err)
		item, err := evidence.NewEvidenceItem(binding.Identity(), evidence.EvidenceKindSource, binding.SliceDigest(), span)
		v4Check(t, err)
		source, err := NewBoundContextSource(value.stage, memory.TaintRepositoryControlled, item, []byte(value.text), binding)
		v4Check(t, err)
		sources = append(sources, source)
	}
	manifest, err := evidence.NewRepositoryManifest(files)
	v4Check(t, err)
	initialSnapshot, err := NewAcquiredReviewPipelineSnapshot(scope.ReviewRunID(), manifest, ranges[:1])
	v4Check(t, err)
	expandedSnapshot, err := NewAcquiredReviewPipelineSnapshot(scope.ReviewRunID(), manifest, ranges)
	v4Check(t, err)
	limits, err := NewContextLimits(65536, 0)
	v4Check(t, err)
	omission, err := NewContextSourceOmission("skip.bin", 0, 0, "analysis_unsupported_content")
	v4Check(t, err)
	initial, err := NewContextPacketWithAccounting(scope, memoryScope, initialSnapshot, ContextTaskCandidateGeneration, sources[:1], []memory.LexicalRetrieval{retrieval}, []ContextSourceOmission{omission}, limits)
	v4Check(t, err)
	expanded, err := NewContextPacketWithAccounting(scope, memoryScope, expandedSnapshot, ContextTaskCandidateGeneration, sources, []memory.LexicalRetrieval{retrieval}, []ContextSourceOmission{omission}, limits)
	v4Check(t, err)
	encoded, err := os.ReadFile("testdata/investigation-policy-v1.json")
	v4Check(t, err)
	p, err := ParseInvestigationPolicy(encoded)
	v4Check(t, err)
	generation, gp := v4Route(t, "a", "1")
	verification, vp := v4Route(t, "b", "1")
	requirements, err := provider.NewModelRequirements(1, 4096, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
	v4Check(t, err)
	zones, err := policy.NewAllowedProviderZones(provider.ProviderZoneLocal)
	v4Check(t, err)
	constraints, err := policy.NewProviderDataConstraints(policy.DataClassificationConfidential, zones, false)
	v4Check(t, err)
	budget, err := provider.NewModelCostBudget(1, 4096, 100000)
	v4Check(t, err)
	ranking, err := gateway.NewRouteRankingPolicy(nil)
	v4Check(t, err)
	independence, err := gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctProvider)
	v4Check(t, err)
	options := InvestigationContextBindingOptions{Scope: scope, HostSessionIdentity: v4Claim("host-session"), Policy: p, HeadSnapshotArtifactIdentity: v4Claim("head-artifact"), HeadSnapshotIdentity: v4Claim("head-snapshot"), HeadManifestIdentity: manifest.Identity(), HeadRevisionIdentity: v4Claim("head-revision"), InitialContext: initial, InitialSnapshot: initialSnapshot, Deadline: time.UnixMilli(6000), Routing: InvestigationContextRouting{RegistryRevision: 1, PerformanceRevision: 1, Generation: generation, Verification: []InvestigationRouteContextClaim{verification}, Performance: []provider.RoutePerformanceObservation{gp, vp}, Requirements: requirements, Constraints: constraints, Budget: budget, VerificationRanking: ranking, Independence: independence, CatalogIdentity: v4Claim("catalog")}}
	return v4Fixture{options, initial, expanded, initialSnapshot, expandedSnapshot, sources[0], sources[1], memoryScope, retrieval, manifest}
}
func v4Initial(t *testing.T, f v4Fixture) InvestigationGenerationContext {
	t.Helper()
	binding, err := NewInvestigationContextBinding(f.binding)
	v4Check(t, err)
	value, err := NewInvestigationGenerationContext(binding, f.initial, f.initialSnapshot, InvestigationContextState{Turn: 1, ScannedBytes: uint64(len(f.changed.Content()))})
	v4Check(t, err)
	return value
}
func v4ResultState(t *testing.T, f v4Fixture) (InvestigationContextState, artifact.Artifact) {
	t.Helper()
	// This inert Host input proves annotation framing, not completed tool work.
	payload := v4JSON(t, map[string]any{"contract": "context-only-data", "text": "quoted<&>", "sources": []any{}})
	value, err := artifact.New(f.binding.Scope, artifact.KindTaskInput, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{v4Claim("data-provenance")}, payload, time.UnixMilli(1000), time.UnixMilli(10000))
	v4Check(t, err)
	annotation, err := NewInvestigationResultAnnotation(value.Identity(), value.Payload())
	v4Check(t, err)
	encoded, err := artifact.Encode(value)
	v4Check(t, err)
	return InvestigationContextState{Turn: 2, PreviousRequestIdentity: v4Claim("prior-request"), PreviousOutcomeIdentity: v4Claim("prior-outcome"), NewResultArtifactIdentities: []string{value.Identity()}, Results: []InvestigationResultAnnotation{annotation}, ScannedBytes: uint64(len(f.changed.Content()) + len(f.extra.Content())), ReturnedBytes: uint64(len(encoded)), ToolCallsUsed: 1}, value
}
func v4Final(t *testing.T, f v4Fixture) (InvestigationGenerationContext, artifact.Artifact) {
	t.Helper()
	state, artifact := v4ResultState(t, f)
	binding, err := NewInvestigationContextBinding(f.binding)
	v4Check(t, err)
	value, err := NewInvestigationGenerationContext(binding, f.expanded, f.expandedSnapshot, state)
	v4Check(t, err)
	return value, artifact
}
func TestInvestigationContextManifestSizeMatchesResolvedRouteBoundary(t *testing.T) {
	for _, size := range []uint32{1 << 20, (1 << 20) + 1} {
		f := newV4Fixture(t)
		f.binding.Routing.Generation.ManifestSizeBytes = size
		_, err := NewInvestigationContextBinding(f.binding)
		if (err == nil) != (size == 1<<20) {
			t.Fatalf("manifest size %d disagrees with accepted resolved-route limit: %v", size, err)
		}
	}
}

func TestInvestigationContextV3ControlAndCanonicalV4Contract(t *testing.T) {
	f := newV4Fixture(t)
	before, err := f.initial.ProviderRequest()
	v4Check(t, err)
	var current contextPacketWire
	v4Check(t, json.Unmarshal(before.Payload(), &current))
	if current.SchemaVersion != 3 || current.ToolCalls != "proposals_only" || current.OutputSchemaIdentity != ModelCandidateBatchSchemaIdentity {
		t.Fatal("current v3 constructor contract changed")
	}
	v4Check(t, ValidateCandidateModelRequest(before, f.binding.Scope.Identity()))
	v4 := v4Initial(t, f)
	request, err := v4.ProviderRequest()
	v4Check(t, err)
	if v4.Validate() != nil || v4.Identity() != v4Hash(request.Payload()) || request.Identity() == before.Identity() {
		t.Fatal("v4 identity/request did not bind exact new bytes")
	}
	var wire struct {
		Version       int             `json:"schema_version"`
		Instructions  string          `json:"instructions"`
		Schema        json.RawMessage `json:"output_schema"`
		SchemaID      string          `json:"output_schema_identity"`
		Tools         string          `json:"tool_calls"`
		Investigation struct {
			Mode   string `json:"routing_mode"`
			Memory string `json:"memory_state"`
			Head   string `json:"snapshot_identity"`
		} `json:"investigation"`
	}
	v4Check(t, json.Unmarshal(request.Payload(), &wire))
	if wire.Version != 4 || wire.Tools != "host_admitted_snapshot_read_v1" || wire.Investigation.Mode != "fixed_generation_route_v1" || wire.Investigation.Memory != "empty_not_ingested" || wire.Investigation.Head != f.binding.HeadSnapshotIdentity {
		t.Fatal("explicit v4 profile or claimed fixed head changed")
	}
	if !bytes.Equal(wire.Schema, InvestigationOutputSchema()) || wire.SchemaID != v4Hash(wire.Schema) || wire.SchemaID != "77367fd94611f87d36e4490729096db927b8d27b9d687a4b6ab515db70e2bbc4" || wire.Instructions != InvestigationInstructions() || v4Hash([]byte(wire.Instructions)) != "990e881d4038ea3c222c4c0aed5b6dad7dbff547faa5f30ff067b3ac18072c8c" {
		t.Fatal("readable proposed host schema/instructions are not exact canonical assets")
	}
	copy := InvestigationOutputSchema()
	copy[0] = 'x'
	if bytes.Equal(copy, InvestigationOutputSchema()) {
		t.Fatal("schema accessor aliases stored bytes")
	}
	if ValidateCandidateModelRequest(request, f.binding.Scope.Identity()) == nil {
		t.Fatal("current v3 gate silently admitted v4")
	}
	after, err := f.initial.ProviderRequest()
	v4Check(t, err)
	if !bytes.Equal(before.Payload(), after.Payload()) || before.Identity() != after.Identity() {
		t.Fatal("v4 construction rewrote current v3")
	}
	v4Check(t, ValidateContextPacketRequest(after.Payload(), f.initial.Identity(), f.binding.Scope.Identity(), f.initial.MemoryScopeIdentity(), f.initial.MemoryIdentity(), f.initialSnapshot, f.initial.EvidenceItems()))
	returned := request.Payload()
	returned[0] = 'x'
	again, err := v4.ProviderRequest()
	v4Check(t, err)
	if bytes.Equal(returned, again.Payload()) {
		t.Fatal("context payload is mutable")
	}
}
func TestInvestigationSchemaAndHostParserHaveExplicitDifferentBoundaries(t *testing.T) {
	var schema map[string]any
	v4Check(t, json.Unmarshal(InvestigationOutputSchema(), &schema))
	var candidate map[string]any
	v4Check(t, json.Unmarshal(reviewschema.CandidateBatch(), &candidate))
	if !reflect.DeepEqual(schema["$defs"], candidate["$defs"]) {
		t.Fatal("candidate definitions changed")
	}
	branch := schema["oneOf"].([]any)[0].(map[string]any)
	for _, key := range []string{"type", "properties", "required", "additionalProperties"} {
		if !reflect.DeepEqual(branch[key], candidate[key]) {
			t.Fatal("candidate schema branch changed")
		}
	}
	tools := schema["oneOf"].([]any)[1].(map[string]any)["properties"].(map[string]any)["tool_calls"].(map[string]any)["items"].(map[string]any)["oneOf"].([]any)
	zero := strings.Repeat("0", 64)
	for _, tool := range tools {
		props := tool.(map[string]any)["properties"].(map[string]any)
		for _, key := range []string{"snapshot_ref", "file_ref", "file_refs"} {
			v, ok := props[key]
			if !ok {
				continue
			}
			ref := v.(map[string]any)
			if key == "file_refs" {
				ref = ref["items"].(map[string]any)
			}
			not := ref["not"].(map[string]any)["anyOf"].([]any)
			found := false
			for _, entry := range not {
				if entry.(map[string]any)["const"] == zero {
					found = true
				}
			}
			if !found {
				t.Fatal("standard schema does not explicitly forbid zero reference")
			}
		}
	}
	ref := strings.Repeat("a", 64)
	for _, test := range []struct{ name, raw string }{
		{"standard schema and host reject zero ref", `{"schema_version":1,"tool_calls":[{"call_id":"a","tool":"snapshot.list","snapshot_ref":"` + zero + `"}]}`},
		{"schema may accept integer value but host rejects exponent lexeme", `{"schema_version":1,"tool_calls":[{"call_id":"a","tool":"snapshot.read","snapshot_ref":"` + ref + `","file_ref":"` + ref + `","start_line":1e0,"end_line":1}]}`},
		{"schema may accept codepoint length but host rejects UTF8 byte length", `{"schema_version":1,"tool_calls":[{"call_id":"a","tool":"snapshot.search","snapshot_ref":"` + ref + `","file_refs":["` + ref + `"],"literal":"` + strings.Repeat("é", 129) + `"}]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseInvestigationProposal([]byte(test.raw)); err == nil {
				t.Fatal("mandatory host lexical/byte check missing")
			}
		})
	}
	if !strings.Contains(InvestigationInstructions(), "UTF-8 bytes") || !strings.Contains(InvestigationInstructions(), "exponents") {
		t.Fatal("schema guidance omits mandatory host-only restrictions")
	}
	// No native JSON-Schema validator/provider conformance is exercised here.
}
func TestInvestigationContextAnnotationHasNoStoredSelfIdentity(t *testing.T) {
	f := newV4Fixture(t)
	value, input := v4Final(t, f)
	before := input.Payload()
	request, err := value.ProviderRequest()
	v4Check(t, err)
	var wire struct {
		Investigation struct {
			Results []map[string]json.RawMessage `json:"tool_results"`
		} `json:"investigation"`
	}
	v4Check(t, json.Unmarshal(request.Payload(), &wire))
	if len(wire.Investigation.Results) != 1 {
		t.Fatal("annotation missing")
	}
	var id string
	v4Check(t, json.Unmarshal(wire.Investigation.Results[0]["artifact_identity"], &id))
	if id != input.Identity() {
		t.Fatal("annotation not bound to actual inert artifact identity")
	}
	delete(wire.Investigation.Results[0], "artifact_identity")
	if !bytes.Equal(v4JSON(t, wire.Investigation.Results[0]), before) || !bytes.Equal(input.Payload(), before) {
		t.Fatal("context annotation changed stored payload")
	}
	bad := v4JSON(t, map[string]any{"artifact_identity": input.Identity(), "text": "self-reference"})
	if _, err := NewInvestigationResultAnnotation(input.Identity(), bad); err == nil {
		t.Fatal("stored result accepted self artifact identity")
	}
	annotation, err := NewInvestigationResultAnnotation(input.Identity(), before)
	v4Check(t, err)
	copied := annotation.Payload()
	copied[0] = 'x'
	if bytes.Equal(copied, annotation.Payload()) {
		t.Fatal("annotation payload aliases caller data")
	}
}
func v4Candidates(t *testing.T, f v4Fixture) CandidateBatch {
	t.Helper()
	ids := []string{f.changed.ReferenceID(), f.extra.ReferenceID()}
	raw := v4JSON(t, map[string]any{"schema_version": 1, "candidates": []any{map[string]any{"title": "Zero input divides by zero", "claim": "The supplied division lacks a zero guard and the note mentions zero requests.", "severity_hint": "high", "source_range": map[string]any{"source_id": ids[0], "start_line": 1, "end_line": 1}, "evidence_ids": ids}}})
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", raw)
	v4Check(t, err)
	usage, err := provider.NewRouteTokenUsage(1, 1, 0)
	v4Check(t, err)
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	v4Check(t, err)
	candidates, err := ParseCandidateBatch(response, f.expandedSnapshot, f.expanded.EvidenceItems())
	v4Check(t, err)
	return candidates
}
func TestInvestigationV4ProjectsExactCurrentVerifierV3(t *testing.T) {
	f := newV4Fixture(t)
	final, _ := v4Final(t, f)
	candidates := v4Candidates(t, f)
	legacy, err := f.expanded.ProviderRequest()
	v4Check(t, err)
	control, err := NewVerificationRequestContext(legacy.Payload(), f.expanded.Identity(), f.binding.Scope.Identity(), f.expanded.MemoryScopeIdentity(), f.expanded.MemoryIdentity(), f.expandedSnapshot, f.expanded.EvidenceItems(), candidates)
	v4Check(t, err)
	projected, err := NewInvestigationVerificationRequestContext(final, candidates)
	v4Check(t, err)
	var expected verificationContextWire
	v4Check(t, json.Unmarshal(control.Payload(), &expected))
	expected.GenerationContextIdentity = final.Identity()
	payload := v4JSON(t, expected)
	if !bytes.Equal(projected.Payload(), payload) || projected.Identity() != v4Hash(payload) || projected.GenerationContextIdentity() != final.Identity() || projected.SnapshotIdentity() != f.expandedSnapshot.Identity() || projected.CandidateBatchIdentity() != candidates.Identity() {
		t.Fatal("named projection changed current v3 mapping or final lineage")
	}
	request, err := projected.ProviderRequest()
	v4Check(t, err)
	v4Check(t, ValidateVerificationModelRequest(request, f.binding.Scope.Identity()))
	if expected.SchemaVersion != 3 || expected.ToolCalls != "proposals_only" || !reflect.DeepEqual(projected.EvidenceItems(), f.expanded.EvidenceItems()) || len(expected.SourceOmissions) != 1 || expected.Sources[1].Stage != "repository_context" {
		t.Fatal("projection inflated source grades/omissions or granted verifier tools")
	}
	if _, err := NewInvestigationVerificationRequestContext(final, CandidateBatch{}); err == nil {
		t.Fatal("projection accepted missing candidate authority")
	}
}

func TestInvestigationContextBindingIdentityIncludesEveryClaimedInput(t *testing.T) {
	f := newV4Fixture(t)
	base, err := NewInvestigationContextBinding(f.binding)
	v4Check(t, err)
	seen := map[string]bool{base.Identity(): true}
	for _, mode := range []string{"host session", "head artifact", "head snapshot", "head revision", "deadline", "catalog", "policy", "budget input", "budget output", "budget cost", "generation version", "generation manifest size", "operational state", "verifier version", "performance revision", "performance latency", "performance samples", "requirements", "privacy", "ranking", "independence", "scope"} {
		t.Run(mode, func(t *testing.T) {
			o := f.binding
			o.Routing.Verification = append([]InvestigationRouteContextClaim(nil), o.Routing.Verification...)
			o.Routing.Performance = append([]provider.RoutePerformanceObservation(nil), o.Routing.Performance...)
			switch mode {
			case "host session":
				o.HostSessionIdentity = v4Claim("other-session")
			case "head artifact":
				o.HeadSnapshotArtifactIdentity = v4Claim("other-artifact")
			case "head snapshot":
				o.HeadSnapshotIdentity = v4Claim("other-snapshot")
			case "head revision":
				o.HeadRevisionIdentity = v4Claim("other-revision")
			case "deadline":
				o.Deadline = o.Deadline.Add(time.Millisecond)
			case "catalog":
				o.Routing.CatalogIdentity = v4Claim("other-catalog")
			case "policy":
				encoded, err := EncodeInvestigationPolicy(o.Policy)
				v4Check(t, err)
				encoded = bytes.Replace(encoded, []byte(`"max_tool_calls":3`), []byte(`"max_tool_calls":2`), 1)
				o.Policy, err = ParseInvestigationPolicy(encoded)
				v4Check(t, err)
			case "budget input":
				o.Routing.Budget, err = provider.NewModelCostBudget(2, 4096, 100000)
				v4Check(t, err)
			case "budget output":
				o.Routing.Budget, err = provider.NewModelCostBudget(1, 4097, 100000)
				v4Check(t, err)
			case "budget cost":
				o.Routing.Budget, err = provider.NewModelCostBudget(1, 4096, 100001)
				v4Check(t, err)
			case "generation version":
				o.Routing.Generation, o.Routing.Performance[0] = v4Route(t, "a", "2")
			case "generation manifest size":
				o.Routing.Generation.ManifestSizeBytes++
			case "operational state":
				o.Routing.Generation.Operational, err = provider.NewRouteOperationalState(o.Routing.Generation.Record.Identity(), 2, provider.RouteHealthHealthy, provider.RouteQuotaAvailable)
				v4Check(t, err)
			case "verifier version":
				o.Routing.Verification[0], o.Routing.Performance[1] = v4Route(t, "b", "2")
			case "performance revision":
				o.Routing.PerformanceRevision = 2
				for i, obs := range o.Routing.Performance {
					o.Routing.Performance[i], err = provider.NewKnownRoutePerformanceObservation(obs.RecordIdentity(), 2, 10, 20)
					v4Check(t, err)
				}
			case "performance latency":
				o.Routing.Performance[0], err = provider.NewKnownRoutePerformanceObservation(o.Routing.Performance[0].RecordIdentity(), 1, 11, 20)
				v4Check(t, err)
			case "performance samples":
				o.Routing.Performance[0], err = provider.NewKnownRoutePerformanceObservation(o.Routing.Performance[0].RecordIdentity(), 1, 10, 21)
				v4Check(t, err)
			case "requirements":
				o.Routing.Requirements, err = provider.NewModelRequirements(2, 4096, []provider.ModelFeature{provider.ModelFeatureStructuredOutput})
				v4Check(t, err)
			case "privacy":
				o.Routing.Constraints, err = policy.NewProviderDataConstraints(o.Routing.Constraints.Classification(), o.Routing.Constraints.AllowedProviderZones(), true)
				v4Check(t, err)
			case "ranking":
				o.Routing.VerificationRanking, err = gateway.NewRouteRankingPolicy([]provider.RouteReference{o.Routing.Verification[0].Record.RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference()})
				v4Check(t, err)
			case "independence":
				o.Routing.Independence, err = gateway.NewRouteIndependencePolicy(gateway.RouteIndependenceDistinctModel)
				v4Check(t, err)
			case "scope":
				o.Scope, err = audit.NewReviewScope("tenant", "repository", "other-context")
				v4Check(t, err)
				o.InitialSnapshot, err = NewAcquiredReviewPipelineSnapshot(o.Scope.ReviewRunID(), f.manifest, []evidence.SourceRange{f.changed.EvidenceItem().SourceRange()})
				v4Check(t, err)
				limits, _ := NewContextLimits(65536, 0)
				o.InitialContext, err = NewContextPacketWithAccounting(o.Scope, f.memoryScope, o.InitialSnapshot, ContextTaskCandidateGeneration, []ContextSource{f.changed}, []memory.LexicalRetrieval{f.retrieval}, f.initial.SourceOmissions(), limits)
				v4Check(t, err)
			}
			binding, err := NewInvestigationContextBinding(o)
			v4Check(t, err)
			if binding.Validate() != nil || seen[binding.Identity()] {
				t.Fatal("session binding omitted a raw claimed input")
			}
			seen[binding.Identity()] = true
		})
	}
}
func TestInvestigationContextRejectsInvalidBindingAndState(t *testing.T) {
	f := newV4Fixture(t)
	if (InvestigationContextBinding{}).Validate() == nil || (InvestigationGenerationContext{}).Validate() == nil {
		t.Fatal("zero pure context validated")
	}
	if _, err := (InvestigationGenerationContext{}).ProviderRequest(); err == nil {
		t.Fatal("zero context emitted request")
	}
	for _, mode := range []string{"scope", "head syntax", "manifest mismatch", "initial packet", "initial snapshot", "deadline", "policy", "registry", "performance", "generation", "verifier", "catalog", "budget"} {
		t.Run(mode, func(t *testing.T) {
			o := f.binding
			switch mode {
			case "scope":
				o.Scope = audit.ReviewScope{}
			case "head syntax":
				o.HeadSnapshotIdentity = "not-a-digest"
			case "manifest mismatch":
				o.HeadManifestIdentity = v4Claim("different-manifest")
			case "initial packet":
				o.InitialContext = ContextPacket{}
			case "initial snapshot":
				o.InitialSnapshot = ReviewSnapshot{}
			case "deadline":
				o.Deadline = time.Time{}
			case "policy":
				o.Policy = InvestigationPolicy{}
			case "registry":
				o.Routing.RegistryRevision = 2
			case "performance":
				o.Routing.PerformanceRevision = 2
			case "generation":
				o.Routing.Generation = InvestigationRouteContextClaim{}
			case "verifier":
				o.Routing.Verification = nil
			case "catalog":
				o.Routing.CatalogIdentity = "bad"
			case "budget":
				o.Routing.Budget, _ = provider.NewModelCostBudget(1, 4096, 1)
			}
			if _, err := NewInvestigationContextBinding(o); err == nil {
				t.Fatal("invalid claimed session binding accepted")
			}
		})
	}
	binding, err := NewInvestigationContextBinding(f.binding)
	v4Check(t, err)
	for _, state := range []InvestigationContextState{{}, {Turn: 2}, {Turn: 1, PreviousRequestIdentity: v4Claim("unexpected")}, {Turn: 1, ScannedBytes: f.binding.Policy.MaxScannedBytes() + 1}, {Turn: 1, ReturnedBytes: f.binding.Policy.MaxReturnedBytes() + 1}, {Turn: 9}, {Turn: 1, ToolCallsUsed: 7}} {
		if _, err := NewInvestigationGenerationContext(binding, f.initial, f.initialSnapshot, state); err == nil {
			t.Fatal("invalid or excessive lineage/counters accepted")
		}
	}
	if _, err := NewInvestigationResultAnnotation(v4Claim("artifact"), bytes.Repeat([]byte{' '}, (64<<10)+1)); err == nil {
		t.Fatal("oversized annotation copied")
	}
	if _, err := NewInvestigationResultAnnotation(v4Claim("artifact"), []byte(`{"x":1,"x":1}`)); err == nil {
		t.Fatal("duplicate annotation field accepted")
	}
}
func TestInvestigationContextPreservesChangedCoverageAndSourceGrade(t *testing.T) {
	f := newV4Fixture(t)
	binding, err := NewInvestigationContextBinding(f.binding)
	v4Check(t, err)
	limits, err := NewContextLimits(65536, 0)
	v4Check(t, err)
	onlyExtra, err := NewAcquiredReviewPipelineSnapshot(f.binding.Scope.ReviewRunID(), f.manifest, []evidence.SourceRange{f.extra.EvidenceItem().SourceRange()})
	v4Check(t, err)
	missing, err := NewContextPacketWithAccounting(f.binding.Scope, f.memoryScope, onlyExtra, ContextTaskCandidateGeneration, []ContextSource{f.extra}, []memory.LexicalRetrieval{f.retrieval}, f.initial.SourceOmissions(), limits)
	v4Check(t, err)
	state, _ := v4ResultState(t, f)
	if _, err := NewInvestigationGenerationContext(binding, f.expanded, f.expandedSnapshot, state); err != nil {
		t.Fatal("positive expanded-state control refused")
	}
	if _, err := NewInvestigationGenerationContext(binding, missing, onlyExtra, state); err == nil {
		t.Fatal("new context dropped initial changed-source coverage")
	}
	inflated, err := NewBoundContextSource(ContextStageDirectReference, memory.TaintRepositoryControlled, f.extra.EvidenceItem(), f.extra.Content(), f.extra.SliceBinding())
	v4Check(t, err)
	packet, err := NewContextPacketWithAccounting(f.binding.Scope, f.memoryScope, f.expandedSnapshot, ContextTaskCandidateGeneration, []ContextSource{f.changed, inflated}, []memory.LexicalRetrieval{f.retrieval}, f.initial.SourceOmissions(), limits)
	v4Check(t, err)
	if _, err := NewInvestigationGenerationContext(binding, packet, f.expandedSnapshot, state); err == nil {
		t.Fatal("new read source inflated into semantic direct-reference proof")
	}
}
func TestInvestigationContextRejectsNonemptyMemory(t *testing.T) {
	f := newV4Fixture(t)
	index := memory.NewLexicalIndex()
	record, err := memory.NewRecord(f.memoryScope, memory.RecordInput{Kind: memory.RecordCanonicalFact, Taint: memory.TaintUserControlled, Path: "a.go", Text: "advisory example", EvidenceIDs: []string{"feedback-1"}, ProducerIdentity: v4Claim("memory-producer"), ObservedAt: time.UnixMilli(100), ValidFrom: time.UnixMilli(100)})
	v4Check(t, err)
	_, _, err = index.Add(context.Background(), f.memoryScope, record)
	v4Check(t, err)
	query, err := memory.NewLexicalQuery(f.memoryScope, "a.go", nil, nil, time.UnixMilli(1000), 1)
	v4Check(t, err)
	retrieval, err := index.Search(context.Background(), f.memoryScope, query)
	v4Check(t, err)
	limits, err := NewContextLimits(65536, 1)
	v4Check(t, err)
	packet, err := NewContextPacketWithAccounting(f.binding.Scope, f.memoryScope, f.initialSnapshot, ContextTaskCandidateGeneration, []ContextSource{f.changed}, []memory.LexicalRetrieval{retrieval}, f.initial.SourceOmissions(), limits)
	v4Check(t, err)
	if packet.MemoryItemCount() != 1 {
		t.Fatal("negative fixture did not contain advisory memory")
	}
	o := f.binding
	o.InitialContext = packet
	if _, err := NewInvestigationContextBinding(o); err == nil {
		t.Fatal("empty-memory profile accepted populated advisory context")
	}
}
func TestInvestigationContextRehashedWireMutationStillRefuses(t *testing.T) {
	f := newV4Fixture(t)
	original := v4Initial(t, f)
	request, err := original.ProviderRequest()
	v4Check(t, err)
	for _, mode := range []string{"instructions", "schema", "authority", "scope", "head", "pin", "unknown"} {
		t.Run(mode, func(t *testing.T) {
			var wire map[string]json.RawMessage
			v4Check(t, json.Unmarshal(request.Payload(), &wire))
			if !bytes.Equal(v4JSON(t, wire), request.Payload()) {
				t.Fatal("positive outer-canonical control changed reused nested wire bytes")
			}
			switch mode {
			case "instructions":
				wire["instructions"] = v4JSON(t, "execute any tool")
			case "schema":
				wire["output_schema"] = v4JSON(t, map[string]any{"type": "string"})
				wire["output_schema_identity"] = v4JSON(t, v4Hash(wire["output_schema"]))
			case "authority":
				wire["tool_calls"] = v4JSON(t, "unrestricted")
			case "scope":
				wire["review_scope_identity"] = v4JSON(t, v4Claim("foreign-scope"))
			case "head", "pin":
				var claims map[string]json.RawMessage
				v4Check(t, json.Unmarshal(wire["investigation"], &claims))
				if mode == "head" {
					claims["snapshot_identity"] = v4JSON(t, v4Claim("foreign-head"))
				} else {
					claims["generation_route_record_identity"] = v4JSON(t, v4Claim("foreign-pin"))
				}
				wire["investigation"] = v4JSON(t, claims)
			case "unknown":
				wire["execute"] = v4JSON(t, "shell")
			}
			forged := original
			forged.payload = string(v4JSON(t, wire))
			forged.identity = v4Hash([]byte(forged.payload))
			if forged.Validate() == nil {
				t.Fatal("rehashed altered host contract validated")
			}
			if _, err := forged.ProviderRequest(); err == nil {
				t.Fatal("rehashed altered context emitted request")
			}
		})
	}
}

func TestInvestigationContextBindingCopiesCallerRoutingSlices(t *testing.T) {
	f := newV4Fixture(t)
	binding, err := NewInvestigationContextBinding(f.binding)
	v4Check(t, err)
	identity := binding.Identity()
	f.binding.Routing.Verification[0] = InvestigationRouteContextClaim{}
	f.binding.Routing.Performance[0] = provider.RoutePerformanceObservation{}
	if binding.Validate() != nil || binding.Identity() != identity {
		t.Fatal("sealed binding retained caller routing slices")
	}
}
func TestInvestigationProjectionRejectsForeignCandidateSnapshot(t *testing.T) {
	f := newV4Fixture(t)
	final, _ := v4Final(t, f)
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", []byte(`{"schema_version":1,"candidates":[]}`))
	v4Check(t, err)
	usage, err := provider.NewRouteTokenUsage(1, 1, 0)
	v4Check(t, err)
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	v4Check(t, err)
	foreign, err := ParseCandidateBatch(response, f.initialSnapshot, f.initial.EvidenceItems())
	v4Check(t, err)
	if _, err := NewInvestigationVerificationRequestContext(final, foreign); err == nil {
		t.Fatal("candidate batch from different selected snapshot projected")
	}
}

func TestInvestigationContextBindingExactNonCircularIdentityPreimage(t *testing.T) {
	f := newV4Fixture(t)
	o := f.binding
	binding, err := NewInvestigationContextBinding(o)
	v4Check(t, err)
	descriptor := func(c InvestigationRouteContextClaim) []any {
		return []any{c.Record.Identity(), c.ManifestSizeBytes, c.Operational.ObservationRevision(), c.Operational.Health().String(), c.Operational.Quota().String()}
	}
	verifiers := append([]InvestigationRouteContextClaim(nil), o.Routing.Verification...)
	sort.Slice(verifiers, func(i, j int) bool { return verifiers[i].Record.Identity() < verifiers[j].Record.Identity() })
	vd := []any{}
	for _, v := range verifiers {
		vd = append(vd, descriptor(v))
	}
	performance := append([]provider.RoutePerformanceObservation(nil), o.Routing.Performance...)
	sort.Slice(performance, func(i, j int) bool { return performance[i].RecordIdentity() < performance[j].RecordIdentity() })
	pd := []any{}
	for _, p := range performance {
		pd = append(pd, []any{p.RecordIdentity(), p.ObservationRevision(), p.LatencyKnown(), p.P95LatencyMilliseconds(), p.SampleCount()})
	}
	features := []string{}
	for _, v := range o.Routing.Requirements.RequiredFeatures() {
		features = append(features, v.String())
	}
	zones := []string{}
	for z := provider.ProviderZoneLocal; z <= provider.ProviderZoneSubscriptionOAuth; z++ {
		if o.Routing.Constraints.AllowedProviderZones().Allows(z) {
			zones = append(zones, z.String())
		}
	}
	preimage := []any{"open-trestle/investigation-session", 1, "fixed_generation_route_v1", o.HostSessionIdentity, o.Scope.Identity(), o.Policy.Identity(), o.HeadSnapshotArtifactIdentity, o.HeadSnapshotIdentity, o.HeadManifestIdentity, o.HeadRevisionIdentity, o.InitialContext.Identity(), o.InitialSnapshot.Identity(), o.Deadline.UnixMilli(), o.Routing.CatalogIdentity, o.Routing.RegistryRevision, o.Routing.PerformanceRevision, descriptor(o.Routing.Generation), vd, pd, o.Routing.VerificationRanking.Identity(), o.Routing.Independence.Identity(), o.Routing.Requirements.MinContextTokens(), o.Routing.Requirements.MinOutputTokens(), features, string(o.Routing.Constraints.Classification()), zones, o.Routing.Constraints.ContentLoggingAllowed(), o.Routing.Budget.EstimatedInputTokens(), o.Routing.Budget.MaxOutputTokens(), o.Routing.Budget.MaxCostMicroUSD()}
	if binding.Identity() != v4Hash(v4JSON(t, preimage)) {
		t.Fatal("session identity omitted raw inputs or included future route/turn/result authority")
	}
}

func TestInvestigationProjectionRejectsForeignEvidenceInSameSnapshot(t *testing.T) {
	f := newV4Fixture(t)
	final, _ := v4Final(t, f)
	span := f.changed.EvidenceItem().SourceRange()
	foreignItem, err := evidence.NewEvidenceItem("foreign-source", evidence.EvidenceKindSource, f.changed.EvidenceItem().Digest(), span)
	v4Check(t, err)
	payload := v4JSON(t, map[string]any{"schema_version": 1, "candidates": []any{map[string]any{"title": "Claim", "claim": "A claim on the same range with a different evidence reference.", "severity_hint": "low", "source_range": map[string]any{"source_id": foreignItem.ID(), "start_line": 1, "end_line": 1}, "evidence_ids": []string{foreignItem.ID()}}}})
	part, err := provider.NewResponsePart(provider.ResponsePartStructuredData, "application/json", payload)
	v4Check(t, err)
	usage, err := provider.NewRouteTokenUsage(1, 1, 0)
	v4Check(t, err)
	response, err := provider.NewResponse(provider.CapabilityReviewV1, provider.ResponseFinishStop, []provider.ResponsePart{part}, usage)
	v4Check(t, err)
	candidate, err := ParseCandidateBatch(response, f.expandedSnapshot, []evidence.EvidenceItem{foreignItem})
	v4Check(t, err)
	if _, err := NewInvestigationVerificationRequestContext(final, candidate); err == nil {
		t.Fatal("same-snapshot candidate imported caller evidence not in final context")
	}
}
