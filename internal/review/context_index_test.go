package review

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/memory"
)

// indexPacketFixture builds a generation context of one changed hunk and one
// caller of it, the unchanged head code a repository index proposes.
func indexPacketFixture(t *testing.T, limits ContextLimits) (ContextPacket, ReviewSnapshot, ContextSource, ContextSource) {
	t.Helper()
	reviewScope, err := audit.NewReviewScope("tenant", "repository", "review-run")
	if err != nil {
		t.Fatal(err)
	}
	memoryScope, err := memory.NewScope("tenant", "repository", "actor", memory.RefVisibilityExact, strings.Repeat("a", 64), []string{"internal"})
	if err != nil {
		t.Fatal(err)
	}
	changedRange, _ := evidence.NewSourceRange("internal/example.go", 10, 10)
	callerRange, _ := evidence.NewSourceRange("internal/caller.go", 4, 4)
	snapshot, err := NewReviewSnapshot("workspace", strings.Repeat("b", 64), []evidence.SourceRange{changedRange, callerRange})
	if err != nil {
		t.Fatal(err)
	}
	changed := v7ContextSource(t, ContextStageChangedHunk, "source-1", "internal/example.go", 10, "return value\n")
	caller := v7ContextSource(t, ContextStageDirectReference, "caller-1", "internal/caller.go", 4, "use(value)\n")
	query, _ := memory.NewLexicalQuery(memoryScope, "internal/example.go", []string{"error"}, []string{"Example"}, time.UnixMilli(200), 5)
	retrieval, err := memory.NewLexicalIndex().Search(context.Background(), memoryScope, query)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := NewContextPacket(reviewScope, memoryScope, snapshot, ContextTaskCandidateGeneration, []ContextSource{changed, caller}, retrieval, limits)
	if err != nil {
		t.Fatal(err)
	}
	return packet, snapshot, changed, caller
}

func indexManifestSpec(changed, caller ContextSource) ContextManifestSpec {
	return ContextManifestSpec{
		Budget: RouteContextBudget(64000, 4096),
		Plan: ContextPlan{
			State: ContextIndexUsed, Complete: true, Dependents: 1,
			Coverage: ContextIndexCoverage{Files: 3, Indexed: 2, LeftOut: 1},
			Checks:   []string{"unit_tests", "lint", "lint"},
		},
		Included: []ContextManifestSource{{SourceID: caller.ReferenceID(), Stage: ContextStageDirectReference, Rank: 1, Depth: 1}},
		Omitted:  []ContextManifestOmission{{Stage: ContextStageRelatedTest, Reason: ContextOmittedStageLimit, Count: 2}},
		Changed:  []ContextManifestDefinition{{SourceID: changed.ReferenceID(), Line: 10, Dependents: 1}},
	}
}

func TestRelatedTestAndRepositoryMapStagesBelongToVersionTenAndNine(t *testing.T) {
	for _, stage := range []ContextStage{ContextStageRelatedTest, ContextStageRepositoryMap} {
		token := stage.String()
		if validContextStageToken(token, true, false) || !validContextStageToken(token, true, true) {
			t.Fatalf("%s is not limited to the index contract versions", token)
		}
	}
	for _, stage := range []ContextStage{ContextStageEnclosingSymbol, ContextStageDirectReference} {
		if !validContextStageToken(stage.String(), true, false) {
			t.Fatalf("%s was readable before the index contract versions and is not now", stage)
		}
	}
	if !validContextStageToken("changed_hunk", false, false) || validContextStageToken("unknown", true, true) {
		t.Fatal("the stage set outside the index stages changed")
	}
}

func TestContextManifestIsRecordedValidatedAndSummarised(t *testing.T) {
	limits, _ := NewContextLimits(1<<20, 5)
	packet, snapshot, changed, caller := indexPacketFixture(t, limits)
	if !packet.manifest.IsZero() {
		t.Fatal("a packet without accounting has a manifest")
	}
	spec := indexManifestSpec(changed, caller)
	bound, err := packet.WithContextManifest(spec)
	if err != nil || bound.Identity() == packet.Identity() {
		t.Fatalf("WithContextManifest() = %v", err)
	}
	if _, err := bound.WithContextManifest(spec); !errors.Is(err, ErrInvalidContextManifest) {
		t.Fatalf("a second manifest was bound: %v", err)
	}
	request, err := bound.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	payload := request.Payload()
	if err := ValidateContextPacketRequest(payload, bound.Identity(), bound.ReviewScopeIdentity(), bound.MemoryScopeIdentity(), bound.MemoryIdentity(), snapshot, bound.EvidenceItems()); err != nil {
		t.Fatalf("manifest packet rejected: %v", err)
	}
	summary, err := ContextManifestOf(payload)
	if err != nil {
		t.Fatal(err)
	}
	if !summary.Present || summary.State != ContextIndexUsed || !summary.Complete || summary.Dependents != 1 || summary.Coverage.Files != 3 || summary.Coverage.LeftOut != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.Budget.Basis != ContextBudgetRouteWindow || summary.Budget.RouteContextTokens != 64000 || summary.Budget.OutputTokens != 4096 {
		t.Fatalf("budget = %+v", summary.Budget)
	}
	if len(summary.Included) != 1 || summary.Included[0] != (ContextManifestSummarySource{SourceID: caller.ReferenceID(), Path: "internal/caller.go", Stage: ContextStageDirectReference, StartLine: 4, EndLine: 4, Rank: 1, Depth: 1}) {
		t.Fatalf("included = %+v", summary.Included)
	}
	if len(summary.Omitted) != 1 || summary.Omitted[0] != (ContextManifestOmission{Stage: ContextStageRelatedTest, Reason: ContextOmittedStageLimit, Count: 2}) {
		t.Fatalf("omitted = %+v", summary.Omitted)
	}
	if len(summary.Changed) != 1 || summary.Changed[0] != (ContextManifestSummaryDefinition{Path: "internal/example.go", Line: 10, Dependents: 1}) {
		t.Fatalf("changed = %+v", summary.Changed)
	}
	if strings.Join(summary.Checks, ",") != "lint,unit_tests" {
		t.Fatalf("checks = %v", summary.Checks)
	}
	// A context before version 10 has no manifest.
	plain, err := ContextManifestOf(mustMarshal(t, legacyGenerationWire(t, mustDecodeGeneration(t, payload), modelGenerationContextVersionV9)))
	if err != nil || plain.Present {
		t.Fatalf("version 9 summary = %+v, %v", plain, err)
	}
	// Only index sources are index context: the changed hunk is change evidence.
	ranges, err := ContextIndexSourceRanges(payload)
	callerRange, _ := evidence.NewSourceRange("internal/caller.go", 4, 4)
	if err != nil || len(ranges) != 1 || !ranges[callerRange] {
		t.Fatalf("index ranges = %v, %v", ranges, err)
	}
	ids, err := ContextChangeEvidence(payload)
	if err != nil || len(ids) != 1 || !ids[changed.ReferenceID()] {
		t.Fatalf("change evidence = %v, %v", ids, err)
	}
}

func TestContextManifestRefusesAccountingThatDisagreesWithTheSources(t *testing.T) {
	limits, _ := NewContextLimits(1<<20, 5)
	packet, _, changed, caller := indexPacketFixture(t, limits)
	for name, mutate := range map[string]func(*ContextManifestSpec){
		"an index source left unlisted":        func(s *ContextManifestSpec) { s.Included = nil },
		"a listed source with the wrong stage": func(s *ContextManifestSpec) { s.Included[0].Stage = ContextStageRelatedTest },
		"an unknown source":                    func(s *ContextManifestSpec) { s.Included[0].SourceID = strings.Repeat("0", 64) },
		"a definition on an index source":      func(s *ContextManifestSpec) { s.Changed[0].SourceID = caller.ReferenceID(); s.Changed[0].Line = 4 },
		"a definition line outside the source": func(s *ContextManifestSpec) { s.Changed[0].Line = 99 },
		"more tests than dependents":           func(s *ContextManifestSpec) { s.Changed[0].Tests = 5 },
		"an unknown omission reason":           func(s *ContextManifestSpec) { s.Omitted[0].Reason = "unlucky" },
		"an unknown budget basis":              func(s *ContextManifestSpec) { s.Budget.Basis = "guess" },
		"an unknown check class":               func(s *ContextManifestSpec) { s.Plan.Checks = []string{"everything"} },
		"an unavailable index with sources":    func(s *ContextManifestSpec) { s.Plan.State, s.Plan.Complete = ContextIndexUnavailable, false },
	} {
		spec := indexManifestSpec(changed, caller)
		mutate(&spec)
		if _, err := packet.WithContextManifest(spec); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func mustDecodeGeneration(t *testing.T, payload []byte) contextPacketWire {
	t.Helper()
	wire, err := decodeGenerationContextWire(payload)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

// A recorded version 9 context cannot carry what version 10 added.
func TestRecordedVersionNineContextRefusesVersionTenFields(t *testing.T) {
	limits, _ := NewContextLimits(1<<20, 5)
	packet, snapshot, changed, caller := indexPacketFixture(t, limits)
	bound, err := packet.WithContextManifest(indexManifestSpec(changed, caller))
	if err != nil {
		t.Fatal(err)
	}
	request, _ := bound.ProviderRequest()
	current := mustDecodeGeneration(t, request.Payload())
	readable := func(wire contextPacketWire) bool {
		encoded := mustMarshal(t, wire)
		return ValidateRecordedContextPacketRequest(encoded, modelContractDigest(encoded), bound.ReviewScopeIdentity(), bound.MemoryScopeIdentity(), bound.MemoryIdentity(), snapshot, bound.EvidenceItems()) == nil
	}
	if !readable(current) {
		t.Fatal("the version 10 context does not read back")
	}
	if !readable(legacyGenerationWire(t, current, modelGenerationContextVersionV9)) {
		t.Fatal("the same sources do not read back as a version 9 context")
	}
	for name, mutate := range map[string]func(*contextPacketWire){
		"a context manifest": func(w *contextPacketWire) { w.ContextManifest = current.ContextManifest },
		"repository checks":  func(w *contextPacketWire) { w.RepositoryChecks = []string{"lint"} },
	} {
		wire := legacyGenerationWire(t, current, modelGenerationContextVersionV9)
		mutate(&wire)
		if readable(wire) {
			t.Fatalf("version 9 context with %s read back", name)
		}
	}
}

// The verifier sees the index sources and the source limit of version 10, and
// never the manifest or the repository checks, which are finder accounting.
func TestVerifierReceivesIndexSourcesWithoutTheManifest(t *testing.T) {
	limits, _ := NewContextLimits(1<<20, 5)
	packet, snapshot, changed, caller := indexPacketFixture(t, limits)
	spec := indexManifestSpec(changed, caller)
	generation, err := packet.WithContextManifest(spec)
	if err != nil {
		t.Fatal(err)
	}
	generationRequest, _ := generation.ProviderRequest()
	document := `{"schema_version":2,"candidates":[{"title":"Caller breaks","claim":"The caller passes a value the change no longer accepts.","category":"correctness","severity_hint":"medium","source_range":{"source_id":"` + changed.ReferenceID() + `","start_line":10,"end_line":10},"evidence_ids":["` + changed.ReferenceID() + `","` + caller.ReferenceID() + `"]}]}`
	candidates, err := ParseContextCandidateBatch(v7Response(t, document), generationRequest.Payload(), snapshot, generation.EvidenceItems())
	if err != nil {
		t.Fatal(err)
	}
	verification, err := NewVerificationContextPacket(generation, candidates)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := verification.ProviderRequest()
	fields := modelContractFields(t, request.Payload())
	if string(fields["schema_version"]) != "9" || fields["context_manifest"] != nil || fields["repository_checks"] != nil {
		t.Fatalf("verifier fields: version=%s manifest=%s checks=%s limits=%s", fields["schema_version"], fields["context_manifest"], fields["repository_checks"], fields["limits"])
	}
	var wire verificationContextWire
	if err := json.Unmarshal(request.Payload(), &wire); err != nil {
		t.Fatal(err)
	}
	stages := []string{}
	for _, source := range wire.Sources {
		stages = append(stages, source.Stage)
	}
	if strings.Join(stages, ",") != "changed_hunk,direct_reference" {
		t.Fatalf("verifier stages = %v", stages)
	}
	system, err := TrustedModelRequestInstructions(request.Payload())
	if err != nil || system != verificationOutputInstructionsV9 || !strings.Contains(system, indexContextVerificationSentence) {
		t.Fatal("the verifier system channel does not explain the index sources")
	}
	generationSystem, err := TrustedModelRequestInstructions(generationRequest.Payload())
	if err != nil || generationSystem != candidateOutputInstructionsV10 || !strings.Contains(generationSystem, indexContextGenerationSentence) || !strings.Contains(generationSystem, repositoryChecksGenerationSentence) {
		t.Fatal("the generation system channel does not explain the index sources and repository checks")
	}
}

func TestContextPlanDeadlineIsAQuarterOfTheTimeLeft(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	bounded, stop := WithContextPlanDeadline(parent)
	defer stop()
	deadline, ok := bounded.Deadline()
	if left := time.Until(deadline); !ok || left > 15*time.Minute || left < 14*time.Minute {
		t.Fatalf("bounded deadline in %s", left)
	}
	if ContextPlanAbandoned(parent, bounded) {
		t.Fatal("work with time left was abandoned")
	}
	stop()
	if !ContextPlanAbandoned(parent, bounded) {
		t.Fatal("work past its bound was not abandoned")
	}
	cancel()
	if ContextPlanAbandoned(parent, bounded) {
		t.Fatal("a canceled review counted as abandoned work")
	}
	unbounded, stopUnbounded := WithContextPlanDeadline(context.Background())
	defer stopUnbounded()
	if _, ok := unbounded.Deadline(); ok {
		t.Fatal("work without a review deadline was given one")
	}
}
