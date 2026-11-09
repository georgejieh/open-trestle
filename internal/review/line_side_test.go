package review

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/gateway"
	"github.com/georgejieh/open-trestle/internal/provider"
)

// removedGuardCandidates admits one categorized head candidate on the removed
// guard's deletion-point window, citing the given evidence.
func removedGuardCandidates(t *testing.T, cited string) (ContextPacket, ReviewSnapshot, []byte, ContextSource, ContextSource, CandidateBatch) {
	t.Helper()
	packet, snapshot, payload, window, removed := removedGuardPacket(t, removedGuardText)
	document := `{"schema_version":2,"candidates":[{"title":"Missing zero guard","claim":"Div no longer checks b before dividing.","category":"correctness","severity_hint":"high","source_range":{"source_id":"` + window.ReferenceID() + `","start_line":3,"end_line":4},"evidence_ids":` + strings.NewReplacer("WINDOW", window.ReferenceID(), "REMOVED", removed.ReferenceID()).Replace(cited) + `}]}`
	candidates, err := ParseContextCandidateBatch(v7Response(t, document), payload, snapshot, packet.EvidenceItems())
	if err != nil {
		t.Fatal(err)
	}
	return packet, snapshot, payload, window, removed, candidates
}

// relabelBaseSide turns the single finding of a verified-set fixture into a
// categorized finding on removed base lines, with its covering evidence on the
// same side, and rederives every identity.
func relabelBaseSide(t *testing.T, verified VerifiedFindingSet) VerifiedFindingSet {
	t.Helper()
	finding := verified.findings[0]
	finding.category, finding.side = CandidateCategoryCorrectness, LineSideBase
	finding.evidenceBindings = append([]candidateEvidenceBinding(nil), finding.evidenceBindings...)
	for index := range finding.evidenceBindings {
		finding.evidenceBindings[index].side = LineSideBase
	}
	finding.fingerprint = deriveVerifiedFindingFingerprint(finding)
	finding.identity = deriveVerifiedFindingIdentity(finding)
	verified.findings = []VerifiedFinding{finding}
	verified.identity = deriveVerifiedFindingSetIdentity(verified)
	if err := verified.Validate(); err != nil {
		t.Fatal(err)
	}
	return verified
}

// rederiveCandidate recomputes a mutated candidate's identities so that only
// the rule under test can refuse it.
func rederiveCandidate(batch CandidateBatch, mutate func(*CandidateFinding)) CandidateBatch {
	findings := append([]CandidateFinding(nil), batch.findings...)
	for index := range findings {
		findings[index].evidenceBindings = append([]candidateEvidenceBinding(nil), findings[index].evidenceBindings...)
		mutate(&findings[index])
		findings[index].identity = deriveCandidateFindingIdentity(findings[index])
	}
	batch.findings = findings
	batch.identity = deriveCandidateBatchIdentity(batch)
	return batch
}

func TestCitedRemovedLinesRecordABaseBinding(t *testing.T) {
	_, _, payload, window, removed, candidates := removedGuardCandidates(t, `["WINDOW","REMOVED"]`)
	finding := candidates.Findings()[0]
	if finding.Side() != LineSideHead {
		t.Fatal("head candidate does not record head lines")
	}
	sides := map[string]LineSide{}
	for _, binding := range finding.evidenceBindings {
		sides[binding.identity] = binding.side
	}
	if sides[window.ReferenceID()] != LineSideHead || sides[removed.ReferenceID()] != LineSideBase {
		t.Fatalf("binding sides = %v", sides)
	}
	encoded, err := EncodeCandidateBatch(candidates)
	if err != nil || bytes.Count(encoded, []byte(`"side":"base"`)) != 1 {
		t.Fatalf("encoded base binding: %s, %v", encoded, err)
	}
	parsed, err := ParseEncodedCandidateBatch(encoded)
	if err != nil || parsed.Identity() != candidates.Identity() || !CandidateBatchMatchesContext(payload, parsed) {
		t.Fatalf("recorded base binding does not read back: %v", err)
	}
	// Removing the recorded side changes the identity, so the bytes refuse.
	forged := bytes.Replace(encoded, []byte(`,"side":"base"`), nil, 1)
	if _, err := ParseEncodedCandidateBatch(forged); err == nil {
		t.Fatal("candidate batch without its recorded base side read back")
	}
	if _, err := ParseEncodedCandidateBatch(bytes.Replace(encoded, []byte(`"side":"base"`), []byte(`"side":"head"`), 1)); err == nil {
		t.Fatal("explicit head side accepted")
	}

	// A head-only batch keeps its sideless bytes.
	_, _, _, _, _, headOnly := removedGuardCandidates(t, `["WINDOW"]`)
	if encoded, err := EncodeCandidateBatch(headOnly); err != nil || bytes.Contains(encoded, []byte(`"side"`)) {
		t.Fatalf("head-only batch records a side: %s", encoded)
	}
}

func TestBaseBindingNeverCoversHeadLinesOnReadback(t *testing.T) {
	_, _, payload, _, removed, candidates := removedGuardCandidates(t, `["WINDOW","REMOVED"]`)
	// Keep only the removed_lines citation and move the head anchor onto the
	// same numbers, calc.go 4-6, which that base binding numerically contains.
	forged := rederiveCandidate(candidates, func(finding *CandidateFinding) {
		finding.evidenceBindings = finding.evidenceBindings[:0:0]
		for _, binding := range candidates.findings[0].evidenceBindings {
			if binding.identity == removed.ReferenceID() {
				finding.evidenceBindings = append(finding.evidenceBindings, binding)
				finding.sourceRange = binding.sourceRange
			}
		}
	})
	if err := forged.Validate(); !errors.Is(err, ErrCandidateEvidenceRangeMismatch) {
		t.Fatalf("base binding covered a head location: %v", err)
	}
	// The same binding recorded as head lines covers it, but the context
	// stage check refuses a head binding that names a removed_lines source.
	relabelled := rederiveCandidate(candidates, func(finding *CandidateFinding) {
		for index := range finding.evidenceBindings {
			finding.evidenceBindings[index].side = LineSideHead
		}
	})
	if err := relabelled.Validate(); err != nil {
		t.Fatal(err)
	}
	if CandidateBatchMatchesContext(payload, relabelled) {
		t.Fatal("readback accepted a removed_lines citation recorded as head lines")
	}
	anchored := rederiveCandidate(candidates, func(finding *CandidateFinding) {
		finding.sourceReferenceID = removed.ReferenceID()
	})
	if CandidateBatchMatchesContext(payload, anchored) {
		t.Fatal("readback accepted a head finding anchored on a removed_lines source")
	}
	// A recorded base-side finding reads back on the removed_lines source it
	// names, only with that source's head line.
	baseAnchored := rederiveCandidate(candidates, func(finding *CandidateFinding) {
		finding.sourceReferenceID, finding.side = removed.ReferenceID(), LineSideBase
		for _, binding := range finding.evidenceBindings {
			if binding.identity == removed.ReferenceID() {
				finding.sourceRange = binding.sourceRange
			}
		}
	})
	if baseAnchored.Validate() != nil || !CandidateBatchMatchesContext(payload, baseAnchored) {
		t.Fatal("readback refused a recorded base-side anchor")
	}
	wrongHeadLine := rederiveCandidate(baseAnchored, func(finding *CandidateFinding) { finding.headLine = 2 })
	if wrongHeadLine.Validate() != nil || CandidateBatchMatchesContext(payload, wrongHeadLine) {
		t.Fatal("readback accepted a base-side anchor with another head line")
	}
	unknown := rederiveCandidate(candidates, func(finding *CandidateFinding) {
		finding.sourceReferenceID = "unknown-source"
	})
	if CandidateBatchMatchesContext(payload, unknown) {
		t.Fatal("readback accepted a finding on a source outside the context")
	}
	if !CandidateBatchMatchesContext(payload, candidates) {
		t.Fatal("admitted batch does not match its own context")
	}
}

func TestUncategorizedBatchesRecordNoSide(t *testing.T) {
	f, investigationRemoved := removedLinesInvestigationFixture(t, "\tif x == 0 { return 0 }\n")
	binding, err := NewInvestigationContextBinding(f.binding)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := NewInvestigationGenerationContext(binding, f.initial, f.initialSnapshot, InvestigationContextState{Turn: 1, ScannedBytes: uint64(len(f.changed.Content()))})
	if err != nil {
		t.Fatal(err)
	}
	document := `{"schema_version":1,"candidates":[{"title":"Missing guard","claim":"The zero check was removed.","severity_hint":"high","source_range":{"source_id":"` + f.changed.ReferenceID() + `","start_line":1,"end_line":1},"evidence_ids":["` + f.changed.ReferenceID() + `","` + investigationRemoved.ReferenceID() + `"]}]}`
	batch, err := ParseInvestigationCandidateBatch(v7Response(t, document), initial)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeCandidateBatch(batch)
	if err != nil || bytes.Contains(encoded, []byte(`"side"`)) || !bytes.Contains(encoded, []byte(`"schema_version":1`)) {
		t.Fatalf("v1 batch records a side: %s", encoded)
	}
	sided := rederiveCandidate(batch, func(finding *CandidateFinding) { finding.evidenceBindings[0].side = LineSideBase })
	if err := sided.Validate(); err == nil {
		t.Fatal("v1 candidate accepted a recorded side")
	}
}

func TestVerdictCitingRemovedLinesUsesVerificationBatchV2(t *testing.T) {
	packet, snapshot, payload, window, removed, candidates := removedGuardCandidates(t, `["WINDOW","REMOVED"]`)
	request, err := NewVerificationRequestContext(payload, packet.Identity(), packet.ReviewScopeIdentity(), packet.MemoryScopeIdentity(), packet.MemoryIdentity(), snapshot, packet.EvidenceItems(), candidates)
	if err != nil {
		t.Fatal(err)
	}
	verdict := func(cited string) provider.Response {
		return v7Response(t, `{"schema_version":1,"verdicts":[{"candidate_id":"`+candidates.Findings()[0].Identity()+`","outcome":"verified","severity":"high","rationale":"The removed guard leaves the division unchecked.","evidence_ids":`+cited+`}]}`)
	}
	headOnly, err := ParseContextVerificationBatch(verdict(`["`+window.ReferenceID()+`"]`), candidates, request)
	if err != nil {
		t.Fatal(err)
	}
	if encoded, err := EncodeVerificationBatch(headOnly); err != nil || !bytes.Contains(encoded, []byte(`"schema_version":1`)) || bytes.Contains(encoded, []byte(`"side"`)) {
		t.Fatalf("head-only verdicts changed their version 1 bytes: %s", encoded)
	}
	batch, err := ParseContextVerificationBatch(verdict(`["`+removed.ReferenceID()+`","`+window.ReferenceID()+`"]`), candidates, request)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeVerificationBatch(batch)
	if err != nil || !bytes.Contains(encoded, []byte(`"schema_version":2`)) || bytes.Count(encoded, []byte(`"side":"base"`)) != 1 {
		t.Fatalf("base citation is not a version 2 batch: %s", encoded)
	}
	parsed, err := ParseEncodedVerificationBatch(encoded)
	if err != nil || parsed.Identity() != batch.Identity() || !VerificationBatchMatchesContext(request, candidates, parsed) {
		t.Fatalf("version 2 verdicts do not read back: %v", err)
	}
	if _, err := ParseEncodedVerificationBatch(bytes.Replace(encoded, []byte(`"schema_version":2`), []byte(`"schema_version":1`), 1)); err == nil {
		t.Fatal("base citation accepted under version 1")
	}
	relabelled := parsed
	relabelled.results = append([]VerificationResult(nil), parsed.results...)
	relabelled.results[0].evidenceBindings = append([]candidateEvidenceBinding(nil), parsed.results[0].evidenceBindings...)
	for index := range relabelled.results[0].evidenceBindings {
		relabelled.results[0].evidenceBindings[index].side = LineSideHead
	}
	relabelled.results[0].identity = deriveVerificationResultIdentity(relabelled.results[0])
	relabelled.identity = deriveVerificationBatchIdentity(relabelled)
	if relabelled.Validate() != nil || VerificationBatchMatchesContext(request, candidates, relabelled) {
		t.Fatal("readback accepted a removed_lines citation recorded as head lines")
	}
	other := parsed
	other.results = append([]VerificationResult(nil), parsed.results...)
	other.results[0].side = LineSideBase
	if VerificationBatchMatchesContext(request, candidates, other) {
		t.Fatal("readback accepted a verdict side unlike its candidate")
	}
}

func TestVerifiedFindingSidesReadBack(t *testing.T) {
	_, _, _, _, removed, candidates := removedGuardCandidates(t, `["WINDOW","REMOVED"]`)
	candidate := candidates.Findings()[0]
	finding := VerifiedFinding{
		independentReceiptIdentity: strings.Repeat("1", 64), snapshotIdentity: candidates.SnapshotIdentity(),
		candidateIdentity: candidate.Identity(), verificationIdentity: strings.Repeat("2", 64),
		title: candidate.Title(), claim: candidate.Claim(), severity: SeverityHigh,
		sourceRange: candidate.SourceRange(), evidenceBindings: candidate.evidenceBindings,
		category: candidate.Category(), side: candidate.Side(),
	}
	finding.fingerprint = deriveVerifiedFindingFingerprint(finding)
	finding.identity = deriveVerifiedFindingIdentity(finding)
	set := VerifiedFindingSet{
		independentReceiptIdentity: finding.independentReceiptIdentity, candidateBatchIdentity: candidates.Identity(),
		verificationBatchIdentity: strings.Repeat("3", 64), snapshotIdentity: candidates.SnapshotIdentity(),
		candidateCount: 1, findings: []VerifiedFinding{finding},
	}
	set.identity = deriveVerifiedFindingSetIdentity(set)
	encoded, err := EncodeVerifiedFindingSet(set)
	if err != nil || bytes.Count(encoded, []byte(`"side":"base"`)) != 1 {
		t.Fatalf("verified set does not record the base binding: %s, %v", encoded, err)
	}
	parsed, err := ParseEncodedVerifiedFindingSet(encoded)
	if err != nil || parsed.Identity() != set.Identity() {
		t.Fatalf("verified set does not read back: %v", err)
	}
	// With the anchor moved onto the base binding's numbers, only that base
	// binding contains it, and the verified finding must refuse it.
	only := finding
	only.evidenceBindings = nil
	for _, binding := range finding.evidenceBindings {
		if binding.identity == removed.ReferenceID() {
			only.evidenceBindings = append(only.evidenceBindings, binding)
			only.sourceRange = binding.sourceRange
		}
	}
	only.fingerprint = deriveVerifiedFindingFingerprint(only)
	only.identity = deriveVerifiedFindingIdentity(only)
	if err := only.Validate(); !errors.Is(err, ErrVerifiedFindingBindingMismatch) {
		t.Fatalf("base binding covered a verified head location: %v", err)
	}
	// A base location never shares a fingerprint with an equal head location.
	base := finding
	base.side = LineSideBase
	if deriveVerifiedFindingFingerprint(base) == finding.fingerprint {
		t.Fatal("base and head locations share a fingerprint")
	}
}

// A diagnostic set version without sides refuses a base-side finding rather
// than export its base lines as head lines.
func TestHeadOnlyConsumersRefuseABaseSideFinding(t *testing.T) {
	receipt, verified := verifiedSetFixture(t, "verified", gateway.RouteIndependenceDistinctProvider)
	base := relabelBaseSide(t, verified)
	scope, _ := audit.NewReviewScope("tenant", "repository", "review-run")
	if _, err := ExportDiagnosticSet(scope, strings.Repeat("1", 40), receipt, verified); err != nil {
		t.Fatalf("head fixture does not export: %v", err)
	}
	// Version 2 cannot record a side; only version 8 carries a base-side finding.
	if _, err := ExportDiagnosticSet(scope, strings.Repeat("1", 40), receipt, base); err == nil {
		t.Fatal("version 2 diagnostic export accepted a base-side finding")
	}
}
