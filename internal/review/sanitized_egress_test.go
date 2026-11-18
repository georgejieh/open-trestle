package review

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/secretscan"
)

type sanitizedEgressFixture struct {
	scope            audit.ReviewScope
	rawRequest       provider.Request
	sanitizedRequest provider.Request
	rawArtifact      artifact.Artifact
	request          SanitizedModelRequest
	receipt          SanitizedEgressReceipt
	requestArtifact  artifact.Artifact
	receiptArtifact  artifact.Artifact
	expected         ScannerBinaryDigests
}

type fixedGenerationProjectionFixture struct {
	complete bool
	failure  secretscan.FailureClass
	sources  [][]byte
	matches  []secretscan.Match
	initial  secretscan.ScanMetadata
	residual secretscan.ScanMetadata
	masked   int
}

func (value fixedGenerationProjectionFixture) Complete() bool                   { return value.complete }
func (value fixedGenerationProjectionFixture) Failure() secretscan.FailureClass { return value.failure }
func (value fixedGenerationProjectionFixture) Sources() [][]byte {
	copied := make([][]byte, len(value.sources))
	for index := range value.sources {
		copied[index] = append([]byte(nil), value.sources[index]...)
	}
	return copied
}
func (value fixedGenerationProjectionFixture) Matches() []secretscan.Match {
	return append([]secretscan.Match(nil), value.matches...)
}
func (value fixedGenerationProjectionFixture) Initial() secretscan.ScanMetadata { return value.initial }
func (value fixedGenerationProjectionFixture) Residual() secretscan.ScanMetadata {
	return value.residual
}
func (value fixedGenerationProjectionFixture) MaskedByteCount() int { return value.masked }

type fixedGenerationClientFixture struct {
	projection sanitizedScanProjection
	helper     string
	calls      int
	observed   [][]byte
}

func (value *fixedGenerationClientFixture) Sanitize(_ context.Context, sources [][]byte) sanitizedScanProjection {
	value.calls++
	value.observed = make([][]byte, len(sources))
	for index := range sources {
		value.observed[index] = append([]byte(nil), sources[index]...)
	}
	return value.projection
}
func (value *fixedGenerationClientFixture) HelperSHA256() string { return value.helper }

func sanitizedFixture(t *testing.T) sanitizedEgressFixture {
	t.Helper()
	const literal = "literal-that-must-not-enter-receipt"
	scope, memoryScope, snapshot, source, retrieval := contextPacketFixture(t, literal+"\n")
	limits, _ := NewContextLimits(1<<20, 5)
	packet, err := NewContextPacket(scope, memoryScope, snapshot, ContextTaskCandidateGeneration, []ContextSource{source}, retrieval, limits)
	if err != nil {
		t.Fatal(err)
	}
	rawRequest, err := packet.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	document, err := parseSanitizableRequest(rawRequest, scope.Identity())
	if err != nil {
		t.Fatal(err)
	}
	fields := make([]SanitizedField, len(document.fields))
	matchCount, redactedCount := 0, 0
	for index, reference := range document.fields {
		matches := []secretscan.Match{}
		fieldRedacted := 0
		if reference.role == FieldRoleSourceContent {
			start := strings.Index(*reference.value, literal)
			if start < 0 {
				t.Fatal("source fixture literal missing")
			}
			match := secretscan.Match{SourceOrdinal: index, RuleID: "generic-api-key", StartByte: start, EndByteExclusive: start + len(literal)}
			match.OccurrenceID = secretscan.OccurrenceID(match)
			matches = append(matches, match)
			matchCount++
			fieldRedacted = len(literal)
			redactedCount += fieldRedacted
		}
		fields[index] = SanitizedField{Role: reference.role, Ordinal: index, ScannedByteCount: len(*reference.value), RedactedByteCount: fieldRedacted, Matches: matches}
	}
	sanitizedPayload, err := projectSanitizedRequestPayload(rawRequest, scope.Identity(), fields)
	if err != nil {
		t.Fatal(err)
	}
	sanitizedRequest, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", sanitizedPayload)
	if err != nil {
		t.Fatal(err)
	}
	rawArtifact, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, rawRequest.Payload(), time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	request, err := NewSanitizedModelRequest(scope.Identity(), rawRequest, sanitizedRequest)
	if err != nil {
		t.Fatal(err)
	}
	totalBytes := 0
	for _, field := range fields {
		totalBytes += field.ScannedByteCount
	}
	receipt, err := NewSanitizedEgressReceipt(SanitizedEgressReceiptInput{
		ReviewScopeIdentity: scope.Identity(), RawRequestIdentity: rawRequest.Identity(), SanitizedRequestIdentity: request.SanitizedRequestIdentity(),
		Scanner:           ScannerProfile{WorkerProtocol: 1, Scanner: secretscan.ScannerName, ScannerVersion: secretscan.ScannerVersion, ScannerCommit: secretscan.ScannerCommit, RulesetIdentity: secretscan.RulesetIdentity, RulesetRuleCount: secretscan.RulesetRuleCount, BuildProfile: secretscan.BuildProfile, HelperSHA256: strings.Repeat("b", 64)},
		Initial:           ScanCompletion{Complete: true, FieldCount: len(fields), ScannedByteCount: totalBytes, MatchCount: matchCount},
		Residual:          ScanCompletion{Complete: true, FieldCount: len(fields), ScannedByteCount: totalBytes, MatchCount: 0},
		RedactedByteCount: redactedCount,
		Fields:            fields,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := ScannerBinaryDigests{HelperSHA256: strings.Repeat("b", 64)}
	requestArtifact, receiptArtifact, err := NewSanitizedEgressArtifacts(rawArtifact, request, receipt, expected, time.UnixMilli(200))
	if err != nil {
		t.Fatal(err)
	}
	return sanitizedEgressFixture{scope, rawRequest, sanitizedRequest, rawArtifact, request, receipt, requestArtifact, receiptArtifact, expected}
}

func TestSanitizationPolicyIdentityMatchesFrozenCanonicalPreimage(t *testing.T) {
	preimage := []byte(`{"contract":"open-trestle/sanitized-egress-policy","schema_version":1,"field_mapping_version":1,"mask_byte":42,"preserved_bytes":[10,13],"merge_touching_spans":true,"require_residual_scan":true}`)
	digest := sha256.Sum256(preimage)
	if got := hex.EncodeToString(digest[:]); got != SanitizationPolicyIdentity {
		t.Fatalf("policy identity=%s", got)
	}
}

func TestSanitizedModelRequestCanonicalRoundTripBindsRawAndSanitizedIdentities(t *testing.T) {
	f := sanitizedFixture(t)
	encoded, err := EncodeSanitizedModelRequest(f.request)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("receipt_identity")) {
		t.Fatal("sanitized request contains cyclic receipt identity")
	}
	parsed, err := ParseSanitizedModelRequest(encoded)
	if err != nil || parsed.Validate() != nil || parsed.Identity() != f.request.Identity() || parsed.ReviewScopeIdentity() != f.scope.Identity() || parsed.RawRequestIdentity() != f.rawRequest.Identity() || parsed.SanitizedRequestIdentity() != f.request.SanitizedRequestIdentity() {
		t.Fatalf("parsed=(%#v,%v)", parsed, err)
	}
	request, err := parsed.ProviderRequest()
	if err != nil || request.Identity() != f.request.SanitizedRequestIdentity() || !bytes.Equal(request.Payload(), encoded) || !bytes.Equal(encoded, mustEncodeSanitizedRequest(t, parsed)) {
		t.Fatalf("request=(%#v,%v)", request, err)
	}
}

func TestSanitizedEgressReceiptCanonicalRoundTripClosesScannerFieldsAndCounts(t *testing.T) {
	f := sanitizedFixture(t)
	encoded, err := EncodeSanitizedEgressReceipt(f.receipt)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSanitizedEgressReceipt(encoded)
	fields := parsed.Fields()
	if err != nil || parsed.Validate() != nil || parsed.Identity() != f.receipt.Identity() || parsed.RawRequestIdentity() != f.rawRequest.Identity() || parsed.SanitizedRequestIdentity() != f.request.SanitizedRequestIdentity() || parsed.SanitizationPolicyIdentity() != SanitizationPolicyIdentity || len(fields) < 2 || fields[1].Role != FieldRoleSourceContent || fields[1].Ordinal != 1 || len(fields[1].Matches) != 1 || fields[1].Matches[0].RuleID != "generic-api-key" || !bytes.Equal(encoded, mustEncodeSanitizedReceipt(t, parsed)) {
		t.Fatalf("parsed=(%#v,%v) fields=%#v", parsed, err, fields)
	}
	scanner := parsed.Scanner()
	if scanner.WorkerProtocol != 1 || scanner.Scanner != secretscan.ScannerName || scanner.BuildProfile != secretscan.BuildProfile || scanner.HelperSHA256 != strings.Repeat("b", 64) || scanner.HelperSHA256 != strings.Repeat("c", 64) || !parsed.Initial().Complete || !parsed.Residual().Complete || parsed.Residual().MatchCount != 0 {
		t.Fatalf("scanner=%#v initial=%#v residual=%#v", scanner, parsed.Initial(), parsed.Residual())
	}
}

func TestSanitizedEgressRejectsMalformedCanonicalAndCrossWiredDocuments(t *testing.T) {
	f := sanitizedFixture(t)
	requestEncoded := mustEncodeSanitizedRequest(t, f.request)
	receiptEncoded := mustEncodeSanitizedReceipt(t, f.receipt)
	cases := []struct {
		name    string
		payload []byte
		parse   func([]byte) error
	}{
		{"request whitespace", append(append([]byte(nil), requestEncoded...), '\n'), func(value []byte) error { _, err := ParseSanitizedModelRequest(value); return err }},
		{"receipt whitespace", append(append([]byte(nil), receiptEncoded...), '\n'), func(value []byte) error { _, err := ParseSanitizedEgressReceipt(value); return err }},
		{"request unknown", addJSONProperty(t, requestEncoded, "unknown", true), func(value []byte) error { _, err := ParseSanitizedModelRequest(value); return err }},
		{"receipt unknown", addJSONProperty(t, receiptEncoded, "unknown", true), func(value []byte) error { _, err := ParseSanitizedEgressReceipt(value); return err }},
		{"request duplicate", append([]byte(`{"contract":"duplicate",`), requestEncoded[1:]...), func(value []byte) error { _, err := ParseSanitizedModelRequest(value); return err }},
		{"receipt duplicate", append([]byte(`{"contract":"duplicate",`), receiptEncoded[1:]...), func(value []byte) error { _, err := ParseSanitizedEgressReceipt(value); return err }},
		{"request identity", replaceJSONText(t, requestEncoded, "identity", strings.Repeat("d", 64)), func(value []byte) error { _, err := ParseSanitizedModelRequest(value); return err }},
		{"receipt raw identity", replaceJSONText(t, receiptEncoded, "raw_request_identity", strings.Repeat("d", 64)), func(value []byte) error { _, err := ParseSanitizedEgressReceipt(value); return err }},
		{"receipt sanitized identity", replaceJSONText(t, receiptEncoded, "sanitized_request_identity", strings.Repeat("d", 64)), func(value []byte) error { _, err := ParseSanitizedEgressReceipt(value); return err }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if err := test.parse(test.payload); err == nil {
				t.Fatal("malformed document accepted")
			}
		})
	}
}

func TestSanitizedEgressReceiptRejectsCountSpanRuleAndCompletionMismatches(t *testing.T) {
	f := sanitizedFixture(t)
	encoded := mustEncodeSanitizedReceipt(t, f.receipt)
	mutations := []struct {
		name, path string
		value      any
	}{
		{"field count", "field_count", float64(2)}, {"scan bytes", "scanned_byte_count", float64(21)}, {"match count", "match_count", float64(2)}, {"redacted bytes", "redacted_byte_count", float64(7)},
		{"initial incomplete", "initial_scan.complete", false}, {"residual incomplete", "residual_scan.complete", false}, {"residual match", "residual_scan.match_count", float64(1)},
		{"ordinal", "fields.0.ordinal", float64(1)}, {"field bytes", "fields.0.scanned_byte_count", float64(11)}, {"field redacted", "fields.1.redacted_byte_count", float64(7)},
		{"span", "fields.1.matches.0.end_byte_exclusive", float64(21)}, {"rule", "fields.1.matches.0.rule_id", "not-a-pinned-rule"}, {"occurrence", "fields.1.matches.0.occurrence_id", strings.Repeat("d", 64)},
		{"worker protocol", "scanner.worker_protocol", float64(2)}, {"rule count", "scanner.ruleset_rule_count", float64(416)}, {"profile", "scanner.build_profile", "other"}, {"launcher digest", "scanner.launcher_sha256", strings.Repeat("0", 64)},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			changed := mutateJSONPath(t, encoded, mutation.path, mutation.value)
			if _, err := ParseSanitizedEgressReceipt(changed); err == nil {
				t.Fatal("mismatch accepted")
			}
		})
	}
}

func TestSanitizedEgressArtifactClosureRejectsScopeLineageRetentionAndHandlingMismatch(t *testing.T) {
	f := sanitizedFixture(t)
	if err := ValidateSanitizedEgressArtifacts(f.rawArtifact, f.requestArtifact, f.receiptArtifact, f.expected); err != nil {
		t.Fatal(err)
	}
	if err := ValidateSanitizedEgressArtifacts(f.rawArtifact, f.requestArtifact, artifact.Artifact{}, f.expected); err == nil {
		t.Fatal("sanitized request artifact alone was accepted")
	}
	if err := ValidateSanitizedEgressArtifacts(f.rawArtifact, artifact.Artifact{}, f.receiptArtifact, f.expected); err == nil {
		t.Fatal("receipt artifact alone was accepted")
	}
	otherScope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-b")
	otherRaw, _ := artifact.New(otherScope, artifact.KindContextPacket, "application/json", f.rawArtifact.Classification(), artifact.OriginHost, f.rawArtifact.Protection(), f.rawArtifact.Provenance(), f.rawArtifact.Payload(), f.rawArtifact.CreatedAt(), f.rawArtifact.ExpiresAt())
	wrongRawRequest, _ := provider.NewRequest(provider.CapabilityReviewV1, "application/json", otherRaw.Payload())
	otherRequest, _ := NewSanitizedModelRequest(otherScope.Identity(), wrongRawRequest, f.sanitizedRequest)
	otherReceiptInput := receiptInputFrom(t, f.receipt)
	otherReceiptInput.ReviewScopeIdentity = otherScope.Identity()
	otherReceiptInput.RawRequestIdentity = wrongRawRequest.Identity()
	otherReceiptInput.SanitizedRequestIdentity = otherRequest.SanitizedRequestIdentity()
	otherReceipt, _ := NewSanitizedEgressReceipt(otherReceiptInput)
	otherRequestArtifact, otherReceiptArtifact, _ := NewSanitizedEgressArtifacts(otherRaw, otherRequest, otherReceipt, f.expected, time.UnixMilli(200))
	if err := ValidateSanitizedEgressArtifacts(f.rawArtifact, otherRequestArtifact, otherReceiptArtifact, f.expected); err == nil {
		t.Fatal("cross-scope artifacts accepted")
	}
	if err := ValidateSanitizedEgressArtifacts(f.rawArtifact, f.requestArtifact, otherReceiptArtifact, f.expected); err == nil {
		t.Fatal("cross-wired receipt accepted")
	}

	wrongs := []struct {
		name    string
		request artifact.Artifact
		receipt artifact.Artifact
	}{
		{"request lineage", artifactCopy(t, f.requestArtifact, artifact.KindSanitizedModelRequest, f.requestArtifact.Classification(), f.requestArtifact.Protection(), []string{strings.Repeat("d", 64)}, f.requestArtifact.CreatedAt(), f.requestArtifact.ExpiresAt()), f.receiptArtifact},
		{"receipt lineage", f.requestArtifact, artifactCopy(t, f.receiptArtifact, artifact.KindSanitizedEgressReceipt, f.receiptArtifact.Classification(), f.receiptArtifact.Protection(), []string{f.rawArtifact.Identity()}, f.receiptArtifact.CreatedAt(), f.receiptArtifact.ExpiresAt())},
		{"classification", artifactCopy(t, f.requestArtifact, artifact.KindSanitizedModelRequest, artifact.ClassificationInternal, f.requestArtifact.Protection(), f.requestArtifact.Provenance(), f.requestArtifact.CreatedAt(), f.requestArtifact.ExpiresAt()), f.receiptArtifact},
		{"protection", artifactCopy(t, f.requestArtifact, artifact.KindSanitizedModelRequest, f.requestArtifact.Classification(), artifact.ProtectionEnvelopeEncrypted, f.requestArtifact.Provenance(), f.requestArtifact.CreatedAt(), f.requestArtifact.ExpiresAt()), f.receiptArtifact},
		{"expiry", artifactCopy(t, f.requestArtifact, artifact.KindSanitizedModelRequest, f.requestArtifact.Classification(), f.requestArtifact.Protection(), f.requestArtifact.Provenance(), f.requestArtifact.CreatedAt(), time.UnixMilli(999)), f.receiptArtifact},
		{"created at", artifactCopy(t, f.requestArtifact, artifact.KindSanitizedModelRequest, f.requestArtifact.Classification(), f.requestArtifact.Protection(), f.requestArtifact.Provenance(), time.UnixMilli(201), f.requestArtifact.ExpiresAt()), f.receiptArtifact},
	}
	for _, wrong := range wrongs {
		t.Run(wrong.name, func(t *testing.T) {
			if err := ValidateSanitizedEgressArtifacts(f.rawArtifact, wrong.request, wrong.receipt, f.expected); err == nil {
				t.Fatal("invalid artifact closure accepted")
			}
		})
	}
}

func TestSanitizedEgressFieldMappingUsesClosedRoleOrder(t *testing.T) {
	generation := sanitizedFixture(t)
	document, err := parseSanitizableRequest(generation.rawRequest, generation.scope.Identity())
	if err != nil {
		t.Fatal(err)
	}
	got := make([]FieldRole, len(document.fields))
	for index, field := range document.fields {
		got[index] = field.role
	}
	wantGeneration := []FieldRole{FieldRoleSourcePath, FieldRoleSourceContent, FieldRoleMemoryPath, FieldRoleMemorySymbol, FieldRoleMemoryText}
	if !reflect.DeepEqual(got, wantGeneration) {
		t.Fatalf("generation roles=%v", got)
	}
	generationPacket, candidates := verificationContextFixture(t)
	verification, err := NewVerificationContextPacket(generationPacket, candidates)
	if err != nil {
		t.Fatal(err)
	}
	request, _ := verification.ProviderRequest()
	verificationDocument, err := parseSanitizableRequest(request, generationPacket.ReviewScopeIdentity())
	if err != nil {
		t.Fatal(err)
	}
	got = got[:0]
	for _, field := range verificationDocument.fields {
		got = append(got, field.role)
	}
	wantVerification := append(append([]FieldRole(nil), wantGeneration...), FieldRoleCandidateTitle, FieldRoleCandidateClaim, FieldRoleCandidatePath)
	if !reflect.DeepEqual(got, wantVerification) {
		t.Fatalf("verification roles=%v", got)
	}
}

func TestSanitizedEgressArtifactsRejectUnmaskedPayloadWithInternallyConsistentIdentities(t *testing.T) {
	f := sanitizedFixture(t)
	unmasked, err := NewSanitizedModelRequest(f.scope.Identity(), f.rawRequest, f.rawRequest)
	if err != nil {
		t.Fatal(err)
	}
	input := receiptInputFrom(t, f.receipt)
	input.SanitizedRequestIdentity = unmasked.SanitizedRequestIdentity()
	forged, err := NewSanitizedEgressReceipt(input)
	if err != nil {
		t.Fatal(err)
	}
	requestArtifact, receiptArtifact, err := NewSanitizedEgressArtifacts(f.rawArtifact, unmasked, forged, f.expected, time.UnixMilli(200))
	if err == nil || requestArtifact.Identity() != "" || receiptArtifact.Identity() != "" {
		t.Fatal("unmasked provider payload closed as sanitized")
	}
}

func TestSanitizedEgressArtifactsRequireAuthoritativeBinaryDigests(t *testing.T) {
	f := sanitizedFixture(t)
	for _, expected := range []ScannerBinaryDigests{
		{HelperSHA256: strings.Repeat("d", 64)},
		{HelperSHA256: f.expected.HelperSHA256},
	} {
		if err := ValidateSanitizedEgressArtifacts(f.rawArtifact, f.requestArtifact, f.receiptArtifact, expected); err == nil {
			t.Fatal("wrong nonzero binary digest accepted")
		}
	}
}

func TestSanitizedEgressReceiptConstructorRejectsInvalidCountsAndEvidence(t *testing.T) {
	f := sanitizedFixture(t)
	mutations := []struct {
		name   string
		mutate func(*SanitizedEgressReceiptInput)
	}{
		{"equal request identities", func(input *SanitizedEgressReceiptInput) { input.SanitizedRequestIdentity = input.RawRequestIdentity }},
		{"field count", func(input *SanitizedEgressReceiptInput) { input.Initial.FieldCount++ }},
		{"initial bytes", func(input *SanitizedEgressReceiptInput) { input.Initial.ScannedByteCount++ }},
		{"residual bytes", func(input *SanitizedEgressReceiptInput) { input.Residual.ScannedByteCount++ }},
		{"match count", func(input *SanitizedEgressReceiptInput) { input.Initial.MatchCount++ }},
		{"residual finding", func(input *SanitizedEgressReceiptInput) { input.Residual.MatchCount = 1 }},
		{"incomplete initial", func(input *SanitizedEgressReceiptInput) { input.Initial.Complete = false }},
		{"incomplete residual", func(input *SanitizedEgressReceiptInput) { input.Residual.Complete = false }},
		{"redacted total", func(input *SanitizedEgressReceiptInput) { input.RedactedByteCount++ }},
		{"unknown role", func(input *SanitizedEgressReceiptInput) { input.Fields[0].Role = FieldRole("open") }},
		{"noncontiguous ordinal", func(input *SanitizedEgressReceiptInput) { input.Fields[0].Ordinal = 1 }},
		{"out of range span", func(input *SanitizedEgressReceiptInput) {
			input.Fields[1].Matches[0].EndByteExclusive = 21
			input.Fields[1].Matches[0].OccurrenceID = secretscan.OccurrenceID(input.Fields[1].Matches[0])
		}},
		{"unknown rule", func(input *SanitizedEgressReceiptInput) {
			input.Fields[1].Matches[0].RuleID = "not-a-pinned-rule"
			input.Fields[1].Matches[0].OccurrenceID = secretscan.OccurrenceID(input.Fields[1].Matches[0])
		}},
		{"forged occurrence", func(input *SanitizedEgressReceiptInput) {
			input.Fields[1].Matches[0].OccurrenceID = strings.Repeat("d", 64)
		}},
		{"scanner", func(input *SanitizedEgressReceiptInput) { input.Scanner.Scanner = "other" }},
		{"scanner version", func(input *SanitizedEgressReceiptInput) { input.Scanner.ScannerVersion = "v0" }},
		{"scanner commit", func(input *SanitizedEgressReceiptInput) { input.Scanner.ScannerCommit = strings.Repeat("d", 40) }},
		{"ruleset", func(input *SanitizedEgressReceiptInput) { input.Scanner.RulesetIdentity = strings.Repeat("d", 64) }},
		{"rule count", func(input *SanitizedEgressReceiptInput) { input.Scanner.RulesetRuleCount-- }},
		{"profile", func(input *SanitizedEgressReceiptInput) { input.Scanner.BuildProfile = "other" }},
		{"launcher", func(input *SanitizedEgressReceiptInput) { input.Scanner.HelperSHA256 = strings.Repeat("0", 64) }},
		{"worker", func(input *SanitizedEgressReceiptInput) { input.Scanner.HelperSHA256 = strings.Repeat("0", 64) }},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			input := receiptInputFrom(t, f.receipt)
			test.mutate(&input)
			if value, err := NewSanitizedEgressReceipt(input); err == nil || value.Identity() != "" {
				t.Fatalf("invalid receipt accepted: %#v", value)
			}
		})
	}
}

func TestSanitizedEgressCleanReceiptStillBindsDistinctRequest(t *testing.T) {
	f := sanitizedFixture(t)
	cleanRequest, err := NewSanitizedModelRequest(f.scope.Identity(), f.rawRequest, f.rawRequest)
	if err != nil || cleanRequest.SanitizedRequestIdentity() == f.rawRequest.Identity() {
		t.Fatalf("clean request=(%#v,%v)", cleanRequest, err)
	}
	input := receiptInputFrom(t, f.receipt)
	input.SanitizedRequestIdentity = cleanRequest.SanitizedRequestIdentity()
	input.Initial.MatchCount = 0
	input.RedactedByteCount = 0
	for index := range input.Fields {
		input.Fields[index].RedactedByteCount = 0
		input.Fields[index].Matches = []secretscan.Match{}
	}
	receipt, err := NewSanitizedEgressReceipt(input)
	if err != nil || receipt.Validate() != nil || receipt.Initial().MatchCount != 0 || receipt.RedactedByteCount() != 0 {
		t.Fatalf("clean receipt=(%#v,%v)", receipt, err)
	}
}

func TestSanitizedEgressReturnedFieldsAreImmutable(t *testing.T) {
	f := sanitizedFixture(t)
	fields := f.receipt.Fields()
	fields[0].Role = FieldRoleCandidateClaim
	fields[1].Matches[0].RuleID = "other"
	if f.receipt.Fields()[0].Role != FieldRoleSourcePath || f.receipt.Fields()[1].Role != FieldRoleSourceContent || f.receipt.Fields()[1].Matches[0].RuleID != "generic-api-key" || f.receipt.Validate() != nil {
		t.Fatal("receipt fields were mutable")
	}
}

func TestSanitizedEgressReceiptIsContentFreeAndOccurrenceIdentityIsContentIndependent(t *testing.T) {
	f := sanitizedFixture(t)
	encoded := mustEncodeSanitizedReceipt(t, f.receipt)
	outer, err := artifact.Encode(f.receiptArtifact)
	if err != nil {
		t.Fatal(err)
	}
	searchable := strings.ToLower(string(encoded) + string(outer) + fmt.Sprintf("%s %#v", f.receipt, f.receipt))
	for _, value := range []string{"literal-that-must-not-enter-receipt", base64.StdEncoding.EncodeToString([]byte("literal-that-must-not-enter-receipt"))} {
		if strings.Contains(searchable, strings.ToLower(value)) {
			t.Fatalf("receipt contains forbidden value %q", value)
		}
	}
	receiptJSON := strings.ToLower(string(encoded))
	for _, value := range []string{`"content":`, `"payload":`, `"path":`, `"snippet":`, `"capture":`, `"source_digest":`, `"secret_hash":`, `"fingerprint":`} {
		if strings.Contains(receiptJSON, value) {
			t.Fatalf("receipt contains forbidden field %q", value)
		}
	}
	fields := f.receipt.Fields()
	match := fields[1].Matches[0]
	if match.OccurrenceID != secretscan.OccurrenceID(secretscan.Match{SourceOrdinal: match.SourceOrdinal, RuleID: match.RuleID, StartByte: match.StartByte, EndByteExclusive: match.EndByteExclusive}) {
		t.Fatal("occurrence identity is not the content-independent scanner tuple")
	}
}

func TestSanitizedEgressSchemasMatchCanonicalRecords(t *testing.T) {
	f := sanitizedFixture(t)
	cases := []struct {
		path     string
		encoded  []byte
		contract string
	}{
		{"sanitized-model-request-v1.schema.json", mustEncodeSanitizedRequest(t, f.request), "open-trestle/sanitized-model-request"},
		{"sanitized-egress-receipt-v1.schema.json", mustEncodeSanitizedReceipt(t, f.receipt), "open-trestle/sanitized-egress-receipt"},
	}
	for _, test := range cases {
		t.Run(test.path, func(t *testing.T) {
			assertSanitizedSchemaShape(t, filepath.Join("..", "..", "schemas", "artifact", test.path), test.encoded, test.contract)
		})
	}
}

func TestSanitizedEgressReceiptSchemaPinsRuleInventoryAndUniqueCollections(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "artifact", "sanitized-egress-receipt-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties struct {
			Fields struct {
				Unique bool `json:"uniqueItems"`
				Items  struct {
					Properties struct {
						Matches struct {
							Unique bool `json:"uniqueItems"`
							Items  struct {
								Properties struct {
									RuleID struct {
										Enum []string `json:"enum"`
									} `json:"rule_id"`
								} `json:"properties"`
							} `json:"items"`
						} `json:"matches"`
					} `json:"properties"`
				} `json:"items"`
			} `json:"fields"`
		} `json:"properties"`
	}
	if json.Unmarshal(encoded, &schema) != nil || !schema.Properties.Fields.Unique || !schema.Properties.Fields.Items.Properties.Matches.Unique || !reflect.DeepEqual(schema.Properties.Fields.Items.Properties.Matches.Items.Properties.RuleID.Enum, secretscan.PinnedRuleIDs()) {
		t.Fatal("receipt schema does not pin the exact rule inventory and unique collections")
	}
}

func TestGenerationSanitizerPreflightsEveryFieldBoundAsResourceLimit(t *testing.T) {
	value := ""
	fields := make([]sanitizedFieldReference, maximumSanitizedFields+1)
	for index := range fields {
		fields[index] = sanitizedFieldReference{role: FieldRoleSourcePath, value: &value}
	}
	if sanitizableFieldBounds(sanitizedRequestDocument{fields: fields}) {
		t.Fatal("257 typed fields reached the scanner")
	}
	oversized := strings.Repeat("x", maximumSanitizedFieldBytes+1)
	if sanitizableFieldBounds(sanitizedRequestDocument{fields: []sanitizedFieldReference{{role: FieldRoleSourceContent, value: &oversized}}}) {
		t.Fatal("oversized typed field reached the scanner")
	}
	chunk := strings.Repeat("x", maximumSanitizedFieldBytes)
	aggregate := make([]sanitizedFieldReference, maximumSanitizedAggregateBytes/maximumSanitizedFieldBytes+1)
	for index := range aggregate {
		aggregate[index] = sanitizedFieldReference{role: FieldRoleSourceContent, value: &chunk}
	}
	if sanitizableFieldBounds(sanitizedRequestDocument{fields: aggregate}) {
		t.Fatal("oversized aggregate reached the scanner")
	}
}

func TestFixedGenerationSanitizerClosesMixedCleanAndDetectedFields(t *testing.T) {
	f := sanitizedFixture(t)
	document, err := parseSanitizableRequest(f.rawRequest, f.scope.Identity())
	if err != nil {
		t.Fatal(err)
	}
	const secret = "literal-that-must-not-enter-receipt"
	sources := make([][]byte, len(document.fields))
	sanitizedSources := make([][]byte, len(document.fields))
	matches := []secretscan.Match{}
	total, masked := 0, 0
	for index, field := range document.fields {
		sources[index] = []byte(*field.value)
		sanitizedSources[index] = append([]byte(nil), sources[index]...)
		total += len(sources[index])
		if start := bytes.Index(sources[index], []byte(secret)); start >= 0 {
			match := secretscan.Match{SourceOrdinal: index, RuleID: "generic-api-key", StartByte: start, EndByteExclusive: start + len(secret)}
			match.OccurrenceID = secretscan.OccurrenceID(match)
			matches = append(matches, match)
			copy(sanitizedSources[index][start:start+len(secret)], bytes.Repeat([]byte{'*'}, len(secret)))
			masked += len(secret)
		}
	}
	helper := strings.Repeat("b", 64)
	metadata := secretscan.ScanMetadata{Scanner: secretscan.ScannerName, ScannerVersion: secretscan.ScannerVersion, ScannerCommit: secretscan.ScannerCommit, RulesetIdentity: secretscan.RulesetIdentity, BuildProfile: secretscan.BuildProfile, HelperSHA256: helper, SourceCount: len(sources), ScannedByteCount: total}
	initial, residual := metadata, metadata
	initial.MatchCount = len(matches)
	client := &fixedGenerationClientFixture{helper: helper, projection: fixedGenerationProjectionFixture{complete: true, sources: sanitizedSources, matches: matches, initial: initial, residual: residual, masked: masked}}
	sanitizer := newFixedGenerationRequestSanitizer(client)
	request, receipt, err := sanitizer.SanitizeGeneration(context.Background(), f.rawRequest, f.scope.Identity())
	if err != nil || client.calls != 1 || len(client.observed) != len(sources) {
		t.Fatalf("sanitize=(%#v,%#v,%v) calls=%d", request, receipt, err, client.calls)
	}
	clean := 0
	for _, field := range receipt.Fields() {
		if field.Matches == nil {
			t.Fatal("clean field retained nil matches")
		}
		if len(field.Matches) == 0 {
			clean++
		}
	}
	encoded, err := EncodeSanitizedEgressReceipt(receipt)
	if err != nil || clean == 0 || bytes.Count(encoded, []byte(`"matches":[]`)) != clean {
		t.Fatalf("receipt clean fields=%d payload=%s err=%v", clean, encoded, err)
	}
	expected := sanitizer.ExpectedBinaryDigests()
	requestArtifact, receiptArtifact, err := NewSanitizedEgressArtifacts(f.rawArtifact, request, receipt, expected, time.UnixMilli(200))
	if err != nil || ValidateSanitizedEgressArtifacts(f.rawArtifact, requestArtifact, receiptArtifact, expected) != nil {
		t.Fatal("mixed projection did not close joint artifacts")
	}
	providerRequest, err := request.ProviderRequest()
	if err != nil || providerRequest.Identity() != receipt.SanitizedRequestIdentity() || bytes.Contains(providerRequest.Payload(), []byte(secret)) || bytes.Contains(providerRequest.Payload(), []byte(base64.StdEncoding.EncodeToString([]byte(secret)))) {
		t.Fatal("sanitized provider request identity or canary mismatch")
	}
}

func TestFixedGenerationSanitizerFailsClosedWithoutScanHelper(t *testing.T) {
	f := sanitizedFixture(t)
	sanitizer := NewFixedGenerationRequestSanitizer(nil)
	request, receipt, err := sanitizer.SanitizeGeneration(context.Background(), f.rawRequest, f.scope.Identity())
	if err == nil || request.Identity() != "" || receipt.Identity() != "" {
		t.Fatal("a sanitizer without a scan helper produced generation authority")
	}
}

func TestGenerationSanitizableWireShapeIsFrozen(t *testing.T) {
	if got := sanitizedWireShapeIdentity(); got != generationSanitizableWireShapeIdentity {
		t.Fatalf("generation wire shape=%s", got)
	}
}

func mustEncodeSanitizedRequest(t *testing.T, value SanitizedModelRequest) []byte {
	t.Helper()
	encoded, err := EncodeSanitizedModelRequest(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
func mustEncodeSanitizedReceipt(t *testing.T, value SanitizedEgressReceipt) []byte {
	t.Helper()
	encoded, err := EncodeSanitizedEgressReceipt(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func receiptInputFrom(t *testing.T, value SanitizedEgressReceipt) SanitizedEgressReceiptInput {
	t.Helper()
	return SanitizedEgressReceiptInput{ReviewScopeIdentity: value.ReviewScopeIdentity(), RawRequestIdentity: value.RawRequestIdentity(), SanitizedRequestIdentity: value.SanitizedRequestIdentity(), Scanner: value.Scanner(), Initial: value.Initial(), Residual: value.Residual(), RedactedByteCount: value.RedactedByteCount(), Fields: value.Fields()}
}

func artifactCopy(t *testing.T, source artifact.Artifact, kind artifact.Kind, classification artifact.Classification, protection artifact.Protection, provenance []string, created, expires time.Time) artifact.Artifact {
	t.Helper()
	value, err := artifact.New(source.Scope(), kind, source.MediaType(), classification, source.Origin(), protection, provenance, source.Payload(), created, expires)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func addJSONProperty(t *testing.T, encoded []byte, key string, value any) []byte {
	t.Helper()
	var object map[string]any
	if json.Unmarshal(encoded, &object) != nil {
		t.Fatal("decode")
	}
	object[key] = value
	changed, _ := json.Marshal(object)
	return changed
}
func replaceJSONText(t *testing.T, encoded []byte, key, value string) []byte {
	t.Helper()
	var object map[string]any
	_ = json.Unmarshal(encoded, &object)
	object[key] = value
	changed, _ := json.Marshal(object)
	return changed
}
func mutateJSONPath(t *testing.T, encoded []byte, path string, value any) []byte {
	t.Helper()
	var root any
	if json.Unmarshal(encoded, &root) != nil {
		t.Fatal("decode")
	}
	parts := strings.Split(path, ".")
	current := root
	for _, part := range parts[:len(parts)-1] {
		if index := int(part[0] - '0'); len(part) == 1 && part[0] >= '0' && part[0] <= '9' {
			current = current.([]any)[index]
		} else {
			current = current.(map[string]any)[part]
		}
	}
	last := parts[len(parts)-1]
	if len(last) == 1 && last[0] >= '0' && last[0] <= '9' {
		current.([]any)[int(last[0]-'0')] = value
	} else {
		current.(map[string]any)[last] = value
	}
	changed, _ := json.Marshal(root)
	return changed
}
func assertSanitizedSchemaShape(t *testing.T, path string, encoded []byte, contract string) {
	t.Helper()
	schemaBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Type                 string                     `json:"type"`
		AdditionalProperties bool                       `json:"additionalProperties"`
		Required             []string                   `json:"required"`
		Properties           map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(schemaBytes, &schema) != nil || schema.Type != "object" || schema.AdditionalProperties || len(schema.Required) == 0 {
		t.Fatal("invalid schema")
	}
	var record map[string]json.RawMessage
	_ = json.Unmarshal(encoded, &record)
	for _, key := range schema.Required {
		if _, ok := record[key]; !ok {
			t.Fatalf("missing required %s", key)
		}
	}
	for key := range record {
		if _, ok := schema.Properties[key]; !ok {
			t.Fatalf("undeclared %s", key)
		}
	}
	var got string
	_ = json.Unmarshal(record["contract"], &got)
	if got != contract {
		t.Fatalf("contract=%s", got)
	}
}

func TestFixedVerificationSanitizerScansEveryTypedUntrustedFieldIndependently(t *testing.T) {
	generation, candidates := verificationContextFixture(t)
	packet, err := NewVerificationContextPacket(generation, candidates)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := packet.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	wire, err := decodeVerificationContextWire(raw.Payload())
	if err != nil {
		t.Fatal(err)
	}
	const secret = "sk-proj-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	wire.Sources[0].Path = "src/" + secret + ".go"
	wire.Sources[0].Content = "clean prefix " + secret
	wire.SourceOmissions = []contextSourceOmissionWire{{Path: "missing/" + secret, StartLine: 1, EndLine: 1, Reason: "bounded", Count: 1}}
	wire.Memory.Items = []contextMemoryItemWire{{Path: "memory/" + secret, Symbols: []string{"symbol-" + secret}, Text: "advice " + secret}}
	wire.AdditionalMemory = []contextMemoryWire{{Items: []contextMemoryItemWire{{Path: "extra/" + secret, Symbols: []string{"extra-" + secret}, Text: "extra advice " + secret}}}}
	wire.Candidates[0].Title = "title " + secret
	wire.Candidates[0].Claim = "claim " + secret
	wire.Candidates[0].Path = "candidate/" + secret
	encoded, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = provider.NewRequest(provider.CapabilityReviewV1, "application/json", encoded)
	if err != nil || ValidateVerificationModelRequest(raw, packet.ReviewScopeIdentity()) != nil {
		t.Fatal("verification fixture lost its closed contract")
	}
	document, err := parseSanitizableRequest(raw, packet.ReviewScopeIdentity())
	if err != nil {
		t.Fatal(err)
	}
	sanitizedSources := make([][]byte, len(document.fields))
	matches := make([]secretscan.Match, 0, len(document.fields))
	roles := make(map[FieldRole]bool)
	total, masked := 0, 0
	for index, field := range document.fields {
		source := []byte(*field.value)
		sanitizedSources[index] = append([]byte(nil), source...)
		total += len(source)
		start := bytes.Index(source, []byte(secret))
		if start < 0 {
			continue
		}
		roles[field.role] = true
		match := secretscan.Match{SourceOrdinal: index, RuleID: "generic-api-key", StartByte: start, EndByteExclusive: start + len(secret)}
		match.OccurrenceID = secretscan.OccurrenceID(match)
		matches = append(matches, match)
		copy(sanitizedSources[index][start:start+len(secret)], bytes.Repeat([]byte{'*'}, len(secret)))
		masked += len(secret)
	}
	for _, role := range []FieldRole{FieldRoleSourcePath, FieldRoleSourceContent, FieldRoleSourceOmissionPath, FieldRoleMemoryPath, FieldRoleMemorySymbol, FieldRoleMemoryText, FieldRoleCandidateTitle, FieldRoleCandidateClaim, FieldRoleCandidatePath} {
		if !roles[role] {
			t.Fatalf("typed verifier field %s was not scanned", role)
		}
	}
	helper := strings.Repeat("b", 64)
	metadata := secretscan.ScanMetadata{Scanner: secretscan.ScannerName, ScannerVersion: secretscan.ScannerVersion, ScannerCommit: secretscan.ScannerCommit, RulesetIdentity: secretscan.RulesetIdentity, BuildProfile: secretscan.BuildProfile, HelperSHA256: helper, SourceCount: len(document.fields), ScannedByteCount: total}
	initial, residual := metadata, metadata
	initial.MatchCount = len(matches)
	client := &fixedGenerationClientFixture{helper: helper, projection: fixedGenerationProjectionFixture{complete: true, sources: sanitizedSources, matches: matches, initial: initial, residual: residual, masked: masked}}
	sanitizer := newFixedVerificationRequestSanitizer(client)
	request, receipt, err := sanitizer.SanitizeVerification(context.Background(), raw, packet.ReviewScopeIdentity())
	if err != nil || client.calls != 1 || receipt.Initial().FieldCount != len(document.fields) {
		t.Fatalf("verification sanitize=(%#v,%#v,%v) calls=%d", request, receipt, err, client.calls)
	}
	dispatch, err := request.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := EncodeSanitizedEgressReceipt(receipt)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{[]byte(secret), []byte(base64.StdEncoding.EncodeToString([]byte(secret)))} {
		if bytes.Contains(dispatch.Payload(), forbidden) || bytes.Contains(receiptBytes, forbidden) {
			t.Fatal("verification egress contains literal or base64 secret")
		}
	}
	if sanitizer.Identity() == deriveGenerationRequestSanitizerIdentity(sanitizer.ExpectedBinaryDigests()) {
		t.Fatal("verification reused generation sanitizer identity")
	}
	generationRequest, err := generation.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	if request, receipt, err := sanitizer.SanitizeVerification(context.Background(), generationRequest, packet.ReviewScopeIdentity()); err == nil || request.Identity() != "" || receipt.Identity() != "" {
		t.Fatal("verification sanitizer accepted a generation request")
	}
	generationSanitizer := newFixedGenerationRequestSanitizer(client)
	before := client.calls
	if request, receipt, err := generationSanitizer.SanitizeGeneration(context.Background(), raw, packet.ReviewScopeIdentity()); err == nil || request.Identity() != "" || receipt.Identity() != "" || client.calls != before {
		t.Fatal("generation sanitizer accepted or scanned a verification request")
	}
}

func TestVerificationSanitizableWireShapeIsFrozen(t *testing.T) {
	if got := verificationWireShapeIdentity(); got != verificationSanitizableWireShapeIdentity {
		t.Fatalf("verification wire shape=%s", got)
	}
}
