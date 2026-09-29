package review

import (
	"bytes"
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
		Scanner:           ScannerProfile{WorkerProtocol: 1, Scanner: secretscan.ScannerName, ScannerVersion: secretscan.ScannerVersion, ScannerCommit: secretscan.ScannerCommit, RulesetIdentity: secretscan.RulesetIdentity, RulesetRuleCount: secretscan.RulesetRuleCount, BuildProfile: secretscan.BuildProfile, LauncherSHA256: strings.Repeat("b", 64), WorkerSHA256: strings.Repeat("c", 64)},
		Initial:           ScanCompletion{Complete: true, FieldCount: len(fields), ScannedByteCount: totalBytes, MatchCount: matchCount},
		Residual:          ScanCompletion{Complete: true, FieldCount: len(fields), ScannedByteCount: totalBytes, MatchCount: 0},
		RedactedByteCount: redactedCount,
		Fields:            fields,
	})
	if err != nil {
		t.Fatal(err)
	}
	expected := ScannerBinaryDigests{LauncherSHA256: strings.Repeat("b", 64), WorkerSHA256: strings.Repeat("c", 64)}
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
	if scanner.WorkerProtocol != 1 || scanner.Scanner != secretscan.ScannerName || scanner.BuildProfile != secretscan.BuildProfile || scanner.LauncherSHA256 != strings.Repeat("b", 64) || scanner.WorkerSHA256 != strings.Repeat("c", 64) || !parsed.Initial().Complete || !parsed.Residual().Complete || parsed.Residual().MatchCount != 0 {
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
		{LauncherSHA256: strings.Repeat("d", 64), WorkerSHA256: f.expected.WorkerSHA256},
		{LauncherSHA256: f.expected.LauncherSHA256, WorkerSHA256: strings.Repeat("d", 64)},
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
		{"launcher", func(input *SanitizedEgressReceiptInput) { input.Scanner.LauncherSHA256 = strings.Repeat("0", 64) }},
		{"worker", func(input *SanitizedEgressReceiptInput) { input.Scanner.WorkerSHA256 = strings.Repeat("0", 64) }},
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
