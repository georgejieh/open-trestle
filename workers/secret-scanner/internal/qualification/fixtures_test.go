package qualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
)

type scannerIdentity struct {
	Scanner          string `json:"scanner"`
	ScannerVersion   string `json:"scanner_version"`
	ScannerCommit    string `json:"scanner_commit"`
	RulesetIdentity  string `json:"ruleset_identity"`
	RulesetRuleCount int    `json:"ruleset_rule_count"`
	BuildProfile     string `json:"build_profile"`
}

type coverageSummary struct {
	ExpectedOccurrences int      `json:"expected_occurrences"`
	AcceptedDetections  int      `json:"accepted_detections"`
	PositiveFixtures    int      `json:"positive_fixtures"`
	DetectedFixtures    int      `json:"detected_fixtures"`
	RepeatedExpected    int      `json:"repeated_expected"`
	RepeatedDetected    int      `json:"repeated_detected"`
	ExactDetectionSpans int      `json:"exact_detection_spans"`
	KnownMisses         []string `json:"known_misses"`
}

type coverageOccurrence struct {
	Name              string `json:"name"`
	AcceptedDetection bool   `json:"accepted_detection"`
	SpanID            string `json:"span_id"`
}

type coverageFixture struct {
	ID            string               `json:"id"`
	FixtureSHA256 string               `json:"fixture_sha256"`
	ContentBase64 string               `json:"content_base64"`
	Occurrences   []coverageOccurrence `json:"occurrences"`
}

type nearMissFinding struct {
	RuleID string `json:"rule_id"`
	SpanID string `json:"span_id"`
}

type nearMissFixture struct {
	ID            string            `json:"id"`
	FixtureSHA256 string            `json:"fixture_sha256"`
	ContentBase64 string            `json:"content_base64"`
	Findings      []nearMissFinding `json:"findings"`
}

type coverageManifest struct {
	Contract        string            `json:"contract"`
	SchemaVersion   int               `json:"schema_version"`
	ScannerIdentity scannerIdentity   `json:"scanner_identity"`
	Summary         coverageSummary   `json:"summary"`
	Fixtures        []coverageFixture `json:"fixtures"`
	NearMiss        nearMissFixture   `json:"near_miss"`
}

type spanFixture struct {
	ID            string `json:"id"`
	FixtureSHA256 string `json:"fixture_sha256"`
}

type expectedSpan struct {
	ID               string   `json:"id"`
	FixtureID        string   `json:"fixture_id"`
	Occurrence       string   `json:"occurrence"`
	Classification   string   `json:"classification"`
	RuleID           string   `json:"rule_id"`
	SourceOrdinal    *int     `json:"source_ordinal"`
	StartLine        int      `json:"start_line"`
	EndLine          int      `json:"end_line"`
	StartColumn      int      `json:"start_column"`
	EndColumn        int      `json:"end_column"`
	StartByte        int      `json:"start_byte"`
	EndByteExclusive int      `json:"end_byte_exclusive"`
	Conditions       []string `json:"conditions"`
}

type spanManifest struct {
	Contract               string          `json:"contract"`
	SchemaVersion          int             `json:"schema_version"`
	ScannerIdentity        scannerIdentity `json:"scanner_identity"`
	CoverageManifestSHA256 string          `json:"coverage_manifest_sha256"`
	Fixtures               []spanFixture   `json:"fixtures"`
	Spans                  []expectedSpan  `json:"spans"`
}

func TestQualificationManifestsArePinnedAndInternallyConsistent(t *testing.T) {
	coverageBytes := readFixtureFile(t, "coverage-manifest.json")
	var coverage coverageManifest
	decodeStrict(t, coverageBytes, &coverage)
	assertIdentity(t, coverage.ScannerIdentity)
	if coverage.Contract != "open-trestle/betterleaks-qualification-coverage" || coverage.SchemaVersion != 1 {
		t.Fatal("unexpected coverage manifest contract")
	}

	contents := validateCoverage(t, coverage)

	spanBytes := readFixtureFile(t, "expected-spans.json")
	var spans spanManifest
	decodeStrict(t, spanBytes, &spans)
	assertIdentity(t, spans.ScannerIdentity)
	if spans.Contract != "open-trestle/betterleaks-expected-spans" || spans.SchemaVersion != 1 {
		t.Fatal("unexpected span manifest contract")
	}
	coverageDigest := sha256.Sum256(coverageBytes)
	if spans.CoverageManifestSHA256 != hex.EncodeToString(coverageDigest[:]) {
		t.Fatal("span manifest does not bind the coverage manifest bytes")
	}
	validateSpans(t, coverage, spans, contents)
}

func validateCoverage(t *testing.T, manifest coverageManifest) map[string][]byte {
	t.Helper()
	if manifest.Summary.ExpectedOccurrences != 14 || manifest.Summary.AcceptedDetections != 11 ||
		manifest.Summary.PositiveFixtures != 11 || manifest.Summary.DetectedFixtures != 10 ||
		manifest.Summary.RepeatedExpected != 2 || manifest.Summary.RepeatedDetected != 2 ||
		manifest.Summary.ExactDetectionSpans != 11 {
		t.Fatalf("unexpected qualification summary: %#v", manifest.Summary)
	}
	misses := append([]string(nil), manifest.Summary.KnownMisses...)
	sort.Strings(misses)
	if strings.Join(misses, ",") != "aws_secret_key,aws_session_token,bearer" {
		t.Fatalf("unexpected known misses: %v", misses)
	}
	if len(manifest.Fixtures) != 11 {
		t.Fatalf("got %d positive fixtures, want 11", len(manifest.Fixtures))
	}

	contents := make(map[string][]byte, len(manifest.Fixtures)+1)
	occurrences := 0
	detections := 0
	detectedFixtures := 0
	missSet := make(map[string]struct{})
	spanIDs := make(map[string]struct{})
	for _, fixture := range manifest.Fixtures {
		content := validateFixture(t, fixture.ID, fixture.FixtureSHA256, fixture.ContentBase64)
		if _, exists := contents[fixture.ID]; exists {
			t.Fatalf("duplicate fixture ID %q", fixture.ID)
		}
		contents[fixture.ID] = content
		hasDetection := false
		for _, occurrence := range fixture.Occurrences {
			occurrences++
			if occurrence.Name == "" {
				t.Fatalf("fixture %q has an empty occurrence name", fixture.ID)
			}
			if occurrence.AcceptedDetection {
				detections++
				hasDetection = true
				if occurrence.SpanID == "" {
					t.Fatalf("detected occurrence %q has no span", occurrence.Name)
				}
				if _, exists := spanIDs[occurrence.SpanID]; exists {
					t.Fatalf("duplicate coverage span ID %q", occurrence.SpanID)
				}
				spanIDs[occurrence.SpanID] = struct{}{}
			} else {
				if occurrence.SpanID != "" {
					t.Fatalf("miss %q names a span", occurrence.Name)
				}
				missSet[occurrence.Name] = struct{}{}
			}
		}
		if hasDetection {
			detectedFixtures++
		}
	}
	if occurrences != 14 || detections != 11 || detectedFixtures != 10 {
		t.Fatalf("derived coverage is %d/%d across %d fixtures", detections, occurrences, detectedFixtures)
	}
	for _, miss := range misses {
		if _, exists := missSet[miss]; !exists {
			t.Fatalf("summary miss %q is not an occurrence miss", miss)
		}
	}
	if len(missSet) != 3 {
		t.Fatalf("got %d occurrence misses, want 3", len(missSet))
	}

	nearMiss := manifest.NearMiss
	contents[nearMiss.ID] = validateFixture(t, nearMiss.ID, nearMiss.FixtureSHA256, nearMiss.ContentBase64)
	if len(nearMiss.Findings) != 1 || nearMiss.Findings[0].RuleID != "generic-api-key" || nearMiss.Findings[0].SpanID == "" {
		t.Fatalf("unexpected near-miss oracle: %#v", nearMiss.Findings)
	}
	return contents
}

func validateSpans(t *testing.T, coverage coverageManifest, manifest spanManifest, contents map[string][]byte) {
	t.Helper()
	if len(manifest.Fixtures) != len(contents) {
		t.Fatalf("span manifest binds %d fixtures, want %d", len(manifest.Fixtures), len(contents))
	}
	bound := make(map[string]struct{}, len(manifest.Fixtures))
	for _, fixture := range manifest.Fixtures {
		content, exists := contents[fixture.ID]
		if !exists {
			t.Fatalf("span manifest binds unknown fixture %q", fixture.ID)
		}
		assertSHA256(t, fixture.ID, fixture.FixtureSHA256, content)
		if _, exists := bound[fixture.ID]; exists {
			t.Fatalf("duplicate span fixture binding %q", fixture.ID)
		}
		bound[fixture.ID] = struct{}{}
	}

	coverageSpans := make(map[string]coverageOccurrence)
	for _, fixture := range coverage.Fixtures {
		for _, occurrence := range fixture.Occurrences {
			if occurrence.AcceptedDetection {
				coverageSpans[occurrence.SpanID] = occurrence
			}
		}
	}
	nearSpanID := coverage.NearMiss.Findings[0].SpanID
	seen := make(map[string]struct{}, len(manifest.Spans))
	conditionCount := make(map[string]int)
	acceptedDetections := 0
	nearMisses := 0
	repeated := make([]expectedSpan, 0, 2)
	for _, span := range manifest.Spans {
		if _, exists := seen[span.ID]; exists {
			t.Fatalf("duplicate expected span ID %q", span.ID)
		}
		seen[span.ID] = struct{}{}
		content, exists := contents[span.FixtureID]
		if span.SourceOrdinal == nil || *span.SourceOrdinal != 0 {
			t.Fatalf("span %q must use source ordinal zero", span.ID)
		}
		if !exists {
			t.Fatalf("span %q references unknown fixture %q", span.ID, span.FixtureID)
		}
		assertCoordinates(t, span, content)
		for _, condition := range span.Conditions {
			conditionCount[condition]++
			switch condition {
			case "crlf":
				if !bytes.Contains(content, []byte("\r\n")) {
					t.Fatalf("span %q claims CRLF", span.ID)
				}
			case "unicode_prefix":
				if utf8.RuneCount(content[:span.StartByte]) == len(content[:span.StartByte]) {
					t.Fatalf("span %q has no Unicode prefix", span.ID)
				}
			case "multiline":
				if span.StartLine == span.EndLine {
					t.Fatalf("span %q is not multiline", span.ID)
				}
			case "end_of_file":
				if span.EndByteExclusive != len(content) {
					t.Fatalf("span %q does not end at EOF", span.ID)
				}
			case "trailing_lf":
				if len(content) == 0 || content[len(content)-1] != '\n' || span.EndByteExclusive >= len(content) {
					t.Fatalf("span %q has no trailing LF", span.ID)
				}
			case "repeated":
				repeated = append(repeated, span)
			default:
				t.Fatalf("span %q has unknown condition %q", span.ID, condition)
			}
		}
		switch span.Classification {
		case "accepted_detection":
			acceptedDetections++
			occurrence, exists := coverageSpans[span.ID]
			if !exists || occurrence.Name != span.Occurrence {
				t.Fatalf("span %q is not bound to its accepted occurrence", span.ID)
			}
		case "accepted_near_miss":
			nearMisses++
			if span.ID != nearSpanID || span.RuleID != "generic-api-key" || span.StartByte != 7 || span.EndByteExclusive != 51 {
				t.Fatalf("unexpected known near-miss span: %#v", span)
			}
		default:
			t.Fatalf("span %q has unknown classification %q", span.ID, span.Classification)
		}
	}
	if acceptedDetections != 11 || nearMisses != 1 || len(manifest.Spans) != 12 {
		t.Fatalf("got %d accepted detections and %d near misses", acceptedDetections, nearMisses)
	}
	if len(coverageSpans) != acceptedDetections {
		t.Fatal("an accepted coverage detection has no span")
	}
	for _, condition := range []string{"crlf", "unicode_prefix", "multiline", "end_of_file", "trailing_lf"} {
		if conditionCount[condition] == 0 {
			t.Fatalf("no span covers %s coordinates", condition)
		}
	}
	if len(repeated) != 2 || repeated[0].FixtureID != repeated[1].FixtureID {
		t.Fatalf("unexpected repeated span set: %#v", repeated)
	}
	first := contents[repeated[0].FixtureID][repeated[0].StartByte:repeated[0].EndByteExclusive]
	second := contents[repeated[1].FixtureID][repeated[1].StartByte:repeated[1].EndByteExclusive]
	if repeated[0].StartByte == repeated[1].StartByte || !bytes.Equal(first, second) {
		t.Fatal("repeated fixture does not preserve two identical values at distinct locations")
	}
}

func assertCoordinates(t *testing.T, span expectedSpan, content []byte) {
	t.Helper()
	if span.StartLine < 1 || span.EndLine < span.StartLine || span.StartColumn < 1 || span.EndColumn < 1 {
		t.Fatalf("span %q has non-positive coordinates", span.ID)
	}
	lineStarts := []int{0}
	for index, value := range content {
		if value == '\n' {
			lineStarts = append(lineStarts, index+1)
		}
	}
	if span.StartLine > len(lineStarts) || span.EndLine > len(lineStarts) {
		t.Fatalf("span %q has an out-of-range line", span.ID)
	}
	start := lineStarts[span.StartLine-1] + span.StartColumn - 1
	end := lineStarts[span.EndLine-1] + span.EndColumn
	if start != span.StartByte || end != span.EndByteExclusive {
		t.Fatalf("span %q coordinates map to [%d,%d), want [%d,%d)", span.ID, start, end, span.StartByte, span.EndByteExclusive)
	}
	if start < 0 || start >= end || end > len(content) || !utf8.Valid(content) ||
		(start > 0 && !utf8.RuneStart(content[start])) || (end < len(content) && !utf8.RuneStart(content[end])) {
		t.Fatalf("span %q is not a valid UTF-8 byte range", span.ID)
	}
}

func validateFixture(t *testing.T, id, wantHash, encoded string) []byte {
	t.Helper()
	content, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil || base64.StdEncoding.EncodeToString(content) != encoded {
		t.Fatalf("fixture %q is not canonical padded base64", id)
	}
	if !utf8.Valid(content) {
		t.Fatalf("fixture %q is not UTF-8", id)
	}
	if !bytes.Contains(content, []byte("NOTREAL")) && !bytes.Contains(content, []byte("INVALID")) && !bytes.Contains(content, []byte("INERT!")) {
		t.Fatalf("fixture %q lacks an explicit inert marker", id)
	}
	assertSHA256(t, id, wantHash, content)
	return content
}

func assertSHA256(t *testing.T, id, want string, content []byte) {
	t.Helper()
	decoded, err := hex.DecodeString(want)
	if err != nil || len(decoded) != sha256.Size || want != strings.ToLower(want) {
		t.Fatalf("fixture %q has an invalid SHA-256", id)
	}
	digest := sha256.Sum256(content)
	if !bytes.Equal(decoded, digest[:]) {
		t.Fatalf("fixture %q SHA-256 mismatch", id)
	}
}

func assertIdentity(t *testing.T, identity scannerIdentity) {
	t.Helper()
	want := scannerIdentity{
		Scanner:          protocol.ScannerName,
		ScannerVersion:   protocol.ScannerVersion,
		ScannerCommit:    protocol.ScannerCommit,
		RulesetIdentity:  protocol.RulesetIdentity,
		RulesetRuleCount: protocol.RulesetRuleCount,
		BuildProfile:     protocol.BuildProfile,
	}
	if identity != want {
		t.Fatalf("unexpected scanner identity: %#v", identity)
	}
}

func decodeStrict(t *testing.T, encoded []byte, target any) {
	t.Helper()
	if err := decodeStrictValue(encoded, target); err != nil {
		t.Fatal(err)
	}
}

func decodeStrictValue(encoded []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("manifest has trailing JSON data")
	}
	return nil
}

func TestQualificationManifestDecoderRejectsTrailingData(t *testing.T) {
	for _, encoded := range [][]byte{
		[]byte(`{} {}`),
		[]byte(`{} ]`),
		[]byte(`{} }`),
	} {
		var value map[string]any
		if decodeStrictValue(encoded, &value) == nil {
			t.Fatalf("trailing JSON accepted: %q", encoded)
		}
	}
}

func readFixtureFile(t *testing.T, name string) []byte {
	t.Helper()
	encoded, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(fmt.Errorf("read %s: %w", name, err))
	}
	return encoded
}
