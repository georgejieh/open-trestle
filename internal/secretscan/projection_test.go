package secretscan

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"
)

type scriptedScanner struct {
	results []ScanResult
	inputs  [][][]byte
}

func (scanner *scriptedScanner) scan(_ context.Context, sources [][]byte) ScanResult {
	copied := cloneSources(sources)
	scanner.inputs = append(scanner.inputs, copied)
	result := scanner.results[0]
	scanner.results = scanner.results[1:]
	return result
}

func completeScan(matches ...Match) ScanResult {
	return ScanResult{
		matches:  matches,
		metadata: ScanMetadata{Scanner: ScannerName, ScannerVersion: ScannerVersion, ScannerCommit: ScannerCommit, RulesetIdentity: RulesetIdentity, BuildProfile: BuildProfile, MatchCount: len(matches)},
		complete: true,
	}
}

func TestProjectionRejectsBoundsBeforeScannerOrCopies(t *testing.T) {
	scanner := &scriptedScanner{}
	projection := newProjector(scanner).Sanitize(context.Background(), [][]byte{make([]byte, maxSourceBytes+1)})
	if projection.Failure() != FailureInvalidInput || len(scanner.inputs) != 0 {
		t.Fatalf("unbounded projection reached scanner: %#v", projection)
	}
}

func TestProjectionMergesOverlappingAndTouchingSpansDeterministically(t *testing.T) {
	source := []byte("aTOKENvaluez")
	matches := []Match{
		{SourceOrdinal: 0, RuleID: "github-pat", StartByte: 1, EndByteExclusive: 6, OccurrenceID: "a"},
		{SourceOrdinal: 0, RuleID: "generic-api-key", StartByte: 4, EndByteExclusive: 8, OccurrenceID: "b"},
		{SourceOrdinal: 0, RuleID: "gitlab-pat", StartByte: 8, EndByteExclusive: 11, OccurrenceID: "c"},
	}
	scanner := &scriptedScanner{results: []ScanResult{completeScan(matches...), completeScan()}}
	projection := newProjector(scanner).Sanitize(context.Background(), [][]byte{source})
	if !projection.Complete() || projection.Failure() != FailureNone || len(scanner.inputs) != 2 {
		t.Fatalf("projection failed: %#v", projection)
	}
	if got := string(projection.Sources()[0]); got != "a**********z" {
		t.Fatalf("unexpected mask %q", got)
	}
	if projection.MaskedByteCount() != 10 || len(projection.Matches()) != 3 {
		t.Fatalf("unexpected metadata: %#v", projection)
	}
	if bytes.Equal(scanner.inputs[0][0], scanner.inputs[1][0]) || string(scanner.inputs[1][0]) != "a**********z" {
		t.Fatal("residual scan did not receive the sanitized projection")
	}
}

func TestProjectionPreservesByteLengthUTF8AndCRLF(t *testing.T) {
	source := []byte("πTOKEN\r\n終")
	match := Match{SourceOrdinal: 0, RuleID: "github-pat", StartByte: 0, EndByteExclusive: len(source), OccurrenceID: "a"}
	scanner := &scriptedScanner{results: []ScanResult{completeScan(match), completeScan()}}
	projection := newProjector(scanner).Sanitize(context.Background(), [][]byte{source})
	if !projection.Complete() || len(projection.Sources()[0]) != len(source) || !bytes.Equal(projection.Sources()[0], []byte("*******\r\n***")) {
		t.Fatalf("mask did not preserve byte layout: %q", projection.Sources())
	}
	if projection.MaskedByteCount() != len(source)-2 {
		t.Fatalf("unexpected masked byte count: %d", projection.MaskedByteCount())
	}
}

func TestProjectionUsesFreshResidualScanAndRequiresZeroMatches(t *testing.T) {
	initial := Match{SourceOrdinal: 0, RuleID: "github-pat", StartByte: 0, EndByteExclusive: 5, OccurrenceID: "a"}
	residual := Match{SourceOrdinal: 0, RuleID: "generic-api-key", StartByte: 0, EndByteExclusive: 1, OccurrenceID: "b"}
	scanner := &scriptedScanner{results: []ScanResult{completeScan(initial), completeScan(residual)}}
	projection := newProjector(scanner).Sanitize(context.Background(), [][]byte{[]byte("TOKEN")})
	if projection.Complete() || projection.Failure() != FailurePolicy || projection.Sources() != nil || len(scanner.inputs) != 2 {
		t.Fatalf("residual finding did not fail closed: %#v", projection)
	}
}

func TestProjectionClosesInitialAndResidualFailures(t *testing.T) {
	tests := []struct {
		name    string
		results []ScanResult
		calls   int
		failure FailureClass
	}{
		{"initial", []ScanResult{{failure: FailureResourceLimit}}, 1, FailureResourceLimit},
		{"residual", []ScanResult{completeScan(), {failure: FailureCanceled}}, 2, FailureCanceled},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			scanner := &scriptedScanner{results: test.results}
			projection := newProjector(scanner).Sanitize(context.Background(), [][]byte{[]byte("clean")})
			if projection.Complete() || projection.Failure() != test.failure || projection.Sources() != nil || len(scanner.inputs) != test.calls {
				t.Fatalf("failure did not close projection: %#v", projection)
			}
		})
	}
}

func TestProjectionRejectsMalformedSpansWithoutResidualScan(t *testing.T) {
	malformed := Match{SourceOrdinal: 0, RuleID: "github-pat", StartByte: 1, EndByteExclusive: 2, OccurrenceID: "a"}
	scanner := &scriptedScanner{results: []ScanResult{completeScan(malformed)}}
	projection := newProjector(scanner).Sanitize(context.Background(), [][]byte{[]byte("π")})
	if projection.Failure() != FailurePolicy || len(scanner.inputs) != 1 || projection.Sources() != nil {
		t.Fatalf("malformed span did not fail closed: %#v", projection)
	}
}

func cloneSources(sources [][]byte) [][]byte {
	cloned := make([][]byte, len(sources))
	for index := range sources {
		cloned[index] = bytes.Clone(sources[index])
	}
	return cloned
}

func TestProjectionGettersReturnDefensiveCopiesAndFormattingIsRedacted(t *testing.T) {
	match := Match{SourceOrdinal: 0, RuleID: "github-pat", StartByte: 0, EndByteExclusive: 5, OccurrenceID: "a"}
	scanner := &scriptedScanner{results: []ScanResult{completeScan(match), completeScan()}}
	projection := newProjector(scanner).Sanitize(context.Background(), [][]byte{[]byte("TOKEN suffix")})
	sources := projection.Sources()
	matches := projection.Matches()
	sources[0][0] = 'x'
	matches[0].RuleID = "changed"
	if string(projection.Sources()[0]) != "***** suffix" || projection.Matches()[0].RuleID != "github-pat" {
		t.Fatal("projection getters expose mutable state")
	}
	formatted := fmt.Sprintf("%v %#v", projection, projection)
	if strings.Contains(formatted, "suffix") || strings.Contains(formatted, "TOKEN") || strings.Contains(formatted, "*****") {
		t.Fatalf("projection formatting retained content: %q", formatted)
	}
}
