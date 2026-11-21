package localreview

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
)

func resultTextFixture(t *testing.T, messages ...string) Result {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant", "repository", "readable-result")
	if err != nil {
		t.Fatal(err)
	}
	findings := make([]diagnostics.Finding, 0, len(messages))
	for index, message := range messages {
		finding, err := diagnostics.NewFinding(strings.Repeat("a", 64), fmt.Sprintf("%064x", index+1), "Verified title", message, diagnostics.SeverityError, "main.go", 3, 4, []string{"source:head:main", "source:base:main"})
		if err != nil {
			t.Fatal(err)
		}
		findings = append(findings, finding)
	}
	omission, err := diagnostics.NewOmissionSummary(diagnostics.OmissionResourceLimit, 2)
	if err != nil {
		t.Fatal(err)
	}
	check, err := diagnostics.NewDeterministicCheck("3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092", strings.Repeat("8", 64), strings.Repeat("7", 64), diagnostics.CheckPassed, 1, 2, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	set, err := diagnostics.NewSetWithDeterministicChecks(scope, strings.Repeat("b", 64), strings.Repeat("c", 40), strings.Repeat("d", 64), strings.Repeat("e", 64), uint16(len(findings)+2), 1, 1, 3, 1, 2, []diagnostics.OmissionSummary{omission}, []diagnostics.DeterministicCheck{check}, findings)
	if err != nil {
		t.Fatal(err)
	}
	result := emptyResult("findings")
	result.diagnostics = set
	return result
}

func TestRenderResultPreservesCanonicalFindingText(t *testing.T) {
	result := resultTextFixture(t, "First line.\nSecond line with\ttab and 100% detail.")
	var text bytes.Buffer
	if err := RenderResult(&text, result); err != nil {
		t.Fatal(err)
	}
	finding := result.diagnostics.Findings()[0]
	for _, value := range append([]string{finding.Title(), finding.Message(), "main.go:3-4"}, finding.EvidenceIDs()...) {
		if !strings.Contains(text.String(), value) {
			t.Errorf("text omitted canonical finding value %q", value)
		}
	}
}

func TestRenderResultIncludesCoverageAndOmissionSummaries(t *testing.T) {
	result := resultTextFixture(t, "Verified explanation.")
	var text bytes.Buffer
	if err := RenderResult(&text, result); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"coverage: candidates=3 verified=1 rejected=1 inconclusive=1\n",
		"source coverage: analyzed=3 selected=1 omitted=2\n",
		"source omission: resource_limit=2\n",
	} {
		if !strings.Contains(text.String(), want) {
			t.Errorf("text omitted %q", want)
		}
	}
}

func TestRenderResultTextBoundDoesNotWritePartialResult(t *testing.T) {
	// Distinct claims ("m0" to "m15" differ in a symbol), so deduplication
	// keeps all sixteen findings and padding grows the text exactly.
	messages := make([]string, 16)
	for index := range messages {
		messages[index] = fmt.Sprintf("m%d", index)
	}
	var baseline bytes.Buffer
	if err := RenderResult(&baseline, resultTextFixture(t, messages...)); err != nil {
		t.Fatal(err)
	}
	remaining := MaxResultTextBytes - baseline.Len()
	for index := range messages {
		padding := min(remaining, 4096-len(messages[index]))
		messages[index] += strings.Repeat("x", padding)
		remaining -= padding
	}
	if remaining != 0 {
		t.Fatal("fixture cannot reach text boundary")
	}
	var text bytes.Buffer
	if err := RenderResult(&text, resultTextFixture(t, messages...)); err != nil || text.Len() != MaxResultTextBytes {
		t.Fatalf("boundary length=%d error=%v", text.Len(), err)
	}
	messages[len(messages)-1] += "x"
	text.Reset()
	if err := RenderResult(&text, resultTextFixture(t, messages...)); !errors.Is(err, ErrInvalidResult) || text.Len() != 0 {
		t.Fatalf("overflow length=%d error=%v", text.Len(), err)
	}
}

type resultTextWriter struct {
	count int
	err   error
}

func (w resultTextWriter) Write(value []byte) (int, error) {
	return min(w.count, len(value)), w.err
}

func TestRenderResultPreservesWriterAndSealedTextBehavior(t *testing.T) {
	failure := errors.New("writer failed")
	for _, sealed := range []bool{false, true} {
		t.Run(fmt.Sprintf("sealed=%t", sealed), func(t *testing.T) {
			result := resultTextFixture(t, "Verified explanation.")
			if sealed {
				result.sealedText = []byte("sealed text\n")
			}
			var text bytes.Buffer
			if err := RenderResult(&text, result); err != nil {
				t.Fatal(err)
			}
			if sealed && !bytes.Equal(text.Bytes(), result.sealedText) {
				t.Fatal("sealed text changed")
			}
			for _, tc := range []struct {
				writer resultTextWriter
				want   error
			}{{resultTextWriter{count: 1}, io.ErrShortWrite}, {resultTextWriter{err: failure}, failure}} {
				if err := RenderResult(tc.writer, result); !errors.Is(err, tc.want) {
					t.Fatalf("error=%v, want %v", err, tc.want)
				}
			}
		})
	}
}
