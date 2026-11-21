package diagnostics

import (
	"bytes"
	"fmt"
	"github.com/georgejieh/open-trestle/audit"
	"strings"
	"testing"
)

func TestSetCanonicalEncodingAndImmutableFindings(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, err := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "possible nil dereference", "The value may be nil before this call.", SeverityError, "internal/example.go", 10, 12, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	set, err := verifiedTestSet(t, scope, []Finding{finding})
	if err != nil || set.Validate() != nil || set.Identity() == "" || set.SchemaVersion() != 5 || set.CandidateCount() != 1 || set.VerifiedCount() != 1 || set.RejectedCount() != 0 || set.InconclusiveCount() != 0 || set.SourceAnalyzedCount() != 1 || set.SourceSelectedCount() != 1 || set.SourceOmittedCount() != 0 {
		t.Fatalf("set=(%#v,%v)", set, err)
	}
	values := set.Findings()
	values[0] = Finding{}
	if set.Findings()[0].Identity() == "" {
		t.Fatal("findings were mutable")
	}
	encoded, err := EncodeSet(set)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSet(encoded)
	if err != nil || parsed.Identity() != set.Identity() || !bytes.Equal(encoded, mustEncodeSet(t, parsed)) {
		t.Fatalf("parsed=(%#v,%v)", parsed, err)
	}
}

// verifiedTestSet builds a version 5 set that counts every finding as a
// verified candidate from one selected source.
func verifiedTestSet(t *testing.T, scope audit.ReviewScope, findings []Finding) (Set, error) {
	t.Helper()
	return verifiedTestSetWithCoverage(t, scope, uint16(len(findings)), 0, 0, 1, 1, 0, nil, findings)
}

func verifiedTestSetWithCoverage(t *testing.T, scope audit.ReviewScope, candidates, rejected, inconclusive uint16, analyzed, selected, omitted uint32, omissions []OmissionSummary, findings []Finding) (Set, error) {
	t.Helper()
	check, err := NewDeterministicCheck("3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092", strings.Repeat("8", 64), strings.Repeat("7", 64), CheckPassed, 1, 2, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	return NewSetWithDeterministicChecks(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64), candidates, rejected, inconclusive, analyzed, selected, omitted, omissions, []DeterministicCheck{check}, findings)
}

func mustEncodeSet(t *testing.T, set Set) []byte {
	t.Helper()
	encoded, err := EncodeSet(set)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestSetRejectsImpossibleCoverage(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, _ := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "verified issue", "The independently verified issue remains.", SeverityWarning, "internal/example.go", 4, 4, []string{strings.Repeat("c", 64)})
	for _, counts := range [][3]uint16{{0, 0, 0}, {2, 0, 0}, {101, 100, 0}, {1, 65535, 1}} {
		if set, err := verifiedTestSetWithCoverage(t, scope, counts[0], counts[1], counts[2], 1, 1, 0, nil, []Finding{finding}); err == nil || set.Identity() != "" {
			t.Fatalf("counts=%v set=%#v err=%v", counts, set, err)
		}
	}
	set, _ := verifiedTestSetWithCoverage(t, scope, 3, 1, 1, 1, 1, 0, nil, []Finding{finding})
	encoded, _ := EncodeSet(set)
	tampered := bytes.Replace(encoded, []byte(`"rejected_count":1`), []byte(`"rejected_count":2`), 1)
	if parsed, err := ParseSet(tampered); err == nil || parsed.Identity() != "" {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
}

func TestSetRejectsImpossibleSourceCoverage(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, _ := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "verified issue", "The independently verified issue remains.", SeverityWarning, "internal/example.go", 4, 4, []string{strings.Repeat("c", 64)})
	for _, counts := range [][3]uint32{{0, 0, 0}, {0, 1, 0}, {1, 2, 0}, {2, 1, 0}, {33, 33, 0}, {65665, 1, 65664}} {
		var omissions []OmissionSummary
		if counts[2] > 0 {
			omission, _ := NewOmissionSummary(OmissionSelectionLimit, counts[2])
			omissions = []OmissionSummary{omission}
		}
		set, err := verifiedTestSetWithCoverage(t, scope, 1, 0, 0, counts[0], counts[1], counts[2], omissions, []Finding{finding})
		if err == nil || set.Identity() != "" {
			t.Fatalf("counts=%v set=%#v err=%v", counts, set, err)
		}
	}
}

func TestSetRejectsImpossibleOmissionReasons(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, _ := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "verified issue", "The independently verified issue remains.", SeverityWarning, "internal/example.go", 4, 4, []string{strings.Repeat("c", 64)})
	selection, _ := NewOmissionSummary(OmissionSelectionLimit, 171)
	duplicate, _ := NewOmissionSummary(OmissionSelectionLimit, 1)
	for _, summaries := range [][]OmissionSummary{nil, {selection}, {selection, duplicate}} {
		set, err := verifiedTestSetWithCoverage(t, scope, 1, 0, 0, 173, 1, 172, summaries, []Finding{finding})
		if err == nil || set.Identity() != "" {
			t.Fatalf("summaries=%#v set=%#v err=%v", summaries, set, err)
		}
	}
	if summary, err := NewOmissionSummary(OmissionReason(0), 1); err == nil || summary.Validate() == nil {
		t.Fatalf("invalid summary=%#v err=%v", summary, err)
	}
}

func TestSetV5CanonicalEncodingPreservesDeterministicCheck(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, _ := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "verified issue", "The independently verified issue remains.", SeverityWarning, "internal/example.go", 4, 4, []string{strings.Repeat("c", 64)})
	omission, _ := NewOmissionSummary(OmissionSelectionLimit, 172)
	check, err := NewDeterministicCheck("3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092", strings.Repeat("8", 64), strings.Repeat("7", 64), CheckPassed, 1, 2, 1, 2, 0)
	if err != nil || check.Validate() != nil || !check.Cleared() || check.Identity() != "ff0b1feb2e6611a131770f547b9dfe855d591bb9cae63c80a43b866fdc84d9d9" {
		t.Fatalf("check=%#v err=%v", check, err)
	}
	set, err := NewSetWithDeterministicChecks(
		scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64),
		3, 1, 1, 173, 1, 172, []OmissionSummary{omission}, []DeterministicCheck{check}, []Finding{finding},
	)
	if err != nil || set.Validate() != nil || set.SchemaVersion() != 5 || set.Identity() != "13d3dfe09f8d7564b66b6a065413c684a98cdf3d91bd1c92277606ad8a323185" || len(set.DeterministicChecks()) != 1 || set.DeterministicChecks()[0].Identity() != check.Identity() {
		t.Fatalf("set=%#v identity=%s err=%v", set, set.Identity(), err)
	}
	checks := set.DeterministicChecks()
	checks[0] = DeterministicCheck{}
	if set.DeterministicChecks()[0].Validate() != nil {
		t.Fatal("checks were mutable")
	}
	encoded, err := EncodeSet(set)
	if err != nil || !bytes.Contains(encoded, []byte(`"checks":[{"identity":"`+check.Identity()+`"`)) {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
	parsed, err := ParseSet(encoded)
	if err != nil || parsed.Identity() != set.Identity() || parsed.SchemaVersion() != 5 || !bytes.Equal(encoded, mustEncodeSet(t, parsed)) {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	for _, tampered := range [][]byte{
		bytes.Replace(encoded, []byte(`"state":"passed"`), []byte(`"state":"failed"`), 1),
		bytes.Replace(encoded, []byte(`"analysis_result_identity":"`+strings.Repeat("8", 64)+`"`), []byte(`"analysis_result_identity":"`+strings.Repeat("9", 64)+`"`), 1),
	} {
		if parsed, err := ParseSet(tampered); err == nil || parsed.Identity() != "" {
			t.Fatalf("tampered parsed=%#v err=%v", parsed, err)
		}
	}
}

func TestDeterministicDiagnosticCheckRejectsImpossibleState(t *testing.T) {
	for _, test := range []struct {
		state                                                                   DeterministicCheckState
		applicableFiles, applicableRanges, checkedFiles, checkedRanges, matches uint32
	}{
		{CheckPassed, 1, 1, 1, 1, 1},
		{CheckFailed, 1, 1, 1, 1, 0},
		{CheckIncomplete, 1, 1, 1, 1, 0},
		{CheckNotApplicable, 1, 1, 0, 0, 0},
		{CheckPassed, 0, 1, 0, 1, 0},
	} {
		candidate := DeterministicCheck{changeIdentity: strings.Repeat("7", 64), state: test.state, applicableFiles: test.applicableFiles, applicableRanges: test.applicableRanges, checkedFiles: test.checkedFiles, checkedRanges: test.checkedRanges, matches: test.matches}
		sourceIdentity := deriveSourceDeterministicCheckIdentity(candidate)
		check, err := NewDeterministicCheck(sourceIdentity, strings.Repeat("8", 64), strings.Repeat("7", 64), test.state, test.applicableFiles, test.applicableRanges, test.checkedFiles, test.checkedRanges, test.matches)
		if err == nil || check.Identity() != "" {
			t.Fatalf("state=%s check=%#v err=%v", test.state, check, err)
		}
	}
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	omission, _ := NewOmissionSummary(OmissionSelectionLimit, 1)
	if set, err := NewSetWithDeterministicChecks(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64), 0, 0, 0, 2, 1, 1, []OmissionSummary{omission}, nil, nil); err == nil || set.Identity() != "" {
		t.Fatalf("empty checks set=%#v err=%v", set, err)
	}
}

func TestSetV6KeepsDeterministicObservationsSeparateFromVerifiedFindings(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	analysisIdentity := strings.Repeat("8", 64)
	changeIdentity := strings.Repeat("7", 64)
	sourceCheck := DeterministicCheck{changeIdentity: changeIdentity, state: CheckFailed, applicableFiles: 1, applicableRanges: 2, checkedFiles: 1, checkedRanges: 2, matches: 1}
	check, err := NewDeterministicCheck(deriveSourceDeterministicCheckIdentity(sourceCheck), analysisIdentity, changeIdentity, CheckFailed, 1, 2, 1, 2, 1)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := NewDeterministicObservation(
		strings.Repeat("6", 64), strings.Repeat("5", 64), analysisIdentity, check.Identity(),
		"Debug output left in source", "The deterministic static rule matched this exact changed range; human review is required.",
		SeverityWarning, "main.go", 6, 6, []string{strings.Repeat("4", 64)},
	)
	if err != nil || observation.Validate() != nil {
		t.Fatalf("observation=(%#v,%v)", observation, err)
	}
	set, err := NewSetWithDeterministicObservations(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), analysisIdentity, []DeterministicCheck{check}, []DeterministicObservation{observation})
	if err != nil || set.Validate() != nil || set.SchemaVersion() != 6 || set.AnalysisResultIdentity() != analysisIdentity || set.VerifiedSetIdentity() != "" || len(set.Findings()) != 0 || len(set.DeterministicObservations()) != 1 {
		t.Fatalf("set=%#v err=%v", set, err)
	}
	encoded, err := EncodeSet(set)
	if err != nil || bytes.Contains(encoded, []byte(`"verified_set_identity"`)) || bytes.Contains(encoded, []byte(`"findings"`)) || !bytes.Contains(encoded, []byte(`"observations"`)) {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
	parsed, err := ParseSet(encoded)
	if err != nil || parsed.Identity() != set.Identity() || !bytes.Equal(encoded, mustEncodeSet(t, parsed)) || parsed.DeterministicObservations()[0].Identity() != observation.Identity() {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	observations := set.DeterministicObservations()
	observations[0] = DeterministicObservation{}
	if set.DeterministicObservations()[0].Validate() != nil {
		t.Fatal("deterministic observations were mutable")
	}
	for _, mutate := range []func(DeterministicObservation) DeterministicObservation{
		func(value DeterministicObservation) DeterministicObservation {
			value.analysisResultIdentity = strings.Repeat("9", 64)
			return value
		},
		func(value DeterministicObservation) DeterministicObservation {
			value.checkIdentity = strings.Repeat("9", 64)
			return value
		},
	} {
		changed := mutate(observation)
		if candidate, candidateErr := NewSetWithDeterministicObservations(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), analysisIdentity, []DeterministicCheck{check}, []DeterministicObservation{changed}); candidateErr == nil || candidate.Identity() != "" {
			t.Fatalf("cross-wired observation admitted: %#v err=%v", candidate, candidateErr)
		}
	}
}

func TestSetV6RequiresExactObservationCount(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	analysisIdentity := strings.Repeat("8", 64)
	changeIdentity := strings.Repeat("7", 64)
	sourceCheck := DeterministicCheck{changeIdentity: changeIdentity, state: CheckFailed, applicableFiles: 1, applicableRanges: 1, checkedFiles: 1, checkedRanges: 1, matches: 1}
	check, _ := NewDeterministicCheck(deriveSourceDeterministicCheckIdentity(sourceCheck), analysisIdentity, changeIdentity, CheckFailed, 1, 1, 1, 1, 1)
	if set, err := NewSetWithDeterministicObservations(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), analysisIdentity, []DeterministicCheck{check}, nil); err == nil || set.Identity() != "" {
		t.Fatalf("missing observations set=%#v err=%v", set, err)
	}
}

func TestSetV6ObservationLimitIsIndependentOfVerifiedFindingLimit(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-many")
	analysisIdentity := strings.Repeat("8", 64)
	changeIdentity := strings.Repeat("7", 64)
	sourceCheck := DeterministicCheck{changeIdentity: changeIdentity, state: CheckFailed, applicableFiles: 1, applicableRanges: 1, checkedFiles: 1, checkedRanges: 1, matches: 101}
	check, err := NewDeterministicCheck(deriveSourceDeterministicCheckIdentity(sourceCheck), analysisIdentity, changeIdentity, CheckFailed, 1, 1, 1, 1, 101)
	if err != nil {
		t.Fatal(err)
	}
	observations := make([]DeterministicObservation, 101)
	for index := range observations {
		path := fmt.Sprintf("file-%03d.go", index)
		observations[index], err = NewDeterministicObservation(fmt.Sprintf("%064x", index+1), fmt.Sprintf("%064x", index+1001), analysisIdentity, check.Identity(), "Debug output left in source", "The deterministic static rule matched this exact changed range; human review is required.", SeverityWarning, path, 1, 1, []string{fmt.Sprintf("%064x", index+2001)})
		if err != nil {
			t.Fatal(err)
		}
	}
	set, err := NewSetWithDeterministicObservations(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), analysisIdentity, []DeterministicCheck{check}, observations)
	if err != nil || set.Validate() != nil || len(set.DeterministicObservations()) != 101 {
		t.Fatalf("set with 101 deterministic observations=(%#v,%v)", set, err)
	}
}
