package diagnostics

import (
	"bytes"
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
	set, err := NewSet(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), []Finding{finding})
	if err != nil || set.Validate() != nil || set.Identity() == "" || set.SchemaVersion() != 1 || set.CandidateCount() != 1 || set.VerifiedCount() != 1 || set.RejectedCount() != 0 || set.InconclusiveCount() != 0 || set.SourceAnalyzedCount() != 0 || set.SourceSelectedCount() != 0 || set.SourceOmittedCount() != 0 {
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
func mustEncodeSet(t *testing.T, set Set) []byte {
	t.Helper()
	encoded, err := EncodeSet(set)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestSetV2CanonicalEncodingPreservesVerificationCoverage(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, err := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "verified issue", "The independently verified issue remains.", SeverityWarning, "internal/example.go", 4, 4, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewSetWithCoverage(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), 3, 1, 1, []Finding{finding})
	if err != nil || set.Validate() != nil || set.SchemaVersion() != 2 || set.CandidateCount() != 3 || set.VerifiedCount() != 1 || set.RejectedCount() != 1 || set.InconclusiveCount() != 1 || len(set.OmissionSummaries()) != 0 || set.Identity() != "be670049c4524c6e75434949bc9397704d576fc2f008fea58fe694c7714c77b5" {
		t.Fatalf("set=%#v err=%v", set, err)
	}
	encoded, err := EncodeSet(set)
	if err != nil || !bytes.Contains(encoded, []byte(`"coverage":{"candidate_count":3,"verified_count":1,"rejected_count":1,"inconclusive_count":1}`)) {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
	parsed, err := ParseSet(encoded)
	if err != nil || parsed.Identity() != set.Identity() || parsed.SchemaVersion() != 2 || !bytes.Equal(encoded, mustEncodeSet(t, parsed)) {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
}

func TestSetV2RejectsImpossibleCoverage(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, _ := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "verified issue", "The independently verified issue remains.", SeverityWarning, "internal/example.go", 4, 4, []string{strings.Repeat("c", 64)})
	for _, counts := range [][3]uint16{{0, 0, 0}, {2, 0, 0}, {101, 100, 0}, {1, 65535, 1}} {
		if set, err := NewSetWithCoverage(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), counts[0], counts[1], counts[2], []Finding{finding}); err == nil || set.Identity() != "" {
			t.Fatalf("counts=%v set=%#v err=%v", counts, set, err)
		}
	}
	set, _ := NewSetWithCoverage(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), 3, 1, 1, []Finding{finding})
	encoded, _ := EncodeSet(set)
	tampered := bytes.Replace(encoded, []byte(`"rejected_count":1`), []byte(`"rejected_count":2`), 1)
	if parsed, err := ParseSet(tampered); err == nil || parsed.Identity() != "" {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
}

func TestSetV3CanonicalEncodingPreservesSourceCoverage(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, _ := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "verified issue", "The independently verified issue remains.", SeverityWarning, "internal/example.go", 4, 4, []string{strings.Repeat("c", 64)})
	set, err := NewSetWithSourceCoverage(
		scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64),
		3, 1, 1, 173, 1, 172, []Finding{finding},
	)
	if err != nil || set.Validate() != nil || set.SchemaVersion() != 3 || set.CandidateCount() != 3 || set.Identity() != "1a8d26bb2328121ac165df191b0393174c904ef130565f2432951ac0c0125ac0" ||
		set.VerificationContextIdentity() != strings.Repeat("f", 64) || set.SourceAnalyzedCount() != 173 || set.SourceSelectedCount() != 1 || set.SourceOmittedCount() != 172 || len(set.OmissionSummaries()) != 0 {
		t.Fatalf("set=%#v err=%v", set, err)
	}
	encoded, err := EncodeSet(set)
	if err != nil || !bytes.Contains(encoded, []byte(`"source_coverage":{"verification_context_identity":"`+strings.Repeat("f", 64)+`","analyzed_count":173,"selected_count":1,"omitted_count":172}`)) {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
	parsed, err := ParseSet(encoded)
	if err != nil || parsed.Identity() != set.Identity() || parsed.SchemaVersion() != 3 || !bytes.Equal(encoded, mustEncodeSet(t, parsed)) {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
	for _, tampered := range [][]byte{
		bytes.Replace(encoded, []byte(`"verification_context_identity":"`+strings.Repeat("f", 64)+`"`), []byte(`"verification_context_identity":"`+strings.Repeat("a", 64)+`"`), 1),
		bytes.Replace(encoded, []byte(`"omitted_count":172`), []byte(`"omitted_count":171`), 1),
		bytes.Replace(encoded, []byte(`"source_coverage":{`), []byte(`"unexpected":true,"source_coverage":{`), 1),
	} {
		if parsed, err := ParseSet(tampered); err == nil || parsed.Identity() != "" {
			t.Fatalf("tampered parsed=%#v err=%v", parsed, err)
		}
	}
}

func TestSetV3RejectsImpossibleSourceCoverage(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, _ := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "verified issue", "The independently verified issue remains.", SeverityWarning, "internal/example.go", 4, 4, []string{strings.Repeat("c", 64)})
	for _, counts := range [][3]uint32{{0, 0, 0}, {0, 1, 0}, {1, 2, 0}, {2, 1, 0}, {33, 33, 0}, {65665, 1, 65664}} {
		set, err := NewSetWithSourceCoverage(
			scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64),
			1, 0, 0, counts[0], counts[1], counts[2], []Finding{finding},
		)
		if err == nil || set.Identity() != "" {
			t.Fatalf("counts=%v set=%#v err=%v", counts, set, err)
		}
	}
}

func TestSetV4CanonicalEncodingPreservesOmissionReasons(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, _ := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "verified issue", "The independently verified issue remains.", SeverityWarning, "internal/example.go", 4, 4, []string{strings.Repeat("c", 64)})
	unsupported, _ := NewOmissionSummary(OmissionUnsupported, 2)
	selection, _ := NewOmissionSummary(OmissionSelectionLimit, 170)
	set, err := NewSetWithOmissionReasons(
		scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64),
		3, 1, 1, 173, 1, 172, []OmissionSummary{unsupported, selection}, []Finding{finding},
	)
	if err != nil || set.Validate() != nil || set.SchemaVersion() != 4 || set.Identity() != "6de783b7c5528df50fe17b4b90668b3df5b70c2e85c278601a414a71eb05b362" || len(set.DeterministicChecks()) != 0 || set.VerificationContextIdentity() != strings.Repeat("f", 64) || len(set.OmissionSummaries()) != 2 || set.OmissionSummaries()[0].Reason() != OmissionSelectionLimit {
		t.Fatalf("set=%#v summaries=%#v err=%v", set, set.OmissionSummaries(), err)
	}
	summaries := set.OmissionSummaries()
	summaries[0] = OmissionSummary{}
	if set.OmissionSummaries()[0].Validate() != nil {
		t.Fatal("omission summaries were mutable")
	}
	encoded, err := EncodeSet(set)
	if err != nil || !bytes.Contains(encoded, []byte(`"omissions":[{"reason":"selection_limit","count":170},{"reason":"unsupported","count":2}]`)) {
		t.Fatalf("encoded=%s err=%v", encoded, err)
	}
	parsed, err := ParseSet(encoded)
	if err != nil || parsed.Identity() != set.Identity() || parsed.SchemaVersion() != 4 || !bytes.Equal(encoded, mustEncodeSet(t, parsed)) {
		t.Fatalf("parsed=%#v err=%v", parsed, err)
	}
}

func TestSetV4RejectsImpossibleOmissionReasons(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	finding, _ := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "verified issue", "The independently verified issue remains.", SeverityWarning, "internal/example.go", 4, 4, []string{strings.Repeat("c", 64)})
	selection, _ := NewOmissionSummary(OmissionSelectionLimit, 171)
	duplicate, _ := NewOmissionSummary(OmissionSelectionLimit, 1)
	for _, summaries := range [][]OmissionSummary{nil, {selection}, {selection, duplicate}} {
		set, err := NewSetWithOmissionReasons(scope, strings.Repeat("d", 64), strings.Repeat("1", 40), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 173, 1, 172, summaries, []Finding{finding})
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
