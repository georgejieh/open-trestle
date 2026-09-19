package memory

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func canonicalRecordInput() RecordInput {
	return RecordInput{
		Kind:             RecordCanonicalFact,
		Taint:            TaintRepositoryControlled,
		Path:             "internal/review/candidate.go",
		Symbols:          []string{"ParseCandidateBatch", "CandidateBatch"},
		Text:             "Candidate batches require exact evidence references.",
		EvidenceIDs:      []string{"evidence-1"},
		ProducerIdentity: strings.Repeat("c", 64),
		ObservedAt:       time.UnixMilli(1_700_000_000_000),
		ValidFrom:        time.UnixMilli(1_699_000_000_000),
	}
}

func TestNewRecordCreatesImmutableCanonicalFact(t *testing.T) {
	scope := testScope(t)
	input := canonicalRecordInput()
	record, err := NewRecord(scope, input)
	if err != nil {
		t.Fatal(err)
	}
	if record.Identity() == "" || record.ScopeIdentity() != scope.Identity() || record.Kind() != RecordCanonicalFact || record.Taint() != TaintRepositoryControlled || record.Path() != input.Path || record.Text() != input.Text || record.ProducerIdentity() != input.ProducerIdentity || !reflect.DeepEqual(record.Symbols(), []string{"CandidateBatch", "ParseCandidateBatch"}) || !reflect.DeepEqual(record.EvidenceIDs(), []string{"evidence-1"}) || record.IsDerived() || record.Validate() != nil {
		t.Fatalf("record did not round trip: %#v", record)
	}
	input.Symbols[0] = "changed"
	input.EvidenceIDs[0] = "changed"
	symbols := record.Symbols()
	symbols[0] = "changed"
	if record.Symbols()[0] != "CandidateBatch" || record.EvidenceIDs()[0] != "evidence-1" {
		t.Fatal("record exposed mutable state")
	}
	if !record.FreshAt(time.UnixMilli(1_700_000_000_001)) || record.FreshAt(time.UnixMilli(1_698_000_000_000)) {
		t.Fatal("canonical validity interval not enforced")
	}
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v"} {
		formatted := fmt.Sprintf(format, record)
		if strings.Contains(formatted, "Candidate batches") || strings.Contains(formatted, input.Path) {
			t.Fatalf("record formatting leaked: %q", formatted)
		}
	}
}

func TestNewDerivedObservationRequiresIndependentSupportAndFreshness(t *testing.T) {
	scope := testScope(t)
	input := canonicalRecordInput()
	input.Kind = RecordDerivedObservation
	input.EvidenceIDs = nil
	input.DerivedFromIDs = []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
	input.CounterEvidenceIDs = []string{strings.Repeat("d", 64)}
	input.StaleAfter = time.UnixMilli(1_800_000_000_000)
	input.FreshnessIdentity = strings.Repeat("e", 64)
	input.ConfidenceBasisPoints = 7_500
	record, err := NewRecord(scope, input)
	if err != nil || !record.IsDerived() || record.FreshnessIdentity() != strings.Repeat("e", 64) || record.ConfidenceBasisPoints() != 7_500 || !reflect.DeepEqual(record.DerivedFromIDs(), []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}) || !record.FreshAt(time.UnixMilli(1_799_999_999_999)) || record.FreshAt(time.UnixMilli(1_800_000_000_000)) || record.Validate() != nil {
		t.Fatalf("derived observation = (%#v, %v)", record, err)
	}
}

func TestNewRecordRejectsUnsafeOrInconsistentInputs(t *testing.T) {
	scope := testScope(t)
	base := canonicalRecordInput()
	tests := []struct {
		name   string
		mutate func(*RecordInput)
		want   error
	}{
		{"kind", func(i *RecordInput) { i.Kind = 0 }, ErrInvalidRecordKind},
		{"taint", func(i *RecordInput) { i.Taint = 0 }, ErrInvalidTaintClass},
		{"path scope", func(i *RecordInput) { i.Path = "docs/outside.md" }, ErrMemoryPathNotAuthorized},
		{"path traversal", func(i *RecordInput) { i.Path = "../secret" }, ErrInvalidMemoryPath},
		{"empty text", func(i *RecordInput) { i.Text = "   " }, ErrInvalidMemoryText},
		{"hidden control", func(i *RecordInput) { i.Text = "unsafe\u202evalue" }, ErrInvalidMemoryText},
		{"symbol", func(i *RecordInput) { i.Symbols = []string{" bad "} }, ErrInvalidMemorySymbol},
		{"duplicate symbol", func(i *RecordInput) { i.Symbols = []string{"Symbol", "Symbol"} }, ErrDuplicateMemorySymbol},
		{"evidence", func(i *RecordInput) { i.EvidenceIDs = nil }, ErrInvalidMemoryEvidence},
		{"duplicate evidence", func(i *RecordInput) { i.EvidenceIDs = []string{"evidence-1", "evidence-1"} }, ErrDuplicateMemoryReference},
		{"producer", func(i *RecordInput) { i.ProducerIdentity = "bad" }, ErrInvalidMemoryProducer},
		{"observed", func(i *RecordInput) { i.ObservedAt = time.Time{} }, ErrInvalidMemoryTime},
		{"valid from", func(i *RecordInput) { i.ValidFrom = i.ObservedAt.Add(time.Second) }, ErrInvalidMemoryTime},
		{"valid until", func(i *RecordInput) { i.ValidUntil = i.ValidFrom }, ErrInvalidMemoryTime},
		{"canonical support", func(i *RecordInput) { i.DerivedFromIDs = []string{strings.Repeat("a", 64)} }, ErrInvalidMemoryDerivation},
		{"canonical stale", func(i *RecordInput) { i.StaleAfter = i.ObservedAt.Add(time.Hour) }, ErrInvalidMemoryDerivation},
		{"derived support", func(i *RecordInput) {
			i.Kind = RecordDerivedObservation
			i.EvidenceIDs = nil
			i.DerivedFromIDs = []string{strings.Repeat("a", 64)}
			i.StaleAfter = i.ObservedAt.Add(time.Hour)
		}, ErrInvalidMemoryDerivation},
		{"derived stale", func(i *RecordInput) {
			i.Kind = RecordDerivedObservation
			i.EvidenceIDs = nil
			i.DerivedFromIDs = []string{strings.Repeat("a", 64), strings.Repeat("b", 64)}
		}, ErrInvalidMemoryDerivation},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := base
			input.Symbols = append([]string(nil), base.Symbols...)
			input.EvidenceIDs = append([]string(nil), base.EvidenceIDs...)
			test.mutate(&input)
			record, err := NewRecord(scope, input)
			if !errors.Is(err, test.want) || record.Identity() != "" {
				t.Fatalf("NewRecord() = (%#v, %v), want %v", record, err, test.want)
			}
		})
	}
}

func TestRecordKindsAndTaintsRoundTrip(t *testing.T) {
	for _, value := range []string{"canonical_fact", "review_episode", "derived_observation", "human_feedback"} {
		kind, err := ParseRecordKind(value)
		if err != nil || kind.String() != value || kind.Validate() != nil {
			t.Fatalf("record kind %q = (%v,%v)", value, kind, err)
		}
	}
	for _, value := range []string{"trusted", "repository_controlled", "user_controlled", "external_unverified"} {
		taint, err := ParseTaintClass(value)
		if err != nil || taint.String() != value || taint.Validate() != nil {
			t.Fatalf("taint %q = (%v,%v)", value, taint, err)
		}
	}
}

func TestRecordIdentityDetectsTampering(t *testing.T) {
	record, _ := NewRecord(testScope(t), canonicalRecordInput())
	forged := record
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidMemoryRecordIdentity) {
		t.Fatal("forged record identity accepted")
	}
}
