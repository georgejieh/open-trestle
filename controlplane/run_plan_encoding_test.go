package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestReviewRunPlanCanonicalEncodingRoundTrips(t *testing.T) {
	plan := runPlanFixture(t)
	encoded, err := EncodeReviewRunPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseReviewRunPlan(encoded)
	if err != nil || parsed.Identity() != plan.Identity() || !bytes.Equal(encoded, mustEncodeReviewRunPlan(t, parsed)) {
		t.Fatalf("roundtrip=(%#v,%v)", parsed, err)
	}
	noncanonical := append([]byte(" "), encoded...)
	if parsed, err := ParseReviewRunPlan(noncanonical); !errors.Is(err, ErrInvalidReviewRunPlanEncoding) || parsed.Identity() != "" {
		t.Fatalf("noncanonical=(%#v,%v)", parsed, err)
	}
}
func TestParseReviewRunPlanRejectsUnknownAndTampered(t *testing.T) {
	encoded := mustEncodeReviewRunPlan(t, runPlanFixture(t))
	unknown := bytes.Replace(encoded, []byte(`"schema_version":1`), []byte(`"schema_version":1,"extra":true`), 1)
	tampered := bytes.Replace(encoded, []byte(`"identity":"`), []byte(`"identity":"f`), 1)
	for _, content := range [][]byte{unknown, tampered} {
		if plan, err := ParseReviewRunPlan(content); err == nil || plan.Identity() != "" {
			t.Fatalf("ParseReviewRunPlan()=(%#v,%v)", plan, err)
		}
	}
}
func mustEncodeReviewRunPlan(t *testing.T, plan ReviewRunPlan) []byte {
	t.Helper()
	encoded, err := EncodeReviewRunPlan(plan)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func TestParseReviewRunPlanRejectsNoncanonicalTaskOrder(t *testing.T) {
	encoded := mustEncodeReviewRunPlan(t, runPlanFixture(t))
	var record reviewRunPlanRecord
	if err := json.Unmarshal(encoded, &record); err != nil {
		t.Fatal(err)
	}
	record.Tasks[0], record.Tasks[len(record.Tasks)-1] = record.Tasks[len(record.Tasks)-1], record.Tasks[0]
	reordered, _ := json.Marshal(record)
	if plan, err := ParseReviewRunPlan(reordered); !errors.Is(err, ErrInvalidReviewRunPlanEncoding) || plan.Identity() != "" {
		t.Fatalf("reordered plan=(%#v,%v)", plan, err)
	}
}
