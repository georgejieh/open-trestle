package diagnostics

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

var testContextShortfall = ContextRefusal{Reason: ContextRefusalRouteContextInsufficient, RequiredTokens: 14282, EstimatedInputTokens: 10186, MaxOutputTokens: 4096, DeclaredContextTokens: 4097}

// A failed full review records its refused context task's reason and counts,
// bound into the identity and restored by parsing.
func TestFinalSetCarriesContextRefusal(t *testing.T) {
	deterministic, err := deterministicSetAtCount(t, "run-context-refusal", 1)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), FinalOutcomeFailed, deterministic, Set{})
	if err != nil {
		t.Fatal(err)
	}
	for name, refusal := range map[string]ContextRefusal{
		"route_context_insufficient": testContextShortfall,
		"no_eligible_route":          {Reason: ContextRefusalNoEligibleRoute},
	} {
		refused, err := failed.WithContextRefusal(refusal)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, ok := refused.ContextRefusal(); !ok || got != refusal || refused.Identity() == failed.Identity() || refused.Validate() != nil {
			t.Fatalf("%s: refusal not bound", name)
		}
		encoded, err := EncodeSet(refused)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(encoded, []byte(`"context_refusal":{"reason":"`+name+`"`)) || (refusal.RequiredTokens != 0) != bytes.Contains(encoded, []byte(`"context_shortfall":{"required_tokens":14282,"estimated_input_tokens":10186,"max_output_tokens":4096,"declared_context_tokens":4097}`)) {
			t.Fatalf("%s: encoded=%s", name, encoded)
		}
		parsed, err := ParseSet(encoded)
		if got, ok := parsed.ContextRefusal(); err != nil || parsed.Identity() != refused.Identity() || !ok || got != refusal {
			t.Fatalf("%s: parsed refusal %v", name, err)
		}
		assertFinalRefusalSchemaShape(t, encoded)
	}
	if _, ok := failed.ContextRefusal(); ok {
		t.Fatal("refusal-free set reports a refusal")
	}
}

func TestFinalSetRefusesMisplacedContextRefusal(t *testing.T) {
	deterministic, err := deterministicSetAtCount(t, "run-context-refusal-misplaced", 1)
	if err != nil {
		t.Fatal(err)
	}
	failed, err := NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), FinalOutcomeFailed, deterministic, Set{})
	if err != nil {
		t.Fatal(err)
	}
	canceled, err := NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), FinalOutcomeCanceled, deterministic, Set{})
	if err != nil {
		t.Fatal(err)
	}
	inconsistent := testContextShortfall
	inconsistent.RequiredTokens++
	above := testContextShortfall
	above.DeclaredContextTokens = 20000
	counted := testContextShortfall
	counted.Reason = ContextRefusalNoEligibleRoute
	refused, _ := failed.WithContextRefusal(testContextShortfall)
	for name, attempt := range map[string]func() (Set, error){
		"canceled outcome":        func() (Set, error) { return canceled.WithContextRefusal(testContextShortfall) },
		"deterministic set":       func() (Set, error) { return deterministic.WithContextRefusal(testContextShortfall) },
		"unknown reason":          func() (Set, error) { return failed.WithContextRefusal(ContextRefusal{Reason: "no_merge_base"}) },
		"inconsistent counts":     func() (Set, error) { return failed.WithContextRefusal(inconsistent) },
		"declared above the need": func() (Set, error) { return failed.WithContextRefusal(above) },
		"counts without reason":   func() (Set, error) { return failed.WithContextRefusal(counted) },
		"second refusal":          func() (Set, error) { return refused.WithContextRefusal(testContextShortfall) },
	} {
		if _, err := attempt(); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	encoded, err := EncodeSet(refused)
	if err != nil {
		t.Fatal(err)
	}
	for name, tampered := range map[string][]byte{
		"count":             bytes.Replace(encoded, []byte(`"declared_context_tokens":4097`), []byte(`"declared_context_tokens":4098`), 1),
		"reason":            bytes.Replace(encoded, []byte(`"reason":"route_context_insufficient"`), []byte(`"reason":"no_eligible_route"`), 1),
		"missing shortfall": bytes.Replace(encoded, []byte(`,"context_shortfall":{"required_tokens":14282,"estimated_input_tokens":10186,"max_output_tokens":4096,"declared_context_tokens":4097}`), nil, 1),
	} {
		if bytes.Equal(tampered, encoded) {
			t.Fatalf("%s: tamper did not apply", name)
		}
		if _, err := ParseSet(tampered); err == nil {
			t.Fatalf("%s: tampered refusal parsed", name)
		}
	}
}

// assertFinalRefusalSchemaShape checks the refusal object against the v7 schema's
// declared properties, required fields and closed reason vocabulary.
func assertFinalRefusalSchemaShape(t *testing.T, encoded []byte) {
	t.Helper()
	raw, err := os.ReadFile("../schemas/diagnostics/full-review-diagnostic-set-v7.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Properties map[string]struct {
			AdditionalProperties bool     `json:"additionalProperties"`
			Required             []string `json:"required"`
			Properties           map[string]struct {
				Enum     []string `json:"enum"`
				Required []string `json:"required"`
			} `json:"properties"`
		} `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	refusal, ok := schema.Properties["context_refusal"]
	if !ok || refusal.AdditionalProperties || strings.Join(refusal.Required, ",") != "reason" || strings.Join(refusal.Properties["reason"].Enum, ",") != "route_context_insufficient,no_eligible_route" || strings.Join(refusal.Properties["context_shortfall"].Required, ",") != "required_tokens,estimated_input_tokens,max_output_tokens,declared_context_tokens" {
		t.Fatalf("schema context_refusal = %+v", refusal)
	}
	var record map[string]map[string]json.RawMessage
	var top map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &top); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"x":`+string(top["context_refusal"])+`}`), &record); err != nil {
		t.Fatal(err)
	}
	for key := range record["x"] {
		if _, declared := refusal.Properties[key]; !declared {
			t.Fatalf("encoded refusal field %q is not in the schema", key)
		}
	}
}
