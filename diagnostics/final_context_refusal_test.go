package diagnostics

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/georgejieh/open-trestle/internal/schemacheck"
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
		assertFinalSetValidates(t, encoded)
		if refusal.RequiredTokens != 0 {
			counts := []byte(`,"context_shortfall":{"required_tokens":14282,"estimated_input_tokens":10186,"max_output_tokens":4096,"declared_context_tokens":4097}`)
			assertFinalSetRefused(t, "missing counts", bytes.Replace(encoded, counts, nil, 1))
			assertFinalSetRefused(t, "zero declared", bytes.Replace(encoded, []byte(`"declared_context_tokens":4097`), []byte(`"declared_context_tokens":0`), 1))
		} else {
			assertFinalSetRefused(t, "unknown reason", bytes.Replace(encoded, []byte(`"reason":"no_eligible_route"`), []byte(`"reason":"no_merge_base"`), 1))
		}
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

// assertFinalSetValidates checks a fully encoded v7 set, every nested part
// included, against the repository's v7 schema.
func assertFinalSetValidates(t *testing.T, encoded []byte) {
	t.Helper()
	registry, err := schemacheck.Load(filepath.Join("..", "schemas"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Validate("urn:open-trestle:schema:diagnostics:set:v7", encoded); err != nil {
		t.Fatalf("v7 set does not validate: %v\n%s", err, encoded)
	}
}

// assertFinalSetRefused checks that the v7 schema refuses a forged encoding.
func assertFinalSetRefused(t *testing.T, name string, encoded []byte) {
	t.Helper()
	registry, err := schemacheck.Load(filepath.Join("..", "schemas"))
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Validate("urn:open-trestle:schema:diagnostics:set:v7", encoded); err == nil {
		t.Fatalf("%s validated against the v7 schema:\n%s", name, encoded)
	}
}
