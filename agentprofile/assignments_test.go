package agentprofile

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/gateway"
)

const routeLight = `{"zone":"local","provider_id":"ollama","adapter_id":"chat-completions","connection_id":"local/ollama","model_id":"qwen3:8b","model_version":""}`
const routeDeep = `{"zone":"local","provider_id":"ollama","adapter_id":"chat-completions","connection_id":"local/ollama","model_id":"qwen3:235b","model_version":""}`
const routeVerifier = `{"zone":"local","provider_id":"llamacpp","adapter_id":"chat-completions","connection_id":"local/llamacpp","model_id":"gemma-3-27b","model_version":""}`

func validAssignmentsJSON() string {
	return `{"schema":"open-trestle/agent-profile-assignments","version":1,"independence":"distinct_provider",` +
		`"tiers":{"light":` + routeLight + `,"deep":` + routeDeep + `},` +
		`"verifier_tiers":{"light":` + routeVerifier + `},` +
		`"profiles":{"security_probe":{"tiers":{"light":` + routeDeep + `}}},` +
		`"escalation_order":["light","standard","deep"],"total_token_budget":500000}`
}

func TestProfileParseAssignmentsAcceptsVersionedDocument(t *testing.T) {
	catalog := mustCatalog(t)
	assignments, err := ParseAssignments(catalog, []byte(validAssignmentsJSON()))
	if err != nil {
		t.Fatalf("ParseAssignments() error = %v", err)
	}
	if err := assignments.Validate(); err != nil || !validDigest(assignments.Identity()) {
		t.Fatalf("Validate() = %v identity=%q", err, assignments.Identity())
	}
	if assignments.Independence().Level() != gateway.RouteIndependenceDistinctProvider || assignments.TotalTokenBudget() != 500000 || len(assignments.EscalationOrder()) != 3 {
		t.Fatal("parsed fields differ")
	}
	selection, ok := assignments.resolve(ProfileSecurityProbe, TierLight, false)
	if !ok || selection.source != routeSourceProfileOverride || selection.route.ModelID() != "qwen3:235b" {
		t.Fatalf("override not applied: %+v", selection)
	}
	selection, ok = assignments.resolve(ProfileBugHunter, TierLight, false)
	if !ok || selection.source != routeSourceGlobal || selection.route.ModelID() != "qwen3:8b" {
		t.Fatalf("global not applied: %+v", selection)
	}
	selection, ok = assignments.resolve(ProfileBugHunter, TierStandard, false)
	if !ok || selection.tier != TierDeep || selection.escalatedFrom != TierStandard {
		t.Fatalf("escalation not recorded: %+v", selection)
	}
}

func TestProfileAssignmentsIdentityIsIndependentOfKeyOrder(t *testing.T) {
	catalog := mustCatalog(t)
	reordered := `{"total_token_budget":500000,"escalation_order":["light","standard","deep"],` +
		`"profiles":{"security_probe":{"tiers":{"light":` + routeDeep + `}}},` +
		`"verifier_tiers":{"light":` + routeVerifier + `},` +
		`"tiers":{"deep":` + routeDeep + `,"light":` + routeLight + `},` +
		`"independence":"distinct_provider","version":1,"schema":"open-trestle/agent-profile-assignments"}`
	first, err := ParseAssignments(catalog, []byte(validAssignmentsJSON()))
	if err != nil {
		t.Fatal(err)
	}
	second, err := ParseAssignments(catalog, []byte(reordered))
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity() != second.Identity() {
		t.Fatalf("identity depends on key order: %s vs %s", first.Identity(), second.Identity())
	}
}

func TestProfileParseAssignmentsRejectsInvalidDocuments(t *testing.T) {
	catalog := mustCatalog(t)
	valid := validAssignmentsJSON()
	replace := func(old, new string) string {
		if !strings.Contains(valid, old) {
			t.Fatalf("fixture does not contain %q", old)
		}
		return strings.Replace(valid, old, new, 1)
	}
	for _, test := range []struct {
		name     string
		document string
		want     error
	}{
		{"empty", ``, ErrInvalidAssignments},
		{"not an object", `[]`, ErrInvalidAssignments},
		{"oversize", `{"schema":"` + strings.Repeat("a", MaxAssignmentsBytes) + `"}`, ErrAssignmentsTooLarge},
		{"unknown top-level field", replace(`"version":1,`, `"version":1,"fallback":true,`), ErrInvalidAssignments},
		{"unknown route field", replace(`"model_version":""}`, `"model_version":"","api_key":"x"}`), ErrInvalidAssignments},
		{"duplicate key", replace(`"version":1,`, `"version":1,"version":1,`), ErrInvalidAssignments},
		{"trailing data", valid + `{}`, ErrInvalidAssignments},
		{"wrong schema", replace(`agent-profile-assignments`, `agent-profile-assignment`), ErrInvalidAssignments},
		{"wrong version", replace(`"version":1`, `"version":2`), ErrInvalidAssignments},
		{"missing independence", replace(`"independence":"distinct_provider",`, ``), ErrInvalidAssignments},
		{"unknown independence", replace(`distinct_provider`, `distinct_vibes`), ErrInvalidAssignments},
		{"unknown tier", replace(`"tiers":{"light":`, `"tiers":{"medium":`), ErrInvalidAssignments},
		{"unknown zone", replace(`"zone":"local"`, `"zone":"cloud"`), ErrInvalidAssignments},
		{"invalid model id", replace(`qwen3:8b`, `Qwen 3`), ErrInvalidAssignments},
		{"unknown profile override", replace(`"security_probe":`, `"linter":`), ErrInvalidAssignments},
		{"orchestrator override", replace(`"security_probe":`, `"orchestrator":`), ErrInvalidAssignments},
		{"empty override", replace(`{"tiers":{"light":`+routeDeep+`}}`, `{}`), ErrInvalidAssignments},
		{"duplicate escalation tier", replace(`["light","standard","deep"]`, `["light","light"]`), ErrInvalidAssignments},
		{"single escalation tier", replace(`["light","standard","deep"]`, `["light"]`), ErrInvalidAssignments},
		{"unknown escalation tier", replace(`["light","standard","deep"]`, `["light","huge"]`), ErrInvalidAssignments},
		{"budget too large", replace(`500000`, `2199023255553`), ErrInvalidAssignments},
		{"negative budget", replace(`500000`, `-1`), ErrInvalidAssignments},
		{"no generator routes", `{"schema":"open-trestle/agent-profile-assignments","version":1,"independence":"distinct_route","verifier_tiers":{"light":` + routeVerifier + `}}`, ErrInvalidAssignments},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseAssignments(catalog, []byte(test.document)); !errors.Is(err, test.want) {
				t.Fatalf("ParseAssignments() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestProfileAssignmentsMissingTiersDoNotBorrowWithoutEscalation(t *testing.T) {
	catalog := mustCatalog(t)
	document := strings.Replace(validAssignmentsJSON(), `,"escalation_order":["light","standard","deep"]`, ``, 1)
	assignments, err := ParseAssignments(catalog, []byte(document))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := assignments.resolve(ProfileBugHunter, TierStandard, false); ok {
		t.Fatal("unassigned tier borrowed a route without an escalation order")
	}
	if _, ok := assignments.resolve(ProfileBugHunter, TierDeep, true); ok {
		t.Fatal("unassigned verifier tier borrowed a route without an escalation order")
	}
}

func TestStrictJSONRejectsCaseFoldedDuplicateKeys(t *testing.T) {
	for _, document := range []string{
		`{"independence":"a","INDEPENDENCE":"b"}`,
		`{"schema":"a","ſchema":"b"}`,
		`{"kind":"a","Kind":"b"}`,
	} {
		var destination map[string]string
		if err := decodeStrictJSON([]byte(document), &destination); !errors.Is(err, errDuplicateJSONKey) {
			t.Fatalf("%s: err=%v, want duplicate key", document, err)
		}
	}
	var destination map[string]string
	if err := decodeStrictJSON([]byte(`{"schema":"a","version":"b"}`), &destination); err != nil {
		t.Fatalf("distinct keys rejected: %v", err)
	}
}
