package evaluation

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/schemacheck"
)

const modelCorpusLabelsSchema = "urn:open-trestle:schema:evaluation:model-corpus-labels:v1"

func syntheticModelCorpusLabels() map[string]any {
	location := func(side string, start, end int) map[string]any {
		return map[string]any{"path": "pkg/file.go", "side": side, "start_line": start, "end_line": end}
	}
	finding := location("base", 4, 6)
	finding["id"] = "f1"
	finding["also_accept_locations"] = []any{location("head", 4, 4)}
	finding["category"] = "correctness"
	finding["also_compatible_categories"] = []any{"reliability"}
	finding["severity_hint"] = "high"
	finding["defect"] = "Synthetic defect statement."
	finding["rationale"] = "Synthetic rationale."
	return map[string]any{
		"contract": "open-trestle/model-corpus-labels", "schema_version": 1, "case_id": "synthetic_case",
		"case_kind": "deletion_defect", "review_state": "pending", "reviewer_identifier": nil, "review_date": nil,
		"fixture_author_identifier": "open-trestle-maintainers", "go_version": "1.22", "go_semantics": "Synthetic.",
		"expected_outcome": "findings", "expected_findings": []any{finding}, "false_positive_traps": []any{},
		"abstention_reason": nil,
	}
}

func syntheticTrap() map[string]any {
	return map[string]any{"id": "t1", "path": "file.go", "side": "head", "start_line": 3, "end_line": 3, "also_match_locations": []any{}, "wrong_finding": "Synthetic.", "why_wrong": "Synthetic."}
}

func TestModelCorpusLabelsSchemaAdmitsOnlyPendingConsistentLabels(t *testing.T) {
	registry, err := schemacheck.Load(filepath.Join("..", "schemas"))
	if err != nil {
		t.Fatal(err)
	}
	check := func(value map[string]any) error {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		return registry.Validate(modelCorpusLabelsSchema, encoded)
	}
	if err := check(syntheticModelCorpusLabels()); err != nil {
		t.Fatalf("valid synthetic labels refused: %v", err)
	}
	nearMiss := syntheticModelCorpusLabels()
	nearMiss["case_kind"], nearMiss["expected_outcome"], nearMiss["expected_findings"], nearMiss["false_positive_traps"] = "near_miss", "no_finding", []any{}, []any{syntheticTrap()}
	if err := check(nearMiss); err != nil {
		t.Fatalf("valid near miss refused: %v", err)
	}
	abstention := syntheticModelCorpusLabels()
	abstention["case_kind"], abstention["expected_outcome"], abstention["expected_findings"], abstention["abstention_reason"] = "abstention", "abstention", []any{}, "The needed definition is absent."
	if err := check(abstention); err != nil {
		t.Fatalf("valid abstention refused: %v", err)
	}
	tests := map[string]func(map[string]any){
		"reviewed":                func(v map[string]any) { v["review_state"] = "adjudicated" },
		"reviewer":                func(v map[string]any) { v["reviewer_identifier"] = "someone" },
		"review date":             func(v map[string]any) { v["review_date"] = "2026-11-09" },
		"other author":            func(v map[string]any) { v["fixture_author_identifier"] = "someone-else" },
		"missing reviewer":        func(v map[string]any) { delete(v, "reviewer_identifier") },
		"unknown field":           func(v map[string]any) { v["decision"] = "confirmed" },
		"deletion without base":   func(v map[string]any) { v["expected_findings"].([]any)[0].(map[string]any)["side"] = "head" },
		"findings without labels": func(v map[string]any) { v["expected_findings"] = []any{} },
		"clean with findings":     func(v map[string]any) { v["case_kind"], v["expected_outcome"] = "clean", "no_finding" },
		"near miss without trap": func(v map[string]any) {
			v["case_kind"], v["expected_outcome"], v["expected_findings"] = "near_miss", "no_finding", []any{}
		},
		"abstention without reason": func(v map[string]any) {
			v["case_kind"], v["expected_outcome"], v["expected_findings"] = "abstention", "abstention", []any{}
		},
		"reason on a finding case": func(v map[string]any) { v["abstention_reason"] = "Not applicable." },
		"unknown category":         func(v map[string]any) { v["expected_findings"].([]any)[0].(map[string]any)["category"] = "naming" },
		"unknown side":             func(v map[string]any) { v["expected_findings"].([]any)[0].(map[string]any)["side"] = "both" },
		"zero line":                func(v map[string]any) { v["expected_findings"].([]any)[0].(map[string]any)["start_line"] = 0 },
		"traversal path": func(v map[string]any) {
			v["expected_findings"].([]any)[0].(map[string]any)["path"] = "../file.go"
		},
		"absolute path": func(v map[string]any) {
			v["expected_findings"].([]any)[0].(map[string]any)["path"] = "/file.go"
		},
		"open location": func(v map[string]any) {
			v["expected_findings"].([]any)[0].(map[string]any)["also_accept_locations"].([]any)[0].(map[string]any)["note"] = "x"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			value := syntheticModelCorpusLabels()
			mutate(value)
			if err := check(value); err == nil {
				t.Fatal("invalid labels accepted")
			}
		})
	}
	if !strings.HasPrefix(modelCorpusLabelsSchema, "urn:open-trestle:schema:evaluation:") || !registry.Has(modelCorpusLabelsSchema) {
		t.Fatal("labels schema not published under the evaluation namespace")
	}
}
