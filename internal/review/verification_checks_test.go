package review

import (
	"encoding/json"
	"strings"
	"testing"
)

func verdictWithCheck(id, outcome, check string) string {
	severity := "high"
	if outcome != "verified" {
		severity = "none"
	}
	return `{"candidate_id":"` + id + `","outcome":"` + outcome + `","severity":"` + severity + `","rationale":"Confirmed.","evidence_ids":["evidence-1"],"check":` + check + `}`
}

// A check is optional in version 2 and its content never refuses the
// verdict; version 1 has no check.
func TestVerificationSyntaxAcceptsAnyCheckInVersionTwo(t *testing.T) {
	for _, check := range []string{`{"framework":"go_test","content":"package a\n"}`, `"not an object"`, `null`, `{"framework":"jest","content":"x","path":"../a"}`} {
		document := `{"schema_version":2,"verdicts":[` + verdictWithCheck("c1", "verified", check) + `]}`
		if err := ValidateVerificationDocumentSyntax([]byte(document)); err != nil {
			t.Errorf("check %s refused the document: %v", check, err)
		}
	}
	v1 := `{"schema_version":1,"verdicts":[` + verdictWithCheck("c1", "verified", `{"framework":"go_test","content":"x"}`) + `]}`
	if err := ValidateVerificationDocumentSyntax([]byte(v1)); err == nil {
		t.Fatal("a version 1 verdict with a check was admitted")
	}
	if err := ValidateVerificationDocumentSyntax([]byte(`{"schema_version":3,"verdicts":[]}`)); err == nil {
		t.Fatal("version 3 was admitted")
	}
}

func TestAuthoredChecksDropInvalidExtraAndUnverifiedChecks(t *testing.T) {
	valid := `{"framework":"go_test","content":"package a\n"}`
	verdicts := []string{
		verdictWithCheck("c1", "verified", valid),
		verdictWithCheck("c2", "rejected", valid),
		verdictWithCheck("c3", "verified", `{"framework":"pytest","content":"x"}`),
		verdictWithCheck("c4", "verified", `{"framework":"go_test","content":"x","path":"a.go"}`),
		verdictWithCheck("c5", "verified", `{"framework":"go_test","content":"`+strings.Repeat("x", MaxAuthoredCheckBytes+1)+`"}`),
		verdictWithCheck("c6", "verified", `{"framework":"go_test","content":"a\u0000"}`),
		verdictWithCheck("c7", "verified", `{"framework":"go_test","content":"  "}`),
		verdictWithCheck("c8", "verified", `"text"`),
		verdictWithCheck("c9", "verified", valid),
		verdictWithCheck("c10", "verified", valid),
		verdictWithCheck("c11", "verified", valid),
	}
	verified := map[string]AuthoredCheck{}
	for _, id := range []string{"c1", "c3", "c4", "c5", "c6", "c7", "c8", "c9", "c10", "c11"} {
		verified[id] = AuthoredCheck{FindingIdentity: "finding-" + id, Path: "a/a.go"}
	}
	payload := []byte(`{"schema_version":2,"verdicts":[` + strings.Join(verdicts, ",") + `]}`)
	checks, dropped := authoredChecks(payload, []string{TestFrameworkGo}, verified)
	if len(checks) != MaxAuthoredChecks || dropped != 8 || checks[0].FindingIdentity != "finding-c1" || checks[1].FindingIdentity != "finding-c9" || checks[2].FindingIdentity != "finding-c10" ||
		checks[0].Content != "package a\n" || checks[0].Framework != TestFrameworkGo || checks[0].Path != "a/a.go" {
		t.Fatalf("checks %+v dropped %d", checks, dropped)
	}
	// Without a test authoring request every check is dropped.
	if checks, dropped := authoredChecks(payload, nil, verified); checks != nil || dropped != 11 {
		t.Fatalf("unrequested checks %+v dropped %d", checks, dropped)
	}
}

func TestTestAuthoringTravelsInCheckRunsAndIsChecked(t *testing.T) {
	runs := sampleCheckRuns(t)
	asked, err := runs.WithTestAuthoring([]string{TestFrameworkPytest, TestFrameworkGo, TestFrameworkGo})
	if err != nil || strings.Join(asked.TestFrameworks(), ",") != "go_test,pytest" || asked.Identity() == runs.Identity() || runs.TestFrameworks() != nil {
		t.Fatalf("test authoring: %v %v", asked.TestFrameworks(), err)
	}
	for _, frameworks := range [][]string{nil, {"jest"}} {
		if _, err := runs.WithTestAuthoring(frameworks); err == nil {
			t.Errorf("frameworks %v admitted", frameworks)
		}
	}
	if _, err := asked.WithTestAuthoring([]string{TestFrameworkGo}); err == nil {
		t.Fatal("a second request was bound")
	}
	_, payload := checkRunsPacket(t, asked)
	read, err := ContextCheckRuns(payload)
	if err != nil || read.Identity() != asked.Identity() || strings.Join(read.TestFrameworks(), ",") != "go_test,pytest" {
		t.Fatalf("readback: %v", err)
	}
	var wire checkRunsWire
	if err := json.Unmarshal(modelContractFields(t, payload)["check_runs"], &wire); err != nil || wire.TestAuthoring == nil || wire.TestAuthoring.Max != 3 {
		t.Fatalf("test_authoring = %+v", wire.TestAuthoring)
	}
	for name, change := range map[string]func(*testAuthoringWire){
		"max":      func(w *testAuthoringWire) { w.Max = 4 },
		"unknown":  func(w *testAuthoringWire) { w.Frameworks = []string{"jest"} },
		"unsorted": func(w *testAuthoringWire) { w.Frameworks = []string{"pytest", "go_test"} },
		"empty":    func(w *testAuthoringWire) { w.Frameworks = []string{} },
	} {
		tampered := *wire.TestAuthoring
		tampered.Frameworks = append([]string{}, tampered.Frameworks...)
		change(&tampered)
		copied := wire
		copied.TestAuthoring = &tampered
		if validCheckRunsWire(&copied) {
			t.Errorf("%s: admitted", name)
		}
	}
}
