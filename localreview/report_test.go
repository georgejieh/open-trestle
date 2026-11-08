package localreview

import "testing"

func TestParseExitPolicyAcceptsOnlyDocumentedNames(t *testing.T) {
	for _, name := range []string{"default", "findings", "strict", "always-zero"} {
		if policy, ok := ParseExitPolicy(name); !ok || string(policy) != name {
			t.Fatalf("%s not accepted", name)
		}
	}
	for _, name := range []string{"", "pass", "Findings", "always_zero", "findings "} {
		if _, ok := ParseExitPolicy(name); ok {
			t.Fatalf("%q accepted", name)
		}
	}
}

func TestExitCodeForNeverPassesAnInvalidOrUnfinishedResult(t *testing.T) {
	if code := (Result{}).ExitCodeFor(ExitPolicyAlwaysZero); code != 1 {
		t.Fatalf("invalid result exit=%d", code)
	}
	for _, status := range []string{"refused", "incomplete", "canceled", "failed"} {
		result, err := NewUnstartedResult(status)
		if err != nil {
			t.Fatal(err)
		}
		for _, policy := range []ExitPolicy{ExitPolicyFindings, ExitPolicyStrict} {
			if code := result.ExitCodeFor(policy); code == 0 || code != result.ExitCode() {
				t.Fatalf("%s under %s exit=%d default=%d", status, policy, code, result.ExitCode())
			}
		}
		if result.ExitCodeFor(ExitPolicyAlwaysZero) != 0 || result.ExitCodeFor(ExitPolicyDefault) != result.ExitCode() {
			t.Fatalf("%s: always-zero or default mapping wrong", status)
		}
		report, err := result.Report()
		if err != nil || len(report.Findings) != 0 || report.RunStatus != "not_opened" || report.Status != status {
			t.Fatalf("%s report=%+v err=%v", status, report, err)
		}
	}
}
