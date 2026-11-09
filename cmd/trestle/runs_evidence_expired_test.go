package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
)

// An evidence-expired final result is named on stderr and in SARIF, as a run
// property and a run-level notification, never as an empty clean result.
func TestRunStatusNamesEvidenceExpiredResult(t *testing.T) {
	receipt := refusedContextReceipt(t, controlplane.TaskFailureReasonNoEligibleRoute, controlplane.TaskFailureContextShortfall{})
	bare, err := diagnostics.NewFinalReviewSet(receipt.Scope(), "", "", diagnostics.FinalOutcomeInconclusive, diagnostics.Set{}, diagnostics.Set{})
	if err != nil {
		t.Fatal(err)
	}
	expired, err := bare.WithEvidenceExpired()
	if err != nil {
		t.Fatal(err)
	}
	want := "runs status: " + diagnostics.EvidenceExpiredText + "\n"
	for _, format := range []string{"json", "sarif"} {
		exit, out, errs := runStatusAgainst(t, receipt, &expired, format)
		if exit != 0 || errs != want {
			t.Fatalf("%s: exit=%d stderr=%q", format, exit, errs)
		}
		if format != "sarif" {
			continue
		}
		var log struct {
			Runs []struct {
				Invocations []struct {
					ExecutionSuccessful        bool `json:"executionSuccessful"`
					ToolExecutionNotifications []struct {
						Level   string `json:"level"`
						Message struct {
							Text string `json:"text"`
						} `json:"message"`
					} `json:"toolExecutionNotifications"`
				} `json:"invocations"`
				Properties struct {
					EvidenceExpired bool   `json:"trestleEvidenceExpired"`
					Reason          string `json:"trestleReason"`
				} `json:"properties"`
				Results []json.RawMessage `json:"results"`
			} `json:"runs"`
		}
		if err := json.Unmarshal([]byte(out), &log); err != nil || len(log.Runs) != 1 {
			t.Fatalf("sarif=%s err=%v", out, err)
		}
		run := log.Runs[0]
		notes := run.Invocations
		if !run.Properties.EvidenceExpired || !strings.Contains(run.Properties.Reason, "evidence expired") || len(run.Results) != 0 || len(notes) != 1 || !notes[0].ExecutionSuccessful || len(notes[0].ToolExecutionNotifications) != 1 || notes[0].ToolExecutionNotifications[0].Message.Text != diagnostics.EvidenceExpiredText || notes[0].ToolExecutionNotifications[0].Level != "note" {
			t.Fatalf("sarif run=%+v", run)
		}
	}
	if exit, out, errs := runStatusAgainst(t, receipt, &bare, "sarif"); exit != 0 || errs != "" || strings.Contains(out, "trestleEvidenceExpired") {
		t.Fatalf("unexpired result: exit=%d stderr=%q", exit, errs)
	}
}
