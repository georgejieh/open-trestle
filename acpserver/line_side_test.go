package acpserver

import (
	"bytes"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/diagnostics"
)

func TestServerMarksBaseSideFindingsAsBaseLines(t *testing.T) {
	scope, receipt, deterministic := acpV6Fixture(t, 1, 64)
	finding, err := diagnostics.NewFindingOnSide(strings.Repeat("a", 64), strings.Repeat("b", 64), "Removed guard", "The zero check was removed.", diagnostics.SeverityError, "calc.go", diagnostics.LineSideBase, 4, 6, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := diagnostics.NewSetWithDeterministicChecks(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []diagnostics.Finding{finding})
	if err != nil || verified.SchemaVersion() != 8 {
		t.Fatalf("verified=%v", err)
	}
	final, err := diagnostics.NewFinalReviewSet(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), diagnostics.FinalOutcomeCompleted, deterministic, verified)
	if err != nil {
		t.Fatal(err)
	}
	for name, set := range map[string]diagnostics.Set{"version 8": verified, "final version 7": final} {
		messages := promptMessages(t, &serviceStub{receipt: receipt, set: set}, scope)
		for _, want := range []string{"1 verified finding(s) are on removed base lines", `\"side\":\"base\"`} {
			if !bytes.Contains(messages[0], []byte(want)) {
				t.Fatalf("%s: missing %q in %s", name, want, messages[0])
			}
		}
	}
	// A head-only set carries no base-line notice.
	head, err := diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue", "Independent verification.", diagnostics.SeverityError, "verified.go", 4, 4, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	headOnly, err := diagnostics.NewSetWithDeterministicChecks(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), []diagnostics.Finding{head})
	if err != nil {
		t.Fatal(err)
	}
	if messages := promptMessages(t, &serviceStub{receipt: receipt, set: headOnly}, scope); bytes.Contains(messages[0], []byte("removed base lines")) {
		t.Fatalf("head-only set has a base-line notice: %s", messages[0])
	}
}
