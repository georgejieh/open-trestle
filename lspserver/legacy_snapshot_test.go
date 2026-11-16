package lspserver

import "testing"

func TestLegacyFindingDiagnosticPreservesReviewSnapshot(t *testing.T) {
	set := lspDiagnosticSet(t)
	item := toLSPDiagnostic(set, set.Findings()[0])
	if item.Data["snapshot_identity"] != set.SnapshotIdentity() || item.Data["diagnostic_set_identity"] != set.Identity() {
		t.Fatal("legacy finding provenance changed")
	}
}
