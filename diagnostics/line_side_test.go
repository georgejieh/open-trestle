package diagnostics

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func sidedFinding(t *testing.T, side LineSide, path string, start uint32, title string) Finding {
	t.Helper()
	finding, err := NewFindingOnSide(strings.Repeat("a", 64), hashValue(title+side.String()), title, "Verified by an independent route.", SeverityError, path, side, start, start+1, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return finding
}

func verifiedSetWith(t *testing.T, findings ...Finding) (Set, error) {
	t.Helper()
	deterministic, err := deterministicSetAtCount(t, "run-sides", 1)
	if err != nil {
		t.Fatal(err)
	}
	count := uint16(len(findings))
	return NewSetWithDeterministicChecks(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), count, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), findings)
}

func TestHeadFindingIdentityIsUnchangedBySide(t *testing.T) {
	head, err := NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue", "Verified by independent route.", SeverityError, "verified.go", 4, 4, []string{strings.Repeat("c", 64)})
	if err != nil {
		t.Fatal(err)
	}
	onSide, err := NewFindingOnSide(strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue", "Verified by independent route.", SeverityError, "verified.go", LineSideHead, 4, 4, []string{strings.Repeat("c", 64)})
	if err != nil || onSide.Identity() != head.Identity() || head.Side() != LineSideHead {
		t.Fatalf("head identity changed: %v", err)
	}
	base, err := NewFindingOnSide(strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue", "Verified by independent route.", SeverityError, "verified.go", LineSideBase, 4, 4, []string{strings.Repeat("c", 64)})
	if err != nil || base.Identity() == head.Identity() || base.Validate() != nil {
		t.Fatalf("base and head findings with equal numbers share an identity: %v", err)
	}
	if _, err := NewFindingOnSide(strings.Repeat("a", 64), strings.Repeat("b", 64), "Verified issue", "Verified by independent route.", SeverityError, "verified.go", LineSide(9), 4, 4, []string{strings.Repeat("c", 64)}); err == nil {
		t.Fatal("unknown side accepted")
	}
}

func TestBaseSideFindingUsesVersion8(t *testing.T) {
	head := sidedFinding(t, LineSideHead, "calc.go", 4, "Head issue")
	base := sidedFinding(t, LineSideBase, "calc.go", 2, "Removed guard")
	headOnly, err := verifiedSetWith(t, head)
	if err != nil || headOnly.SchemaVersion() != 5 || bytes.Contains(mustEncodeSet(t, headOnly), []byte(`"side"`)) {
		t.Fatalf("head-only set is not version 5: %v", err)
	}
	set, err := verifiedSetWith(t, base, head)
	if err != nil || set.SchemaVersion() != 8 {
		t.Fatalf("base finding did not select version 8: %v", err)
	}
	// Head lines of a path sort before its removed base lines.
	if findings := set.Findings(); findings[0].Side() != LineSideHead || findings[1].Side() != LineSideBase {
		t.Fatal("base finding sorted before the head finding of the same path")
	}
	encoded := mustEncodeSet(t, set)
	if !bytes.Contains(encoded, []byte(`"schema_version":8`)) || bytes.Count(encoded, []byte(`"side":"base"`)) != 1 {
		t.Fatalf("encoded=%s", encoded)
	}
	parsed, err := ParseSet(encoded)
	if err != nil || parsed.Identity() != set.Identity() || parsed.SchemaVersion() != 8 || parsed.Findings()[1].Side() != LineSideBase {
		t.Fatalf("version 8 does not read back: %v", err)
	}
	for name, tampered := range map[string][]byte{
		"version 5 with a side":   bytes.Replace(encoded, []byte(`"schema_version":8`), []byte(`"schema_version":5`), 1),
		"version 8 without base":  bytes.Replace(encoded, []byte(`,"side":"base"`), nil, 1),
		"explicit head side":      bytes.Replace(encoded, []byte(`"side":"base"`), []byte(`"side":"head"`), 1),
		"head version without it": mustEncodeSetVersion(t, headOnly, 8),
	} {
		if _, err := ParseSet(tampered); err == nil {
			t.Fatalf("%s read back", name)
		}
	}
	// Versions that cannot record a side refuse a base finding outright.
	if _, err := NewSetWithCoverage(set.Scope(), set.SnapshotIdentity(), set.HeadRevision(), strings.Repeat("e", 64), 1, 0, 0, []Finding{base}); err == nil {
		t.Fatal("version 2 accepted a base-side finding")
	}
	if _, err := NewSetWithOmissionReasons(set.Scope(), set.SnapshotIdentity(), set.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, []Finding{base}); err == nil {
		t.Fatal("version 4 accepted a base-side finding")
	}
}

func TestFinalSetCarriesVersion8Verification(t *testing.T) {
	deterministic, err := deterministicSetAtCount(t, "run-sides", 1)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := verifiedSetWith(t, sidedFinding(t, LineSideBase, "removed.go", 1, "Removed check"))
	if err != nil || verified.SchemaVersion() != 8 {
		t.Fatalf("verified=%v", err)
	}
	final, err := NewFinalReviewSet(deterministic.Scope(), deterministic.SnapshotIdentity(), deterministic.HeadRevision(), FinalOutcomeCompleted, deterministic, verified)
	if err != nil || final.SchemaVersion() != 7 || len(final.Findings()) != 1 || final.Findings()[0].Side() != LineSideBase {
		t.Fatalf("final=%v", err)
	}
	encoded := mustEncodeSet(t, final)
	if !bytes.Contains(encoded, []byte(`"verified":{"contract":"open-trestle/review-diagnostic-set","schema_version":8`)) {
		t.Fatalf("final set does not embed version 8: %s", encoded)
	}
	parsed, err := ParseSet(encoded)
	if err != nil || parsed.Identity() != final.Identity() || !bytes.Equal(encoded, mustEncodeSet(t, parsed)) || parsed.Findings()[0].Side() != LineSideBase {
		t.Fatalf("final set does not read back: %v", err)
	}
}

// mustEncodeSetVersion relabels a canonical encoding with another schema
// version, to show that readback refuses it.
func mustEncodeSetVersion(t *testing.T, set Set, version int) []byte {
	t.Helper()
	encoded := mustEncodeSet(t, set)
	return bytes.Replace(encoded, []byte(fmt.Sprintf(`"schema_version":%d`, set.SchemaVersion())), []byte(fmt.Sprintf(`"schema_version":%d`, version)), 1)
}
