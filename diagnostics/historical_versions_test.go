package diagnostics

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/audit"
)

func TestParseSetRetainsHistoricalMixedTiedFindingOrderAcrossVersions(t *testing.T) {
	versions := []int{5, 7}
	wantTiedTitles := []string{"tied finding 5", "tied finding 1", "tied finding 2", "tied finding 3", "tied finding 0", "tied finding 4"}
	identities := make(map[string]bool, len(versions))
	for _, version := range versions {
		payload, err := os.ReadFile(fmt.Sprintf("testdata/historical-tied-findings-v%d.json", version))
		if err != nil {
			t.Fatal(err)
		}
		set, err := ParseSet(payload)
		if err != nil {
			t.Fatalf("historical V%d tied order was rejected: %v", version, err)
		}
		if set.SchemaVersion() != version || set.Validate() != nil {
			t.Fatalf("historical V%d set=%#v", version, set)
		}
		if version == 7 && (set.VerifiedSetIdentity() == "" || len(set.DeterministicChecks()) != 1) {
			t.Fatalf("historical V7 lost embedded V5 lineage: %#v", set)
		}
		if roundTrip, err := EncodeSet(set); err != nil || !bytes.Equal(roundTrip, payload) {
			t.Fatalf("historical V%d changed on readback: %v", version, err)
		}
		if got := tiedFindingTitles(set.Findings()); !sameStrings(got, wantTiedTitles) {
			t.Fatalf("historical V%d tied titles=%v want=%v", version, got, wantTiedTitles)
		}
		identities[set.Identity()] = true
	}
	if len(identities) != len(versions) {
		t.Fatalf("historical identities were collapsed: %d", len(identities))
	}
}

func TestNewSetPreservesRelativeOrderForMixedTiedFindings(t *testing.T) {
	findings, wantTiedTitles := historicalMixedTiedFindings(t)
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "historical-mixed-ties")
	if err != nil {
		t.Fatal(err)
	}
	set, err := verifiedTestSet(t, scope, findings)
	if err != nil {
		t.Fatal(err)
	}
	if got := tiedFindingTitles(set.Findings()); !sameStrings(got, wantTiedTitles) {
		t.Fatalf("tied titles=%v want=%v", got, wantTiedTitles)
	}
}

func historicalMixedTiedFindings(t *testing.T) ([]Finding, []string) {
	t.Helper()
	layout := []struct {
		rank, tieID int
	}{
		{2, -1}, {3, -1}, {1, 1}, {3, -1}, {3, -1}, {2, -1}, {1, 2},
		{1, 3}, {3, -1}, {1, 5}, {1, 0}, {1, 4}, {4, -1},
	}
	findings := make([]Finding, len(layout))
	wantTiedTitles := make([]string, 0, 6)
	for index, item := range layout {
		var err error
		if item.tieID >= 0 {
			findings[index], err = NewFinding(fmt.Sprintf("%064x", item.tieID+1), strings.Repeat("b", 64), fmt.Sprintf("tied finding %d", item.tieID), fmt.Sprintf("tied finding message %d", item.tieID), SeverityWarning, "internal/a-tied.go", 7, 7, []string{fmt.Sprintf("%064x", item.tieID+101)})
			wantTiedTitles = append(wantTiedTitles, findings[index].Title())
		} else {
			findings[index], err = NewFinding(fmt.Sprintf("%064x", index+1001), fmt.Sprintf("%064x", item.rank+2001), fmt.Sprintf("rank finding %d", index), fmt.Sprintf("rank %d finding %d", item.rank, index), SeverityInformation, fmt.Sprintf("internal/rank-%d.go", item.rank), 1, 1, []string{fmt.Sprintf("%064x", index+3001)})
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return findings, wantTiedTitles
}

func tiedFindingTitles(findings []Finding) []string {
	titles := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding.Path() == "internal/a-tied.go" {
			titles = append(titles, finding.Title())
		}
	}
	return titles
}

func sameStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}
