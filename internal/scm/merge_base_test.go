package scm

import (
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func TestMergeBaseResultsAreClosedForTheirRequest(t *testing.T) {
	repository, _ := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	adapter, _ := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "test", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	revision := func(algorithm evidence.RevisionAlgorithm, digit string, length int) evidence.RevisionIdentity {
		value, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, strings.Repeat(digit, length))
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	base, head, merge := revision(evidence.RevisionAlgorithmSHA1, "a", 40), revision(evidence.RevisionAlgorithmSHA1, "b", 40), revision(evidence.RevisionAlgorithmSHA1, "c", 40)
	request, err := NewMergeBaseRequest(repository, base, head, adapter)
	if err != nil || request.Base() != base || request.Head() != head || request.Repository().Identity() != repository.Identity() {
		t.Fatalf("request: %v", err)
	}
	if _, err := NewMergeBaseRequest(repository, base, revision(evidence.RevisionAlgorithmSHA256, "b", 64), adapter); err == nil {
		t.Fatal("mixed object algorithms accepted")
	}
	none := evidence.AcquisitionReasonNone
	for _, valid := range []MergeBaseResult{
		{Outcome: MergeBaseResolved, MergeBase: merge, Reason: none},
		{Outcome: MergeBaseNone, Reason: none},
		{Outcome: MergeBaseUnavailable, Reason: evidence.AcquisitionReasonAdapterUnavailable},
	} {
		if err := ValidateMergeBaseResult(request, valid); err != nil {
			t.Fatalf("valid result %+v refused", valid)
		}
	}
	for _, invalid := range []MergeBaseResult{
		{},
		{Outcome: MergeBaseResolved, Reason: none},
		{Outcome: MergeBaseResolved, MergeBase: revision(evidence.RevisionAlgorithmSHA256, "c", 64), Reason: none},
		{Outcome: MergeBaseResolved, MergeBase: merge, Reason: evidence.AcquisitionReasonAdapterFailure},
		{Outcome: MergeBaseNone, MergeBase: merge, Reason: none},
		{Outcome: MergeBaseUnavailable, Reason: none},
		{Outcome: MergeBaseUnavailable},
		{Outcome: MergeBaseUnavailable + 1, Reason: none},
	} {
		if err := ValidateMergeBaseResult(request, invalid); err == nil {
			t.Fatalf("invalid result %+v accepted", invalid)
		}
	}
}
