package github

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

func mergeBaseTestRequest(t *testing.T, adapter *Adapter, base, head string) scm.MergeBaseRequest {
	t.Helper()
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	baseRevision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, base)
	if err != nil {
		t.Fatal(err)
	}
	headRevision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, head)
	if err != nil {
		t.Fatal(err)
	}
	request, err := scm.NewMergeBaseRequest(repository, baseRevision, headRevision, adapter.Identity())
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// The adapter reads only merge_base_commit from one bounded compare page.
func TestResolveMergeBaseReadsTheCompareMergeBase(t *testing.T) {
	fixture := newGitHubFixture(t)
	defer fixture.close()
	base, head, merge := strings.Repeat("a", 40), strings.Repeat("b", 40), strings.Repeat("c", 40)
	fixture.compare = map[string]string{base + "..." + head: `{"status":"diverged","ahead_by":1,"behind_by":2,"merge_base_commit":{"sha":"` + merge + `","commit":{"message":"ignored"}},"files":[{"filename":"x"}]}`}
	adapter := testAdapter(t, fixture, &tokenProvider{token: testToken(t)})
	request := mergeBaseTestRequest(t, adapter, base, head)
	result := adapter.ResolveMergeBase(context.Background(), request)
	if scm.ValidateMergeBaseResult(request, result) != nil || result.Outcome != scm.MergeBaseResolved || result.MergeBase.Digest() != merge {
		t.Fatalf("result=%+v", result)
	}
	if query, _ := fixture.compareQuery.Load().(string); query != "per_page=1" {
		t.Fatalf("compare query=%q", query)
	}
	if !fixture.authorizationOK.Load() && fixture.calls.Load() != 1 {
		t.Fatal("compare was not a single authenticated read")
	}
}

func TestResolveMergeBaseClassifiesMissingHistoryAndFailures(t *testing.T) {
	base, head := strings.Repeat("a", 40), strings.Repeat("b", 40)
	cases := []struct {
		name          string
		compare       string
		compareStatus int
		headExists    bool
		outcome       scm.MergeBaseOutcome
		reason        evidence.RepositoryAcquisitionReason
	}{
		// No GitHub message for unrelated histories is sourced here, so a
		// compare 404 never claims there is no merge base, whatever its body.
		{"404 naming no common ancestor", `{"message":"No common ancestor between main and feature."}`, http.StatusNotFound, true, scm.MergeBaseUnavailable, evidence.AcquisitionReasonAdapterFailure},
		{"404 not found", `{"message":"Not Found"}`, http.StatusNotFound, true, scm.MergeBaseUnavailable, evidence.AcquisitionReasonAdapterFailure},
		{"404 without body", "", http.StatusNotFound, false, scm.MergeBaseUnavailable, evidence.AcquisitionReasonAdapterFailure},
		{"server error", "", http.StatusBadGateway, true, scm.MergeBaseUnavailable, evidence.AcquisitionReasonAdapterUnavailable},
		{"unauthorized", "", http.StatusForbidden, true, scm.MergeBaseUnavailable, evidence.AcquisitionReasonAuthorizationRequired},
		{"missing merge base field", `{"status":"ahead"}`, 0, true, scm.MergeBaseUnavailable, evidence.AcquisitionReasonArtifactIncomplete},
		{"wrong length merge base", `{"merge_base_commit":{"sha":"` + strings.Repeat("c", 64) + `"}}`, 0, true, scm.MergeBaseUnavailable, evidence.AcquisitionReasonArtifactIncomplete},
		{"duplicate member", `{"merge_base_commit":{"sha":"` + strings.Repeat("c", 40) + `"},"merge_base_commit":{"sha":"` + strings.Repeat("d", 40) + `"}}`, 0, true, scm.MergeBaseUnavailable, evidence.AcquisitionReasonArtifactIncomplete},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fixture := newGitHubFixture(t)
			defer fixture.close()
			fixture.compareStatus = c.compareStatus
			if c.compare != "" {
				fixture.compare = map[string]string{base + "..." + head: c.compare}
			}
			fixture.otherCommits = map[string]bool{head: c.headExists}
			adapter := testAdapter(t, fixture, &tokenProvider{token: testToken(t)})
			request := mergeBaseTestRequest(t, adapter, base, head)
			result := adapter.ResolveMergeBase(context.Background(), request)
			if scm.ValidateMergeBaseResult(request, result) != nil || result.Outcome != c.outcome || result.Reason != c.reason {
				t.Fatalf("result=%+v", result)
			}
		})
	}
}

func TestResolveMergeBaseRefusesCrossWiredRequestsBeforeNetwork(t *testing.T) {
	fixture := newGitHubFixture(t)
	defer fixture.close()
	adapter := testAdapter(t, fixture, &tokenProvider{token: testToken(t)})
	repository, _ := evidence.NewRepositoryIdentity("example.com", []string{"owner"}, "repo")
	base, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("a", 40))
	head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("b", 40))
	request, err := scm.NewMergeBaseRequest(repository, base, head, adapter.Identity())
	if err != nil {
		t.Fatal(err)
	}
	if result := adapter.ResolveMergeBase(context.Background(), request); result.Outcome != scm.MergeBaseUnavailable || result.Reason != evidence.AcquisitionReasonPolicyBlocked || fixture.calls.Load() != 0 {
		t.Fatalf("cross-wired request result=%+v calls=%d", result, fixture.calls.Load())
	}
	sha256Head, _ := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA256, strings.Repeat("b", 64))
	if _, err := scm.NewMergeBaseRequest(repository, base, sha256Head, adapter.Identity()); err == nil {
		t.Fatal("mixed object algorithms accepted")
	}
}
