package github

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
)

// The prepared base task acquires the merge base of pull_request.base.sha and
// pull_request.head.sha; equal commits are planned so the source task records
// the refusal, while the unprepared planner still refuses them outright.
func TestPreparedPlannerPlansTheMergeBaseOfBaseAndHead(t *testing.T) {
	planner, err := NewBuiltInPreparedPullRequestPlanner("github.com", "owner/repository", strings.Repeat("e", 64), "tenant-github-review", controlplane.ReviewRunAdvisory, plannerBindings()[:8], artifact.ClassificationRestricted, artifact.ProtectionProcessPrivate, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	payload := func(base, head string) string {
		return `{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"` + base + `","repo":{"full_name":"owner/repository"}},"head":{"sha":"` + head + `","repo":{"full_name":"owner/repository"}}}}`
	}
	base, head := strings.Repeat("1", 40), strings.Repeat("2", 40)
	plan, inputs, err := planner.Prepare(context.Background(), storedPullRequest(t, payload(base, head)))
	if err != nil {
		t.Fatal(err)
	}
	baseTask, _ := plan.Task("source-base")
	headTask, _ := plan.Task("source-head")
	for _, value := range inputs {
		input, err := sourcehandler.ParseInput(value.Payload())
		if err != nil {
			t.Fatal(err)
		}
		mergeHead, derived := input.MergeBaseHead()
		switch value.Identity() {
		case baseTask.InputIdentity():
			if input.SchemaVersion() != 3 || !derived || input.Revision().Digest() != base || mergeHead.Digest() != head {
				t.Fatal("base task does not acquire the merge base of base.sha and head.sha")
			}
		case headTask.InputIdentity():
			if input.SchemaVersion() != 1 || derived || input.Revision().Digest() != head {
				t.Fatal("head task does not acquire head.sha")
			}
		default:
			t.Fatal("unexpected prepared input")
		}
	}
	if _, _, err := planner.Prepare(context.Background(), storedPullRequest(t, payload(head, head))); err != nil {
		t.Fatalf("equal base and head were not planned for a recorded refusal: %v", err)
	}
	if _, _, err := planner.Prepare(context.Background(), storedPullRequest(t, payload(base, strings.Repeat("2", 64)))); !errors.Is(err, ErrInvalidPullRequestPayload) {
		t.Fatalf("mixed object formats err=%v", err)
	}
	unprepared, err := NewPullRequestPlanner("owner/repository", strings.Repeat("e", 64), controlplane.ReviewRunAdvisory, plannerBindings()[:8])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := unprepared.Plan(context.Background(), storedPullRequest(t, payload(head, head))); !errors.Is(err, ErrInvalidPullRequestPayload) {
		t.Fatalf("unprepared planner accepted equal base and head: %v", err)
	}
}
