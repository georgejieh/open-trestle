package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestRequiredPipelinePlannerAttemptContracts(t *testing.T) {
	payload := `{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"1111111111111111111111111111111111111111","repo":{"full_name":"owner/repository"}},"head":{"sha":"2222222222222222222222222222222222222222","repo":{"full_name":"owner/repository"}}}}`
	for _, mode := range []controlplane.ReviewRunMode{controlplane.ReviewRunAdvisory, controlplane.ReviewRunRequired} {
		t.Run(mode.String(), func(t *testing.T) {
			bindings := make([]TaskHandlerBinding, 0, 9)
			for _, binding := range plannerBindings() {
				if mode == controlplane.ReviewRunAdvisory && binding.Kind == controlplane.TaskPublishResult {
					continue
				}
				bindings = append(bindings, binding)
			}
			for _, prepared := range []bool{false, true} {
				name := "pull_request"
				if prepared {
					name = "prepared_pull_request"
				}
				t.Run(name, func(t *testing.T) {
					stored := storedPullRequest(t, payload)
					legacyIdentity := legacyAttemptPlannerIdentity(t, mode, bindings)
					var plan controlplane.ReviewRunPlan
					var err error
					wantTasks := 8
					if prepared {
						planner, constructionErr := NewBuiltInPreparedPullRequestPlanner("github.com", "owner/repository", strings.Repeat("e", 64), "github-review", mode, bindings, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, time.Hour)
						if constructionErr != nil {
							t.Fatal(constructionErr)
						}
						if planner.base.Identity() == legacyIdentity {
							t.Error("prepared planner retained the legacy v3 base behavior identity")
						}
						var inputs []artifact.Artifact
						plan, inputs, err = planner.Prepare(context.Background(), stored)
						wantInputs := 2
						if mode == controlplane.ReviewRunRequired {
							wantInputs++
						}
						if len(inputs) != wantInputs {
							t.Fatalf("prepared inputs=%d, want %d: %v", len(inputs), wantInputs, err)
						}
						wantTasks++
					} else {
						planner, constructionErr := NewPullRequestPlanner("owner/repository", strings.Repeat("e", 64), mode, bindings)
						if constructionErr != nil {
							t.Fatal(constructionErr)
						}
						if planner.Identity() == legacyIdentity {
							t.Error("planner retained the legacy v3 behavior identity")
						}
						plan, err = planner.Plan(context.Background(), stored)
					}
					if err != nil {
						t.Fatal(err)
					}
					if mode == controlplane.ReviewRunRequired {
						wantTasks++
					}
					if plan.Validate() != nil || plan.Mode() != mode || plan.TaskCount() != wantTasks {
						t.Fatalf("plan mode=%s tasks=%d, want mode=%s tasks=%d", plan.Mode(), plan.TaskCount(), mode, wantTasks)
					}
					wantAttempts := map[controlplane.TaskKind]uint8{
						controlplane.TaskAcquireSource:        3,
						controlplane.TaskBuildChange:          3,
						controlplane.TaskInspectDeterministic: 3,
						controlplane.TaskRetrieveContext:      3,
						controlplane.TaskAssembleContext:      1,
						controlplane.TaskGenerateCandidates:   1,
						controlplane.TaskVerifyCandidates:     1,
						controlplane.TaskEvaluatePublication:  3,
						controlplane.TaskPublishResult:        1,
					}
					for _, task := range plan.Tasks() {
						want, known := wantAttempts[task.Kind()]
						if !known || task.MaxAttempts() != want {
							t.Errorf("task %s (%s) max attempts=%d, want %d", task.Key(), task.Kind(), task.MaxAttempts(), want)
						}
					}
					_, publication := plan.Task("publication")
					if publication != (mode == controlplane.ReviewRunRequired) {
						t.Fatal("publication task presence did not match run mode")
					}
				})
			}
		})
	}
}

func legacyAttemptPlannerIdentity(t *testing.T, mode controlplane.ReviewRunMode, bindings []TaskHandlerBinding) string {
	t.Helper()
	type legacyBinding struct {
		Kind            string `json:"kind"`
		HandlerIdentity string `json:"handler_identity"`
	}
	values := make([]legacyBinding, len(bindings))
	for index, binding := range bindings {
		values[index] = legacyBinding{binding.Kind.String(), binding.HandlerIdentity}
	}
	sort.Slice(values, func(i, j int) bool { return values[i].Kind < values[j].Kind })
	encoded, err := json.Marshal(struct {
		Contract       string          `json:"contract"`
		SchemaVersion  int             `json:"schema_version"`
		Repository     string          `json:"repository"`
		PolicyIdentity string          `json:"policy_identity"`
		Mode           string          `json:"mode"`
		Bindings       []legacyBinding `json:"bindings"`
	}{"open-trestle/github-pull-request-planner", 3, "owner/repository", strings.Repeat("e", 64), mode.String(), values})
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
