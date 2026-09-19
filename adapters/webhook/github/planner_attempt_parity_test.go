package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/webhook"
)

func attemptParityHash(t *testing.T, value any) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func TestPlannerAttemptExtractionPreservesExactPlanBytes(t *testing.T) {
	payload := `{"action":"synchronize","number":42,"repository":{"full_name":"owner/repository"},"pull_request":{"base":{"sha":"1111111111111111111111111111111111111111","repo":{"full_name":"owner/repository"}},"head":{"sha":"2222222222222222222222222222222222222222","repo":{"full_name":"owner/repository"}}}}`
	for _, mode := range []controlplane.ReviewRunMode{controlplane.ReviewRunLocal, controlplane.ReviewRunAdvisory, controlplane.ReviewRunRequired} {
		for _, prepared := range []bool{false, true} {
			name := mode.String() + "/unprepared"
			if prepared {
				name = mode.String() + "/prepared"
			}
			t.Run(name, func(t *testing.T) {
				bindings := plannerBindings()
				if mode != controlplane.ReviewRunRequired {
					bindings = bindings[:8]
				}
				stored := storedPullRequest(t, payload)
				var plan controlplane.ReviewRunPlan
				var inputs []artifact.Artifact
				var err error
				base, err := NewPullRequestPlanner("owner/repository", strings.Repeat("e", 64), mode, bindings)
				if err != nil {
					t.Fatal(err)
				}
				type bindingWire struct {
					Kind    string `json:"kind"`
					Handler string `json:"handler_identity"`
				}
				wireBindings := make([]bindingWire, len(bindings))
				for i, binding := range bindings {
					wireBindings[i] = bindingWire{binding.Kind.String(), binding.HandlerIdentity}
				}
				sort.Slice(wireBindings, func(i, j int) bool { return wireBindings[i].Kind < wireBindings[j].Kind })
				baseIdentity := attemptParityHash(t, struct {
					Contract   string        `json:"contract"`
					Version    int           `json:"schema_version"`
					Repository string        `json:"repository"`
					Policy     string        `json:"policy_identity"`
					Mode       string        `json:"mode"`
					Bindings   []bindingWire `json:"bindings"`
				}{"open-trestle/github-pull-request-planner", 4, "owner/repository", strings.Repeat("e", 64), mode.String(), wireBindings})
				if base.Identity() != baseIdentity {
					t.Fatal("attempt extraction changed the accepted v4 planner identity")
				}
				if prepared {
					planner, constructionErr := NewBuiltInPreparedPullRequestPlanner("github.com", "owner/repository", strings.Repeat("e", 64), "github-review", mode, bindings, artifact.ClassificationConfidential, artifact.ProtectionProcessPrivate, time.Hour)
					if constructionErr != nil {
						t.Fatal(constructionErr)
					}
					identity := attemptParityHash(t, struct {
						Contract       string `json:"contract"`
						Version        int    `json:"schema_version"`
						Base           string `json:"base"`
						Authority      string `json:"authority"`
						Publisher      string `json:"publisher"`
						Adapter        string `json:"adapter"`
						Classification string `json:"classification"`
						Protection     string `json:"protection"`
						Retention      int64  `json:"retention"`
					}{"open-trestle/prepared-github-pull-request-planner", 1, baseIdentity, "github.com", "github-review", planner.sourceAdapter.Identity(), "confidential", "process_private", time.Hour.Milliseconds()})
					if planner.Identity() != identity {
						t.Fatal("attempt extraction changed the accepted prepared planner identity")
					}
					plan, inputs, err = planner.Prepare(context.Background(), stored)
				} else {
					plan, err = base.Plan(context.Background(), stored)
				}
				if err != nil {
					t.Fatal(err)
				}
				want := attemptParityPlan(t, mode, prepared, bindings, stored, inputs)
				actualBytes, err := controlplane.EncodeReviewRunPlan(plan)
				if err != nil {
					t.Fatal(err)
				}
				expectedBytes, err := controlplane.EncodeReviewRunPlan(want)
				if err != nil {
					t.Fatal(err)
				}
				if plan.Identity() != want.Identity() || !bytes.Equal(actualBytes, expectedBytes) {
					t.Fatal("attempt extraction changed accepted task, plan identity, or canonical plan bytes")
				}
			})
		}
	}
}

func attemptParityPlan(t *testing.T, mode controlplane.ReviewRunMode, prepared bool, bindings []TaskHandlerBinding, stored webhook.StoredDelivery, inputs []artifact.Artifact) controlplane.ReviewRunPlan {
	t.Helper()
	type spec struct {
		key  string
		kind controlplane.TaskKind
		deps []string
	}
	specs := []spec{{"source", controlplane.TaskAcquireSource, nil}}
	changeDeps := []string{"source"}
	if prepared {
		specs = []spec{{"source-base", controlplane.TaskAcquireSource, nil}, {"source-head", controlplane.TaskAcquireSource, nil}}
		changeDeps = []string{"source-base", "source-head"}
	}
	specs = append(specs, []spec{
		{"change", controlplane.TaskBuildChange, changeDeps},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}},
		{"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}},
		{"candidates", controlplane.TaskGenerateCandidates, []string{"context"}},
		{"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}},
		{"readiness", controlplane.TaskEvaluatePublication, []string{"analysis", "change", "verification"}},
	}...)
	if mode == controlplane.ReviewRunRequired {
		specs = append(specs, spec{"publication", controlplane.TaskPublishResult, []string{"readiness"}})
	}
	rootInputs := map[string]string{}
	for _, input := range inputs {
		source, err := sourcehandler.ParseInput(input.Payload())
		if err != nil {
			rootInputs["publication"] = input.Identity()
			continue
		}
		key := "source-head"
		if source.Revision().Digest() == strings.Repeat("1", 40) {
			key = "source-base"
		}
		rootInputs[key] = input.Identity()
	}
	handlers := map[controlplane.TaskKind]string{}
	for _, binding := range bindings {
		handlers[binding.Kind] = binding.HandlerIdentity
	}
	identities := map[string]string{}
	tasks := []controlplane.TaskDefinition{}
	for _, spec := range specs {
		dependencies := make([]string, len(spec.deps))
		for i, key := range spec.deps {
			dependencies[i] = identities[key]
		}
		input := attemptParityHash(t, struct {
			Delivery     string   `json:"delivery_identity"`
			Payload      string   `json:"payload_digest"`
			Repository   string   `json:"repository"`
			Number       int64    `json:"number"`
			Base         string   `json:"base"`
			Head         string   `json:"head"`
			Kind         string   `json:"kind"`
			Dependencies []string `json:"dependencies"`
		}{stored.Delivery().Identity(), stored.Delivery().BodyDigest(), "owner/repository", 42, strings.Repeat("1", 40), strings.Repeat("2", 40), spec.kind.String(), dependencies})
		if prepared && (spec.key == "source-base" || spec.key == "source-head" || spec.key == "publication") {
			input = rootInputs[spec.key]
			if input == "" {
				t.Fatal("missing prepared root input")
			}
		}
		attempts := uint8(3)
		switch spec.kind {
		case controlplane.TaskAssembleContext, controlplane.TaskGenerateCandidates, controlplane.TaskVerifyCandidates, controlplane.TaskPublishResult:
			attempts = 1
		}
		task, err := controlplane.NewTaskDefinition(spec.key, spec.kind, input, handlers[spec.kind], spec.deps, attempts, 1000, 30000, true)
		if err != nil {
			t.Fatal(err)
		}
		identities[spec.key] = task.Identity()
		tasks = append(tasks, task)
	}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", webhook.ReviewRunIDForDelivery(stored.Delivery()))
	if err != nil {
		t.Fatal(err)
	}
	plan, err := controlplane.NewReviewRunPlan(scope, stored.Delivery().Identity(), strings.Repeat("e", 64), mode, tasks)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}
