package github

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/webhook"
	"io"
	"sort"
	"strings"
)

var (
	// ErrInvalidPullRequestPlanner identifies missing repository, policy, mode, or handler bindings.
	ErrInvalidPullRequestPlanner = errors.New("invalid GitHub pull request planner")
	// ErrInvalidPullRequestPayload identifies ambiguous, incomplete, or cross-repository data.
	ErrInvalidPullRequestPayload = errors.New("invalid GitHub pull request payload")
)

// TaskHandlerBinding selects one exact implementation for a review task kind.
type TaskHandlerBinding struct {
	Kind            controlplane.TaskKind
	HandlerIdentity string
}

// PullRequestPlanner creates a deterministic run graph without trusting conversational state.
type PullRequestPlanner struct {
	identity, repositoryFullName, policyIdentity string
	mode                                         controlplane.ReviewRunMode
	handlers                                     map[controlplane.TaskKind]string
}

func NewPullRequestPlanner(repositoryFullName, policyIdentity string, mode controlplane.ReviewRunMode, bindings []TaskHandlerBinding) (*PullRequestPlanner, error) {
	if !validRepositoryFullName(repositoryFullName) || !validDigest(policyIdentity) || mode.Validate() != nil {
		return nil, ErrInvalidPullRequestPlanner
	}
	required := []controlplane.TaskKind{controlplane.TaskAcquireSource, controlplane.TaskBuildChange, controlplane.TaskInspectDeterministic, controlplane.TaskRetrieveContext, controlplane.TaskAssembleContext, controlplane.TaskGenerateCandidates, controlplane.TaskVerifyCandidates, controlplane.TaskEvaluatePublication}
	if mode == controlplane.ReviewRunRequired {
		required = append(required, controlplane.TaskPublishResult)
	}
	if len(bindings) != len(required) {
		return nil, ErrInvalidPullRequestPlanner
	}
	handlers := make(map[controlplane.TaskKind]string, len(bindings))
	for _, binding := range bindings {
		if binding.Kind.Validate() != nil || controlplane.ValidateHandlerIdentity(binding.HandlerIdentity) != nil {
			return nil, ErrInvalidPullRequestPlanner
		}
		if _, exists := handlers[binding.Kind]; exists {
			return nil, ErrInvalidPullRequestPlanner
		}
		handlers[binding.Kind] = binding.HandlerIdentity
	}
	for _, kind := range required {
		if handlers[kind] == "" {
			return nil, ErrInvalidPullRequestPlanner
		}
	}
	planner := &PullRequestPlanner{repositoryFullName: repositoryFullName, policyIdentity: policyIdentity, mode: mode, handlers: handlers}
	planner.identity = derivePlannerIdentity(planner)
	return planner, nil
}
func (p *PullRequestPlanner) Identity() string {
	if p == nil {
		return ""
	}
	return p.identity
}
func (p *PullRequestPlanner) Plan(ctx context.Context, stored webhook.StoredDelivery) (controlplane.ReviewRunPlan, error) {
	scope, payload, err := p.parseDelivery(ctx, stored)
	if err != nil {
		return controlplane.ReviewRunPlan{}, err
	}
	tasks, err := p.tasks(stored.Delivery(), payload.Number, payload.PullRequest.Base.SHA, payload.PullRequest.Head.SHA)
	if err != nil {
		return controlplane.ReviewRunPlan{}, err
	}
	return controlplane.NewReviewRunPlan(scope, stored.Delivery().Identity(), p.policyIdentity, p.mode, tasks)
}
func (p *PullRequestPlanner) parseDelivery(ctx context.Context, stored webhook.StoredDelivery) (audit.ReviewScope, pullRequestPayload, error) {
	if p == nil || ctx == nil || ctx.Err() != nil || stored.Validate() != nil {
		return audit.ReviewScope{}, pullRequestPayload{}, ErrInvalidPullRequestPayload
	}
	delivery := stored.Delivery()
	if delivery.Source() != webhook.SourceGitHub || delivery.EventType() != "pull_request" || !allowedPullRequestAction(delivery.Action()) {
		return audit.ReviewScope{}, pullRequestPayload{}, ErrInvalidPullRequestPayload
	}
	var payload pullRequestPayload
	if rejectDuplicateJSONKeys(delivery.Payload()) != nil || json.Unmarshal(delivery.Payload(), &payload) != nil {
		return audit.ReviewScope{}, pullRequestPayload{}, ErrInvalidPullRequestPayload
	}
	base, head := payload.PullRequest.Base.SHA, payload.PullRequest.Head.SHA
	matchingEvent := payload.Action == delivery.Action() && payload.Number > 0
	matchingRepository := strings.ToLower(payload.Repository.FullName) == p.repositoryFullName
	exactSourceRepositories := strings.ToLower(payload.PullRequest.Base.Repository.FullName) == p.repositoryFullName && strings.ToLower(payload.PullRequest.Head.Repository.FullName) == p.repositoryFullName
	if !matchingEvent || !matchingRepository || !exactSourceRepositories || !validGitObjectID(base) || !validGitObjectID(head) || base == head {
		return audit.ReviewScope{}, pullRequestPayload{}, ErrInvalidPullRequestPayload
	}
	scope, err := audit.NewReviewScope(delivery.Scope().TenantID(), delivery.Scope().RepositoryID(), webhook.ReviewRunIDForDelivery(delivery))
	if err != nil {
		return audit.ReviewScope{}, pullRequestPayload{}, ErrInvalidPullRequestPayload
	}
	return scope, payload, nil
}

func (p *PullRequestPlanner) tasks(delivery webhook.VerifiedDelivery, number int64, base, head string) ([]controlplane.TaskDefinition, error) {
	specifications := []taskSpecification{
		{"source", controlplane.TaskAcquireSource, nil},
		{"change", controlplane.TaskBuildChange, []string{"source"}},
		{"analysis", controlplane.TaskInspectDeterministic, []string{"change"}},
		{"memory", controlplane.TaskRetrieveContext, []string{"change"}},
		{"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}},
		{"candidates", controlplane.TaskGenerateCandidates, []string{"context"}},
		{"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}},
		{"readiness", controlplane.TaskEvaluatePublication, []string{"analysis", "change", "verification"}},
	}
	if p.mode == controlplane.ReviewRunRequired {
		specifications = append(specifications, taskSpecification{"publication", controlplane.TaskPublishResult, []string{"readiness"}})
	}
	identities := make(map[string]string, len(specifications))
	tasks := make([]controlplane.TaskDefinition, 0, len(specifications))
	for _, specification := range specifications {
		dependencyIdentities := make([]string, len(specification.dependencies))
		for index, key := range specification.dependencies {
			dependencyIdentities[index] = identities[key]
		}
		inputIdentity := hashPlannerValue(struct {
			DeliveryIdentity string   `json:"delivery_identity"`
			PayloadDigest    string   `json:"payload_digest"`
			Repository       string   `json:"repository"`
			Number           int64    `json:"number"`
			Base             string   `json:"base"`
			Head             string   `json:"head"`
			Kind             string   `json:"kind"`
			Dependencies     []string `json:"dependencies"`
		}{delivery.Identity(), delivery.BodyDigest(), p.repositoryFullName, number, base, head, specification.kind.String(), dependencyIdentities})
		attempt, err := controlplane.DefaultTaskAttemptPolicy(specification.kind)
		if err != nil {
			return nil, err
		}
		task, err := controlplane.NewTaskDefinition(specification.key, specification.kind, inputIdentity, p.handlers[specification.kind], specification.dependencies, attempt.MaximumAttempts(), attempt.RetryDelayMilliseconds(), attempt.LeaseDurationMilliseconds(), true)
		if err != nil {
			return nil, err
		}
		identities[specification.key] = task.Identity()
		tasks = append(tasks, task)
	}
	return tasks, nil
}

type taskSpecification struct {
	key          string
	kind         controlplane.TaskKind
	dependencies []string
}
type pullRequestPayload struct {
	Action     string `json:"action"`
	Number     int64  `json:"number"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	PullRequest struct {
		Base struct {
			SHA        string `json:"sha"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"base"`
		Head struct {
			SHA        string `json:"sha"`
			Repository struct {
				FullName string `json:"full_name"`
			} `json:"repo"`
		} `json:"head"`
	} `json:"pull_request"`
}

func allowedPullRequestAction(action string) bool {
	switch action {
	case "opened", "reopened", "synchronize", "ready_for_review":
		return true
	default:
		return false
	}
}
func validRepositoryFullName(value string) bool {
	if value != strings.ToLower(value) || len(value) < 3 || len(value) > 141 {
		return false
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return false
	}
	for _, part := range parts {
		for _, candidate := range part {
			if candidate >= 'a' && candidate <= 'z' || candidate >= '0' && candidate <= '9' || candidate == '.' || candidate == '_' || candidate == '-' {
				continue
			}
			return false
		}
	}
	return true
}
func validGitObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || hex.EncodeToString(decoded) != value {
		return false
	}
	nonzero := byte(0)
	for _, candidate := range decoded {
		nonzero |= candidate
	}
	return nonzero != 0
}
func derivePlannerIdentity(planner *PullRequestPlanner) string {
	type bindingRecord struct {
		Kind            string `json:"kind"`
		HandlerIdentity string `json:"handler_identity"`
	}
	bindings := make([]bindingRecord, 0, len(planner.handlers))
	for kind, identity := range planner.handlers {
		bindings = append(bindings, bindingRecord{Kind: kind.String(), HandlerIdentity: identity})
	}
	sort.Slice(bindings, func(i, j int) bool { return bindings[i].Kind < bindings[j].Kind })
	return hashPlannerValue(struct {
		Contract       string          `json:"contract"`
		SchemaVersion  int             `json:"schema_version"`
		Repository     string          `json:"repository"`
		PolicyIdentity string          `json:"policy_identity"`
		Mode           string          `json:"mode"`
		Bindings       []bindingRecord `json:"bindings"`
	}{"open-trestle/github-pull-request-planner", 4, planner.repositoryFullName, planner.policyIdentity, planner.mode.String(), bindings})
}
func hashPlannerValue(value any) string {
	encoded, _ := json.Marshal(value)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func rejectDuplicateJSONKeys(encoded []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := consumeJSONValue(decoder); err != nil {
		return ErrInvalidPullRequestPayload
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return ErrInvalidPullRequestPayload
	}
	return nil
}
func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return ErrInvalidPullRequestPayload
			}
			if _, exists := seen[key]; exists {
				return ErrInvalidPullRequestPayload
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return ErrInvalidPullRequestPayload
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return ErrInvalidPullRequestPayload
		}
	default:
		return ErrInvalidPullRequestPayload
	}
	return nil
}
