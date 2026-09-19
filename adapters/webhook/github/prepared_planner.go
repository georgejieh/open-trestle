package github

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strconv"
	"strings"
	"time"

	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/controlplane"
	publicationhandler "github.com/georgejieh/open-trestle/handlers/publication"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/webhook"
)

const DefaultGitHubPublisherID = "github-review"

// PreparedPullRequestPlanner creates a two-revision executable source boundary.
type PreparedPullRequestPlanner struct {
	identity, repositoryAuthority, publisherID string
	base                                       *PullRequestPlanner
	sourceAdapter                              evidence.SourceAdapterIdentity
	classification                             artifact.Classification
	protection                                 artifact.Protection
	retention                                  time.Duration
}

func NewBuiltInPreparedPullRequestPlanner(repositoryAuthority, repositoryFullName, policyIdentity, publisherID string, mode controlplane.ReviewRunMode, bindings []TaskHandlerBinding, classification artifact.Classification, protection artifact.Protection, retention time.Duration) (*PreparedPullRequestPlanner, error) {
	adapter, err := githubsource.SourceAdapterIdentity()
	if err != nil {
		return nil, ErrInvalidPullRequestPlanner
	}
	return NewPreparedPullRequestPlanner(repositoryAuthority, repositoryFullName, policyIdentity, publisherID, mode, bindings, adapter, classification, protection, retention)
}

func NewPreparedPullRequestPlanner(repositoryAuthority, repositoryFullName, policyIdentity, publisherID string, mode controlplane.ReviewRunMode, bindings []TaskHandlerBinding, sourceAdapter evidence.SourceAdapterIdentity, classification artifact.Classification, protection artifact.Protection, retention time.Duration) (*PreparedPullRequestPlanner, error) {
	base, err := NewPullRequestPlanner(repositoryFullName, policyIdentity, mode, bindings)
	canonical, adapterErr := evidence.NewSourceAdapterIdentity(sourceAdapter.Kind(), sourceAdapter.Name(), sourceAdapter.Version(), sourceAdapter.Capabilities())
	repository, repositoryErr := evidence.NewRepositoryIdentity(repositoryAuthority, []string{"owner"}, "repository")
	validRetention := retention >= time.Minute && retention <= 10*365*24*time.Hour && retention%time.Millisecond == 0
	if err != nil || adapterErr != nil || canonical.Identity() != sourceAdapter.Identity() || !canonical.HasCapability(evidence.SourceCapabilityReadManifest) || !canonical.HasCapability(evidence.SourceCapabilityReadContent) || repositoryErr != nil || repository.Authority() != repositoryAuthority || review.ValidatePublisherID(publisherID) != nil || classification.String() == "" || protection.String() == "" || !validRetention {
		return nil, ErrInvalidPullRequestPlanner
	}
	planner := &PreparedPullRequestPlanner{repositoryAuthority: strings.Clone(repositoryAuthority), publisherID: strings.Clone(publisherID), base: base, sourceAdapter: canonical, classification: classification, protection: protection, retention: retention}
	planner.identity = derivePreparedPlannerIdentity(planner)
	return planner, nil
}
func (p *PreparedPullRequestPlanner) Identity() string {
	if p == nil {
		return ""
	}
	return p.identity
}
func (p *PreparedPullRequestPlanner) Prepare(ctx context.Context, stored webhook.StoredDelivery) (controlplane.ReviewRunPlan, []artifact.Artifact, error) {
	if p == nil || p.base == nil || p.identity != derivePreparedPlannerIdentity(p) {
		return controlplane.ReviewRunPlan{}, nil, ErrInvalidPullRequestPlanner
	}
	scope, payload, err := p.base.parseDelivery(ctx, stored)
	if err != nil {
		return controlplane.ReviewRunPlan{}, nil, err
	}
	fullName := strings.Split(p.base.repositoryFullName, "/")
	repository, err := evidence.NewRepositoryIdentity(p.repositoryAuthority, []string{fullName[0]}, fullName[1])
	if err != nil {
		return controlplane.ReviewRunPlan{}, nil, ErrInvalidPullRequestPayload
	}
	baseRevision, err := plannerRevision(payload.PullRequest.Base.SHA)
	if err != nil {
		return controlplane.ReviewRunPlan{}, nil, err
	}
	headRevision, err := plannerRevision(payload.PullRequest.Head.SHA)
	if err != nil {
		return controlplane.ReviewRunPlan{}, nil, err
	}
	created := stored.Receipt().AcceptedAt()
	expires := created.Add(p.retention)
	baseInput, _ := sourcehandler.NewInput(repository, baseRevision, p.sourceAdapter)
	headInput, _ := sourcehandler.NewInput(repository, headRevision, p.sourceAdapter)
	baseArtifact, err := sourcehandler.NewInputArtifact(scope, baseInput, p.classification, p.protection, []string{stored.Delivery().Identity()}, created, expires)
	if err != nil {
		return controlplane.ReviewRunPlan{}, nil, err
	}
	headArtifact, err := sourcehandler.NewInputArtifact(scope, headInput, p.classification, p.protection, []string{stored.Delivery().Identity()}, created, expires)
	if err != nil {
		return controlplane.ReviewRunPlan{}, nil, err
	}
	publicationInputIdentity := ""
	inputs := []artifact.Artifact{baseArtifact, headArtifact}
	if p.base.mode == controlplane.ReviewRunRequired {
		publicationInput, inputErr := publicationhandler.NewInput(p.publisherID, repository, strconv.FormatInt(payload.Number, 10), headRevision)
		if inputErr != nil {
			return controlplane.ReviewRunPlan{}, nil, inputErr
		}
		publicationArtifact, artifactErr := publicationhandler.NewInputArtifact(scope, publicationInput, p.classification, p.protection, []string{stored.Delivery().Identity()}, created, expires)
		if artifactErr != nil {
			return controlplane.ReviewRunPlan{}, nil, artifactErr
		}
		publicationInputIdentity = publicationArtifact.Identity()
		inputs = append(inputs, publicationArtifact)
	}
	tasks, err := p.tasks(stored.Delivery(), payload.Number, payload.PullRequest.Base.SHA, payload.PullRequest.Head.SHA, baseArtifact.Identity(), headArtifact.Identity(), publicationInputIdentity)
	if err != nil {
		return controlplane.ReviewRunPlan{}, nil, err
	}
	plan, err := controlplane.NewReviewRunPlan(scope, stored.Delivery().Identity(), p.base.policyIdentity, p.base.mode, tasks)
	if err != nil {
		return controlplane.ReviewRunPlan{}, nil, err
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Identity() < inputs[j].Identity() })
	return plan, inputs, nil
}
func (p *PreparedPullRequestPlanner) tasks(delivery webhook.VerifiedDelivery, number int64, base, head, baseInput, headInput, publicationInput string) ([]controlplane.TaskDefinition, error) {
	specs := []taskSpecification{{"source-base", controlplane.TaskAcquireSource, nil}, {"source-head", controlplane.TaskAcquireSource, nil}, {"change", controlplane.TaskBuildChange, []string{"source-base", "source-head"}}, {"analysis", controlplane.TaskInspectDeterministic, []string{"change"}}, {"memory", controlplane.TaskRetrieveContext, []string{"change"}}, {"context", controlplane.TaskAssembleContext, []string{"analysis", "memory"}}, {"candidates", controlplane.TaskGenerateCandidates, []string{"context"}}, {"verification", controlplane.TaskVerifyCandidates, []string{"candidates"}}, {"readiness", controlplane.TaskEvaluatePublication, []string{"analysis", "change", "verification"}}}
	if p.base.mode == controlplane.ReviewRunRequired {
		specs = append(specs, taskSpecification{"publication", controlplane.TaskPublishResult, []string{"readiness"}})
	}
	identities := make(map[string]string, len(specs))
	tasks := make([]controlplane.TaskDefinition, 0, len(specs))
	for _, spec := range specs {
		dependencyIdentities := make([]string, len(spec.dependencies))
		for index, key := range spec.dependencies {
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
		}{delivery.Identity(), delivery.BodyDigest(), p.base.repositoryFullName, number, base, head, spec.kind.String(), dependencyIdentities})
		if spec.key == "source-base" {
			inputIdentity = baseInput
		} else if spec.key == "source-head" {
			inputIdentity = headInput
		} else if spec.key == "publication" {
			inputIdentity = publicationInput
		}
		attempt, err := controlplane.DefaultTaskAttemptPolicy(spec.kind)
		if err != nil {
			return nil, err
		}
		task, err := controlplane.NewTaskDefinition(spec.key, spec.kind, inputIdentity, p.base.handlers[spec.kind], spec.dependencies, attempt.MaximumAttempts(), attempt.RetryDelayMilliseconds(), attempt.LeaseDurationMilliseconds(), true)
		if err != nil {
			return nil, err
		}
		identities[spec.key] = task.Identity()
		tasks = append(tasks, task)
	}
	return tasks, nil
}
func plannerRevision(value string) (evidence.RevisionIdentity, error) {
	algorithm := evidence.RevisionAlgorithmSHA1
	if len(value) == 64 {
		algorithm = evidence.RevisionAlgorithmSHA256
	}
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, algorithm, value)
	if err != nil {
		return evidence.RevisionIdentity{}, ErrInvalidPullRequestPayload
	}
	return revision, nil
}
func derivePreparedPlannerIdentity(p *PreparedPullRequestPlanner) string {
	if p == nil || p.base == nil {
		return ""
	}
	encoded, _ := json.Marshal(struct {
		Contract       string `json:"contract"`
		SchemaVersion  int    `json:"schema_version"`
		Base           string `json:"base"`
		Authority      string `json:"authority"`
		Publisher      string `json:"publisher"`
		Adapter        string `json:"adapter"`
		Classification string `json:"classification"`
		Protection     string `json:"protection"`
		Retention      int64  `json:"retention"`
	}{"open-trestle/prepared-github-pull-request-planner", 1, p.base.Identity(), p.repositoryAuthority, p.publisherID, p.sourceAdapter.Identity(), p.classification.String(), p.protection.String(), p.retention.Milliseconds()})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func (p *PreparedPullRequestPlanner) String() string { return "prepared GitHub pull request planner" }
