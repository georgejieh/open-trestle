package runtimecatalog

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

func preparedReviewOptions(t *testing.T) PreparedReviewRequestOptions {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "host-request-a")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("example.test", []string{"team"}, "repository")
	if err != nil {
		t.Fatal(err)
	}
	base, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	if err != nil {
		t.Fatal(err)
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("2", 40))
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "local-git-loose", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
	if err != nil {
		t.Fatal(err)
	}
	kinds := []controlplane.TaskKind{controlplane.TaskAcquireSource, controlplane.TaskBuildChange, controlplane.TaskInspectDeterministic, controlplane.TaskRetrieveContext, controlplane.TaskAssembleContext, controlplane.TaskGenerateCandidates, controlplane.TaskVerifyCandidates, controlplane.TaskEvaluatePublication}
	handlers := make([]controlplane.TaskHandler, len(kinds))
	for i, kind := range kinds {
		handlers[i] = handler{kind, strings.Repeat(string("12345678"[i]), 64)}
	}
	catalog, err := NewPipelineCatalog(controlplane.ReviewRunLocal, handlers)
	if err != nil {
		t.Fatal(err)
	}
	return PreparedReviewRequestOptions{Scope: scope, HostRequestIdentity: strings.Repeat("a", 64), Repository: repository, BaseRevision: base, HeadRevision: head, SourceAdapter: adapter, SourceRootIdentity: strings.Repeat("b", 64), InventoryIdentity: strings.Repeat("c", 64), RuntimePolicyIdentity: strings.Repeat("d", 64), ReviewPolicyIdentity: strings.Repeat("e", 64), Classification: artifact.ClassificationConfidential, Protection: artifact.ProtectionProcessPrivate, CreatedAt: time.UnixMilli(1000), Retention: time.Hour, Catalog: catalog}
}

func TestPreparedReviewCreatesExactHostInputsWithoutForgeAuthority(t *testing.T) {
	options := preparedReviewOptions(t)
	request, err := NewPreparedReviewRequest(options)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := PrepareReviewRun(context.Background(), request)
	if err != nil || prepared.Validate() != nil {
		t.Fatal("host preparation did not produce a valid immutable plan")
	}
	plan, inputs := prepared.Plan(), prepared.Inputs()
	if plan.Mode() != controlplane.ReviewRunLocal || plan.TaskCount() != 9 || len(inputs) != 2 || plan.RequestIdentity() != prepared.RequestIdentity() || plan.PolicyIdentity() != options.ReviewPolicyIdentity || plan.Scope().Identity() != options.Scope.Identity() {
		t.Fatal("prepared plan lost exact local host/policy/scope authority")
	}
	if _, found := plan.Task("publication"); found {
		t.Fatal("local prepared plan gained forge publication authority")
	}
	seenInputs := map[string]bool{}
	for _, input := range inputs {
		value, err := sourcehandler.ParseInput(input.Payload())
		if err != nil || input.Origin() != artifact.OriginHost || input.Protection() != artifact.ProtectionProcessPrivate || input.Classification() != artifact.ClassificationConfidential || input.Scope().Identity() != options.Scope.Identity() || value.Repository().Identity() != options.Repository.Identity() || value.SourceAdapterIdentity() != options.SourceAdapter.Identity() || !input.CreatedAt().Equal(options.CreatedAt) || !input.ExpiresAt().Equal(options.CreatedAt.Add(options.Retention)) {
			t.Fatal("prepared source artifact is not legitimate bound host input")
		}
		key := "source-base"
		if value.Revision().Identity() == options.HeadRevision.Identity() {
			key = "source-head"
		} else if value.Revision().Identity() != options.BaseRevision.Identity() {
			t.Fatal("prepared source uses an unrequested revision")
		}
		if seenInputs[key] {
			t.Fatal("duplicate prepared source revision")
		}
		seenInputs[key] = true
		bound := false
		for _, parent := range input.Provenance() {
			bound = bound || parent == prepared.RequestIdentity()
		}
		if !bound {
			t.Fatal("source input omitted prepared host request provenance")
		}
		task, found := plan.Task(key)
		if !found || task.InputIdentity() != input.Identity() {
			t.Fatal("source task does not use the actual protected input artifact")
		}
	}
	first := inputs[0].Identity()
	inputs[0] = artifact.Artifact{}
	if prepared.Inputs()[0].Identity() != first || prepared.Validate() != nil {
		t.Fatal("caller changed sealed inputs through a returned slice")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := PrepareReviewRun(ctx, request); err == nil {
		t.Fatal("pre-canceled caller obtained a prepared run")
	}
}

func TestPreparedReviewIdentityBindsEveryHostAuthorityField(t *testing.T) {
	options := preparedReviewOptions(t)
	base, err := NewPreparedReviewRequest(options)
	if err != nil {
		t.Fatal(err)
	}
	original, err := PrepareReviewRun(context.Background(), base)
	if err != nil {
		t.Fatal(err)
	}
	changes := map[string]func(*PreparedReviewRequestOptions){
		"scope": func(o *PreparedReviewRequestOptions) {
			o.Scope, _ = audit.NewReviewScope("tenant-b", "repo-a", "host-request-a")
		},
		"host request": func(o *PreparedReviewRequestOptions) { o.HostRequestIdentity = strings.Repeat("f", 64) },
		"repository": func(o *PreparedReviewRequestOptions) {
			o.Repository, _ = evidence.NewRepositoryIdentity("example.test", []string{"other"}, "repository")
		},
		"base": func(o *PreparedReviewRequestOptions) {
			o.BaseRevision, _ = evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("3", 40))
		},
		"head": func(o *PreparedReviewRequestOptions) {
			o.HeadRevision, _ = evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA1, strings.Repeat("4", 40))
		},
		"adapter": func(o *PreparedReviewRequestOptions) {
			o.SourceAdapter, _ = evidence.NewSourceAdapterIdentity(evidence.SourceAdapterKindGit, "other-loose-adapter", "1.0.0", []evidence.SourceAdapterCapability{evidence.SourceCapabilityReadManifest, evidence.SourceCapabilityReadContent})
		},
		"opened root":    func(o *PreparedReviewRequestOptions) { o.SourceRootIdentity = strings.Repeat("f", 64) },
		"inventory":      func(o *PreparedReviewRequestOptions) { o.InventoryIdentity = strings.Repeat("f", 64) },
		"runtime policy": func(o *PreparedReviewRequestOptions) { o.RuntimePolicyIdentity = strings.Repeat("f", 64) },
		"review policy":  func(o *PreparedReviewRequestOptions) { o.ReviewPolicyIdentity = strings.Repeat("f", 64) },
		"classification": func(o *PreparedReviewRequestOptions) { o.Classification = artifact.ClassificationRestricted },
		"time":           func(o *PreparedReviewRequestOptions) { o.CreatedAt = o.CreatedAt.Add(time.Millisecond) },
		"retention":      func(o *PreparedReviewRequestOptions) { o.Retention = 2 * time.Hour },
		"handler catalog": func(o *PreparedReviewRequestOptions) {
			handlers := []controlplane.TaskHandler{}
			for _, binding := range o.Catalog.Bindings() {
				id := binding.HandlerIdentity
				if binding.Kind == controlplane.TaskGenerateCandidates {
					id = strings.Repeat("f", 64)
				}
				handlers = append(handlers, handler{binding.Kind, id})
			}
			o.Catalog, _ = NewPipelineCatalog(controlplane.ReviewRunLocal, handlers)
		},
	}
	for name, mutate := range changes {
		t.Run(name, func(t *testing.T) {
			changed := options
			mutate(&changed)
			request, err := NewPreparedReviewRequest(changed)
			if err != nil {
				t.Fatal(err)
			}
			prepared, err := PrepareReviewRun(context.Background(), request)
			if err != nil || prepared.RequestIdentity() == original.RequestIdentity() || prepared.Plan().Identity() == original.Plan().Identity() {
				t.Fatal("changed host authority retained old executable identity")
			}
		})
	}
}

func TestPreparedReviewRejectsInvalidOrPublicationShapedAuthority(t *testing.T) {
	for _, name := range []string{"zero scope", "zero root", "zero policy", "equal revisions", "short retention", "unbounded retention", "zero catalog", "required catalog", "mixed algorithms", "zero protection"} {
		t.Run(name, func(t *testing.T) {
			o := preparedReviewOptions(t)
			switch name {
			case "zero scope":
				o.Scope = audit.ReviewScope{}
			case "zero root":
				o.SourceRootIdentity = ""
			case "zero policy":
				o.RuntimePolicyIdentity = ""
			case "equal revisions":
				o.HeadRevision = o.BaseRevision
			case "short retention":
				o.Retention = time.Millisecond
			case "unbounded retention":
				o.Retention = 25 * time.Hour
			case "zero protection":
				o.Protection = 0
			case "zero catalog":
				o.Catalog = PipelineCatalog{}
			case "mixed algorithms":
				o.HeadRevision, _ = evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithmSHA256, strings.Repeat("2", 64))
			case "required catalog":
				handlers := []controlplane.TaskHandler{}
				for _, binding := range o.Catalog.Bindings() {
					handlers = append(handlers, handler{binding.Kind, binding.HandlerIdentity})
				}
				handlers = append(handlers, handler{controlplane.TaskPublishResult, strings.Repeat("f", 64)})
				o.Catalog, _ = NewPipelineCatalog(controlplane.ReviewRunRequired, handlers)
			}
			if _, err := NewPreparedReviewRequest(o); err == nil {
				t.Fatal("invalid prepared authority was admitted")
			}
		})
	}
}
