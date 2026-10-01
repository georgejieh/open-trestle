package runtimecatalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
)

const (
	maximumLocalDeterministicIntentBytes = 32 << 10
	localDeterministicIntentFreshness    = 5 * time.Minute
)

var (
	ErrInvalidLocalDeterministicReview  = errors.New("invalid local deterministic review")
	ErrLocalDeterministicReviewConflict = errors.New("local deterministic review conflict")
	ErrLocalDeterministicReviewExpired  = errors.New("local deterministic review expired")
)

// LocalDeterministicReviewIntent identifies one provider-free review without carrying filesystem, route, credential, or publication authority.
type LocalDeterministicReviewIntent struct {
	identity   string
	scope      audit.ReviewScope
	repository evidence.RepositoryIdentity
	base, head evidence.RevisionIdentity
	createdAt  time.Time
}

func NewLocalDeterministicReviewIntent(scope audit.ReviewScope, repository evidence.RepositoryIdentity, base, head evidence.RevisionIdentity, createdAt time.Time) (LocalDeterministicReviewIntent, error) {
	createdAt = createdAt.UTC().Truncate(time.Millisecond)
	canonicalRepository, repositoryErr := evidence.NewRepositoryIdentity(repository.Authority(), repository.Namespace(), repository.Name())
	canonicalBase, baseErr := evidence.NewRevisionIdentity(base.Kind(), base.Algorithm(), base.Digest())
	canonicalHead, headErr := evidence.NewRevisionIdentity(head.Kind(), head.Algorithm(), head.Digest())
	validTime := createdAt.UnixMilli() > 0 && createdAt.Year() <= 9999
	if scope.Validate() != nil || repositoryErr != nil || canonicalRepository.Identity() != repository.Identity() || baseErr != nil || canonicalBase != base || headErr != nil || canonicalHead != head || base.Kind() != evidence.RevisionKindGitCommit || head.Kind() != evidence.RevisionKindGitCommit || base.Algorithm() != head.Algorithm() || base.Identity() == head.Identity() || !validTime {
		return LocalDeterministicReviewIntent{}, ErrInvalidLocalDeterministicReview
	}
	intent := LocalDeterministicReviewIntent{scope: scope, repository: repository, base: base, head: head, createdAt: createdAt}
	intent.identity = localDeterministicIntentIdentity(intent)
	return intent, nil
}
func (i LocalDeterministicReviewIntent) Identity() string                        { return i.identity }
func (i LocalDeterministicReviewIntent) Scope() audit.ReviewScope                { return i.scope }
func (i LocalDeterministicReviewIntent) Repository() evidence.RepositoryIdentity { return i.repository }
func (i LocalDeterministicReviewIntent) BaseRevision() evidence.RevisionIdentity { return i.base }
func (i LocalDeterministicReviewIntent) HeadRevision() evidence.RevisionIdentity { return i.head }
func (i LocalDeterministicReviewIntent) CreatedAt() time.Time                    { return i.createdAt }
func (i LocalDeterministicReviewIntent) Validate() error {
	rebuilt, err := NewLocalDeterministicReviewIntent(i.scope, i.repository, i.base, i.head, i.createdAt)
	if err != nil || rebuilt.identity != i.identity {
		return ErrInvalidLocalDeterministicReview
	}
	return nil
}
func (i LocalDeterministicReviewIntent) String() string { return "local deterministic review intent" }
func (i LocalDeterministicReviewIntent) GoString() string {
	return "runtimecatalog.LocalDeterministicReviewIntent{<redacted>}"
}

type localDeterministicIntentWire struct {
	Contract                  string                     `json:"contract"`
	SchemaVersion             int                        `json:"schema_version"`
	Identity                  string                     `json:"identity"`
	TenantID                  string                     `json:"tenant_id"`
	RepositoryID              string                     `json:"repository_id"`
	ReviewRunID               string                     `json:"review_run_id"`
	RepositoryAuthority       string                     `json:"repository_authority"`
	RepositoryNamespace       []string                   `json:"repository_namespace"`
	RepositoryName            string                     `json:"repository_name"`
	RevisionAlgorithm         evidence.RevisionAlgorithm `json:"revision_algorithm"`
	BaseRevisionDigest        string                     `json:"base_revision_digest"`
	HeadRevisionDigest        string                     `json:"head_revision_digest"`
	CreatedAtUnixMilliseconds int64                      `json:"created_at_unix_milliseconds"`
}

func localDeterministicIntentWireValue(i LocalDeterministicReviewIntent) localDeterministicIntentWire {
	return localDeterministicIntentWire{Contract: "open-trestle/local-deterministic-review-intent", SchemaVersion: 1, Identity: i.identity, TenantID: i.scope.TenantID(), RepositoryID: i.scope.RepositoryID(), ReviewRunID: i.scope.ReviewRunID(), RepositoryAuthority: i.repository.Authority(), RepositoryNamespace: i.repository.Namespace(), RepositoryName: i.repository.Name(), RevisionAlgorithm: i.base.Algorithm(), BaseRevisionDigest: i.base.Digest(), HeadRevisionDigest: i.head.Digest(), CreatedAtUnixMilliseconds: i.createdAt.UnixMilli()}
}
func localDeterministicIntentIdentity(i LocalDeterministicReviewIntent) string {
	wire := localDeterministicIntentWireValue(i)
	wire.Identity = ""
	encoded, _ := json.Marshal(wire)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}
func EncodeLocalDeterministicReviewIntent(i LocalDeterministicReviewIntent) ([]byte, error) {
	if i.Validate() != nil {
		return nil, ErrInvalidLocalDeterministicReview
	}
	encoded, err := json.Marshal(localDeterministicIntentWireValue(i))
	if err != nil || len(encoded) > maximumLocalDeterministicIntentBytes {
		return nil, ErrInvalidLocalDeterministicReview
	}
	return encoded, nil
}
func ParseLocalDeterministicReviewIntent(encoded []byte) (LocalDeterministicReviewIntent, error) {
	if len(encoded) == 0 || len(encoded) > maximumLocalDeterministicIntentBytes {
		return LocalDeterministicReviewIntent{}, ErrInvalidLocalDeterministicReview
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var wire localDeterministicIntentWire
	if decoder.Decode(&wire) != nil || decoder.Decode(&struct{}{}) != io.EOF {
		return LocalDeterministicReviewIntent{}, ErrInvalidLocalDeterministicReview
	}
	canonical, _ := json.Marshal(wire)
	if !bytes.Equal(canonical, encoded) || wire.Contract != "open-trestle/local-deterministic-review-intent" || wire.SchemaVersion != 1 {
		return LocalDeterministicReviewIntent{}, ErrInvalidLocalDeterministicReview
	}
	scope, err := audit.NewReviewScope(wire.TenantID, wire.RepositoryID, wire.ReviewRunID)
	if err != nil {
		return LocalDeterministicReviewIntent{}, ErrInvalidLocalDeterministicReview
	}
	repository, err := evidence.NewRepositoryIdentity(wire.RepositoryAuthority, wire.RepositoryNamespace, wire.RepositoryName)
	if err != nil {
		return LocalDeterministicReviewIntent{}, ErrInvalidLocalDeterministicReview
	}
	base, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, wire.RevisionAlgorithm, wire.BaseRevisionDigest)
	if err != nil {
		return LocalDeterministicReviewIntent{}, ErrInvalidLocalDeterministicReview
	}
	head, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, wire.RevisionAlgorithm, wire.HeadRevisionDigest)
	if err != nil {
		return LocalDeterministicReviewIntent{}, ErrInvalidLocalDeterministicReview
	}
	intent, err := NewLocalDeterministicReviewIntent(scope, repository, base, head, time.UnixMilli(wire.CreatedAtUnixMilliseconds))
	if err != nil || intent.identity != wire.Identity {
		return LocalDeterministicReviewIntent{}, ErrInvalidLocalDeterministicReview
	}
	reencoded, _ := EncodeLocalDeterministicReviewIntent(intent)
	if !bytes.Equal(reencoded, encoded) {
		return LocalDeterministicReviewIntent{}, ErrInvalidLocalDeterministicReview
	}
	return intent, nil
}

// LocalDeterministicReviewAdmissionConfig binds daemon-owned source and handler authority.
type LocalDeterministicReviewAdmissionConfig struct {
	Repository           evidence.RepositoryIdentity
	SourceAdapter        evidence.SourceAdapterIdentity
	SourceRootIdentity   string
	ReviewPolicyIdentity string
	Classification       artifact.Classification
	Protection           artifact.Protection
	Retention            time.Duration
	Catalog              PipelineCatalog
}
type LocalDeterministicReviewAdmitter struct {
	coordinator *controlplane.Coordinator
	store       artifact.Store
	config      LocalDeterministicReviewAdmissionConfig
}

func NewLocalDeterministicReviewAdmitter(journal controlplane.RunJournal, store artifact.Store, config LocalDeterministicReviewAdmissionConfig) (*LocalDeterministicReviewAdmitter, error) {
	if nilLocalValue(journal) || nilLocalValue(store) || validateLocalAdmissionConfig(config) != nil {
		return nil, ErrInvalidLocalDeterministicReview
	}
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		return nil, ErrInvalidLocalDeterministicReview
	}
	return &LocalDeterministicReviewAdmitter{coordinator: coordinator, store: store, config: config}, nil
}
func validateLocalAdmissionConfig(c LocalDeterministicReviewAdmissionConfig) error {
	repository, err := evidence.NewRepositoryIdentity(c.Repository.Authority(), c.Repository.Namespace(), c.Repository.Name())
	adapter, adapterErr := evidence.NewSourceAdapterIdentity(c.SourceAdapter.Kind(), c.SourceAdapter.Name(), c.SourceAdapter.Version(), c.SourceAdapter.Capabilities())
	bindings := c.Catalog.Bindings()
	want := []controlplane.TaskKind{controlplane.TaskAcquireSource, controlplane.TaskBuildChange, controlplane.TaskInspectDeterministic}
	validBindings := len(bindings) == len(want)
	for index, binding := range bindings {
		if index >= len(want) || binding.Kind != want[index] {
			validBindings = false
		}
	}
	if err != nil || repository.Identity() != c.Repository.Identity() || adapterErr != nil || adapter.Identity() != c.SourceAdapter.Identity() || controlplane.ValidateHandlerIdentity(c.SourceRootIdentity) != nil || controlplane.ValidateHandlerIdentity(c.ReviewPolicyIdentity) != nil || c.Classification.String() == "" || c.Protection != artifact.ProtectionProcessPrivate || c.Retention < time.Minute || c.Retention > 24*time.Hour || c.Catalog.Validate() != nil || c.Catalog.Mode() != controlplane.ReviewRunLocal || !validBindings {
		return ErrInvalidLocalDeterministicReview
	}
	return nil
}
func (a *LocalDeterministicReviewAdmitter) Admit(ctx context.Context, intent LocalDeterministicReviewIntent, at time.Time) (controlplane.ReviewRunState, error) {
	if a == nil || a.coordinator == nil || nilLocalValue(a.store) || ctx == nil || ctx.Err() != nil || intent.Validate() != nil || validateLocalAdmissionConfig(a.config) != nil {
		return controlplane.ReviewRunState{}, ErrInvalidLocalDeterministicReview
	}
	if intent.Repository().Identity() != a.config.Repository.Identity() {
		return controlplane.ReviewRunState{}, ErrInvalidLocalDeterministicReview
	}
	prepared, err := a.prepare(ctx, intent)
	if err != nil {
		return controlplane.ReviewRunState{}, err
	}
	plan := prepared.Plan()
	existingPlan, _, resumeErr := a.coordinator.Resume(ctx, intent.Scope())
	if resumeErr == nil {
		if existingPlan.Identity() != plan.Identity() {
			return controlplane.ReviewRunState{}, ErrLocalDeterministicReviewConflict
		}
		state, advanceErr := a.coordinator.Advance(ctx, existingPlan, at.UTC())
		if advanceErr != nil {
			return controlplane.ReviewRunState{}, advanceErr
		}
		return state, nil
	}
	if !errors.Is(resumeErr, controlplane.ErrRunNotOpened) {
		return controlplane.ReviewRunState{}, resumeErr
	}
	at = at.UTC()
	if at.Before(intent.CreatedAt()) || at.Sub(intent.CreatedAt()) > localDeterministicIntentFreshness || !intent.CreatedAt().Add(a.config.Retention).After(at) {
		return controlplane.ReviewRunState{}, ErrLocalDeterministicReviewExpired
	}
	for _, input := range prepared.Inputs() {
		if input.Scope().Identity() != intent.Scope().Identity() || !input.ExpiresAt().After(at) {
			return controlplane.ReviewRunState{}, ErrInvalidLocalDeterministicReview
		}
		if _, err := a.store.Put(ctx, input, at); err != nil {
			return controlplane.ReviewRunState{}, err
		}
	}
	state, err := a.coordinator.Open(ctx, plan, at)
	if err == nil {
		state, err = a.coordinator.Advance(ctx, plan, at)
	}
	return state, err
}
func (a *LocalDeterministicReviewAdmitter) prepare(ctx context.Context, intent LocalDeterministicReviewIntent) (PreparedReviewRun, error) {
	request, err := NewPreparedReviewRequest(PreparedReviewRequestOptions{Scope: intent.Scope(), HostRequestIdentity: intent.Identity(), Repository: intent.Repository(), BaseRevision: intent.BaseRevision(), HeadRevision: intent.HeadRevision(), SourceAdapter: a.config.SourceAdapter, SourceRootIdentity: a.config.SourceRootIdentity, ReviewPolicyIdentity: a.config.ReviewPolicyIdentity, Classification: a.config.Classification, Protection: a.config.Protection, CreatedAt: intent.CreatedAt(), Retention: a.config.Retention, Catalog: a.config.Catalog})
	if err != nil {
		return PreparedReviewRun{}, err
	}
	return PrepareReviewRun(ctx, request)
}
func nilLocalValue(value any) bool {
	if value == nil {
		return true
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return reflected.IsNil()
	}
	return false
}
