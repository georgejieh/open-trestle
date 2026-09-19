// Package localreview owns explicitly requested, process-private local model reviews.
// It has no forge publisher, head resolver, effect authority, or resume service.
package localreview

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	publicationhandler "github.com/georgejieh/open-trestle/handlers/publication"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/evidence"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	"github.com/georgejieh/open-trestle/internal/provider"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"github.com/georgejieh/open-trestle/worker"
	"io"
	"os"
	"reflect"
	"sync"
	"time"
)

type Egress string

const (
	EgressLocalOnly      Egress = "local-only"
	EgressPolicyApproved Egress = "policy-approved"
)

var (
	// ErrUnsupportedSource identifies unsupported or unsafe local object storage.
	ErrUnsupportedSource      = errors.New("unsupported local Git object storage")
	ErrInvalidSession         = errors.New("invalid local review session")
	ErrReviewRunAlreadyExists = errors.New("local review scope already admitted")
	ErrSessionBusy            = errors.New("local review session busy")
	ErrPreparedReviewMismatch = errors.New("prepared review does not belong to this session")
	ErrSessionClosed          = errors.New("local review session closed")
)

type SessionOptions struct {
	TenantID, RepositoryID              string
	Repository                          evidence.RepositoryIdentity
	ObjectsRoot                         *os.Root
	ObjectStoreProfile                  scm.LocalGitObjectStoreProfile
	ObjectAlgorithm                     evidence.RevisionAlgorithm
	Inventory                           runtimeconfig.RouteInventory
	Policy                              runtimeconfig.RuntimePolicy
	Egress                              Egress
	Credentials                         runtimecatalog.OpenAICredentialResolver
	Clock                               artifact.Clock
	Timeout, RenewalInterval, Retention time.Duration
	ArtifactCapacity                    int
	RetainedMemoryInput                 *runtimeconfig.RetainedMemoryInput
}
type Session struct {
	mu                               sync.Mutex
	options                          SessionOptions
	rootID                           string
	adapter                          evidence.SourceAdapterIdentity
	objectStore                      *scm.LocalGitObjectStore
	classification                   artifact.Classification
	catalog                          runtimecatalog.PipelineCatalog
	store                            artifact.Store
	diagnostics                      diagnostics.Store
	ledger                           audit.Ledger
	journal                          controlplane.RunJournal
	coordinator                      *controlplane.Coordinator
	finalizer                        *controlplane.RunFinalizer
	issued                           map[string]bool
	admitted                         map[string]bool
	cancel                           context.CancelFunc
	done                             chan struct{}
	runner                           *worker.Runner
	active, blocked, closing, closed bool
	closeErr                         error
	investigation                    *investigationSession
	activeInvestigation              *modelhandler.InvestigationPipeline
	lastInvestigationResult          Result
}

// NewSession transfers root ownership only on success and never starts work.
func NewSession(o SessionOptions) (*Session, error) {
	return newSession(o, nil)
}

func newSession(o SessionOptions, investigationPolicy *review.InvestigationPolicy) (*Session, error) {
	if o.RetainedMemoryInput != nil && (investigationPolicy != nil || o.Egress != EgressLocalOnly) {
		return nil, ErrInvalidSession
	}
	if _, err := audit.NewReviewScope(o.TenantID, o.RepositoryID, "session-validation"); err != nil {
		return nil, ErrInvalidSession
	}
	if o.ObjectsRoot == nil || nilValue(o.Clock) || nilValue(o.Credentials) || o.Timeout < time.Second || o.Timeout > 15*time.Minute || o.Inventory.Validate() != nil || o.Policy.ValidateAgainstInventory(o.Inventory) != nil || (o.Egress != EgressLocalOnly && o.Egress != EgressPolicyApproved) {
		return nil, ErrInvalidSession
	}
	if o.ObjectStoreProfile == "" {
		o.ObjectStoreProfile = scm.LocalGitObjectStoreProfileLooseOnly
	}
	if o.ObjectStoreProfile == scm.LocalGitObjectStoreProfileLooseAndPackIndexV1 {
		if o.ObjectAlgorithm != evidence.RevisionAlgorithmSHA1 && o.ObjectAlgorithm != evidence.RevisionAlgorithmSHA256 {
			return nil, ErrInvalidSession
		}
	} else if o.ObjectStoreProfile != scm.LocalGitObjectStoreProfileLooseOnly {
		return nil, ErrInvalidSession
	}
	if o.RenewalInterval == 0 {
		o.RenewalInterval = 10 * time.Second
	}
	if o.RenewalInterval < 10*time.Millisecond || o.RenewalInterval > 10*time.Second {
		return nil, ErrInvalidSession
	}
	if o.Retention == 0 {
		o.Retention = time.Hour
	}
	if o.Retention < time.Minute || o.Retention > 24*time.Hour || o.Retention <= o.Timeout {
		return nil, ErrInvalidSession
	}
	if o.ArtifactCapacity == 0 {
		o.ArtifactCapacity = 4096
	}
	if o.ArtifactCapacity < 1 || o.ArtifactCapacity > 16384 {
		return nil, ErrInvalidSession
	}
	classification := artifact.Classification(0)
	for _, candidate := range []artifact.Classification{artifact.ClassificationPublic, artifact.ClassificationInternal, artifact.ClassificationConfidential, artifact.ClassificationRestricted} {
		if candidate.String() == string(o.Policy.Constraints().Classification()) {
			classification = candidate
		}
	}
	if classification == 0 || o.Clock.Now().UnixMilli() <= 0 {
		return nil, ErrInvalidSession
	}
	if investigationPolicy != nil && validateInvestigationSessionPolicy(o, *investigationPolicy) != nil {
		return nil, ErrInvalidSession
	}
	var objects *scm.LocalGitObjectStore
	var err error
	if o.ObjectStoreProfile == scm.LocalGitObjectStoreProfileLooseAndPackIndexV1 {
		if err := scm.ValidateLocalGitPackedLayout(o.ObjectsRoot); err != nil {
			return nil, ErrUnsupportedSource
		}
		objects, err = scm.NewLocalGitObjectStoreWithOptions(scm.LocalGitObjectStoreOptions{ObjectsRoot: o.ObjectsRoot, Repository: o.Repository, Profile: o.ObjectStoreProfile, ObjectAlgorithm: o.ObjectAlgorithm})
		if err != nil {
			return nil, ErrInvalidSession
		}
	} else {
		objects, err = scm.NewLocalGitObjectStore(o.ObjectsRoot, o.Repository)
		if err != nil {
			return nil, ErrInvalidSession
		}
		if err := validateLocalObjectLayout(o.ObjectsRoot); err != nil {
			return nil, err
		}
	}
	constructed := false
	defer func() {
		if !constructed {
			_ = objects.Close(context.Background())
		}
	}()
	var source *scm.LocalGitSourceAdapter
	if o.ObjectStoreProfile == scm.LocalGitObjectStoreProfileLooseAndPackIndexV1 {
		source, err = scm.NewLocalGitPackedSourceAdapter(objects)
	} else {
		source, err = scm.NewLocalGitSourceAdapter(objects)
	}
	if err != nil {
		return nil, ErrInvalidSession
	}
	// Validate the complete local egress posture before resolving any credentials.
	if o.Egress == EgressLocalOnly {
		for _, candidate := range o.Inventory.Candidates() {
			if candidate.ResolvedRecord().RouteRegistryRecord().RouteCandidateDeclaration().RouteCapabilityDeclaration().RouteReference().Zone() != provider.ProviderZoneLocal {
				return nil, ErrInvalidSession
			}
		}
		for _, connection := range o.Policy.Connections() {
			locality, err := provider.ClassifyServiceEndpoint(connection.Endpoint())
			if err != nil || locality != provider.ServiceEndpointLoopback {
				return nil, ErrInvalidSession
			}
		}
	}
	var retainedRetriever *retainedMemoryRetriever
	if o.RetainedMemoryInput != nil {
		// The loader value is immutable; the caller's pointer is not Session authority.
		input := *o.RetainedMemoryInput
		o.RetainedMemoryInput = &input
		if validateRetainedMemory(o, input.Scope().RefSetIdentity(), o.Clock.Now()) != nil {
			return nil, ErrInvalidSession
		}
		retainedRetriever, err = newRetainedMemoryRetriever(input)
		if err != nil {
			return nil, ErrInvalidSession
		}
	}
	factory := runtimecatalog.NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy
	if o.Egress == EgressPolicyApproved {
		factory = runtimecatalog.NewOpenAIRouteDispatcherCatalogFromRuntimePolicy
	}
	dispatchers, err := factory(o.Inventory, o.Policy, o.Credentials)
	if err != nil {
		return nil, ErrInvalidSession
	}
	store, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, o.ArtifactCapacity)
	if err != nil {
		return nil, ErrInvalidSession
	}
	ledger := audit.NewMemoryLedger()
	diagnosticStore := diagnostics.NewMemoryStore()
	var catalog runtimecatalog.PipelineCatalog
	if investigationPolicy == nil {
		generationAuthority, err := runtimecatalog.NewGenerationPolicyAuthorizerFromRuntimePolicy(o.Policy, o.Inventory, ledger)
		if err != nil {
			return nil, ErrInvalidSession
		}
		verificationInventory, err := runtimecatalog.NewStaticVerificationRouteInventory(o.Inventory)
		if err != nil {
			return nil, ErrInvalidSession
		}
		verificationAuthority, err := runtimecatalog.NewVerificationPolicyAuthorizerFromRuntimePolicy(o.Policy, verificationInventory, ledger, o.Clock)
		if err != nil {
			return nil, ErrInvalidSession
		}
		sourceHandler, err := sourcehandler.NewHandler(store, source, o.Clock)
		if err != nil {
			return nil, ErrInvalidSession
		}
		change, err := changehandler.NewHandler(store, o.Clock)
		if err != nil {
			return nil, ErrInvalidSession
		}
		analysis, err := analysishandler.NewHandler(store, o.Clock)
		if err != nil {
			return nil, ErrInvalidSession
		}
		var retriever memoryhandler.Retriever
		retrieverIdentity := digest("empty-memory-index-v1")
		if retainedRetriever == nil {
			retriever = memorycore.NewLexicalIndex()
		} else {
			retriever = retainedRetriever
			retrieverIdentity = o.RetainedMemoryInput.Identity()
		}
		memory, err := memoryhandler.NewHandler(store, o.Clock, retriever, retrieverIdentity, o.Policy.ReviewPolicyIdentity(), "local-reviewer", []string{"."}, 10, 20)
		if err != nil {
			return nil, ErrInvalidSession
		}
		assembly, err := contexthandler.NewHandler(store, o.Clock, generationAuthority)
		if err != nil {
			return nil, ErrInvalidSession
		}
		generation, err := modelhandler.NewGenerationHandler(store, dispatchers, ledger, o.Clock)
		if err != nil {
			return nil, ErrInvalidSession
		}
		verification, err := modelhandler.NewVerificationHandler(store, dispatchers, ledger, verificationAuthority, o.Clock)
		if err != nil {
			return nil, ErrInvalidSession
		}
		readiness, err := publicationhandler.NewReadinessHandler(store, diagnosticStore, o.Clock, o.Policy.ReviewPolicyIdentity(), o.Policy.Publication())
		if err != nil {
			return nil, ErrInvalidSession
		}
		catalog, err = runtimecatalog.NewPipelineCatalog(controlplane.ReviewRunLocal, []controlplane.TaskHandler{sourceHandler, change, analysis, memory, assembly, generation, verification, readiness})
		if err != nil {
			return nil, ErrInvalidSession
		}
	}
	journal := controlplane.NewMemoryRunJournal()
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		return nil, ErrInvalidSession
	}
	finalizer, err := controlplane.NewRunFinalizer(journal)
	if err != nil {
		return nil, ErrInvalidSession
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrInvalidSession
	}
	// This nonce binds a live opened root capability, not a pathname or Git origin.
	rootID := digest("open-trestle/local-root-session/v1:" + hex.EncodeToString(nonce))
	session := &Session{options: o, rootID: rootID, adapter: source.Identity(), objectStore: objects, classification: classification, catalog: catalog, store: store, diagnostics: diagnosticStore, ledger: ledger, journal: journal, coordinator: coordinator, finalizer: finalizer, issued: map[string]bool{}, admitted: map[string]bool{}}
	if investigationPolicy != nil {
		profile, err := runtimecatalog.NewInvestigationProfileFromRuntimePolicy(o.Policy, o.Inventory, *investigationPolicy, dispatchers.Identity())
		if err != nil {
			return nil, ErrInvalidSession
		}
		configuration := runtimecatalog.InvestigationCatalogOptions{Store: store, Diagnostics: diagnosticStore, Ledger: ledger, Journal: journal, Clock: o.Clock, Dispatchers: dispatchers, Source: source}
		catalog, prototype, err := runtimecatalog.NewInvestigationPipelineCatalog(profile, configuration)
		if err != nil {
			return nil, ErrInvalidSession
		}
		session.catalog = catalog
		session.investigation = &investigationSession{profile: profile, configuration: configuration, prototype: prototype}
	}
	constructed = true
	return session, nil
}
func (s *Session) RenewalInterval() time.Duration {
	if s == nil {
		return 0
	}
	return s.options.RenewalInterval
}
func (s *Session) Prepare(ctx context.Context, scope audit.ReviewScope, hostID string, base, head evidence.RevisionIdentity) (runtimecatalog.PreparedReviewRun, error) {
	if s == nil || ctx == nil || ctx.Err() != nil {
		return runtimecatalog.PreparedReviewRun{}, ErrInvalidSession
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closing || s.closed {
		return runtimecatalog.PreparedReviewRun{}, ErrSessionClosed
	}
	if scope.TenantID() != s.options.TenantID || scope.RepositoryID() != s.options.RepositoryID || len(s.issued) >= 1024 {
		return runtimecatalog.PreparedReviewRun{}, ErrPreparedReviewMismatch
	}
	if s.options.ObjectStoreProfile == scm.LocalGitObjectStoreProfileLooseAndPackIndexV1 && (base.Algorithm() != s.options.ObjectAlgorithm || head.Algorithm() != s.options.ObjectAlgorithm) {
		return runtimecatalog.PreparedReviewRun{}, ErrPreparedReviewMismatch
	}
	at := s.options.Clock.Now()
	if s.options.RetainedMemoryInput != nil && validateRetainedMemory(s.options, head.Identity(), at) != nil {
		return runtimecatalog.PreparedReviewRun{}, ErrPreparedReviewMismatch
	}
	request, err := runtimecatalog.NewPreparedReviewRequest(runtimecatalog.PreparedReviewRequestOptions{Scope: scope, HostRequestIdentity: hostID, Repository: s.options.Repository, BaseRevision: base, HeadRevision: head, SourceAdapter: s.adapter, SourceRootIdentity: s.rootID, InventoryIdentity: s.options.Inventory.Identity(), RuntimePolicyIdentity: s.options.Policy.Identity(), ReviewPolicyIdentity: s.options.Policy.ReviewPolicyIdentity(), Classification: s.classification, Protection: artifact.ProtectionProcessPrivate, CreatedAt: at, Retention: s.options.Retention, Catalog: s.catalog})
	if err != nil {
		return runtimecatalog.PreparedReviewRun{}, err
	}
	prepared, err := runtimecatalog.PrepareReviewRun(ctx, request)
	if err != nil {
		return runtimecatalog.PreparedReviewRun{}, err
	}
	s.issued[prepared.RequestIdentity()] = true
	return prepared, nil
}
func (s *Session) Run(ctx context.Context, prepared runtimecatalog.PreparedReviewRun) (result Result, resultErr error) {
	if s == nil || ctx == nil || prepared.Validate() != nil {
		return Result{}, ErrPreparedReviewMismatch
	}
	s.mu.Lock()
	if s.closed || s.closing {
		s.mu.Unlock()
		return Result{}, ErrSessionClosed
	}
	if !s.issued[prepared.RequestIdentity()] {
		s.mu.Unlock()
		return Result{}, ErrPreparedReviewMismatch
	}
	scope := prepared.Plan().Scope()
	if s.admitted[scope.Identity()] {
		s.mu.Unlock()
		return Result{}, ErrReviewRunAlreadyExists
	}
	if s.active {
		s.mu.Unlock()
		return Result{}, ErrSessionBusy
	}
	if s.blocked {
		s.mu.Unlock()
		return Result{}, worker.ErrWorkerDrain
	}
	if input := s.options.RetainedMemoryInput; input != nil && ctx.Err() == nil {
		at := s.options.Clock.Now()
		// Prepare checked the actual head; validated issued membership binds it here.
		if validateRetainedMemory(s.options, input.Scope().RefSetIdentity(), at) != nil {
			s.mu.Unlock()
			return Result{}, ErrPreparedReviewMismatch
		}
		through := at.Add(s.options.Timeout)
		for _, record := range input.Records() {
			if !time.UnixMilli(record.ValidUntilUnixMilliseconds()).After(through) {
				s.mu.Unlock()
				return Result{}, ErrPreparedReviewMismatch
			}
		}
	}
	timeout := s.options.Timeout
	if s.investigation != nil {
		timeout = min(timeout, time.Duration(s.investigation.profile.Policy().TimeoutMilliseconds())*time.Millisecond)
	}
	execution, cancel := context.WithTimeout(ctx, timeout)
	done := make(chan struct{})
	s.cancel = cancel
	s.done = done
	s.active = true
	s.admitted[scope.Identity()] = true
	if s.investigation != nil {
		s.lastInvestigationResult = Result{}
	}
	s.mu.Unlock()
	defer func() { cancel(); s.mu.Lock(); s.active = false; close(done); s.mu.Unlock() }()
	if s.investigation != nil {
		diagnostic := s.unstarted(prepared, "failed")
		diagnostic.wire.RunStatus = "unknown"
		diagnostic.wire.Limitations = append(diagnostic.wire.Limitations, "execution_state_unavailable", "unknown_final_usage")
		s.rememberInvestigationResult(diagnostic)
		defer func() { s.finishInvestigationRun(&result, &resultErr) }()
	}
	if execution.Err() != nil {
		return s.unstarted(prepared, "canceled"), nil
	}
	catalog := s.catalog
	if s.investigation != nil {
		var err error
		catalog, err = s.newInvestigationRuntime(prepared)
		if err != nil {
			return s.unstarted(prepared, "failed"), err
		}
	}
	for _, input := range prepared.Inputs() {
		if _, err := s.store.Put(execution, input, s.options.Clock.Now()); err != nil {
			if execution.Err() != nil {
				return s.unstarted(prepared, "canceled"), nil
			}
			result := s.unstarted(prepared, "failed")
			result.wire.Failure = "internal"
			if errors.Is(err, artifact.ErrStoreCapacity) {
				result = s.unstarted(prepared, "refused")
				result.wire.Failure = "resource_limit"
			}
			return result, nil
		}
	}
	if _, err := s.coordinator.Open(execution, prepared.Plan(), s.options.Clock.Now()); err != nil {
		if s.investigation != nil {
			wasCanceled := execution.Err() != nil
			cancel()
			return s.readFailedInvestigationRun(prepared, wasCanceled)
		}
		if execution.Err() != nil {
			return s.unstarted(prepared, "canceled"), nil
		}
		return Result{}, ErrInvalidSession
	}
	var runnerErr error
	if s.investigation != nil {
		runnerErr = s.activeInvestigation.StartRun(execution, prepared.Plan())
		if runnerErr != nil {
			cancel()
		}
	}
	if runnerErr == nil {
		setupFailed := false
		runnerErr = func() error {
			control, err := worker.NewLocalControl(s.journal, s.options.Clock, "local-review-worker")
			if err != nil {
				setupFailed = true
				return ErrInvalidSession
			}
			renewal := s.options.RenewalInterval
			if renewal > s.options.Timeout/2 {
				renewal = s.options.Timeout / 2
			}
			runner, err := worker.New(control, catalog.Catalog(), worker.Options{Scope: scope, PollInterval: 250 * time.Millisecond, RenewalInterval: renewal, ExecutionTimeout: s.options.Timeout})
			if err != nil {
				setupFailed = true
				return ErrInvalidSession
			}
			s.mu.Lock()
			s.runner = runner
			s.mu.Unlock()
			return runner.Run(execution)
		}()
		if setupFailed && s.investigation == nil {
			return Result{}, ErrInvalidSession
		}
		if s.investigation != nil && runnerErr != nil {
			cancel()
		}
		if errors.Is(runnerErr, worker.ErrWorkerDrain) {
			s.mu.Lock()
			s.blocked = true
			s.mu.Unlock()
			// Seal leases without touching or closing resources still held by a handler.
			// Failure to seal cannot become a success claim; callers receive ErrWorkerDrain.
			cleanup, stop := context.WithTimeout(context.Background(), time.Second)
			state, err := s.coordinator.CancelRun(cleanup, prepared.Plan(), s.options.Clock.Now())
			if s.investigation != nil && err == nil {
				result, _ = s.readResult(cleanup, prepared, state)
			}
			stop()
			return result, runnerErr
		}
	}
	// Detached context is cleanup/readback only. No handler or model receives it.
	cleanup, stop := context.WithTimeout(context.Background(), 2*time.Second)
	defer stop()
	var state controlplane.ReviewRunState
	var err error
	if execution.Err() != nil {
		state, err = s.coordinator.CancelRun(cleanup, prepared.Plan(), s.options.Clock.Now())
	} else {
		state, _, err = s.finalizer.ReconcileRun(cleanup, scope, s.options.Clock.Now())
		if err == nil && state.Status() == controlplane.ReviewRunActive {
			state, err = s.coordinator.CancelRun(cleanup, prepared.Plan(), s.options.Clock.Now())
			if runnerErr == nil {
				runnerErr = ErrInvalidSession
			}
		}
	}
	if err != nil {
		if s.investigation != nil {
			wasCanceled := execution.Err() != nil
			cancel()
			return s.readFailedInvestigationRun(prepared, wasCanceled)
		}
		return Result{}, ErrInvalidSession
	}
	result, err = s.readResult(cleanup, prepared, state)
	if err != nil {
		return Result{}, err
	}
	if runnerErr != nil && (s.investigation != nil || execution.Err() == nil) {
		result.wire.Status = "failed"
		result.wire.CI = "error"
	}
	return result, nil
}

// Close never abandons a live handler's root. A failed drain requires an explicit
// later Close after the handler exits; there is no background reaper.
func (s *Session) Close(ctx context.Context) error {
	if s == nil || ctx == nil {
		return ErrInvalidSession
	}
	s.mu.Lock()
	if s.closed {
		err := s.closeErr
		s.mu.Unlock()
		return err
	}
	s.closing = true
	cancel := s.cancel
	done := s.done
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return worker.ErrWorkerDrain
		}
	}
	s.mu.Lock()
	runner := s.runner
	objectStore := s.objectStore
	s.mu.Unlock()
	if runner != nil {
		if err := runner.Wait(ctx); err != nil {
			return err
		}
	}
	if err := s.closeInvestigationResources(ctx); err != nil {
		return err
	}
	if objectStore != nil {
		if err := objectStore.Close(ctx); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	if err := s.options.ObjectsRoot.Close(); err != nil {
		s.closeErr = ErrSessionClosed
	}
	s.closed = true
	return s.closeErr
}
func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
func nilValue(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Func, reflect.Map, reflect.Slice, reflect.Chan:
		return v.IsNil()
	}
	return false
}

func (s *Session) String() string   { return "local review session" }
func (s *Session) GoString() string { return "localreview.Session{<redacted>}" }

// validateLocalObjectLayout refuses storage formats this entrypoint cannot review.
// It never opens an alternate/indirection file or an unpinned format node.
func validateLocalObjectLayout(objects *os.Root) error {
	for _, name := range []string{"alternates", "http-alternates", "commondir", "gitdir", ".git", "objects", "HEAD", "config"} {
		if _, err := objects.Lstat(name); !errors.Is(err, os.ErrNotExist) {
			return ErrUnsupportedSource
		}
	}
	for _, name := range []string{"pack", "info"} {
		if err := validateLocalFormatDirectory(objects, name); err != nil {
			return ErrUnsupportedSource
		}
	}
	return nil
}

func validateLocalFormatDirectory(objects *os.Root, name string) (resultErr error) {
	before, err := objects.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !before.IsDir() {
		return ErrUnsupportedSource
	}
	// Keep "/." literal: on Go 1.24 Unix, a bare OpenRoot(name) can open
	// a replaced FIFO before checking its type. A nonterminal name is opened
	// by the directory-only traversal; the final "." belongs to that pin.
	directory, err := objects.OpenRoot(name + "/.")
	if err != nil {
		return ErrUnsupportedSource
	}
	defer func() {
		if directory.Close() != nil {
			resultErr = ErrUnsupportedSource
		}
	}()
	pinned, err := directory.Stat(".")
	if err != nil || !pinned.IsDir() || !os.SameFile(before, pinned) {
		return ErrUnsupportedSource
	}
	if name == "pack" {
		// Open only the pinned directory itself, never the replaceable name.
		file, err := directory.Open(".")
		if err != nil {
			return ErrUnsupportedSource
		}
		entries, readErr := file.ReadDir(1)
		closeErr := file.Close()
		if len(entries) != 0 || !errors.Is(readErr, io.EOF) || closeErr != nil {
			return ErrUnsupportedSource
		}
	} else {
		for _, marker := range []string{"alternates", "http-alternates"} {
			if _, err := directory.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
				return ErrUnsupportedSource
			}
		}
	}
	after, err := objects.Lstat(name)
	if err != nil || !after.IsDir() || !os.SameFile(pinned, after) || before.Mode() != after.Mode() || !before.ModTime().Equal(after.ModTime()) {
		return ErrUnsupportedSource
	}
	return nil
}
