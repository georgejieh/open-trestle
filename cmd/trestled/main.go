package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	openaiadapter "github.com/georgejieh/open-trestle/adapters/providers/openai"
	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	githubwebhook "github.com/georgejieh/open-trestle/adapters/webhook/github"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/controlplane/httpapi"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	contexthandler "github.com/georgejieh/open-trestle/handlers/context"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	publicationhandler "github.com/georgejieh/open-trestle/handlers/publication"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/buildinfo"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	reviewcore "github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimeadmin"
	"github.com/georgejieh/open-trestle/runtimecatalog"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"github.com/georgejieh/open-trestle/runtimehealth"
	"github.com/georgejieh/open-trestle/setup"
	webconsole "github.com/georgejieh/open-trestle/web"
	"github.com/georgejieh/open-trestle/webhook"
	"github.com/georgejieh/open-trestle/worker"
)

const (
	defaultDaemonListenAddress = "127.0.0.1:8741"
	daemonShutdownTimeout      = 10 * time.Second
)

var (
	ErrInvalidDaemonConfiguration = errors.New("invalid Open Trestle daemon configuration")
	ErrDaemonRuntimeUnavailable   = errors.New("Open Trestle daemon runtime unavailable")
	ErrDaemonPlanIncompatible     = errors.New("active local full review plan has an incompatible context handler")
)

type repositoryFlags []string

func (r *repositoryFlags) String() string         { return "configured repository identifiers" }
func (r *repositoryFlags) Set(value string) error { *r = append(*r, value); return nil }

type daemonSupervisor interface {
	Run(context.Context) error
	Ready() <-chan struct{}
}

type daemon struct {
	server                 *http.Server
	admission              *daemonAdmission
	journal                controlplane.RunJournal
	inboxStore             webhook.Store
	diagnosticStore        diagnostics.Store
	artifactStore          artifact.RetentionStore
	supervisors            []daemonSupervisor
	supervisorNames        []string
	closers                []io.Closer
	closeMu                sync.Mutex
	finishStarted          bool
	runStarted             bool
	finishGate             chan struct{}
	runtimeContext         context.Context
	stopRuntime            context.CancelFunc
	runtimeResults         []*daemonRuntimeResult
	shutdownDone           chan struct{}
	shutdownErr            error
	closersDone            chan struct{}
	closeErr               error
	handlerDrainTimeout    time.Duration
	tlsCertificate, tlsKey string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := runDaemon(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	if err != nil {
		var incomplete *daemonShutdownIncomplete
		if errors.As(err, &incomplete) {
			fmt.Fprintln(os.Stderr, "trestled: shutdown incomplete; terminating with cleanup unconfirmed")
		}
		fmt.Fprintf(os.Stderr, "trestled: %v\n", err)
		os.Exit(1)
	}
}

// buildDaemon prepares the secret scanner's cache only once the configuration
// is valid, so a configuration error is reported at once.
func buildDaemon(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) (*daemon, error) {
	scanner := installedDaemonScanner(getenv)
	sanitizer := scanner.sanitizer()
	d, err := buildDaemonWithDependencies(ctx, args, getenv, stderr, daemonDependencies{clock: httpapi.SystemClock{}, generationSanitizer: reviewcore.NewFixedGenerationRequestSanitizer(sanitizer), verificationSanitizer: reviewcore.NewFixedVerificationRequestSanitizer(sanitizer)})
	if err != nil {
		return nil, err
	}
	scanner.prepare(ctx, stderr)
	return d, nil
}
func publicationContentScannerFromGenerationSanitizer(sanitizer reviewcore.GenerationRequestSanitizer) reviewcore.PublicationContentScanner {
	if provider, ok := sanitizer.(interface {
		PublicationContentScanner() reviewcore.PublicationContentScanner
	}); ok {
		return provider.PublicationContentScanner()
	}
	return reviewcore.NewFixedPublicationContentScanner(nil)
}

func buildDaemonWithDependencies(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer, deps daemonDependencies) (result *daemon, err error) {
	if daemonNilDependency(ctx) || getenv == nil || daemonNilDependency(stderr) || daemonNilDependency(deps.clock) {
		return nil, ErrInvalidDaemonConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if daemonNilDependency(deps.generationSanitizer) {
		deps.generationSanitizer = reviewcore.NewFixedGenerationRequestSanitizer(nil)
	}
	if daemonNilDependency(deps.verificationSanitizer) {
		deps.verificationSanitizer = reviewcore.NewFixedVerificationRequestSanitizer(nil)
	}
	flags := flag.NewFlagSet("trestled", flag.ContinueOnError)
	flags.SetOutput(stderr)
	listenAddress := flags.String("listen", defaultDaemonListenAddress, "TCP listen address")
	stateDirectory := flags.String("state-dir", "", "private durable state directory")
	setupState := flags.String("setup-state", "", "initialized local_single_node scope plan; does not grant setup readiness")
	expectedSetupRootIdentity := flags.String("expected-setup-root-identity", "", "expected setup root identity for scope and posture binding only")
	localGitObjectsRoot := flags.String("local-git-objects-root", "", "daemon-owned loose Git objects directory")
	localGitRepositoryAuthority := flags.String("local-git-repository-authority", "", "local Git repository authority label")
	localGitRepositoryNamespace := flags.String("local-git-repository-namespace", "", "local Git repository namespace")
	localGitRepositoryName := flags.String("local-git-repository-name", "", "local Git repository name")
	localFullReview := flags.Bool("local-full-review", false, "admit policy-bound local reviews")
	localModelWorkers := flags.Bool("local-model-workers", false, "execute policy-bound local generation, verification, and readiness tasks")
	tenantID := flags.String("tenant", "", "tenant identifier")
	tlsCertificate := flags.String("tls-cert", "", "TLS certificate file")
	tlsKey := flags.String("tls-key", "", "TLS private key file")
	githubRepository := flags.String("github-webhook-repository", "", "repository identifier for the GitHub webhook endpoint")
	githubKeyID := flags.String("github-webhook-key-id", "", "non-secret GitHub webhook key version")
	githubOpenRuns := flags.Bool("github-open-runs", false, "open review runs from durable GitHub deliveries")
	githubLocalDeterministicWorkers := flags.Bool("github-local-deterministic-workers", false, "execute built-in source, change, analysis, and memory handlers")
	githubSourceBrokerAuthority := flags.String("approve-github-source-broker-authority-identity", "", "exact approved GitHub source broker authority identity")
	runtimeRouteInventory := flags.String("runtime-route-inventory", "", "path to an exact runtime route inventory")
	runtimePolicy := flags.String("runtime-policy", "", "path to an exact runtime policy")
	githubFullName := flags.String("github-repository-full-name", "", "lowercase owner/name expected in GitHub payloads")
	githubPolicyIdentity := flags.String("github-review-policy-identity", "", "exact review policy identity")
	githubPublisherID := flags.String("github-publisher-id", githubwebhook.DefaultGitHubPublisherID, "exact publisher implementation identifier")
	githubReviewMode := flags.String("github-review-mode", "advisory", "review mode: local or advisory")
	var githubHandlers repositoryFlags
	flags.Var(&githubHandlers, "github-handler", "task kind=handler identity; repeat for each required kind")
	var repositories repositoryFlags
	flags.Var(&repositories, "repository", "authorized repository identifier; repeat for each repository")
	if err := flags.Parse(args); err != nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	if *localModelWorkers && (!*localFullReview || *setupState == "" || *localGitObjectsRoot == "" || *runtimeRouteInventory == "" || *runtimePolicy == "" || *githubOpenRuns || *githubLocalDeterministicWorkers || !daemonLoopbackAddress(*listenAddress)) {
		return nil, ErrInvalidDaemonConfiguration
	}
	credential := getenv("OPEN_TRESTLE_API_TOKEN")
	observerCredential := getenv("OPEN_TRESTLE_OBSERVER_TOKEN")
	githubSecretValue := getenv("OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET")
	githubSecret := []byte(githubSecretValue)
	githubSecretValue = ""
	defer clear(githubSecret)
	githubAPIToken := getenv("OPEN_TRESTLE_GITHUB_API_TOKEN")
	githubSourceBrokerConfigPath := getenv("OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG")
	githubConfigured := len(githubSecret) != 0 || *githubRepository != "" || *githubKeyID != ""
	if githubConfigured {
		githubScope, scopeErr := webhook.NewRepositoryScope(*tenantID, *githubRepository)
		_, verifierErr := githubwebhook.VerifierConfigurationIdentity(githubScope, *githubKeyID)
		invalid := githubwebhook.ValidateRuntimeSecret(githubSecret) != nil || *githubRepository == "" || scopeErr != nil || verifierErr != nil || !containsRepository(repositories, *githubRepository) || sameDaemonCredential(githubSecret, credential) || sameDaemonCredential(githubSecret, observerCredential) || sameDaemonCredential(githubSecret, githubAPIToken)
		if invalid {
			return nil, ErrInvalidDaemonConfiguration
		}
	}
	plannerConfigured := *githubOpenRuns || *githubLocalDeterministicWorkers || *githubFullName != "" || *githubPolicyIdentity != "" || len(githubHandlers) != 0 || *githubReviewMode != "advisory" || *githubPublisherID != githubwebhook.DefaultGitHubPublisherID
	runtimeConfigured := *runtimeRouteInventory != "" || *runtimePolicy != ""
	localGitValues := []string{*setupState, *expectedSetupRootIdentity, *localGitObjectsRoot, *localGitRepositoryAuthority, *localGitRepositoryNamespace, *localGitRepositoryName}
	localGitConfigured := false
	localGitComplete := true
	for _, value := range localGitValues {
		localGitConfigured = localGitConfigured || value != ""
		localGitComplete = localGitComplete && value != ""
	}
	if *localModelWorkers && (!*localFullReview || !localGitConfigured) {
		return nil, ErrInvalidDaemonConfiguration
	}
	if localGitConfigured && (!localGitComplete || githubConfigured || plannerConfigured || runtimeConfigured != *localFullReview || len(repositories) != 1 || *tlsCertificate != "" || *tlsKey != "" || !daemonLoopbackAddress(*listenAddress)) {
		return nil, ErrInvalidDaemonConfiguration
	}
	if *setupState != "" {
		stateRoot, rootErr := filepath.Abs(*stateDirectory)
		setupParent, parentErr := filepath.Abs(filepath.Dir(*setupState))
		if rootErr != nil || parentErr != nil {
			return nil, ErrInvalidDaemonConfiguration
		}
		if filepath.Clean(setupParent) == filepath.Clean(stateRoot) {
			return nil, fmt.Errorf("local metadata startup rejected: --setup-state directly inside --state-dir is unsupported; stop writers and restore a verified offline setup backup with its receipts under --state-dir/setup/plan.json or outside --state-dir, then update --setup-state and inspect; no automatic move or deletion: %w", ErrInvalidDaemonConfiguration)
		}
	}
	var localSetupPlan setup.Plan
	var localRepository evidence.RepositoryIdentity
	if localGitConfigured {
		// Deterministic review performs no setup, model, egress, or publication effect.
		// The initialized plan binds scope and denied-effect posture only; its pending
		// readiness gates remain pending and confer no runtime authorization.
		var setupErr error
		localSetupPlan, setupErr = setup.InspectStateFile(ctx, *setupState)
		var repositoryErr error
		localRepository, repositoryErr = evidence.NewRepositoryIdentity(*localGitRepositoryAuthority, strings.Split(*localGitRepositoryNamespace, "/"), *localGitRepositoryName)
		posture := localSetupPlan.Posture()
		if setupErr != nil || repositoryErr != nil || localRepository.Identity() == "" || !daemonNonzeroDigest(*expectedSetupRootIdentity) || localSetupPlan.RootIdentity() != *expectedSetupRootIdentity || localSetupPlan.Profile() != setup.ProfileLocalSingleNode || localSetupPlan.TenantID() != *tenantID || localSetupPlan.RepositoryID() != repositories[0] || posture.MetadataBackend() != setup.MetadataLocal || posture.ArtifactBackend() != setup.ArtifactLocal || posture.Egress() != setup.EgressDenied || posture.PublicationEnabled() || posture.DynamicValidationEnabled() {
			return nil, ErrInvalidDaemonConfiguration
		}
	}
	if *localFullReview && !localGitConfigured || runtimeConfigured && (*runtimeRouteInventory == "" || *runtimePolicy == "" || !*githubLocalDeterministicWorkers && !*localFullReview) {
		return nil, ErrInvalidDaemonConfiguration
	}
	// Required review needs a publication fence, which no local store provides.
	if *githubReviewMode == "required" {
		return nil, ErrInvalidDaemonConfiguration
	}
	if plannerConfigured != *githubOpenRuns || *githubOpenRuns && !githubConfigured || *githubLocalDeterministicWorkers && !*githubOpenRuns || githubAPIToken != "" && !*githubLocalDeterministicWorkers {
		return nil, ErrInvalidDaemonConfiguration
	}
	if flags.NArg() != 0 || *stateDirectory == "" || *tenantID == "" || len(repositories) == 0 || credential == "" || !validListenAddress(*listenAddress, *tlsCertificate, *tlsKey) {
		return nil, ErrInvalidDaemonConfiguration
	}
	githubSourceConfig, err := loadGitHubSourceConfiguration(ctx, githubSourceBrokerConfigPath, githubAPIToken, *tenantID, *githubRepository, *githubFullName, *githubSourceBrokerAuthority, *githubLocalDeterministicWorkers)
	if err != nil {
		return nil, err
	}
	if *tlsCertificate != "" {
		if !regularFile(*tlsCertificate, false) || !regularFile(*tlsKey, true) {
			return nil, ErrInvalidDaemonConfiguration
		}
	}
	capabilities := []httpapi.Capability{httpapi.CapabilityRunRead, httpapi.CapabilityRunWrite, httpapi.CapabilityRuntimeRead}
	if !*localFullReview {
		capabilities = append(capabilities, httpapi.CapabilityTaskClaim, httpapi.CapabilityTaskComplete)
	}
	principal, err := httpapi.NewPrincipal("daemon-operator", *tenantID, repositories, capabilities)
	if err != nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	tokens := []httpapi.StaticToken{{Token: credential, Principal: principal}}
	if observerCredential != "" {
		observer, observerErr := httpapi.NewPrincipal("daemon-observer", *tenantID, repositories, []httpapi.Capability{httpapi.CapabilityRunRead, httpapi.CapabilityRuntimeRead})
		if observerErr != nil {
			return nil, ErrInvalidDaemonConfiguration
		}
		tokens = append(tokens, httpapi.StaticToken{Token: observerCredential, Principal: observer})
	}
	authenticator, err := httpapi.NewStaticTokenAuthenticator(tokens)
	if err != nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	runtimeContext, stopRuntime := context.WithCancel(context.Background())
	resources := &daemon{runtimeContext: runtimeContext, stopRuntime: stopRuntime}
	resources.admission = &daemonAdmission{runtime: runtimeContext}
	built := false
	defer func() {
		if !built {
			err = errors.Join(err, resources.Close())
		}
	}()
	var daemonArtifactClock artifact.Clock = httpapi.SystemClock{}
	if localGitConfigured && *localFullReview {
		daemonArtifactClock = deps.clock
	}
	var daemonGitHubSourceClock githubsource.BrokerClock = githubsource.SystemBrokerClock{}
	var daemonWebhookClock githubwebhook.Clock = githubwebhook.SystemClock{}
	var generationStartup *localGenerationStartupAuthority
	if *localFullReview {
		generationStartup, err = loadLocalGenerationStartupAuthority(ctx, *runtimeRouteInventory, *runtimePolicy, getenv, deps.generationSanitizer)
		if err != nil {
			return nil, ErrInvalidDaemonConfiguration
		}
		generationStartup.verificationSanitizer = deps.verificationSanitizer
	}
	var localObjectsRoot *os.Root
	var localObjectStore *scm.LocalGitObjectStore
	var localSourceAdapter *scm.LocalGitSourceAdapter
	var localRootDigest string
	if localGitConfigured {
		var rootErr error
		localObjectsRoot, localRootDigest, rootErr = openDaemonLocalGitRoot(*localGitObjectsRoot, localRepository)
		if rootErr != nil {
			return nil, rootErr
		}
		resources.closers = append(resources.closers, localObjectsRoot)
		gitPath, pathErr := filepath.Abs(*localGitObjectsRoot)
		if pathErr != nil {
			return nil, pathErr
		}
		if _, rootErr = observeLocalSourceDirectory(gitPath, localObjectsRoot); rootErr != nil {
			return nil, rootErr
		}
		localObjectStore, rootErr = scm.NewLocalGitObjectStore(localObjectsRoot, localRepository)
		if rootErr != nil {
			return nil, rootErr
		}
		localSourceAdapter, rootErr = scm.NewLocalGitSourceAdapter(localObjectStore)
		if rootErr != nil {
			return nil, rootErr
		}
	}
	var journal controlplane.RunJournal
	var packetOwner *localPacketOwner
	var artifactStore artifact.RetentionStore
	artifactProtection := artifact.ProtectionProcessPrivate
	active, fileJournal, bootOwner, gateErr := startLocalSourceOwnerGateWithAuthority(ctx, resources, *stateDirectory, *setupState, &localSetupPlan, *tenantID, repositories[0], localRepository, localObjectsRoot, localObjectStore, localSourceAdapter, localRootDigest, daemonArtifactClock, generationStartup, nil)
	if gateErr != nil {
		if localGitConfigured && (errors.Is(gateErr, errLocalSourceOwnerSnapshot) || errors.Is(gateErr, errLocalMissingStateBoundary)) {
			return nil, errors.Join(ErrInvalidDaemonConfiguration, gateErr)
		}
		return nil, gateErr
	}
	artifactStore = active
	journal = fileJournal
	packetOwner = bootOwner
	if packetOwner != nil && len(packetOwner.pendingExpiredPackets) > 0 && (!*localFullReview || !localGitConfigured) {
		return nil, errHistoricalPacketExpiryStartup
	}
	var taskNotificationQueue controlplane.TaskNotificationQueue
	var diagnosticStore diagnostics.Store
	var auditLedger audit.Ledger
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fileAudit, err := audit.NewFileLedger(filepath.Join(*stateDirectory, "audit"))
	if err != nil {
		return nil, err
	}
	resources.closers = append(resources.closers, fileAudit)
	auditLedger = fileAudit
	if packetOwner != nil && packetOwner.pendingSettlementAudit {
		if err := verifyOwnerSettledStartup(ctx, packetOwner, fileAudit, localObjectsRoot); err != nil {
			return nil, err
		}
		packetOwner.pendingSettlementAudit = false
	}
	taskNotificationQueue = controlplane.NewMemoryTaskNotificationQueue()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fileDiagnostics, err := diagnostics.NewFileStore(filepath.Join(*stateDirectory, "diagnostics"))
	if err != nil {
		return nil, err
	}
	resources.closers = append(resources.closers, fileDiagnostics)
	diagnosticStore = fileDiagnostics
	taskScheduler, err := controlplane.NewTaskNotificationScheduler(journal, taskNotificationQueue)
	if err != nil {
		return nil, err
	}
	taskWaiter, ok := taskNotificationQueue.(controlplane.TaskNotificationWaiter)
	if !ok {
		return nil, ErrInvalidDaemonConfiguration
	}
	taskSupervisor, err := controlplane.NewTaskNotificationSupervisor(taskScheduler, taskWaiter, *tenantID, []string(repositories), controlplane.TaskNotificationSupervisorOptions{ReconcileInterval: 30 * time.Second, MaximumRetries: 5, RetryDelay: time.Second, Clock: httpapi.SystemClock{}})
	if err != nil {
		return nil, err
	}
	resources.supervisors = append(resources.supervisors, taskSupervisor)
	resources.supervisorNames = append(resources.supervisorNames, "task_notifications")
	var inboxStore webhook.Store
	var refusalReader httpapi.DeliveryRefusalReader
	var githubHTTPHandler http.Handler
	var statusHandlers []runtimeadmin.HandlerBinding
	var statusInventoryIdentity, statusPolicyIdentity string
	var statusRouteCount uint32
	var localReviewAdmitter *runtimecatalog.LocalDeterministicReviewAdmitter
	var localFullAdmitter *runtimecatalog.LocalFullReviewAdmitter
	if localGitConfigured {
		rootIdentity := localRootDigest
		objectStore, sourceAdapter := localObjectStore, localSourceAdapter
		sourceTask, sourceErr := sourcehandler.NewHandlerWithSourceRoot(artifactStore, sourceAdapter, rootIdentity, daemonArtifactClock)
		changeTask, changeErr := changehandler.NewHandler(artifactStore, daemonArtifactClock)
		analysisTask, analysisErr := analysishandler.NewHandlerWithDiagnostics(artifactStore, diagnosticStore, daemonArtifactClock)
		if sourceErr != nil || changeErr != nil || analysisErr != nil {
			return nil, ErrInvalidDaemonConfiguration
		}
		localHandlers := []controlplane.TaskHandler{sourceTask, changeTask, analysisTask}
		var pipeline runtimecatalog.PipelineCatalog
		var pipelineErr error
		if *localFullReview {
			analysisTask, analysisErr = analysishandler.NewHandler(artifactStore, daemonArtifactClock)
			if analysisErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			localHandlers = []controlplane.TaskHandler{sourceTask, changeTask, analysisTask}
			inventory, configuration := generationStartup.inventory, generationStartup.configuration
			memoryTask, memoryErr := memoryhandler.NewHandler(artifactStore, daemonArtifactClock, memorycore.NewLexicalIndex(), daemonComponentIdentity("empty-memory-index-v1"), configuration.ReviewPolicyIdentity(), "trestled", []string{"."}, 64, 50)
			dispatchers := generationStartup.dispatchers
			verificationInventory, inventoryErr := runtimecatalog.NewStaticVerificationRouteInventory(inventory)
			if memoryErr != nil || inventoryErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			verificationAuthorizer, verificationAuthErr := runtimecatalog.NewVerificationPolicyAuthorizerFromRuntimePolicy(configuration, verificationInventory, auditLedger, daemonArtifactClock)
			contextCoordinator, coordinatorErr := controlplane.NewCoordinator(journal)
			if coordinatorErr != nil {
				return nil, coordinatorErr
			}
			if packetOwner == nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			pair, pairErr := runtimecatalog.ResolveLocalGenerationRoutePair(configuration, inventory)
			fileAudit, fileAuditOK := auditLedger.(*audit.FileLedger)
			if pairErr != nil || !fileAuditOK {
				return nil, ErrInvalidDaemonConfiguration
			}
			abstentionPlanner, contextErr := contexthandler.NewJournaledPacketOnlyHandler(artifactStore, daemonArtifactClock, contextCoordinator)
			contextTask := &localContextOwnerTask{owner: packetOwner, ledger: fileAudit, sanitizer: deps.generationSanitizer, configuration: configuration, inventory: inventory, pair: pair, abstentionPlanner: abstentionPlanner}
			generationTask, generationErr := modelhandler.NewGenerationHandler(artifactStore, dispatchers, auditLedger, daemonArtifactClock, deps.generationSanitizer.ExpectedBinaryDigests())
			verificationTask, verificationErr := modelhandler.NewVerificationHandler(artifactStore, dispatchers, auditLedger, verificationAuthorizer, daemonArtifactClock, deps.verificationSanitizer)
			readinessTask, readinessErr := publicationhandler.NewFinalOnlyReadinessHandler(artifactStore, daemonArtifactClock, configuration.ReviewPolicyIdentity(), configuration.Publication(), publicationContentScannerFromGenerationSanitizer(deps.generationSanitizer))
			if verificationAuthErr != nil || contextErr != nil || generationErr != nil || verificationErr != nil || readinessErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			localHandlers = append(localHandlers, memoryTask, contextTask, generationTask, verificationTask, readinessTask)
			pipeline, pipelineErr = runtimecatalog.NewPipelineCatalog(controlplane.ReviewRunLocal, localHandlers)
			if pipelineErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			if err := checkLocalFullReviewStartupPlans(ctx, journal, *tenantID, repositories, contextTask.HandlerIdentity(), analysisTask.HandlerIdentity()); err != nil {
				return nil, err
			}
			if err := verifyOwnerRejectedGenerationCatalog(ctx, packetOwner, localObjectsRoot, pipeline, configuration.ReviewPolicyIdentity()); err != nil {
				return nil, err
			}
			if len(packetOwner.pendingExpiredPackets) > 0 {
				if err := verifyOwnerExpiredPacketStartup(ctx, packetOwner, fileAudit, localObjectsRoot, pipeline, configuration.ReviewPolicyIdentity()); err != nil {
					return nil, err
				}
			}
			if err := recoverLocalFullReviewPrepared(ctx, journal, artifactStore, contextCoordinator, *tenantID, repositories, daemonArtifactClock.Now()); err != nil {
				return nil, err
			}
			localFullAdmitter, err = runtimecatalog.NewLocalFullReviewAdmitter(journal, artifactStore, runtimecatalog.LocalFullReviewAdmissionConfig{Source: objectStore, Repository: localRepository, SourceAdapter: sourceAdapter.Identity(), SourceRootIdentity: rootIdentity, Inventory: inventory, Policy: configuration, Classification: artifact.ClassificationInternal, Protection: artifactProtection, Retention: 24 * time.Hour, Catalog: pipeline})
			if err != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			preModelCatalog, catalogErr := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{sourceTask, changeTask, analysisTask, memoryTask, contextTask})
			if catalogErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			finalProjector, projectorErr := NewLocalFinalDiagnosticProjector(artifactStore, diagnosticStore, analysisTask.HandlerIdentity())
			if projectorErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			finalProjector.clock = daemonArtifactClock
			localSupervisor, supervisorErr := worker.NewRepositorySupervisor(journal, preModelCatalog, worker.RepositorySupervisorOptions{TenantID: *tenantID, RepositoryIDs: []string(repositories), WorkerIdentity: "trestled-local-premodel", PollInterval: time.Second, RenewalInterval: 10 * time.Second, ExecutionTimeout: 30 * time.Minute, Clock: daemonArtifactClock, FinalizeSettled: true, OnTerminal: finalProjector.Project})
			if supervisorErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			resources.supervisors = append(resources.supervisors, localSupervisor)
			resources.supervisorNames = append(resources.supervisorNames, "local_workers")
			if *localModelWorkers {
				modelCatalog, catalogErr := controlplane.NewTaskHandlerCatalog([]controlplane.TaskHandler{generationTask, verificationTask, readinessTask})
				if catalogErr != nil {
					return nil, ErrInvalidDaemonConfiguration
				}
				modelSupervisor, supervisorErr := worker.NewRepositorySupervisor(journal, modelCatalog, worker.RepositorySupervisorOptions{TenantID: *tenantID, RepositoryIDs: []string(repositories), WorkerIdentity: "trestled-local-model", PollInterval: time.Second, RenewalInterval: 10 * time.Second, ExecutionTimeout: 30 * time.Minute, Clock: daemonArtifactClock, FinalizeSettled: true})
				if supervisorErr != nil {
					return nil, ErrInvalidDaemonConfiguration
				}
				resources.supervisors = append(resources.supervisors, modelSupervisor)
				resources.supervisorNames = append(resources.supervisorNames, "local_model_workers")
			}
			statusInventoryIdentity, statusPolicyIdentity, statusRouteCount = inventory.Identity(), configuration.Identity(), uint32(len(inventory.Candidates()))
		} else {
			pipeline, pipelineErr = runtimecatalog.NewPipelineCatalog(controlplane.ReviewRunLocal, localHandlers)
			if pipelineErr != nil {
				return nil, pipelineErr
			}
			localReviewPolicyIdentity := daemonComponentIdentity("local-deterministic-static-debug-review-v1")
			localReviewAdmitter, err = runtimecatalog.NewLocalDeterministicReviewAdmitter(journal, artifactStore, runtimecatalog.LocalDeterministicReviewAdmissionConfig{Repository: localRepository, SourceAdapter: sourceAdapter.Identity(), SourceRootIdentity: rootIdentity, ReviewPolicyIdentity: localReviewPolicyIdentity, Classification: artifact.ClassificationInternal, Protection: artifactProtection, Retention: 24 * time.Hour, Catalog: pipeline})
			if err != nil {
				return nil, err
			}
			localSupervisor, supervisorErr := worker.NewRepositorySupervisor(journal, pipeline.Catalog(), worker.RepositorySupervisorOptions{TenantID: *tenantID, RepositoryIDs: []string(repositories), WorkerIdentity: "trestled-local", PollInterval: time.Second, RenewalInterval: 10 * time.Second, ExecutionTimeout: 30 * time.Minute, Clock: httpapi.SystemClock{}, FinalizeSettled: true})
			if supervisorErr != nil {
				return nil, supervisorErr
			}
			resources.supervisors = append(resources.supervisors, localSupervisor)
			resources.supervisorNames = append(resources.supervisorNames, "local_workers")
		}
		bindings := pipeline.Bindings()
		statusHandlers = make([]runtimeadmin.HandlerBinding, len(bindings))
		for index, binding := range bindings {
			statusHandlers[index] = runtimeadmin.HandlerBinding{Kind: binding.Kind.String(), Identity: binding.HandlerIdentity}
		}
	}
	if githubConfigured {
		scope, scopeErr := webhook.NewRepositoryScope(*tenantID, *githubRepository)
		if scopeErr != nil {
			return nil, ErrInvalidDaemonConfiguration
		}
		verifier, verifierErr := githubwebhook.NewRuntimeVerifier(githubSecret, scope, *githubKeyID)
		clear(githubSecret)
		if verifierErr != nil {
			return nil, ErrInvalidDaemonConfiguration
		}
		resources.closers = append(resources.closers, verifier)
		configurationIdentity := verifier.Identity()
		policy, policyErr := webhook.NewAdmissionPolicy([]webhook.VerifierAuthority{{Scope: scope, Source: webhook.SourceGitHub, VerifierIdentity: configurationIdentity}})
		if policyErr != nil {
			return nil, ErrInvalidDaemonConfiguration
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fileInbox, err := webhook.NewFileStore(filepath.Join(*stateDirectory, "webhook-inbox"))
		if err != nil {
			return nil, err
		}
		resources.closers = append(resources.closers, fileInbox)
		inboxStore = fileInbox
		inbox, inboxErr := webhook.NewInbox(inboxStore, policy)
		if inboxErr != nil {
			return nil, inboxErr
		}
		var notifier webhook.DeliveryNotifier
		if *githubOpenRuns {
			mode, modeErr := parseReviewRunMode(*githubReviewMode)
			bindings, bindingErr := parseGitHubHandlerBindings(githubHandlers)
			if modeErr != nil || bindingErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			var sourceAdapterIdentity evidence.SourceAdapterIdentity
			if *githubLocalDeterministicWorkers {
				source, sourceErr := buildGitHubSource(ctx, githubSourceConfig, getenv, artifactStore, daemonGitHubSourceClock)
				if sourceErr != nil {
					return nil, sourceErr
				}
				resources.closers = append(resources.closers, source)
				sourceAdapterIdentity = source.adapter.Identity()
				changeTask, changeErr := changehandler.NewHandler(artifactStore, daemonArtifactClock)
				analysisTask, analysisErr := analysishandler.NewHandler(artifactStore, daemonArtifactClock)
				memoryIndex := memorycore.NewLexicalIndex()
				memoryBackendIdentity := daemonComponentIdentity("empty-memory-index-v1")
				memoryTask, memoryErr := memoryhandler.NewHandler(artifactStore, daemonArtifactClock, memoryIndex, memoryBackendIdentity, *githubPolicyIdentity, "trestled", []string{"."}, 64, 50)
				if changeErr != nil || analysisErr != nil || memoryErr != nil {
					return nil, ErrInvalidDaemonConfiguration
				}
				localHandlers := []controlplane.TaskHandler{source.handler, changeTask, analysisTask, memoryTask}
				var pipeline runtimecatalog.PipelineCatalog
				if runtimeConfigured {
					inventory, configuration, configErr := loadRuntimeConfiguration(ctx, *runtimeRouteInventory, *runtimePolicy)
					if configErr != nil || configuration.ReviewPolicyIdentity() != *githubPolicyIdentity {
						return nil, ErrInvalidDaemonConfiguration
					}
					statusInventoryIdentity = inventory.Identity()
					statusPolicyIdentity = configuration.Identity()
					statusRouteCount = uint32(len(inventory.Candidates()))
					dispatchers, dispatcherErr := runtimecatalog.NewOpenAIRouteDispatcherCatalogWithOptions(inventory, configuration, environmentOpenAICredentialResolver{getenv: getenv}, runtimecatalog.OpenAICatalogOptions{Clock: daemonArtifactClock, HTTPClient: deps.modelHTTPClient, HTTPClientIdentity: deps.modelHTTPClientIdentity})
					generationAuthorizer, authErr := runtimecatalog.NewGenerationPolicyAuthorizerFromRuntimePolicy(configuration, inventory, auditLedger)
					verificationInventory, inventoryErr := runtimecatalog.NewStaticVerificationRouteInventory(inventory)
					if dispatcherErr != nil || authErr != nil || inventoryErr != nil {
						return nil, ErrInvalidDaemonConfiguration
					}
					verificationAuthorizer, verificationAuthErr := runtimecatalog.NewVerificationPolicyAuthorizerFromRuntimePolicy(configuration, verificationInventory, auditLedger, httpapi.SystemClock{})
					sanitizer := deps.generationSanitizer
					contextTask, contextErr := contexthandler.NewHandler(artifactStore, daemonArtifactClock, generationAuthorizer, sanitizer)
					generationTask, generationErr := modelhandler.NewGenerationHandler(artifactStore, dispatchers, auditLedger, daemonArtifactClock, sanitizer.ExpectedBinaryDigests())
					verificationTask, verificationErr := modelhandler.NewVerificationHandler(artifactStore, dispatchers, auditLedger, verificationAuthorizer, daemonArtifactClock, deps.verificationSanitizer)
					readinessTask, readinessErr := publicationhandler.NewReadinessHandler(artifactStore, diagnosticStore, daemonArtifactClock, configuration.ReviewPolicyIdentity(), configuration.Publication(), publicationContentScannerFromGenerationSanitizer(deps.generationSanitizer))
					if verificationAuthErr != nil || contextErr != nil || generationErr != nil || verificationErr != nil || readinessErr != nil {
						return nil, ErrInvalidDaemonConfiguration
					}
					localHandlers = append(localHandlers, contextTask, generationTask, verificationTask, readinessTask)
					pipeline, configErr = runtimecatalog.NewPipelineCatalog(mode, localHandlers)
					if configErr != nil {
						return nil, ErrInvalidDaemonConfiguration
					}
				}
				bindings, bindingErr = mergeGitHubHandlerBindings(bindings, localHandlers)
				if bindingErr != nil {
					return nil, ErrInvalidDaemonConfiguration
				}
				var catalog controlplane.TaskHandlerCatalog
				var catalogErr error
				if runtimeConfigured {
					catalog = pipeline.Catalog()
				} else {
					catalog, catalogErr = controlplane.NewTaskHandlerCatalog(localHandlers)
				}
				if catalogErr != nil {
					return nil, catalogErr
				}
				localSupervisor, supervisorErr := worker.NewRepositorySupervisor(journal, catalog, worker.RepositorySupervisorOptions{TenantID: *tenantID, RepositoryIDs: []string(repositories), WorkerIdentity: "trestled-local", PollInterval: time.Second, RenewalInterval: 10 * time.Second, ExecutionTimeout: 30 * time.Minute, Clock: httpapi.SystemClock{}})
				if supervisorErr != nil {
					return nil, supervisorErr
				}
				resources.supervisors = append(resources.supervisors, localSupervisor)
				resources.supervisorNames = append(resources.supervisorNames, "local_workers")
			}
			statusHandlers = make([]runtimeadmin.HandlerBinding, len(bindings))
			for index, binding := range bindings {
				statusHandlers[index] = runtimeadmin.HandlerBinding{Kind: binding.Kind.String(), Identity: binding.HandlerIdentity}
			}
			var planner *githubwebhook.PreparedPullRequestPlanner
			var plannerErr error
			if githubSourceConfig.brokerConfigured {
				planner, plannerErr = githubwebhook.NewPreparedPullRequestPlanner("github.com", *githubFullName, *githubPolicyIdentity, *githubPublisherID, mode, bindings, sourceAdapterIdentity, artifact.ClassificationRestricted, artifactProtection, 24*time.Hour)
			} else {
				planner, plannerErr = githubwebhook.NewBuiltInPreparedPullRequestPlanner("github.com", *githubFullName, *githubPolicyIdentity, *githubPublisherID, mode, bindings, artifact.ClassificationRestricted, artifactProtection, 24*time.Hour)
			}
			if plannerErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			processor, processorErr := webhook.NewPreparedProcessor(journal, planner, artifactStore)
			if refusals, recordsRefusals := inboxStore.(webhook.RefusalStore); recordsRefusals {
				refusalReader = daemonDeliveryRefusals{store: refusals, source: webhook.SourceGitHub, plannerIdentity: planner.Identity()}
			}
			if processorErr != nil {
				return nil, processorErr
			}
			supervisor, supervisorErr := webhook.NewSupervisor(inboxStore, processor, scope, webhook.SourceGitHub, webhook.SupervisorOptions{
				QueueCapacity: 1024, MaximumRetries: 5, RetryDelay: time.Second, Clock: daemonWebhookClock,
			})
			if supervisorErr != nil {
				return nil, supervisorErr
			}
			resources.supervisors = append(resources.supervisors, supervisor)
			resources.supervisorNames = append(resources.supervisorNames, "webhook_processing")
			notifier = supervisor
		}
		webhookHandler, handlerErr := githubwebhook.NewHTTPHandlerWithNotifier(scope, verifier, inbox, notifier, daemonWebhookClock, 64)
		if handlerErr != nil {
			return nil, handlerErr
		}
		githubHTTPHandler = webhookHandler
	}
	readiness := make([]<-chan struct{}, len(resources.supervisors))
	for index, supervisor := range resources.supervisors {
		readiness[index] = supervisor.Ready()
	}
	componentReadiness := readiness
	componentNames := append([]string(nil), resources.supervisorNames...)
	statusMode := runtimeadmin.ReviewDisabled
	if localGitConfigured {
		statusMode = runtimeadmin.ReviewLocal
	}
	if *githubOpenRuns {
		switch *githubReviewMode {
		case "local":
			statusMode = runtimeadmin.ReviewLocal
		case "advisory":
			statusMode = runtimeadmin.ReviewAdvisory
		case "required":
			statusMode = runtimeadmin.ReviewRequired
		}
	}
	statusConfiguration, err := runtimeadmin.NewConfiguration(runtimeadmin.ConfigurationOptions{
		TenantID: *tenantID, RepositoryIDs: []string(repositories), MetadataBackend: runtimeadmin.MetadataLocal,
		ArtifactBackend: runtimeadmin.ArtifactLocal, ArtifactProtection: runtimeadmin.Protection(artifactProtection.String()), NotificationBackend: runtimeadmin.NotificationProcessLocal, RateLimitBackend: runtimeadmin.RateLimitProcessLocal,
		ReviewMode: statusMode, WebhookIngress: githubConfigured, LocalWorkers: localGitConfigured || *githubLocalDeterministicWorkers,
		RouteInventoryIdentity: statusInventoryIdentity, RuntimePolicyIdentity: statusPolicyIdentity, RouteCount: statusRouteCount, Handlers: statusHandlers,
	})
	if err != nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	probes := make([]runtimeadmin.ReadinessProbe, len(componentReadiness))
	for index := range componentReadiness {
		probes[index] = runtimeadmin.ReadinessProbe{Name: componentNames[index], Ready: componentReadiness[index]}
	}
	statusService, err := runtimeadmin.NewService(statusConfiguration, probes)
	if err != nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	var requestLimiter, principalLimiter httpapi.RateLimiter
	requestLimiter, err = httpapi.NewMemoryRateLimiter(120, time.Minute, 10_000)
	if err == nil {
		principalLimiter, err = httpapi.NewMemoryRateLimiter(600, time.Minute, 1_024)
	}
	if err != nil {
		return nil, err
	}
	var apiHandler *httpapi.Server
	if localGitConfigured && *localFullReview {
		apiHandler, err = httpapi.NewServerWithLocalFullRuntimeAdministrationAndRateLimiters(journal, authenticator, daemonArtifactClock, diagnosticStore, taskNotificationQueue, statusService, requestLimiter, principalLimiter, localFullAdmitter)
	} else if localGitConfigured {
		apiHandler, err = httpapi.NewServerWithLocalDeterministicRuntimeAdministrationAndRateLimiters(journal, authenticator, httpapi.SystemClock{}, diagnosticStore, taskNotificationQueue, statusService, requestLimiter, principalLimiter, localReviewAdmitter)
	} else {
		apiHandler, err = httpapi.NewServerWithRuntimeAdministrationAndRateLimiters(journal, authenticator, httpapi.SystemClock{}, diagnosticStore, taskNotificationQueue, statusService, requestLimiter, principalLimiter)
	}
	if err != nil {
		return nil, err
	}
	apiHandler, err = apiHandler.WithProgressArtifacts(artifactStore)
	if err != nil {
		return nil, err
	}
	if refusalReader != nil {
		if apiHandler, err = apiHandler.WithDeliveryRefusals(refusalReader); err != nil {
			return nil, err
		}
	}
	var handler http.Handler = apiHandler
	if githubHTTPHandler != nil {
		mux := http.NewServeMux()
		mux.Handle("/webhooks/github", githubHTTPHandler)
		mux.Handle("/", apiHandler)
		handler = mux
	}
	healthHandler, err := runtimehealth.New(readiness)
	if err != nil {
		return nil, err
	}
	rootMux := http.NewServeMux()
	consoleHandler := webconsole.NewHandler()
	rootMux.Handle("/console", consoleHandler)
	rootMux.Handle("/console/", consoleHandler)
	rootMux.Handle("/healthz", healthHandler)
	rootMux.Handle("/readyz", healthHandler)
	rootMux.Handle("/", handler)
	handler = rootMux
	handler = resources.admission.wrap(handler)
	server := &http.Server{
		Addr: *listenAddress, Handler: handler,
		BaseContext:       func(net.Listener) context.Context { return runtimeContext },
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second,
		WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second,
		MaxHeaderBytes: 16 << 10, ErrorLog: log.New(stderr, "trestled: ", log.LstdFlags),
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13},
	}
	resources.server = server
	resources.journal = journal
	resources.inboxStore = inboxStore
	resources.diagnosticStore = diagnosticStore
	resources.artifactStore = artifactStore
	resources.tlsCertificate, resources.tlsKey = *tlsCertificate, *tlsKey
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	built = true
	return resources, nil
}
func runDaemon(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) error {
	if ctx == nil || stdout == nil {
		return ErrInvalidDaemonConfiguration
	}
	if ctx.Err() != nil {
		return nil
	}
	if len(args) > 0 && args[0] == "build-info" {
		if len(args) != 1 {
			return ErrInvalidDaemonConfiguration
		}
		return buildinfo.Write(stdout, "trestled")
	}
	if len(args) > 0 && (args[0] == "recovery-point" || args[0] == "verify-restore") {
		return runLocalRecoveryCommand(ctx, args, stdout, stderr)
	}
	d, err := buildDaemon(ctx, args, getenv, stderr)
	if err != nil {
		if onlyDaemonStartupCancellation(err, ctx.Err()) {
			return nil
		}
		return err
	}
	return d.run(ctx, stdout)
}

func (d *daemon) run(ctx context.Context, stdout io.Writer) (runErr error) {
	defer func() { runErr = errors.Join(runErr, d.Close()) }()
	if ctx.Err() != nil {
		return nil
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", d.server.Addr)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "trestled listening on %s\n", listener.Addr().String()); err != nil {
		return errors.Join(err, listener.Close())
	}
	d.closeMu.Lock()
	if d.finishStarted || d.runStarted {
		d.closeMu.Unlock()
		return errors.Join(ErrDaemonRuntimeUnavailable, listener.Close())
	}
	d.runStarted = true
	if d.runtimeContext == nil {
		d.runtimeContext, d.stopRuntime = context.WithCancel(context.Background())
	}
	returned := make(chan struct{}, len(d.supervisors)+1)
	start := func(run func() error) {
		result := &daemonRuntimeResult{done: make(chan struct{})}
		d.runtimeResults = append(d.runtimeResults, result)
		go func() {
			result.err = run()
			if d.runtimeContext.Err() == nil && (result.err == nil || onlyDaemonStartupCancellation(result.err, context.Canceled) || onlyDaemonStartupCancellation(result.err, http.ErrServerClosed) || onlyDaemonStartupCancellation(result.err, worker.ErrRepositorySupervisorShutdown)) {
				result.err = errors.Join(ErrDaemonRuntimeUnavailable, result.err)
			}
			close(result.done)
			returned <- struct{}{}
		}()
	}
	start(func() error {
		if d.tlsCertificate != "" {
			return d.server.ServeTLS(listener, d.tlsCertificate, d.tlsKey)
		}
		return d.server.Serve(listener)
	})
	for _, supervisor := range d.supervisors {
		start(func() error { return supervisor.Run(d.runtimeContext) })
	}
	d.closeMu.Unlock()
	select {
	case <-returned:
	case <-ctx.Done():
	}
	return nil
}

// Ignore a build interruption only when the entire bounded error tree is
// exactly the context cancellation. A joined cleanup failure remains visible.
func onlyDaemonStartupCancellation(err, cancellation error) bool {
	if err == nil || cancellation == nil {
		return false
	}
	visited := 0
	var check func(error, int) (bool, bool)
	check = func(current error, depth int) (bool, bool) {
		if current == nil || depth >= 64 || visited >= 256 {
			return false, false
		}
		visited++
		if _, incomplete := current.(*daemonShutdownIncomplete); incomplete {
			return false, false
		}
		if children, ok := current.(interface{ Unwrap() []error }); ok {
			values := children.Unwrap()
			any := false
			for _, child := range values {
				if child == nil {
					continue
				}
				matched, valid := check(child, depth+1)
				if !valid || !matched {
					return false, false
				}
				any = true
			}
			return any, any
		}
		if wrapper, ok := current.(interface{ Unwrap() error }); ok {
			child := wrapper.Unwrap()
			if child == nil {
				return false, false
			}
			return check(child, depth+1)
		}
		return current == cancellation, true
	}
	matched, valid := check(err, 0)
	return valid && matched
}

func (d *daemon) Close() error {
	if d == nil {
		return nil
	}
	timeout := d.handlerDrainTimeout
	if timeout <= 0 {
		timeout = daemonShutdownTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.Finish(ctx)
}

func parseReviewRunMode(value string) (controlplane.ReviewRunMode, error) {
	for mode := controlplane.ReviewRunLocal; mode <= controlplane.ReviewRunRequired; mode++ {
		if mode.String() == value {
			return mode, nil
		}
	}
	return 0, ErrInvalidDaemonConfiguration
}
func parseGitHubHandlerBindings(values []string) ([]githubwebhook.TaskHandlerBinding, error) {
	bindings := make([]githubwebhook.TaskHandlerBinding, 0, len(values))
	seen := make(map[controlplane.TaskKind]bool, len(values))
	for _, value := range values {
		name, identity, found := strings.Cut(value, "=")
		kind := parseTaskKind(name)
		if !found || kind == 0 || seen[kind] || controlplane.ValidateHandlerIdentity(identity) != nil {
			return nil, ErrInvalidDaemonConfiguration
		}
		seen[kind] = true
		bindings = append(bindings, githubwebhook.TaskHandlerBinding{Kind: kind, HandlerIdentity: identity})
	}
	return bindings, nil
}
func parseTaskKind(value string) controlplane.TaskKind {
	for kind := controlplane.TaskAcquireSource; kind <= controlplane.TaskPublishResult; kind++ {
		if kind.String() == value {
			return kind
		}
	}
	return 0
}

func daemonNonzeroDigest(value string) bool {
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return false
	}
	for _, entry := range decoded {
		if entry != 0 {
			return true
		}
	}
	return false
}

func loadRuntimeConfiguration(ctx context.Context, inventoryPath, policyPath string) (runtimeconfig.RouteInventory, runtimeconfig.RuntimePolicy, error) {
	inventoryFile, err := openRuntimeConfigurationFile(inventoryPath)
	if err != nil {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, err
	}
	inventory, decodeErr := runtimeconfig.DecodeRouteInventory(ctx, inventoryFile)
	closeErr := inventoryFile.Close()
	if decodeErr != nil || closeErr != nil {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, ErrInvalidDaemonConfiguration
	}
	policyFile, err := openRuntimeConfigurationFile(policyPath)
	if err != nil {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, err
	}
	configuration, decodeErr := runtimeconfig.DecodeRuntimePolicy(ctx, policyFile, inventory)
	closeErr = policyFile.Close()
	if decodeErr != nil || closeErr != nil {
		return runtimeconfig.RouteInventory{}, runtimeconfig.RuntimePolicy{}, ErrInvalidDaemonConfiguration
	}
	return inventory, configuration, nil
}
func openRuntimeConfigurationFile(path string) (*os.File, error) {
	file, err := fileauthority.OpenReadOnly(path)
	if err != nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	return file, nil
}

type environmentOpenAICredentialResolver struct{ getenv func(string) string }

func (r environmentOpenAICredentialResolver) ResolveOpenAICredentials(reference string) (openaiadapter.APIKeyProvider, error) {
	if r.getenv == nil || reference == "" {
		return nil, ErrInvalidDaemonConfiguration
	}
	return environmentOpenAIKeyProvider{reference: reference, getenv: r.getenv}, nil
}

type environmentOpenAIKeyProvider struct {
	reference string
	getenv    func(string) string
}

func (p environmentOpenAIKeyProvider) Retrieve(ctx context.Context) (openaiadapter.APIKey, error) {
	if ctx == nil || ctx.Err() != nil || p.getenv == nil {
		return openaiadapter.APIKey{}, openaiadapter.ErrCredentialsUnavailable
	}
	value := p.getenv(p.reference)
	if value == "" {
		return openaiadapter.APIKey{}, openaiadapter.ErrCredentialsUnavailable
	}
	key, err := openaiadapter.NewAPIKey([]byte(value))
	if err != nil {
		return openaiadapter.APIKey{}, openaiadapter.ErrCredentialsUnavailable
	}
	return key, nil
}

type staticGitHubTokenProvider struct{ token githubsource.Token }

func (p staticGitHubTokenProvider) Retrieve(ctx context.Context) (githubsource.Token, error) {
	if ctx == nil || ctx.Err() != nil {
		return githubsource.Token{}, ErrDaemonRuntimeUnavailable
	}
	return p.token, nil
}
func daemonComponentIdentity(name string) string {
	digest := sha256.Sum256([]byte("open-trestle/daemon/" + name))
	return hex.EncodeToString(digest[:])
}
func mergeGitHubHandlerBindings(bindings []githubwebhook.TaskHandlerBinding, handlers []controlplane.TaskHandler) ([]githubwebhook.TaskHandlerBinding, error) {
	merged := append([]githubwebhook.TaskHandlerBinding(nil), bindings...)
	byKind := make(map[controlplane.TaskKind]string, len(merged))
	for _, binding := range merged {
		byKind[binding.Kind] = binding.HandlerIdentity
	}
	for _, handler := range handlers {
		if existing := byKind[handler.Kind()]; existing != "" && existing != handler.HandlerIdentity() {
			return nil, ErrInvalidDaemonConfiguration
		} else if existing == "" {
			merged = append(merged, githubwebhook.TaskHandlerBinding{Kind: handler.Kind(), HandlerIdentity: handler.HandlerIdentity()})
			byKind[handler.Kind()] = handler.HandlerIdentity()
		}
	}
	return merged, nil
}

func daemonLoopbackAddress(address string) bool {
	host, _, err := net.SplitHostPort(address)
	parsed := net.ParseIP(host)
	return err == nil && parsed != nil && parsed.IsLoopback()
}

func openDaemonLocalGitRoot(path string, repository evidence.RepositoryIdentity) (*os.Root, string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil || filepath.Clean(absolute) != absolute || repository.Identity() == "" {
		return nil, "", ErrInvalidDaemonConfiguration
	}
	before, err := os.Lstat(absolute)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, "", ErrInvalidDaemonConfiguration
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil || resolved != absolute {
		return nil, "", ErrInvalidDaemonConfiguration
	}
	root, err := os.OpenRoot(absolute)
	if err != nil {
		return nil, "", ErrInvalidDaemonConfiguration
	}
	opened, err := root.Stat(".")
	after, afterErr := os.Lstat(absolute)
	if err != nil || afterErr != nil || !opened.IsDir() || !os.SameFile(before, opened) || !os.SameFile(opened, after) {
		_ = root.Close()
		return nil, "", ErrInvalidDaemonConfiguration
	}
	encoded, _ := json.Marshal(struct {
		Contract   string `json:"contract"`
		Version    int    `json:"version"`
		Path       string `json:"path"`
		Repository string `json:"repository"`
		Profile    string `json:"profile"`
	}{"open-trestle/local-git-source-root", 1, absolute, repository.Identity(), string(scm.LocalGitObjectStoreProfileLooseOnly)})
	digest := sha256.Sum256(encoded)
	return root, hex.EncodeToString(digest[:]), nil
}

func validListenAddress(address, certificate, key string) bool {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return false
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber > 65535 {
		return false
	}
	tlsEnabled := certificate != "" && key != ""
	if (certificate == "") != (key == "") {
		return false
	}
	if tlsEnabled {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
func regularFile(path string, private bool) bool {
	information, err := os.Lstat(path)
	if err != nil || !information.Mode().IsRegular() {
		return false
	}
	return !private || information.Mode().Perm()&0o077 == 0
}

func containsRepository(repositories []string, value string) bool {
	for _, repository := range repositories {
		if repository == value {
			return true
		}
	}
	return false
}
func sameDaemonCredential(left []byte, right string) bool {
	if right == "" || len(left) != len(right) {
		return false
	}
	rightBytes := []byte(right)
	defer clear(rightBytes)
	return subtle.ConstantTimeCompare(left, rightBytes) == 1
}

// checkLocalFullReviewStartupPlans rejects active local work bound to incompatible context or full-review analysis handlers.
func checkLocalFullReviewStartupPlans(ctx context.Context, journal controlplane.RunJournal, tenantID string, repositories []string, contextHandlerIdentity, analysisHandlerIdentity string) error {
	const pageSize = 100
	const maximumPlansPerRepository = 10_000
	coordinator, err := controlplane.NewCoordinator(journal)
	if err != nil {
		return err
	}
	for _, repositoryID := range repositories {
		after := ""
		for examined := 0; ; {
			plans, err := journal.ListPlans(ctx, tenantID, repositoryID, after, pageSize)
			if err != nil {
				return err
			}
			if examined+len(plans) > maximumPlansPerRepository {
				return ErrDaemonRuntimeUnavailable
			}
			for _, plan := range plans {
				if plan.Scope().ReviewRunID() <= after {
					return ErrDaemonRuntimeUnavailable
				}
				_, state, err := coordinator.Resume(ctx, plan.Scope())
				if err != nil {
					return err
				}
				if state.Status() != controlplane.ReviewRunActive || plan.Mode() != controlplane.ReviewRunLocal {
					continue
				}
				fullReview := isLocalFullReviewPlan(plan)
				for _, definition := range plan.Tasks() {
					task, found := state.Task(definition.Key())
					if !found {
						return ErrDaemonRuntimeUnavailable
					}
					if definition.Kind() == controlplane.TaskAssembleContext && task.Status() != controlplane.TaskRuntimeSucceeded && task.Status() != controlplane.TaskRuntimeSkipped && definition.HandlerIdentity() != contextHandlerIdentity || fullReview && definition.Kind() == controlplane.TaskInspectDeterministic && definition.HandlerIdentity() != analysisHandlerIdentity {
						return fmt.Errorf("%w: tenant %s repository %s run %s", ErrDaemonPlanIncompatible, tenantID, repositoryID, plan.Scope().ReviewRunID())
					}
				}
			}
			examined += len(plans)
			if len(plans) < pageSize {
				break
			}
			after = plans[len(plans)-1].Scope().ReviewRunID()
		}
	}
	return nil
}

func isLocalFullReviewPlan(plan controlplane.ReviewRunPlan) bool {
	if plan.Mode() != controlplane.ReviewRunLocal || plan.TaskCount() != 9 {
		return false
	}
	for _, expected := range []struct {
		key  string
		kind controlplane.TaskKind
	}{
		{"source-base", controlplane.TaskAcquireSource},
		{"source-head", controlplane.TaskAcquireSource},
		{"change", controlplane.TaskBuildChange},
		{"analysis", controlplane.TaskInspectDeterministic},
		{"memory", controlplane.TaskRetrieveContext},
		{"context", controlplane.TaskAssembleContext},
		{"candidates", controlplane.TaskGenerateCandidates},
		{"verification", controlplane.TaskVerifyCandidates},
		{"readiness", controlplane.TaskEvaluatePublication},
	} {
		task, found := plan.Task(expected.key)
		if !found || task.Kind() != expected.kind {
			return false
		}
	}
	return true
}

// recoverLocalFullReviewPrepared resolves journaled content-free abstentions before
// any supervisor or listener can settle an expired one-attempt context lease.
func recoverLocalFullReviewPrepared(ctx context.Context, journal controlplane.RunJournal, store artifact.Store, coordinator *controlplane.Coordinator, tenantID string, repositories []string, at time.Time) error {
	const pageSize = 100
	const maximumPlansPerRepository = 10_000
	for _, repositoryID := range repositories {
		after := ""
		for examined := 0; ; {
			plans, err := journal.ListPlans(ctx, tenantID, repositoryID, after, pageSize)
			if err != nil {
				return err
			}
			if examined+len(plans) > maximumPlansPerRepository {
				return ErrDaemonRuntimeUnavailable
			}
			for _, plan := range plans {
				if plan.Scope().ReviewRunID() <= after {
					return ErrDaemonRuntimeUnavailable
				}
				if plan.Mode() != controlplane.ReviewRunLocal {
					continue
				}
				if err := contexthandler.RecoverPreparedContextAbstention(ctx, coordinator, store, plan, at); err != nil {
					return fmt.Errorf("%w: tenant %s repository %s run %s: %v", ErrDaemonRuntimeUnavailable, tenantID, repositoryID, plan.Scope().ReviewRunID(), err)
				}
				if err := contexthandler.RecoverOwnerPreparedContextAbstention(ctx, coordinator, store, plan, at); err != nil {
					return fmt.Errorf("%w: tenant %s repository %s run %s: %v", ErrDaemonRuntimeUnavailable, tenantID, repositoryID, plan.Scope().ReviewRunID(), err)
				}
			}
			examined += len(plans)
			if len(plans) < pageSize {
				break
			}
			after = plans[len(plans)-1].Scope().ReviewRunID()
		}
	}
	return nil
}
