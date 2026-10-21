package main

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"database/sql"
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

	"github.com/aws/aws-sdk-go-v2/aws"
	awskmsclient "github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/georgejieh/open-trestle/adapters/keys/awskms"
	openaiadapter "github.com/georgejieh/open-trestle/adapters/providers/openai"
	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	s3store "github.com/georgejieh/open-trestle/adapters/storage/s3"
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
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	memorycore "github.com/georgejieh/open-trestle/internal/memory"
	providerconfig "github.com/georgejieh/open-trestle/internal/provider"
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
	journal                controlplane.RunJournal
	inboxStore             webhook.Store
	diagnosticStore        diagnostics.Store
	artifactStore          artifact.RetentionStore
	supervisors            []daemonSupervisor
	supervisorNames        []string
	closers                []io.Closer
	closeOnce              sync.Once
	closeErr               error
	tlsCertificate, tlsKey string
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := runDaemon(ctx, os.Args[1:], os.Getenv, os.Stdout, os.Stderr)
	stop()
	if err != nil {
		fmt.Fprintf(os.Stderr, "trestled: %v\n", err)
		os.Exit(1)
	}
}
func newDaemonRemoteStorageTransport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DisableKeepAlives = true
	transport.ForceAttemptHTTP2 = false
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	transport.Protocols = protocols
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	transport.TLSClientConfig.NextProtos = []string{"http/1.1"}
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	transport.ResponseHeaderTimeout = 10 * time.Second
	transport.MaxResponseHeaderBytes = 1 << 20
	return transport
}

type daemonCloserFunc func() error

func (f daemonCloserFunc) Close() error { return f() }

func buildDaemon(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) (*daemon, error) {
	return buildDaemonWithDependencies(ctx, args, getenv, stderr, daemonDependencies{openPostgres: postgresstore.Open, clock: httpapi.SystemClock{}, generationSanitizer: reviewcore.NewFixedGenerationRequestSanitizer(), verificationSanitizer: reviewcore.NewFixedVerificationRequestSanitizer()})
}
func publicationContentScannerFromGenerationSanitizer(sanitizer reviewcore.GenerationRequestSanitizer) reviewcore.PublicationContentScanner {
	if provider, ok := sanitizer.(interface {
		PublicationContentScanner() reviewcore.PublicationContentScanner
	}); ok {
		return provider.PublicationContentScanner()
	}
	return reviewcore.NewFixedPublicationContentScanner()
}

func buildDaemonWithDependencies(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer, deps daemonDependencies) (result *daemon, err error) {
	if daemonNilDependency(ctx) || getenv == nil || daemonNilDependency(stderr) || deps.openPostgres == nil || daemonNilDependency(deps.clock) {
		return nil, ErrInvalidDaemonConfiguration
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if daemonNilDependency(deps.generationSanitizer) {
		deps.generationSanitizer = reviewcore.NewFixedGenerationRequestSanitizer()
	}
	if daemonNilDependency(deps.verificationSanitizer) {
		deps.verificationSanitizer = reviewcore.NewFixedVerificationRequestSanitizer()
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
	metadataStore := flags.String("metadata-store", "local", "metadata store: local or postgres")
	postgresAuthorityIdentity := flags.String("postgres-authority-identity", "", "non-secret PostgreSQL publication authority identity")
	postgresDatabaseAuthorityIdentity := flags.String("postgres-database-authority-identity", "", "expected runtime-role PostgreSQL database authority identity")
	applyMigrations := flags.Bool("apply-migrations", false, "apply PostgreSQL migrations before startup")
	artifactStoreMode := flags.String("artifact-store", "local", "artifact store: local or s3")
	artifactErasureMode := flags.String("artifact-erasure-mode", "legacy", "artifact erasure mode: legacy or budgeted")
	erasurePolicyPath := flags.String("erasure-policy", "", "protected artifact erasure policy path")
	s3ErasureTrustedCAPath := flags.String("s3-erasure-trusted-ca", "", "protected S3 erasure CA PEM path")
	s3Endpoint := flags.String("s3-endpoint", "", "path-style S3 endpoint")
	s3Region := flags.String("s3-region", "", "S3 region")
	s3Bucket := flags.String("s3-bucket", "", "S3 artifact bucket")
	s3Prefix := flags.String("s3-prefix", "open-trestle", "S3 object prefix")
	kmsRegion := flags.String("kms-region", "", "AWS KMS region")
	kmsKeyARN := flags.String("kms-key-arn", "", "exact tenant AWS KMS key ARN")
	kmsEndpoint := flags.String("kms-endpoint", "", "optional AWS KMS endpoint")
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
	githubEnablePublication := flags.Bool("github-enable-publication", false, "enable repository-policy-authorized GitHub publication")
	githubPublicationPolicyIdentity := flags.String("github-publication-policy-identity", "", "publication effect policy identity")
	githubPublicationPrincipalIdentity := flags.String("github-publication-principal-identity", "", "publication authority principal identity")
	githubPublicationAuthorizationTTL := flags.Duration("github-publication-authorization-ttl", 10*time.Minute, "lifetime of a scope-bound publication authorization")
	githubReviewMode := flags.String("github-review-mode", "advisory", "review mode: local, advisory, or required")
	var githubHandlers repositoryFlags
	flags.Var(&githubHandlers, "github-handler", "task kind=handler identity; repeat for each required kind")
	var repositories repositoryFlags
	flags.Var(&repositories, "repository", "authorized repository identifier; repeat for each repository")
	if err := flags.Parse(args); err != nil {
		return nil, ErrInvalidDaemonConfiguration
	}
	if *localModelWorkers && (!*localFullReview || *setupState == "" || *localGitObjectsRoot == "" || *runtimeRouteInventory == "" || *runtimePolicy == "" || *githubOpenRuns || *githubLocalDeterministicWorkers || *githubEnablePublication || *metadataStore != "local" || *artifactStoreMode != "local" || !daemonLoopbackAddress(*listenAddress)) {
		return nil, ErrInvalidDaemonConfiguration
	}
	credential := getenv("OPEN_TRESTLE_API_TOKEN")
	observerCredential := getenv("OPEN_TRESTLE_OBSERVER_TOKEN")
	postgresURL := getenv("OPEN_TRESTLE_POSTGRES_URL")
	migrationURL := getenv("OPEN_TRESTLE_POSTGRES_MIGRATION_URL")
	awsAccessKey := getenv("OPEN_TRESTLE_AWS_ACCESS_KEY_ID")
	awsSecretKey := getenv("OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY")
	awsSessionToken := getenv("OPEN_TRESTLE_AWS_SESSION_TOKEN")
	s3AccessKey := getenv("OPEN_TRESTLE_S3_ACCESS_KEY_ID")
	s3SecretKey := getenv("OPEN_TRESTLE_S3_SECRET_ACCESS_KEY")
	s3SessionToken := getenv("OPEN_TRESTLE_S3_SESSION_TOKEN")
	budgetedArtifactErasure := *artifactErasureMode == "budgeted"
	validArtifactErasureMode := *artifactErasureMode == "legacy" || budgetedArtifactErasure
	if !validArtifactErasureMode || !budgetedArtifactErasure && (*erasurePolicyPath != "" || *s3ErasureTrustedCAPath != "") {
		return nil, ErrInvalidDaemonConfiguration
	}
	if budgetedArtifactErasure && (*erasurePolicyPath == "" || *s3ErasureTrustedCAPath == "" || *metadataStore != "postgres" || *artifactStoreMode != "s3" || *applyMigrations || migrationURL != "") {
		return nil, ErrInvalidDaemonConfiguration
	}
	validStore := *metadataStore == "local" || *metadataStore == "postgres"
	validPostgres := *metadataStore != "postgres" || postgresURL != "" && daemonNonzeroDigest(*postgresDatabaseAuthorityIdentity) && (*applyMigrations == (migrationURL != ""))
	validLocal := *metadataStore != "local" || postgresURL == "" && migrationURL == "" && !*applyMigrations && *postgresAuthorityIdentity == "" && *postgresDatabaseAuthorityIdentity == ""
	if !validStore || !validPostgres || !validLocal {
		return nil, ErrInvalidDaemonConfiguration
	}
	if *postgresAuthorityIdentity != "" && !daemonNonzeroDigest(*postgresAuthorityIdentity) || *postgresDatabaseAuthorityIdentity != "" && !daemonNonzeroDigest(*postgresDatabaseAuthorityIdentity) {
		return nil, ErrInvalidDaemonConfiguration
	}
	remoteValues := *s3Endpoint != "" || *s3Region != "" || *s3Bucket != "" || *kmsRegion != "" || *kmsKeyARN != "" || *kmsEndpoint != "" || awsAccessKey != "" || awsSecretKey != "" || awsSessionToken != "" || s3AccessKey != "" || s3SecretKey != "" || s3SessionToken != ""
	validArtifactMode := *artifactStoreMode == "local" || *artifactStoreMode == "s3"
	validS3 := *artifactStoreMode != "s3" || *metadataStore == "postgres" && *s3Endpoint != "" && *s3Region != "" && *s3Bucket != "" && *kmsRegion != "" && *kmsKeyARN != "" && s3AccessKey != "" && s3SecretKey != "" && awsAccessKey != "" && awsSecretKey != "" && s3AccessKey != awsAccessKey && (*kmsEndpoint == "" || validSecureServiceEndpoint(*kmsEndpoint))
	validLocalArtifact := *artifactStoreMode != "local" || !remoteValues
	if !validArtifactMode || !validS3 || !validLocalArtifact {
		return nil, ErrInvalidDaemonConfiguration
	}
	githubSecretValue := getenv("OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET")
	githubSecret := []byte(githubSecretValue)
	githubSecretValue = ""
	defer clear(githubSecret)
	githubAPIToken := getenv("OPEN_TRESTLE_GITHUB_API_TOKEN")
	githubSourceBrokerConfigPath := getenv("OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG")
	githubConfigured := len(githubSecret) != 0 || *githubRepository != "" || *githubKeyID != ""
	if githubConfigured {
		githubSetupToken := getenv("OPEN_TRESTLE_GITHUB_SETUP_TOKEN")
		setupServiceToken := getenv("OPEN_TRESTLE_SETUP_TOKEN")
		githubScope, scopeErr := webhook.NewRepositoryScope(*tenantID, *githubRepository)
		_, verifierErr := githubwebhook.VerifierConfigurationIdentity(githubScope, *githubKeyID)
		invalid := githubwebhook.ValidateRuntimeSecret(githubSecret) != nil || *githubRepository == "" || scopeErr != nil || verifierErr != nil || !containsRepository(repositories, *githubRepository) || sameDaemonCredential(githubSecret, credential) || sameDaemonCredential(githubSecret, observerCredential) || sameDaemonCredential(githubSecret, githubAPIToken) || sameDaemonCredential(githubSecret, githubSetupToken) || sameDaemonCredential(githubSecret, setupServiceToken)
		githubSetupToken = ""
		setupServiceToken = ""
		if invalid {
			return nil, ErrInvalidDaemonConfiguration
		}
	}
	githubSecretDigest := sha256.Sum256(githubSecret)
	plannerConfigured := *githubOpenRuns || *githubLocalDeterministicWorkers || *githubFullName != "" || *githubPolicyIdentity != "" || len(githubHandlers) != 0 || *githubReviewMode != "advisory" || *githubPublisherID != githubwebhook.DefaultGitHubPublisherID || *githubEnablePublication || *githubPublicationPolicyIdentity != "" || *githubPublicationPrincipalIdentity != "" || *githubPublicationAuthorizationTTL != 10*time.Minute
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
	if localGitConfigured && (!localGitComplete || githubConfigured || plannerConfigured || runtimeConfigured != *localFullReview || *metadataStore != "local" || *artifactStoreMode != "local" || len(repositories) != 1 || *tlsCertificate != "" || *tlsKey != "" || !daemonLoopbackAddress(*listenAddress)) {
		return nil, ErrInvalidDaemonConfiguration
	}
	if *metadataStore == "local" && *setupState != "" {
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
	publicationConfigured := *githubEnablePublication || *githubPublicationPolicyIdentity != "" || *githubPublicationPrincipalIdentity != "" || *githubPublicationAuthorizationTTL != 10*time.Minute
	if publicationConfigured != *githubEnablePublication || *githubEnablePublication && (!runtimeConfigured || *githubReviewMode != "required" || *metadataStore != "postgres" || !daemonNonzeroDigest(*postgresAuthorityIdentity) || !daemonNonzeroDigest(*githubPublicationPolicyIdentity) || !daemonNonzeroDigest(*githubPublicationPrincipalIdentity) || *githubPublicationAuthorizationTTL < time.Minute || *githubPublicationAuthorizationTTL > 24*time.Hour || *githubPublicationAuthorizationTTL%time.Millisecond != 0) {
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
	resources := &daemon{}
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
	var budgetedClock daemonErasureClock
	var budgetedStartupSample time.Time
	if budgetedArtifactErasure {
		budgetedClock = daemonErasureClock{inner: deps.clock}
		budgetedStartupSample = budgetedClock.Now()
		if !daemonValidErasureClockSample(budgetedStartupSample) {
			return nil, ErrInvalidDaemonConfiguration
		}
		daemonArtifactClock = budgetedClock
		daemonGitHubSourceClock = budgetedClock
		daemonWebhookClock = budgetedClock
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
	if *metadataStore == "local" && *artifactStoreMode != "local" {
		if mixedErr := rejectMixedLocalOwner(*stateDirectory); mixedErr != nil {
			return nil, mixedErr
		}
	}
	var journal controlplane.RunJournal
	var packetOwner *localPacketOwner
	var artifactStore artifact.RetentionStore
	var artifactKeyProvider artifact.EnvelopeKeyProvider
	var budgetedPolicy artifact.ProtectedErasurePolicy
	var budgetedErasureBackend *s3store.ErasureBackend
	budgetedErasureConstructed := false
	artifactProtection := artifact.ProtectionProcessPrivate
	if *artifactStoreMode == "local" && *metadataStore == "local" {
		active, fileJournal, bootOwner, gateErr := startLocalSourceOwnerGate(ctx, resources, *stateDirectory, *setupState, &localSetupPlan, *tenantID, repositories[0], localRepository, localObjectsRoot, localObjectStore, localSourceAdapter, localRootDigest, daemonArtifactClock)
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
	} else if *artifactStoreMode == "local" {
		physicalArtifacts, storeErr := artifact.NewFileStore(filepath.Join(*stateDirectory, "artifacts"))
		if storeErr != nil {
			return nil, storeErr
		}
		resources.closers = append(resources.closers, physicalArtifacts)
		artifactStore = physicalArtifacts
	} else {
		s3Credentials, err := s3store.NewCredentials(s3AccessKey, s3SecretKey, s3SessionToken)
		if err != nil {
			return nil, ErrInvalidDaemonConfiguration
		}
		var s3Backend *s3store.Backend
		if !budgetedArtifactErasure {
			s3CredentialProvider, err := s3store.NewStaticCredentialsProvider(s3Credentials)
			if err != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			s3Transport := newDaemonRemoteStorageTransport()
			s3HTTPClient := &http.Client{Transport: s3Transport, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidDaemonConfiguration }}
			s3Backend, err = s3store.New(s3store.Config{Endpoint: *s3Endpoint, Region: *s3Region, Bucket: *s3Bucket, Credentials: s3CredentialProvider, HTTPClient: s3HTTPClient})
			if err != nil {
				s3Transport.CloseIdleConnections()
				return nil, ErrInvalidDaemonConfiguration
			}
			resources.closers = append(resources.closers, daemonCloserFunc(func() error { s3Transport.CloseIdleConnections(); return nil }))
		}
		transport := newDaemonRemoteStorageTransport()
		kmsHTTPClient := &http.Client{
			Transport:     boundedResponseTransport{inner: transport, maximum: 1 << 20},
			Timeout:       30 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return ErrInvalidDaemonConfiguration },
		}
		kmsCredentials := aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{AccessKeyID: awsAccessKey, SecretAccessKey: awsSecretKey, SessionToken: awsSessionToken, Source: "open-trestle-explicit"}, nil
		}))
		awsConfiguration := aws.Config{
			Region: *kmsRegion, Credentials: kmsCredentials, HTTPClient: kmsHTTPClient,
			RetryMaxAttempts: 3, RetryMode: aws.RetryModeStandard,
		}
		kmsClient := awskmsclient.NewFromConfig(awsConfiguration, func(options *awskmsclient.Options) {
			if *kmsEndpoint != "" {
				options.BaseEndpoint = aws.String(*kmsEndpoint)
			}
		})
		keyProvider, err := awskms.New(kmsClient, *kmsRegion, []awskms.TenantKey{{TenantID: *tenantID, KeyARN: *kmsKeyARN}})
		if err != nil {
			transport.CloseIdleConnections()
			return nil, ErrInvalidDaemonConfiguration
		}
		resources.closers = append(resources.closers, daemonCloserFunc(func() error { transport.CloseIdleConnections(); return nil }))
		artifactKeyProvider = keyProvider
		if budgetedArtifactErasure {
			policy, policyErr := artifact.LoadProtectedErasurePolicy(ctx, *erasurePolicyPath)
			if policyErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			trustedCAPEM, caErr := loadProtectedErasureTrustedCA(ctx, *s3ErasureTrustedCAPath)
			if caErr != nil {
				return nil, caErr
			}
			erasureBackend, backendErr := s3store.NewErasureBackend(s3store.ErasureConfig{Endpoint: *s3Endpoint, Region: *s3Region, Bucket: *s3Bucket, Credentials: s3Credentials, TrustedCAPEM: trustedCAPEM})
			clear(trustedCAPEM)
			if backendErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			if err := validateBudgetedErasureStartupPolicy(policy, erasureBackend, *postgresDatabaseAuthorityIdentity, *s3Prefix, budgetedStartupSample); err != nil {
				return nil, err
			}
			budgetedPolicy = policy
			budgetedErasureBackend = erasureBackend
		} else {
			envelopeStore, err := artifact.NewEnvelopeStore(*s3Prefix, s3Backend, keyProvider)
			if err != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			artifactStore = envelopeStore
		}
		artifactProtection = artifact.ProtectionEnvelopeEncrypted
	}
	var taskNotificationQueue controlplane.TaskNotificationQueue
	var diagnosticStore diagnostics.Store
	var auditLedger audit.Ledger
	var publicationAttemptGuard reviewcore.PublicationAttemptGuard
	var postgresDatabase *sql.DB
	if *metadataStore == "local" {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if *artifactStoreMode != "local" {
			fileJournal, journalErr := controlplane.NewFileRunJournal(*stateDirectory)
			if journalErr != nil {
				return nil, journalErr
			}
			resources.closers = append(resources.closers, fileJournal)
			if *artifactStoreMode != "local" {
				if mixedErr := fileJournal.WithOwnedRoot(ctx, func(root *os.Root) error {
					if err := noGitOwnerAbsent(root); err != nil {
						return err
					}
					if _, err := fileJournal.InspectStartupInventory(ctx); err != nil {
						return localStartupInventoryError(err)
					}
					return noGitOwnerAbsent(root)
				}); mixedErr != nil {
					return nil, mixedErr
				}
			} else if _, inventoryErr := fileJournal.InspectStartupInventory(ctx); inventoryErr != nil {
				return nil, localStartupInventoryError(inventoryErr)
			}
			journal = fileJournal
		}
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
	} else {
		if *applyMigrations {
			migrationContext, cancel := context.WithTimeout(ctx, 45*time.Second)
			migrationDatabase, openErr := deps.openPostgres(migrationContext, migrationURL, postgresstore.PoolOptions{})
			if openErr == nil {
				openErr = postgresstore.ApplyMigrations(migrationContext, migrationDatabase)
			}
			if migrationDatabase != nil {
				_ = migrationDatabase.Close()
			}
			cancel()
			if openErr != nil {
				return nil, openErr
			}
		}
		connectContext, cancel := context.WithTimeout(ctx, 15*time.Second)
		database, err := deps.openPostgres(connectContext, postgresURL, postgresstore.PoolOptions{})
		if err == nil {
			var databaseAuthority postgresstore.VerifiedDatabaseAuthority
			databaseAuthority, err = postgresstore.VerifyDatabaseStorageAuthority(connectContext, database)
			if err == nil && databaseAuthority.Identity() != *postgresDatabaseAuthorityIdentity {
				err = postgresstore.ErrDatabaseAuthorityMismatch
			}
		}
		cancel()
		if err != nil {
			if database != nil {
				_ = database.Close()
			}
			return nil, err
		}
		resources.closers = append(resources.closers, database)
		postgresDatabase = database
		var postgresJournal *postgresstore.Store
		if *postgresAuthorityIdentity != "" {
			authorityContext, authorityCancel := context.WithTimeout(ctx, 15*time.Second)
			postgresJournal, err = postgresstore.NewWithPublicationAuthority(authorityContext, database, *postgresAuthorityIdentity)
			authorityCancel()
		} else {
			postgresJournal, err = postgresstore.New(database)
		}
		if err != nil {
			return nil, err
		}
		index, err := postgresstore.NewArtifactIndex(database)
		if err != nil {
			return nil, err
		}
		var indexedArtifacts *postgresstore.IndexedArtifactStore
		if budgetedArtifactErasure {
			budgetedIndexContext, budgetedIndexCancel := context.WithTimeout(ctx, 15*time.Second)
			budgetedIndexAuthority, verifyErr := postgresstore.VerifyBudgetedErasureIndex(budgetedIndexContext, index)
			budgetedIndexCancel()
			if verifyErr != nil {
				return nil, verifyErr
			}
			indexedArtifacts, err = postgresstore.NewIndexedBudgetedEnvelopeStore(index, postgresstore.BudgetedEnvelopeDependencies{
				Backend: budgetedErasureBackend, Keys: artifactKeyProvider, Clock: budgetedClock, IndexAuthority: budgetedIndexAuthority,
			}, budgetedPolicy)
			if err == nil {
				budgetedErasureConstructed = true
			}
		} else {
			indexedArtifacts, err = postgresstore.NewIndexedArtifactStore(index, artifactStore)
		}
		if err != nil {
			return nil, err
		}
		artifactStore = indexedArtifacts
		postgresDiagnostics, err := postgresstore.NewDiagnosticStore(database, artifactStore, postgresstore.DiagnosticStoreOptions{
			Classification: artifact.ClassificationRestricted, Protection: artifactProtection,
			Retention: 30 * 24 * time.Hour, Clock: daemonArtifactClock,
		})
		if err != nil {
			return nil, err
		}
		journal, diagnosticStore = postgresJournal, postgresDiagnostics
		publicationAttemptGuard = postgresJournal
		postgresAudit, err := postgresstore.NewAuditLedger(database)
		if err != nil {
			return nil, err
		}
		auditLedger = postgresAudit
		taskNotificationQueue = postgresJournal
	}
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
			inventory, configuration, configErr := loadRuntimeConfiguration(ctx, *runtimeRouteInventory, *runtimePolicy)
			if configErr != nil {
				return nil, ErrInvalidDaemonConfiguration
			}
			memoryTask, memoryErr := memoryhandler.NewHandler(artifactStore, daemonArtifactClock, memorycore.NewLexicalIndex(), daemonComponentIdentity("empty-memory-index-v1"), configuration.ReviewPolicyIdentity(), "trestled", []string{"."}, 64, 50)
			dispatchers, dispatcherErr := runtimecatalog.NewLocalOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory, configuration, environmentOpenAICredentialResolver{getenv: getenv})
			verificationInventory, inventoryErr := runtimecatalog.NewStaticVerificationRouteInventory(inventory)
			if memoryErr != nil || dispatcherErr != nil || inventoryErr != nil {
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
		if *metadataStore == "local" {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			fileInbox, err := webhook.NewFileStore(filepath.Join(*stateDirectory, "webhook-inbox"))
			if err != nil {
				return nil, err
			}
			resources.closers = append(resources.closers, fileInbox)
			inboxStore = fileInbox
		} else {
			postgresInbox, err := postgresstore.NewWebhookStore(postgresDatabase, artifactStore, postgresstore.WebhookStoreOptions{
				Classification: artifact.ClassificationRestricted, Protection: artifactProtection,
				Retention: 24 * time.Hour, Clock: daemonArtifactClock,
			})
			if err != nil {
				return nil, err
			}
			inboxStore = postgresInbox
		}
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
					if mode == controlplane.ReviewRunRequired && !*githubEnablePublication {
						return nil, ErrInvalidDaemonConfiguration
					}
					inventory, configuration, configErr := loadRuntimeConfiguration(ctx, *runtimeRouteInventory, *runtimePolicy)
					if configErr != nil || configuration.ReviewPolicyIdentity() != *githubPolicyIdentity {
						return nil, ErrInvalidDaemonConfiguration
					}
					statusInventoryIdentity = inventory.Identity()
					statusPolicyIdentity = configuration.Identity()
					statusRouteCount = uint32(len(inventory.Candidates()))
					dispatchers, dispatcherErr := runtimecatalog.NewOpenAIRouteDispatcherCatalogFromRuntimePolicy(inventory, configuration, environmentOpenAICredentialResolver{getenv: getenv})
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
					if mode == controlplane.ReviewRunRequired {
						effectAuthorizer, effectErr := reviewcore.NewRepositoryPublicationAuthorizer(*tenantID, *githubRepository, *githubPublicationPolicyIdentity, *githubPublicationPrincipalIdentity, *githubPublicationAuthorizationTTL)
						publicationCredentials := repositoryPublicationTokenProvider{tenantID: *tenantID, repositoryID: *githubRepository, repositoryFullName: *githubFullName, publisherID: *githubPublisherID, environment: "OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN", forbiddenCredentialDigest: githubSecretDigest, getenv: getenv}
						publicationAdapter, adapterErr := githubsource.NewPublicationAdapter(githubsource.PublicationConfig{PublisherID: *githubPublisherID, RepositoryAuthority: "github.com", Credentials: publicationCredentials, CredentialIdentity: publicationCredentials.ConfigurationIdentity(), AttemptGuard: publicationAttemptGuard})
						if effectErr != nil || adapterErr != nil {
							return nil, ErrInvalidDaemonConfiguration
						}
						publishers, publisherErr := reviewcore.NewPublisherCatalog([]reviewcore.Publisher{publicationAdapter})
						resolvers, resolverErr := reviewcore.NewHeadResolverCatalog([]reviewcore.HeadResolver{publicationAdapter})
						publicationTask, publicationErr := publicationhandler.NewHandler(artifactStore, daemonArtifactClock, auditLedger, configuration.ReviewPolicyIdentity(), configuration.Publication(), effectAuthorizer, publishers, resolvers)
						if publisherErr != nil || resolverErr != nil || publicationErr != nil {
							return nil, ErrInvalidDaemonConfiguration
						}
						localHandlers = append(localHandlers, publicationTask)
					}
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
	if budgetedErasureConstructed {
		ready := make(chan struct{})
		close(ready)
		componentReadiness = append(componentReadiness, ready)
		componentNames = append(componentNames, "artifact_erasure_budgeted")
	}
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
	metadataBackend := runtimeadmin.MetadataBackend(*metadataStore)
	artifactBackend := runtimeadmin.ArtifactBackend(*artifactStoreMode)
	notificationBackend := runtimeadmin.NotificationProcessLocal
	rateLimitBackend := runtimeadmin.RateLimitProcessLocal
	rateLimitAuthorityIdentity := ""
	if *metadataStore == "postgres" {
		notificationBackend = runtimeadmin.NotificationPostgres
		rateLimitBackend = runtimeadmin.RateLimitPostgres
		rateLimitAuthorityIdentity, err = postgresstore.RuntimeAPIRateLimitAuthorityIdentity(*postgresDatabaseAuthorityIdentity)
		if err != nil {
			return nil, err
		}
	}
	statusConfiguration, err := runtimeadmin.NewConfiguration(runtimeadmin.ConfigurationOptions{
		TenantID: *tenantID, RepositoryIDs: []string(repositories), MetadataBackend: metadataBackend, DatabaseAuthorityIdentity: *postgresDatabaseAuthorityIdentity,
		ArtifactBackend: artifactBackend, ArtifactProtection: runtimeadmin.Protection(artifactProtection.String()), NotificationBackend: notificationBackend, RateLimitBackend: rateLimitBackend, RateLimitAuthorityIdentity: rateLimitAuthorityIdentity,
		ReviewMode: statusMode, WebhookIngress: githubConfigured, LocalWorkers: localGitConfigured || *githubLocalDeterministicWorkers,
		PublicationEnabled: *githubEnablePublication, PublicationFenceVerified: *postgresAuthorityIdentity != "",
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
	if postgresDatabase != nil {
		requestLimiter, principalLimiter, err = postgresstore.NewRuntimeAPIRateLimiters(postgresDatabase, *postgresDatabaseAuthorityIdentity)
	} else {
		requestLimiter, err = httpapi.NewMemoryRateLimiter(120, time.Minute, 10_000)
		if err == nil {
			principalLimiter, err = httpapi.NewMemoryRateLimiter(600, time.Minute, 1_024)
		}
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
	server := &http.Server{
		Addr: *listenAddress, Handler: handler,
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
func runDaemon(ctx context.Context, args []string, getenv func(string) string, stdout, stderr io.Writer) (runErr error) {
	if ctx == nil || stdout == nil {
		return ErrInvalidDaemonConfiguration
	}
	if ctx.Err() != nil {
		return nil
	}
	daemon, err := buildDaemon(ctx, args, getenv, stderr)
	if err != nil {
		if onlyDaemonStartupCancellation(err, ctx.Err()) {
			return nil
		}
		return err
	}
	defer func() { runErr = errors.Join(runErr, daemon.Close()) }()
	if ctx.Err() != nil {
		return nil
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", daemon.server.Addr)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(stdout, "trestled listening on %s\n", listener.Addr().String()); err != nil {
		return errors.Join(err, listener.Close())
	}
	runtimeContext, stopRuntime := context.WithCancel(ctx)
	defer stopRuntime()
	type runtimeResult struct {
		server bool
		err    error
	}
	results := make(chan runtimeResult, len(daemon.supervisors)+1)
	go func() {
		if daemon.tlsCertificate != "" {
			results <- runtimeResult{server: true, err: daemon.server.ServeTLS(listener, daemon.tlsCertificate, daemon.tlsKey)}
			return
		}
		results <- runtimeResult{server: true, err: daemon.server.Serve(listener)}
	}()
	for _, supervisor := range daemon.supervisors {
		current := supervisor
		go func() { results <- runtimeResult{err: current.Run(runtimeContext)} }()
	}
	firstErr := error(nil)
	resultConsumed := false
	select {
	case result := <-results:
		resultConsumed = true
		if result.err != nil && !errors.Is(result.err, http.ErrServerClosed) {
			firstErr = result.err
		}
		if result.err == nil && !result.server && ctx.Err() == nil {
			firstErr = ErrDaemonRuntimeUnavailable
		}
	case <-ctx.Done():
	}
	stopRuntime()
	shutdownContext, cancel := context.WithTimeout(context.Background(), daemonShutdownTimeout)
	shutdownErr := daemon.server.Shutdown(shutdownContext)
	cancel()
	remaining := len(daemon.supervisors) + 1
	if resultConsumed {
		remaining--
	}
	for range remaining {
		result := <-results
		if result.err != nil && !errors.Is(result.err, http.ErrServerClosed) {
			firstErr = errors.Join(firstErr, result.err)
		}
	}
	firstErr = errors.Join(firstErr, shutdownErr)
	return firstErr
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
	d.closeOnce.Do(func() {
		for index := len(d.closers) - 1; index >= 0; index-- {
			if d.closers[index] == nil {
				continue
			}
			d.closeErr = errors.Join(d.closeErr, d.closers[index].Close())
		}
		d.closers = nil
	})
	return d.closeErr
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

type repositoryPublicationTokenProvider struct {
	tenantID, repositoryID, repositoryFullName, publisherID, environment string
	forbiddenCredentialDigest                                            [sha256.Size]byte
	getenv                                                               func(string) string
}

func (p repositoryPublicationTokenProvider) ConfigurationIdentity() string {
	encoded, _ := json.Marshal(struct {
		Contract                        string `json:"contract"`
		Version                         int    `json:"version"`
		Tenant                          string `json:"tenant"`
		Repository                      string `json:"repository"`
		FullName                        string `json:"full_name"`
		Publisher                       string `json:"publisher"`
		Environment                     string `json:"environment"`
		WebhookSecretSeparationRequired bool   `json:"webhook_secret_separation_required"`
	}{"open-trestle/github-publication-credential-provider", 1, p.tenantID, p.repositoryID, p.repositoryFullName, p.publisherID, p.environment, p.forbiddenCredentialDigest != [sha256.Size]byte{}})
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func (p repositoryPublicationTokenProvider) RetrievePublicationToken(ctx context.Context, scope audit.ReviewScope, target reviewcore.PublicationTarget) (githubsource.Token, error) {
	if ctx == nil || ctx.Err() != nil || scope.Validate() != nil || target.Validate() != nil || scope.TenantID() != p.tenantID || scope.RepositoryID() != p.repositoryID || target.PublisherID() != p.publisherID || p.getenv == nil {
		return githubsource.Token{}, githubsource.ErrPublicationCredentialsUnavailable
	}
	parts := strings.Split(p.repositoryFullName, "/")
	repository := target.RepositoryIdentity()
	if len(parts) != 2 || repository.Authority() != "github.com" || len(repository.Namespace()) != 1 || repository.Namespace()[0] != parts[0] || repository.Name() != parts[1] {
		return githubsource.Token{}, githubsource.ErrPublicationCredentialsUnavailable
	}
	value := p.getenv(p.environment)
	if value == "" {
		return githubsource.Token{}, githubsource.ErrPublicationCredentialsUnavailable
	}
	raw := []byte(value)
	value = ""
	defer clear(raw)
	digest := sha256.Sum256(raw)
	if p.forbiddenCredentialDigest != [sha256.Size]byte{} && subtle.ConstantTimeCompare(digest[:], p.forbiddenCredentialDigest[:]) == 1 {
		return githubsource.Token{}, githubsource.ErrPublicationCredentialsUnavailable
	}
	token, err := githubsource.NewToken(raw)
	if err != nil {
		return githubsource.Token{}, githubsource.ErrPublicationCredentialsUnavailable
	}
	return token, nil
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

type boundedResponseTransport struct {
	inner   http.RoundTripper
	maximum int64
}

func (t boundedResponseTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.inner.RoundTrip(request)
	if err != nil {
		return nil, err
	}
	if response.ContentLength > t.maximum {
		_ = response.Body.Close()
		return nil, ErrInvalidDaemonConfiguration
	}
	response.Body = &boundedResponseBody{inner: response.Body, remaining: t.maximum}
	return response, nil
}

type boundedResponseBody struct {
	inner     io.ReadCloser
	remaining int64
}

func (b *boundedResponseBody) Read(buffer []byte) (int, error) {
	if b.remaining == 0 {
		var probe [1]byte
		count, err := b.inner.Read(probe[:])
		if count != 0 {
			return 0, ErrInvalidDaemonConfiguration
		}
		return 0, err
	}
	if int64(len(buffer)) > b.remaining {
		buffer = buffer[:b.remaining]
	}
	count, err := b.inner.Read(buffer)
	b.remaining -= int64(count)
	return count, err
}
func (b *boundedResponseBody) Close() error { return b.inner.Close() }

func validSecureServiceEndpoint(raw string) bool {
	endpoint, err := providerconfig.ParseServiceEndpoint(raw)
	if err != nil || endpoint.Path != "" && endpoint.Path != "/" {
		return false
	}
	_, err = providerconfig.ClassifyServiceEndpoint(raw)
	return err == nil
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
