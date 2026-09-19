package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
	setupcore "github.com/georgejieh/open-trestle/setup"
	"github.com/georgejieh/open-trestle/tui"
)

type setupTUIInspectService struct{ path string }

func (s setupTUIInspectService) Current(ctx context.Context) (setupcore.Plan, error) {
	return setupcore.InspectStateFile(ctx, s.path)
}
func (s setupTUIInspectService) RunCheck(context.Context, setupcore.CheckKey, string) (setupcore.Plan, setupcore.CheckReceipt, error) {
	return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
}

type setupTUIService struct {
	state                                  *setupcore.StateFile
	clock                                  setupClock
	getenv                                 func(string) string
	inferenceFactory                       setupcore.LocalInferenceDispatcherFactory
	postgresProbe                          setupcore.PostgresStorageProbe
	kmsExecutor                            setupKMSExecutor
	envelopeExecutor                       setupEnvelopeExecutor
	githubPermissionExecutor               setupGitHubPermissionExecutor
	githubPermissionSession                *setupGitHubPermissionSession
	githubPermissionHost                   setupGitHubPermissionHostConfiguration
	githubBrokerAuthorityIdentity          string
	githubAllowTokenCreation               bool
	githubWebhookExecutor                  setupGitHubWebhookExecutor
	sharedRateLimitExecutor                setupSharedRateLimitExecutor
	replicaReconciliationExecutor          setupReplicaReconciliationExecutor
	signedBundleExecutor                   setupSignedBundleExecutor
	statePath                              string
	storageRoot                            string
	backupSnapshot                         string
	administratorApprovedBy                string
	postgresAuthorityIdentity              string
	postgresApprovedBy                     string
	kmsAuthorityIdentity                   string
	kmsRegion                              string
	kmsKeyARN                              string
	kmsEndpoint                            string
	kmsApprovedBy                          string
	envelopeAuthorityIdentity              string
	s3Endpoint                             string
	s3Region                               string
	s3Bucket                               string
	s3Prefix                               string
	envelopeApprovedBy                     string
	integrationPermissionAuthorityIdentity string
	githubAPIEndpoint                      string
	githubAPIVersion                       string
	githubRepositoryFullName               string
	integrationApprovedBy                  string
	webhookAuthorityIdentity               string
	githubWebhookKeyID                     string
	webhookApprovedBy                      string
	sharedRateLimitAuthorityIdentity       string
	replicaReconciliationAuthorityIdentity string
	postgresDatabaseAuthorityIdentity      string
	sharedRateLimitApprovedBy              string
	replicaReconciliationApprovedBy        string
	signedBundleAuthorityIdentity          string
	signedBundlePath                       string
	signedBundleDigest                     string
	signedBundlePublicKey                  string
	signedBundleSignature                  string
	signedBundleApprovedBy                 string
	signedBundleBytes                      uint64
	routeInventory                         string
	runtimePolicy                          string
	inventoryIdentity                      string
	runtimePolicyIdentity                  string
	reviewPolicyIdentity                   string
	approvedBy                             string
	githubInstallationID                   uint64
}

func (s *setupTUIService) Close() error {
	if s == nil {
		return nil
	}
	return s.githubPermissionSession.Close()
}

func (s *setupTUIService) Current(ctx context.Context) (setupcore.Plan, error) {
	if s == nil || s.state == nil {
		return setupcore.Plan{}, tui.ErrSetupCheckUnavailable
	}
	return s.state.Current(ctx)
}
func (s *setupTUIService) RunCheck(ctx context.Context, key setupcore.CheckKey, expectedPlanIdentity string) (setupcore.Plan, setupcore.CheckReceipt, error) {
	if s == nil || s.state == nil || s.clock == nil || s.getenv == nil {
		return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
	}
	var checker setupcore.Checker
	var err error
	switch key {
	case setupcore.CheckStateStoragePostureValidated:
		if s.storageRoot == "" {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		checker, err = setupcore.NewStateStorageChecker(s.storageRoot)
	case setupcore.CheckObserverCredentialPostureValidated:
		checker, err = setupcore.NewObserverCredentialPostureChecker(s.getenv)
	case setupcore.CheckPostgresStorageValidated:
		if s.postgresProbe == nil || !validAdminDigest(s.postgresAuthorityIdentity) || !validSetupApprovalLabel(s.postgresApprovedBy) {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		plan, currentErr := s.state.Current(ctx)
		if currentErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, currentErr
		}
		checker, err = setupcore.NewPostgresStorageChecker(plan, s.postgresAuthorityIdentity, s.postgresApprovedBy, s.postgresProbe)
	case setupcore.CheckIntegrationPermissionsValidated:
		if s.githubPermissionExecutor == nil || s.githubPermissionSession == nil || !s.githubAllowTokenCreation || !validAdminDigest(s.githubBrokerAuthorityIdentity) || !validAdminDigest(s.integrationPermissionAuthorityIdentity) || !validSetupApprovalLabel(s.integrationApprovedBy) || s.githubAPIEndpoint != "" || s.githubAPIVersion != "" || s.githubInstallationID != 0 || s.githubRepositoryFullName != "" {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		plan, currentErr := s.state.Current(ctx)
		if currentErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, currentErr
		}
		configuration := setupGitHubPermissionConfiguration{host: s.githubPermissionHost, session: s.githubPermissionSession, expectedBrokerAuthority: s.githubBrokerAuthorityIdentity, allowTokenCreation: s.githubAllowTokenCreation}
		probe, _, probeErr := newSetupGitHubPermissionProbe(s.getenv, plan, configuration, s.githubPermissionExecutor)
		if probeErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		checker, err = setupcore.NewIntegrationPermissionChecker(plan, s.integrationPermissionAuthorityIdentity, s.integrationApprovedBy, probe)
	case setupcore.CheckSharedRateLimitValidated:
		if s.sharedRateLimitExecutor == nil || !validAdminDigest(s.sharedRateLimitAuthorityIdentity) || !validAdminDigest(s.postgresDatabaseAuthorityIdentity) || !validSetupApprovalLabel(s.sharedRateLimitApprovedBy) {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		plan, currentErr := s.state.Current(ctx)
		if currentErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, currentErr
		}
		probe, _, probeErr := newSetupSharedRateLimitProbe(s.getenv, plan, s.postgresDatabaseAuthorityIdentity, s.sharedRateLimitExecutor)
		if probeErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		checker, err = setupcore.NewSharedRateLimitChecker(plan, s.sharedRateLimitAuthorityIdentity, s.sharedRateLimitApprovedBy, probe)
	case setupcore.CheckReplicaReconciliationValidated:
		if s.replicaReconciliationExecutor == nil || !validAdminDigest(s.replicaReconciliationAuthorityIdentity) || !validAdminDigest(s.postgresDatabaseAuthorityIdentity) || !validSetupApprovalLabel(s.replicaReconciliationApprovedBy) {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		plan, currentErr := s.state.Current(ctx)
		if currentErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, currentErr
		}
		probe, _, probeErr := newSetupReplicaReconciliationProbe(s.getenv, plan, s.postgresDatabaseAuthorityIdentity, s.replicaReconciliationExecutor)
		if probeErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		checker, err = setupcore.NewReplicaReconciliationChecker(plan, s.replicaReconciliationAuthorityIdentity, s.replicaReconciliationApprovedBy, probe)
	case setupcore.CheckSignedBundleValidated:
		configuration := setupSignedBundleConfiguration{bundlePath: s.signedBundlePath, bundleDigest: s.signedBundleDigest, bundleBytes: s.signedBundleBytes, publicKeyHex: s.signedBundlePublicKey, signatureHex: s.signedBundleSignature}
		if s.signedBundleExecutor == nil || !validAdminDigest(s.signedBundleAuthorityIdentity) || !validSetupSignedBundleConfiguration(configuration) || !validSetupApprovalLabel(s.signedBundleApprovedBy) {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		plan, currentErr := s.state.Current(ctx)
		if currentErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, currentErr
		}
		probe, _, probeErr := newSetupSignedBundleProbe(plan, configuration, s.signedBundleExecutor)
		if probeErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		checker, err = setupcore.NewSignedBundleChecker(plan, s.signedBundleAuthorityIdentity, s.signedBundleApprovedBy, probe)
	case setupcore.CheckWebhookValidated:
		if s.githubWebhookExecutor == nil || !validAdminDigest(s.webhookAuthorityIdentity) || s.githubWebhookKeyID == "" || !validSetupApprovalLabel(s.webhookApprovedBy) {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		plan, currentErr := s.state.Current(ctx)
		if currentErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, currentErr
		}
		probe, _, probeErr := newSetupGitHubWebhookProbe(s.getenv, plan, s.githubWebhookKeyID, s.githubWebhookExecutor)
		if probeErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		checker, err = setupcore.NewWebhookChecker(plan, s.webhookAuthorityIdentity, s.webhookApprovedBy, probe)
	case setupcore.CheckEnvelopeStorageValidated:
		if s.envelopeExecutor == nil || !validAdminDigest(s.envelopeAuthorityIdentity) || !validSetupApprovalLabel(s.envelopeApprovedBy) {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		plan, currentErr := s.state.Current(ctx)
		if currentErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, currentErr
		}
		configuration := setupEnvelopeConfiguration{tenantID: plan.TenantID(), s3Endpoint: s.s3Endpoint, s3Region: s.s3Region, s3Bucket: s.s3Bucket, s3Prefix: s.s3Prefix, kmsRegion: s.kmsRegion, kmsKeyARN: s.kmsKeyARN, kmsEndpoint: s.kmsEndpoint}
		probe, _, probeErr := newSetupEnvelopeStorageProbe(s.getenv, plan, configuration, s.envelopeExecutor)
		if probeErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		checker, err = setupcore.NewEnvelopeStorageChecker(plan, s.envelopeAuthorityIdentity, s.envelopeApprovedBy, probe)
	case setupcore.CheckSecretBackendValidated:
		if s.kmsExecutor == nil || !validAdminDigest(s.kmsAuthorityIdentity) || !validSetupApprovalLabel(s.kmsApprovedBy) {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		plan, currentErr := s.state.Current(ctx)
		if currentErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, currentErr
		}
		probe, _, probeErr := newSetupKMSProbe(s.getenv, plan.TenantID(), s.kmsRegion, s.kmsKeyARN, s.kmsEndpoint, s.kmsExecutor)
		if probeErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		checker, err = setupcore.NewSecretBackendChecker(plan, s.kmsAuthorityIdentity, s.kmsApprovedBy, probe)
	case setupcore.CheckLocalAdministratorValidated, setupcore.CheckBackupValidated:
		if key == setupcore.CheckLocalAdministratorValidated && s.administratorApprovedBy == "" || key == setupcore.CheckBackupValidated && s.backupSnapshot == "" {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		plan, currentErr := s.state.Current(ctx)
		if currentErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, currentErr
		}
		if key == setupcore.CheckLocalAdministratorValidated {
			checker, err = setupcore.NewLocalAdministratorChecker(plan, s.administratorApprovedBy)
		} else {
			checker, err = setupcore.NewBackupSnapshotChecker(s.statePath, s.backupSnapshot, plan)
		}
	case setupcore.CheckRemoteProviderAuthorized, setupcore.CheckPolicyValidated, setupcore.CheckDryRunValidated, setupcore.CheckLocalInferenceValidated:
		if !s.policyConfigured() {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
		}
		plan, currentErr := s.state.Current(ctx)
		if currentErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, currentErr
		}
		approval, approvalErr := setupcore.NewRuntimePolicyApproval(plan, s.inventoryIdentity, s.runtimePolicyIdentity, s.reviewPolicyIdentity, s.approvedBy)
		if approvalErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, approvalErr
		}
		policyChecker, policyErr := setupcore.NewRuntimePolicyFileChecker(s.routeInventory, s.runtimePolicy, approval)
		if policyErr != nil {
			return setupcore.Plan{}, setupcore.CheckReceipt{}, policyErr
		}
		checker = policyChecker
		if key == setupcore.CheckRemoteProviderAuthorized {
			checker, err = setupcore.NewRemoteProviderAuthorizationChecker(policyChecker)
		}
		if key == setupcore.CheckDryRunValidated {
			checker, err = setupcore.NewDryRunChecker(policyChecker)
		}
		if key == setupcore.CheckLocalInferenceValidated {
			if s.inferenceFactory == nil {
				return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
			}
			checker, err = setupcore.NewLocalInferenceChecker(policyChecker, s.inferenceFactory)
		}
	default:
		return setupcore.Plan{}, setupcore.CheckReceipt{}, tui.ErrSetupCheckUnavailable
	}
	if err != nil {
		return setupcore.Plan{}, setupcore.CheckReceipt{}, err
	}
	runner, err := setupcore.NewRunner(s.state, []setupcore.Checker{checker}, s.clock)
	if err != nil {
		return setupcore.Plan{}, setupcore.CheckReceipt{}, err
	}
	return runner.RunExpected(ctx, key, expectedPlanIdentity)
}
func (s *setupTUIService) policyConfigured() bool {
	return s.routeInventory != "" && s.runtimePolicy != "" && validAdminDigest(s.inventoryIdentity) && validAdminDigest(s.runtimePolicyIdentity) && validAdminDigest(s.reviewPolicyIdentity) && s.approvedBy != ""
}
func runSetupTUI(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runSetupTUIWithClock(args, stdin, stdout, stderr, systemSetupClock{}, os.Getenv)
}
func runSetupTUIWithClock(args []string, stdin io.Reader, stdout, stderr io.Writer, clock setupClock, getenv func(string) string) (exitCode int) {
	flags := flag.NewFlagSet("trestle setup tui", flag.ContinueOnError)
	flags.SetOutput(stderr)
	statePath := flags.String("state", "", "protected setup state file")
	storageRoot := flags.String("storage-root", "", "private local storage root")
	backupSnapshot := flags.String("backup-snapshot", "", "protected setup backup snapshot")
	administratorApprovedBy := flags.String("administrator-approved-by", "", "named recovery owner approving the current process identity")
	postgresAuthorityIdentity := flags.String("approve-postgres-authority-identity", "", "exact approved PostgreSQL database authority identity")
	postgresApprovedBy := flags.String("postgres-approved-by", "", "named recovery owner approving PostgreSQL authority")
	envelopeAuthorityIdentity := flags.String("approve-envelope-storage-authority-identity", "", "exact approved envelope storage authority identity")
	s3Endpoint := flags.String("s3-endpoint", "", "exact S3 service endpoint")
	s3Region := flags.String("s3-region", "", "S3 region")
	s3Bucket := flags.String("s3-bucket", "", "S3 bucket")
	s3Prefix := flags.String("s3-prefix", "", "S3 object prefix")
	envelopeApprovedBy := flags.String("envelope-approved-by", "", "named recovery owner approving envelope storage authority")
	integrationPermissionAuthorityIdentity := flags.String("approve-integration-permission-authority-identity", "", "exact approved integration permission authority identity")
	githubBrokerAuthorityIdentity := flags.String("approve-github-source-broker-authority-identity", "", "exact approved protected source broker identity")
	githubAllowTokenCreation := flags.Bool("allow-github-installation-token-creation", false, "approve retained setup owner records, token creation, and foreground demand renewal")
	githubAPIEndpoint := flags.String("github-api-endpoint", "", "exact GitHub API endpoint")
	githubAPIVersion := flags.String("github-api-version", "", "exact GitHub API version")
	githubInstallationID := flags.Uint64("github-installation-id", 0, "GitHub App installation identifier")
	githubRepositoryFullName := flags.String("github-repository-full-name", "", "lowercase owner/repository")
	integrationApprovedBy := flags.String("integration-approved-by", "", "named recovery owner approving integration permissions")
	webhookAuthorityIdentity := flags.String("approve-webhook-authority-identity", "", "exact approved GitHub webhook authority identity")
	githubWebhookKeyID := flags.String("github-webhook-key-id", "", "non-secret GitHub webhook key identifier")
	webhookApprovedBy := flags.String("webhook-approved-by", "", "named recovery owner approving webhook authority")
	sharedRateLimitAuthorityIdentity := flags.String("approve-shared-rate-limit-authority-identity", "", "exact approved shared rate-limit authority identity")
	replicaReconciliationAuthorityIdentity := flags.String("approve-replica-reconciliation-authority-identity", "", "exact approved replica reconciliation authority identity")
	postgresDatabaseAuthorityIdentity := flags.String("postgres-database-authority-identity", "", "exact PostgreSQL runtime database authority identity")
	sharedRateLimitApprovedBy := flags.String("shared-rate-limit-approved-by", "", "named recovery owner approving shared rate-limit authority")
	replicaReconciliationApprovedBy := flags.String("replica-reconciliation-approved-by", "", "named recovery owner approving replica reconciliation authority")
	signedBundleAuthorityIdentity := flags.String("approve-signed-bundle-authority-identity", "", "exact approved signed bundle authority identity")
	signedBundlePath := flags.String("bundle", "", "exact opaque offline bundle path")
	signedBundleDigest := flags.String("bundle-sha256", "", "exact opaque bundle SHA-256 digest")
	signedBundleBytes := flags.Uint64("bundle-bytes", 0, "exact opaque bundle byte count")
	signedBundlePublicKey := flags.String("public-key", "", "exact Ed25519 public key as lowercase hexadecimal")
	signedBundleSignature := flags.String("signature", "", "exact Ed25519 signature as lowercase hexadecimal")
	signedBundleApprovedBy := flags.String("signed-bundle-approved-by", "", "named recovery owner approving signed bundle authority")
	kmsAuthorityIdentity := flags.String("approve-kms-authority-identity", "", "exact approved KMS authority identity")
	kmsRegion := flags.String("kms-region", "", "AWS KMS region")
	kmsKeyARN := flags.String("kms-key-arn", "", "exact tenant KMS key ARN")
	kmsEndpoint := flags.String("kms-endpoint", "", "optional approved KMS service endpoint")
	kmsApprovedBy := flags.String("kms-approved-by", "", "named recovery owner approving KMS authority")
	routeInventory := flags.String("route-inventory", "", "protected runtime route inventory")
	runtimePolicy := flags.String("runtime-policy", "", "protected runtime policy")
	inventoryIdentity := flags.String("approve-inventory-identity", "", "exact approved inventory identity")
	runtimePolicyIdentity := flags.String("approve-runtime-policy-identity", "", "exact approved runtime policy identity")
	reviewPolicyIdentity := flags.String("approve-review-policy-identity", "", "exact approved review policy identity")
	approvedBy := flags.String("approved-by", "", "named setup recovery owner granting approval")
	width := flags.Int("width", 100, "display width")
	plain := flags.Bool("plain", defaultPlainTerminalOutput(stdout), "disable terminal control sequences")
	once := flags.Bool("once", false, "render one setup snapshot and exit")
	if flags.Parse(args) != nil {
		return 2
	}
	legacyGitHubFieldsPresent, brokerGitHubFieldsPresent := false, false
	flags.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "github-api-endpoint", "github-api-version", "github-installation-id", "github-repository-full-name":
			legacyGitHubFieldsPresent = true
		case "approve-github-source-broker-authority-identity", "allow-github-installation-token-creation":
			brokerGitHubFieldsPresent = true
		}
	})
	policyValues := []string{*routeInventory, *runtimePolicy, *inventoryIdentity, *runtimePolicyIdentity, *reviewPolicyIdentity, *approvedBy}
	policyCount := 0
	for _, value := range policyValues {
		if value != "" {
			policyCount++
		}
	}
	policyValid := policyCount == 0 || policyCount == len(policyValues) && validAdminDigest(*inventoryIdentity) && validAdminDigest(*runtimePolicyIdentity) && validAdminDigest(*reviewPolicyIdentity)
	postgresConfigured := *postgresAuthorityIdentity != "" || *postgresApprovedBy != ""
	postgresValid := !postgresConfigured || validAdminDigest(*postgresAuthorityIdentity) && validSetupApprovalLabel(*postgresApprovedBy)
	kmsConfigurationSet := *kmsRegion != "" || *kmsKeyARN != "" || *kmsEndpoint != ""
	secretConfigured := *kmsAuthorityIdentity != "" || *kmsApprovedBy != ""
	envelopeConfigured := *envelopeAuthorityIdentity != "" || *s3Endpoint != "" || *s3Region != "" || *s3Bucket != "" || *s3Prefix != "" || *envelopeApprovedBy != ""
	secretValid := !secretConfigured || validAdminDigest(*kmsAuthorityIdentity) && *kmsRegion != "" && *kmsKeyARN != "" && validSetupApprovalLabel(*kmsApprovedBy)
	envelopeValid := !envelopeConfigured || validAdminDigest(*envelopeAuthorityIdentity) && *s3Endpoint != "" && *s3Region != "" && *s3Bucket != "" && *s3Prefix != "" && *kmsRegion != "" && *kmsKeyARN != "" && validSetupApprovalLabel(*envelopeApprovedBy)
	integrationConfigured := legacyGitHubFieldsPresent || brokerGitHubFieldsPresent || *integrationPermissionAuthorityIdentity != "" || *githubAPIEndpoint != "" || *githubAPIVersion != "" || *githubInstallationID != 0 || *githubRepositoryFullName != "" || *integrationApprovedBy != ""
	integrationValid := !integrationConfigured || !legacyGitHubFieldsPresent && validAdminDigest(*integrationPermissionAuthorityIdentity) && validAdminDigest(*githubBrokerAuthorityIdentity) && *githubAllowTokenCreation && validSetupApprovalLabel(*integrationApprovedBy)
	webhookConfigured := *webhookAuthorityIdentity != "" || *githubWebhookKeyID != "" || *webhookApprovedBy != ""
	webhookValid := !webhookConfigured || validAdminDigest(*webhookAuthorityIdentity) && *githubWebhookKeyID != "" && validSetupApprovalLabel(*webhookApprovedBy)
	sharedRateLimitConfigured := *sharedRateLimitAuthorityIdentity != "" || *sharedRateLimitApprovedBy != ""
	replicaReconciliationConfigured := *replicaReconciliationAuthorityIdentity != "" || *replicaReconciliationApprovedBy != ""
	postgresRuntimeAuthorityConfigured := *postgresDatabaseAuthorityIdentity != ""
	sharedRateLimitValid := !sharedRateLimitConfigured || validAdminDigest(*sharedRateLimitAuthorityIdentity) && validAdminDigest(*postgresDatabaseAuthorityIdentity) && validSetupApprovalLabel(*sharedRateLimitApprovedBy)
	replicaReconciliationValid := !replicaReconciliationConfigured || validAdminDigest(*replicaReconciliationAuthorityIdentity) && validAdminDigest(*postgresDatabaseAuthorityIdentity) && validSetupApprovalLabel(*replicaReconciliationApprovedBy)
	postgresRuntimeAuthorityValid := postgresRuntimeAuthorityConfigured == (sharedRateLimitConfigured || replicaReconciliationConfigured)
	signedBundleConfigured := *signedBundleAuthorityIdentity != "" || *signedBundlePath != "" || *signedBundleDigest != "" || *signedBundleBytes != 0 || *signedBundlePublicKey != "" || *signedBundleSignature != "" || *signedBundleApprovedBy != ""
	signedBundleConfiguration := setupSignedBundleConfiguration{bundlePath: *signedBundlePath, bundleDigest: *signedBundleDigest, bundleBytes: *signedBundleBytes, publicKeyHex: *signedBundlePublicKey, signatureHex: *signedBundleSignature}
	signedBundleValid := !signedBundleConfigured || validAdminDigest(*signedBundleAuthorityIdentity) && validSetupSignedBundleConfiguration(signedBundleConfiguration) && validSetupApprovalLabel(*signedBundleApprovedBy)
	kmsValid := !kmsConfigurationSet || secretConfigured || envelopeConfigured
	if flags.NArg() != 0 || *statePath == "" || !policyValid || !postgresValid || !kmsValid || !secretValid || !envelopeValid || !integrationValid || !webhookValid || !sharedRateLimitValid || !replicaReconciliationValid || !postgresRuntimeAuthorityValid || !signedBundleValid || *administratorApprovedBy != "" && !validSetupApprovalLabel(*administratorApprovedBy) || clock == nil || getenv == nil || *width < 60 || *width > 240 {
		writeSetupTUIUsage(stderr)
		return 2
	}
	inferenceFactory, factoryErr := newSetupLocalInferenceFactory(getenv)
	if factoryErr != nil {
		fmt.Fprintln(stderr, "setup tui failed")
		return 2
	}
	postgresProbe, probeErr := newSetupPostgresStorageProbe(getenv, executeSetupPostgresStorage)
	if probeErr != nil {
		fmt.Fprintln(stderr, "setup tui failed")
		return 2
	}
	if _, err := setupcore.InspectStateFile(context.Background(), *statePath); err != nil {
		fmt.Fprintln(stderr, "setup tui failed")
		return 1
	}
	if *once {
		interface_, err := tui.NewSetup(setupTUIInspectService{path: *statePath}, stdin, stdout, tui.SetupOptions{Width: *width, Plain: *plain, Once: true})
		if err != nil || interface_.Run(context.Background()) != nil {
			fmt.Fprintln(stderr, "setup tui failed")
			return 1
		}
		return 0
	}
	// --once returned above, without capturing broker or comparison environments.
	brokerPath := getenv("OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG")
	staticToken := ""
	if brokerPath != "" {
		staticToken = getenv("OPEN_TRESTLE_GITHUB_API_TOKEN")
	}
	githubHost, hostErr := loadSetupGitHubPermissionHostConfiguration(context.Background(), brokerPath, *githubBrokerAuthorityIdentity, staticToken)
	staticToken = ""
	if hostErr != nil || integrationConfigured && !githubHost.configured {
		fmt.Fprintln(stderr, "setup tui failed")
		return 2
	}
	ownerContext := context.Background()
	var permissionSession *setupGitHubPermissionSession
	var permissionService *setupTUIService
	if githubHost.configured {
		owned, cancel := context.WithCancel(ownerContext)
		defer cancel()
		ownerContext = owned
		var sessionErr error
		permissionSession, sessionErr = newSetupGitHubPermissionSession(ownerContext, githubHost.broker, getenv, githubadapter.SystemBrokerClock{})
		if sessionErr != nil {
			fmt.Fprintln(stderr, "setup tui failed")
			return 2
		}
	}
	defer func() {
		var closeErr error
		if permissionService != nil {
			closeErr = permissionService.Close()
		} else {
			closeErr = permissionSession.Close()
		}
		if closeErr != nil {
			fmt.Fprintln(stderr, "setup credential cleanup failed")
			exitCode = 1
		}
	}()
	state, err := setupcore.OpenStateFile(*statePath)
	if err != nil {
		fmt.Fprintln(stderr, "setup tui failed")
		return 1
	}
	defer state.Close()
	service := &setupTUIService{state: state, clock: clock, getenv: getenv, inferenceFactory: inferenceFactory, postgresProbe: postgresProbe, kmsExecutor: executeSetupKMS, envelopeExecutor: executeSetupEnvelopeStorage, githubPermissionExecutor: executeSetupGitHubPermission, githubPermissionSession: permissionSession, githubPermissionHost: githubHost, githubBrokerAuthorityIdentity: *githubBrokerAuthorityIdentity, githubAllowTokenCreation: *githubAllowTokenCreation, githubWebhookExecutor: executeSetupGitHubWebhook, sharedRateLimitExecutor: executeSetupSharedRateLimit, replicaReconciliationExecutor: executeSetupReplicaReconciliation, signedBundleExecutor: executeSetupSignedBundle, statePath: *statePath, storageRoot: *storageRoot, backupSnapshot: *backupSnapshot, administratorApprovedBy: *administratorApprovedBy, postgresAuthorityIdentity: *postgresAuthorityIdentity, postgresApprovedBy: *postgresApprovedBy, kmsAuthorityIdentity: *kmsAuthorityIdentity, kmsRegion: *kmsRegion, kmsKeyARN: *kmsKeyARN, kmsEndpoint: *kmsEndpoint, kmsApprovedBy: *kmsApprovedBy, envelopeAuthorityIdentity: *envelopeAuthorityIdentity, s3Endpoint: *s3Endpoint, s3Region: *s3Region, s3Bucket: *s3Bucket, s3Prefix: *s3Prefix, envelopeApprovedBy: *envelopeApprovedBy, integrationPermissionAuthorityIdentity: *integrationPermissionAuthorityIdentity, integrationApprovedBy: *integrationApprovedBy, webhookAuthorityIdentity: *webhookAuthorityIdentity, githubWebhookKeyID: *githubWebhookKeyID, webhookApprovedBy: *webhookApprovedBy, sharedRateLimitAuthorityIdentity: *sharedRateLimitAuthorityIdentity, replicaReconciliationAuthorityIdentity: *replicaReconciliationAuthorityIdentity, postgresDatabaseAuthorityIdentity: *postgresDatabaseAuthorityIdentity, sharedRateLimitApprovedBy: *sharedRateLimitApprovedBy, replicaReconciliationApprovedBy: *replicaReconciliationApprovedBy, signedBundleAuthorityIdentity: *signedBundleAuthorityIdentity, signedBundlePath: *signedBundlePath, signedBundleDigest: *signedBundleDigest, signedBundleBytes: *signedBundleBytes, signedBundlePublicKey: *signedBundlePublicKey, signedBundleSignature: *signedBundleSignature, signedBundleApprovedBy: *signedBundleApprovedBy, routeInventory: *routeInventory, runtimePolicy: *runtimePolicy, inventoryIdentity: *inventoryIdentity, runtimePolicyIdentity: *runtimePolicyIdentity, reviewPolicyIdentity: *reviewPolicyIdentity, approvedBy: *approvedBy}
	permissionService = service
	interface_, err := tui.NewSetup(service, stdin, stdout, tui.SetupOptions{Width: *width, Plain: *plain, Once: *once})
	if err != nil {
		fmt.Fprintln(stderr, "setup tui failed")
		return 2
	}
	if err = interface_.Run(ownerContext); err != nil {
		if !errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "setup tui failed")
		}
		return 1
	}
	return 0
}
func writeSetupTUIUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: trestle setup tui --state PATH [--storage-root PATH] [--backup-snapshot PATH] [--administrator-approved-by NAME] [--approve-postgres-authority-identity HEX64 --postgres-approved-by NAME] [--approve-kms-authority-identity HEX64 --kms-region REGION --kms-key-arn ARN [--kms-endpoint URL] --kms-approved-by NAME] [--approve-envelope-storage-authority-identity HEX64 --s3-endpoint URL --s3-region REGION --s3-bucket BUCKET --s3-prefix PREFIX --kms-region REGION --kms-key-arn ARN [--kms-endpoint URL] --envelope-approved-by NAME] [--approve-integration-permission-authority-identity HEX64 --approve-github-source-broker-authority-identity HEX64 --allow-github-installation-token-creation --integration-approved-by NAME] [--approve-webhook-authority-identity HEX64 --github-webhook-key-id ID --webhook-approved-by NAME] [--approve-shared-rate-limit-authority-identity HEX64 --postgres-database-authority-identity HEX64 --shared-rate-limit-approved-by NAME] [--approve-replica-reconciliation-authority-identity HEX64 --postgres-database-authority-identity HEX64 --replica-reconciliation-approved-by NAME] [--approve-signed-bundle-authority-identity HEX64 --bundle PATH --bundle-sha256 HEX64 --bundle-bytes BYTES --public-key HEX64 --signature HEX128 --signed-bundle-approved-by NAME] [--route-inventory PATH --runtime-policy PATH --approve-inventory-identity HEX64 --approve-runtime-policy-identity HEX64 --approve-review-policy-identity HEX64 --approved-by NAME] [--width COLUMNS] [--plain] [--once]")
}

func validSetupApprovalLabel(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r == '-' || r == '_' || r == '.' || r == ':' || r == '@' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
