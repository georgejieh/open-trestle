package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	githubadapter "github.com/georgejieh/open-trestle/adapters/scm/github"
	setupcore "github.com/georgejieh/open-trestle/setup"
)

type setupClock interface{ Now() time.Time }
type systemSetupClock struct{}

func (systemSetupClock) Now() time.Time { return time.Now().UTC() }
func runSetup(args []string, stdout, stderr io.Writer) int {
	return runSetupWithClock(args, stdout, stderr, systemSetupClock{})
}
func runSetupWithClock(args []string, stdout, stderr io.Writer, clock setupClock) int {
	factory, err := newSetupLocalInferenceFactory(providerCredentialLookup)
	if err != nil {
		writeSetupUsage(stderr)
		return 2
	}
	return runSetupWithDependencies(args, stdout, stderr, clock, factory, executeSetupGitHubPermission, executeSetupGitHubWebhook)
}
func runSetupWithClockAndInference(args []string, stdout, stderr io.Writer, clock setupClock, inferenceFactory setupcore.LocalInferenceDispatcherFactory) int {
	return runSetupWithDependencies(args, stdout, stderr, clock, inferenceFactory, executeSetupGitHubPermission, executeSetupGitHubWebhook)
}
func runSetupWithDependencies(args []string, stdout, stderr io.Writer, clock setupClock, inferenceFactory setupcore.LocalInferenceDispatcherFactory, githubPermissionExecutor setupGitHubPermissionExecutor, githubWebhookExecutor setupGitHubWebhookExecutor) int {
	if len(args) == 0 || clock == nil || inferenceFactory == nil || githubPermissionExecutor == nil || githubWebhookExecutor == nil {
		writeSetupUsage(stderr)
		return 2
	}
	switch args[0] {
	case "bootstrap":
		return runSetupBootstrap(args[1:], stdout, stderr)
	case "init":
		return runSetupInit(args[1:], stdout, stderr, clock)
	case "inspect":
		return runSetupInspect(args[1:], stdout, stderr)
	case "check":
		return runSetupCheck(args[1:], stdout, stderr, clock, inferenceFactory, githubPermissionExecutor, githubWebhookExecutor)
	case "backup":
		return runSetupBackup(args[1:], stdout, stderr)
	default:
		writeSetupUsage(stderr)
		return 2
	}
}
func runSetupInit(args []string, stdout, stderr io.Writer, clock setupClock) int {
	flags := flag.NewFlagSet("trestle setup init", flag.ContinueOnError)
	flags.SetOutput(stderr)
	profileValue := flags.String("profile", "", "deployment profile")
	tenant := flags.String("tenant", "", "tenant identifier")
	repository := flags.String("repository", "", "repository identifier")
	owner := flags.String("recovery-owner", "", "named recovery owner")
	state := flags.String("state", "", "private setup state file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *profileValue == "" || *tenant == "" || *repository == "" || *owner == "" || *state == "" {
		writeSetupUsage(stderr)
		return 2
	}
	profile, err := setupcore.ParseProfile(*profileValue)
	if err != nil {
		writeSetupUsage(stderr)
		return 2
	}
	plan, err := setupcore.NewCurrentPlan(profile, *tenant, *repository, *owner, clock.Now())
	if err != nil {
		writeSetupUsage(stderr)
		return 2
	}
	store, err := setupcore.OpenStateFile(*state)
	if err != nil {
		fmt.Fprintln(stderr, "setup initialization failed")
		return 1
	}
	defer store.Close()
	if store.Initialize(context.Background(), plan) != nil {
		fmt.Fprintln(stderr, "setup initialization failed")
		return 1
	}
	result := struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		PlanIdentity  string `json:"plan_identity"`
		Revision      uint64 `json:"revision"`
		Ready         bool   `json:"ready"`
	}{"open-trestle/setup-command-result", 1, "created", plan.Identity(), plan.Revision(), plan.Ready()}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}
func runSetupInspect(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle setup inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	state := flags.String("state", "", "private setup state file")
	expectedRoot := flags.String("expected-root-identity", "", "expected initial setup plan identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *state == "" || (*expectedRoot != "" && !validAdminDigest(*expectedRoot)) {
		writeSetupUsage(stderr)
		return 2
	}
	plan, err := setupcore.InspectStateFile(context.Background(), *state)
	if err == nil && *expectedRoot != "" && plan.RootIdentity() != *expectedRoot {
		err = setupcore.ErrStateConflict
	}
	if err != nil {
		fmt.Fprintln(stderr, "setup inspection failed")
		return 1
	}
	canonical, _ := setupcore.EncodePlan(plan)
	if _, err = stdout.Write(append(canonical, '\n')); err != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}
func runSetupCheck(args []string, stdout, stderr io.Writer, clock setupClock, inferenceFactory setupcore.LocalInferenceDispatcherFactory, githubPermissionExecutor setupGitHubPermissionExecutor, githubWebhookExecutor setupGitHubWebhookExecutor) (exitCode int) {
	if len(args) == 0 {
		writeSetupUsage(stderr)
		return 2
	}
	flags := flag.NewFlagSet("trestle setup check "+args[0], flag.ContinueOnError)
	flags.SetOutput(stderr)
	state := flags.String("state", "", "private setup state file")
	storageRoot := flags.String("storage-root", "", "private local storage root")
	backupSnapshot := flags.String("backup-snapshot", "", "protected setup backup snapshot")
	routeInventory := flags.String("route-inventory", "", "protected runtime route inventory")
	runtimePolicy := flags.String("runtime-policy", "", "protected runtime policy")
	approveInventory := flags.String("approve-inventory-identity", "", "exact approved inventory identity")
	approveRuntimePolicy := flags.String("approve-runtime-policy-identity", "", "exact approved runtime policy identity")
	approveReviewPolicy := flags.String("approve-review-policy-identity", "", "exact approved review policy identity")
	approveIntegrationPermission := flags.String("approve-integration-permission-authority-identity", "", "exact approved integration permission authority identity")
	approveGitHubBroker := flags.String("approve-github-source-broker-authority-identity", "", "exact approved protected source broker identity")
	allowGitHubTokenCreation := flags.Bool("allow-github-installation-token-creation", false, "approve retained setup owner records, token creation, and foreground demand renewal")
	approveWebhook := flags.String("approve-webhook-authority-identity", "", "exact approved GitHub webhook authority identity")
	githubAPIEndpoint := flags.String("github-api-endpoint", "", "exact GitHub API endpoint")
	githubAPIVersion := flags.String("github-api-version", "", "exact GitHub API version")
	githubInstallationID := flags.Uint64("github-installation-id", 0, "GitHub App installation identifier")
	githubRepositoryFullName := flags.String("github-repository-full-name", "", "lowercase owner/repository")
	githubWebhookKeyID := flags.String("github-webhook-key-id", "", "non-secret GitHub webhook key identifier")
	approvedBy := flags.String("approved-by", "", "named setup recovery owner granting approval")
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *state == "" {
		writeSetupUsage(stderr)
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
	policyFieldsSet := *routeInventory != "" || *runtimePolicy != "" || *approveInventory != "" || *approveRuntimePolicy != "" || *approveReviewPolicy != ""
	integrationFieldSet := legacyGitHubFieldsPresent || brokerGitHubFieldsPresent || *approveIntegrationPermission != "" || *githubAPIEndpoint != "" || *githubAPIVersion != "" || *githubInstallationID != 0 || *githubRepositoryFullName != ""
	webhookFieldSet := *approveWebhook != "" || *githubWebhookKeyID != ""
	switch args[0] {
	case "storage":
		if *storageRoot == "" || *backupSnapshot != "" || policyFieldsSet || integrationFieldSet || webhookFieldSet || *approvedBy != "" {
			writeSetupUsage(stderr)
			return 2
		}
	case "observer":
		if *storageRoot != "" || *backupSnapshot != "" || policyFieldsSet || integrationFieldSet || webhookFieldSet || *approvedBy != "" {
			writeSetupUsage(stderr)
			return 2
		}
	case "administrator":
		if *storageRoot != "" || *backupSnapshot != "" || policyFieldsSet || integrationFieldSet || webhookFieldSet || !validSetupApprovalLabel(*approvedBy) {
			writeSetupUsage(stderr)
			return 2
		}
	case "backup":
		if *storageRoot != "" || *backupSnapshot == "" || policyFieldsSet || integrationFieldSet || webhookFieldSet || *approvedBy != "" {
			writeSetupUsage(stderr)
			return 2
		}
	case "integration":
		if *storageRoot != "" || *backupSnapshot != "" || policyFieldsSet || webhookFieldSet || !validAdminDigest(*approveIntegrationPermission) || !validAdminDigest(*approveGitHubBroker) || !*allowGitHubTokenCreation || legacyGitHubFieldsPresent || !validSetupApprovalLabel(*approvedBy) {
			writeSetupUsage(stderr)
			return 2
		}
	case "webhook":
		if *storageRoot != "" || *backupSnapshot != "" || policyFieldsSet || integrationFieldSet || !validAdminDigest(*approveWebhook) || *githubWebhookKeyID == "" || !validSetupApprovalLabel(*approvedBy) {
			writeSetupUsage(stderr)
			return 2
		}
	case "provider", "policy", "dry-run", "inference":
		if *storageRoot != "" || *backupSnapshot != "" || integrationFieldSet || webhookFieldSet || *routeInventory == "" || *runtimePolicy == "" || !validAdminDigest(*approveInventory) || !validAdminDigest(*approveRuntimePolicy) || !validAdminDigest(*approveReviewPolicy) || !validSetupApprovalLabel(*approvedBy) {
			writeSetupUsage(stderr)
			return 2
		}
	default:
		writeSetupUsage(stderr)
		return 2
	}
	var githubHost setupGitHubPermissionHostConfiguration
	if args[0] == "integration" {
		path := os.Getenv("OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG")
		staticToken := ""
		if path != "" {
			staticToken = os.Getenv("OPEN_TRESTLE_GITHUB_API_TOKEN")
		}
		var hostErr error
		githubHost, hostErr = loadSetupGitHubPermissionHostConfiguration(context.Background(), path, *approveGitHubBroker, staticToken)
		staticToken = ""
		if hostErr != nil || !githubHost.configured {
			writeSetupUsage(stderr)
			return 2
		}
	}
	var permissionSession *setupGitHubPermissionSession
	cleanupReported := false
	defer func() {
		if permissionSession != nil && permissionSession.Close() != nil {
			if !cleanupReported {
				fmt.Fprintln(stderr, "setup credential cleanup failed")
			}
			exitCode = 1
		}
	}()
	expectedPlanIdentity := ""
	store, err := setupcore.OpenStateFile(*state)
	if err != nil {
		fmt.Fprintln(stderr, "setup check failed")
		return 1
	}
	defer store.Close()
	var checker setupcore.Checker
	switch args[0] {
	case "storage":
		checker, err = setupcore.NewStateStorageChecker(*storageRoot)
	case "observer":
		checker, err = setupcore.NewObserverCredentialPostureChecker(os.Getenv)
	case "administrator", "backup":
		plan, currentErr := store.Current(context.Background())
		if currentErr != nil {
			err = currentErr
			break
		}
		if args[0] == "administrator" {
			checker, err = setupcore.NewLocalAdministratorChecker(plan, *approvedBy)
		} else {
			checker, err = setupcore.NewBackupSnapshotChecker(*state, *backupSnapshot, plan)
		}
	case "integration":
		plan, currentErr := store.Current(context.Background())
		if currentErr != nil {
			err = currentErr
			break
		}
		expectedPlanIdentity = plan.Identity()
		permissionSession, err = newSetupGitHubPermissionSession(context.Background(), githubHost.broker, os.Getenv, githubadapter.SystemBrokerClock{})
		if err != nil {
			break
		}
		configuration := setupGitHubPermissionConfiguration{host: githubHost, session: permissionSession, expectedBrokerAuthority: *approveGitHubBroker, allowTokenCreation: *allowGitHubTokenCreation}
		probe, _, probeErr := newSetupGitHubPermissionProbe(os.Getenv, plan, configuration, githubPermissionExecutor)
		if probeErr != nil {
			err = probeErr
			break
		}
		checker, err = setupcore.NewIntegrationPermissionChecker(plan, *approveIntegrationPermission, *approvedBy, probe)
	case "webhook":
		plan, currentErr := store.Current(context.Background())
		if currentErr != nil {
			err = currentErr
			break
		}
		probe, _, probeErr := newSetupGitHubWebhookProbe(os.Getenv, plan, *githubWebhookKeyID, githubWebhookExecutor)
		if probeErr != nil {
			err = probeErr
			break
		}
		checker, err = setupcore.NewWebhookChecker(plan, *approveWebhook, *approvedBy, probe)
	case "provider", "policy", "dry-run", "inference":
		plan, currentErr := store.Current(context.Background())
		if currentErr != nil {
			fmt.Fprintln(stderr, "setup check failed")
			return 1
		}
		approval, approvalErr := setupcore.NewRuntimePolicyApproval(plan, *approveInventory, *approveRuntimePolicy, *approveReviewPolicy, *approvedBy)
		if approvalErr != nil {
			fmt.Fprintln(stderr, "setup check failed")
			return 1
		}
		policyChecker, policyErr := setupcore.NewRuntimePolicyFileChecker(*routeInventory, *runtimePolicy, approval)
		if policyErr != nil {
			err = policyErr
			break
		}
		checker = policyChecker
		if args[0] == "provider" {
			checker, err = setupcore.NewRemoteProviderAuthorizationChecker(policyChecker)
		}
		if args[0] == "dry-run" {
			checker, err = setupcore.NewDryRunChecker(policyChecker)
		}
		if args[0] == "inference" {
			checker, err = setupcore.NewLocalInferenceChecker(policyChecker, inferenceFactory)
		}
	}
	if err != nil {
		fmt.Fprintln(stderr, "setup check failed")
		return 1
	}
	runner, err := setupcore.NewRunner(store, []setupcore.Checker{checker}, clock)
	if err != nil {
		fmt.Fprintln(stderr, "setup check failed")
		return 1
	}
	var receipt setupcore.CheckReceipt
	if args[0] == "integration" {
		_, receipt, err = runner.RunExpected(context.Background(), checker.Key(), expectedPlanIdentity)
	} else {
		_, receipt, err = runner.Run(context.Background(), checker.Key())
	}
	if err != nil {
		fmt.Fprintln(stderr, "setup check failed")
		return 1
	}
	encoded, err := setupcore.EncodeCheckReceipt(receipt)
	if err != nil {
		fmt.Fprintln(stderr, "setup check failed")
		return 1
	}
	if _, err = stdout.Write(append(encoded, '\n')); err != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	// A durable receipt is never rolled back to repair credential cleanup.
	if permissionSession != nil && permissionSession.Close() != nil {
		fmt.Fprintln(stderr, "setup credential cleanup failed")
		cleanupReported = true
		return 1
	}
	if receipt.State() != setupcore.CheckPassed {
		return 3
	}
	return 0
}

func runSetupBackup(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		writeSetupUsage(stderr)
		return 2
	}
	var plan setupcore.Plan
	var err error
	status := ""
	switch args[0] {
	case "create":
		flags := flag.NewFlagSet("trestle setup backup create", flag.ContinueOnError)
		flags.SetOutput(stderr)
		state := flags.String("state", "", "protected setup state file")
		destination := flags.String("destination", "", "new protected backup snapshot")
		expected := flags.String("expected-plan-identity", "", "exact current setup plan identity")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *state == "" || *destination == "" || !validAdminDigest(*expected) {
			writeSetupUsage(stderr)
			return 2
		}
		plan, err = setupcore.CreateBackupSnapshot(context.Background(), *state, *destination, *expected)
		status = "backup_created"
	case "restore":
		flags := flag.NewFlagSet("trestle setup backup restore", flag.ContinueOnError)
		flags.SetOutput(stderr)
		snapshot := flags.String("snapshot", "", "protected setup backup snapshot")
		destination := flags.String("destination", "", "new protected setup state file")
		expectedRoot := flags.String("expected-root-identity", "", "expected initial setup plan identity")
		expectedPlan := flags.String("expected-plan-identity", "", "expected backed-up plan identity")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *snapshot == "" || *destination == "" || !validAdminDigest(*expectedRoot) || !validAdminDigest(*expectedPlan) {
			writeSetupUsage(stderr)
			return 2
		}
		plan, err = setupcore.RestoreBackupSnapshot(context.Background(), *snapshot, *destination, *expectedRoot, *expectedPlan)
		status = "backup_restored"
	default:
		writeSetupUsage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "setup backup failed")
		return 1
	}
	result := struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		PlanIdentity  string `json:"plan_identity"`
		Revision      uint64 `json:"revision"`
		Ready         bool   `json:"ready"`
	}{"open-trestle/setup-command-result", 1, status, plan.Identity(), plan.Revision(), plan.Ready()}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}

func writeSetupUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: trestle setup bootstrap init|check|inspect (local-first protected configuration and first-review commands)")
	fmt.Fprintln(writer, "usage: trestle setup init --profile PROFILE --tenant ID --repository ID --recovery-owner NAME --state PATH")
	fmt.Fprintln(writer, "       trestle setup inspect --state PATH [--expected-root-identity HEX64]")
	fmt.Fprintln(writer, "       trestle setup check storage --state PATH --storage-root PATH")
	fmt.Fprintln(writer, "       trestle setup check observer --state PATH")
	fmt.Fprintln(writer, "       trestle setup check integration --state PATH --approve-integration-permission-authority-identity HEX64 --approve-github-source-broker-authority-identity HEX64 --allow-github-installation-token-creation --approved-by NAME (protected OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG; retained owner records and token creation)")
	fmt.Fprintln(writer, "       trestle setup check webhook --state PATH --approve-webhook-authority-identity HEX64 --github-webhook-key-id ID --approved-by NAME")
	fmt.Fprintln(writer, "       trestle setup check administrator --state PATH --approved-by NAME")
	fmt.Fprintln(writer, "       trestle setup backup create --state PATH --destination PATH --expected-plan-identity HEX64")
	fmt.Fprintln(writer, "       trestle setup backup restore --snapshot PATH --destination PATH --expected-root-identity HEX64 --expected-plan-identity HEX64")
	fmt.Fprintln(writer, "       trestle setup check backup --state PATH --backup-snapshot PATH")
	fmt.Fprintln(writer, "       trestle setup check provider --state PATH --route-inventory PATH --runtime-policy PATH --approve-inventory-identity HEX64 --approve-runtime-policy-identity HEX64 --approve-review-policy-identity HEX64 --approved-by NAME")
	fmt.Fprintln(writer, "       trestle setup check policy --state PATH --route-inventory PATH --runtime-policy PATH --approve-inventory-identity HEX64 --approve-runtime-policy-identity HEX64 --approve-review-policy-identity HEX64 --approved-by NAME")
	fmt.Fprintln(writer, "       trestle setup check dry-run --state PATH --route-inventory PATH --runtime-policy PATH --approve-inventory-identity HEX64 --approve-runtime-policy-identity HEX64 --approve-review-policy-identity HEX64 --approved-by NAME")
	fmt.Fprintln(writer, "       trestle setup check inference --state PATH --route-inventory PATH --runtime-policy PATH --approve-inventory-identity HEX64 --approve-runtime-policy-identity HEX64 --approve-review-policy-identity HEX64 --approved-by NAME")
	fmt.Fprintln(writer, "       trestle setup tui --state PATH [OPTIONS]")
	fmt.Fprintln(writer, "       trestle setup web --state PATH [--listen LOOPBACK:PORT]")
}
