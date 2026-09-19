//go:build unix

package main

import (
	"context"
	"encoding/json"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	s3store "github.com/georgejieh/open-trestle/adapters/storage/s3"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/review"
)

const daemonBudgetedPipelineReviewPolicyID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type daemonBudgetedPipelineHarness struct {
	sql              *daemonBudgetedSQLService
	s3               *daemonBudgetedS3Fixture
	kms              *daemonBudgetedKMSFixture
	clock            *daemonBudgetedHandlerClock
	github           *daemonBudgetedGitHubFixture
	model            *daemonBudgetedModelFixture
	policyPath       string
	caPath           string
	sqlAuthority     string
	githubAuthority  string
	githubConfigPath string
	values           map[string]string
	reads            map[string]int
	readMu           sync.Mutex
}

func newDaemonBudgetedPipelineHarness(t *testing.T) *daemonBudgetedPipelineHarness {
	t.Helper()
	clock := newDaemonBudgetedHandlerClock()
	sqlService := newDaemonBudgetedSQLService(t)
	s3 := newDaemonBudgetedS3FixtureWithProfile(t, daemonBudgetedBucket, daemonBudgetedRegion, daemonBudgetedS3Access, daemonBudgetedS3Secret, daemonBudgetedS3Session, daemonBudgetedS3Profile{MaxRawRequests: 512, MaxBodyBytes: daemonBudgetedS3MaxBodyBytes, MaxAggregateBytes: 16 << 20})
	kms := newDaemonBudgetedKMSFixtureWithProfile(t, daemonBudgetedRegion, daemonBudgetedKMSKeyARN, daemonBudgetedKMSAccess, daemonBudgetedKMSSecret, daemonBudgetedKMSSession, daemonBudgetedKMSProfile{MaxRawRequests: 256, MaxBodyBytes: daemonBudgetedKMSMaxBodyBytes, MaxAggregateBytes: 16 << 20})
	sqlAuthority := daemonBudgetedAuthorityIdentity(sqlService.catalog)
	backendIdentity, err := s3store.ConfigurationIdentity(s3.Endpoint(), daemonBudgetedRegion, daemonBudgetedBucket)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := daemonBudgetedProtectedFile(t, "policy.json", daemonBudgetedPolicyWire(t, backendIdentity, sqlAuthority, clock.UTCMS()))
	caPath := daemonBudgetedProtectedFile(t, "ca.pem", string(s3.CAPEM()))
	root := t.TempDir()
	github := newDaemonBudgetedGitHubFixture(t, clock.Now())
	githubConfigPath, githubAuthority := writeDaemonBudgetedGitHubBrokerDescriptor(t, root, github)
	model := newDaemonBudgetedModelFixture(t, daemonBudgetedPipelineReviewPolicyID)
	values := map[string]string{
		"OPEN_TRESTLE_API_TOKEN":                   strings.Repeat("t", 32),
		"OPEN_TRESTLE_POSTGRES_URL":                "postgres://budgeted-runtime.fixture/open_trestle",
		"OPEN_TRESTLE_S3_ACCESS_KEY_ID":            daemonBudgetedS3Access,
		"OPEN_TRESTLE_S3_SECRET_ACCESS_KEY":        daemonBudgetedS3Secret,
		"OPEN_TRESTLE_S3_SESSION_TOKEN":            daemonBudgetedS3Session,
		"OPEN_TRESTLE_AWS_ACCESS_KEY_ID":           daemonBudgetedKMSAccess,
		"OPEN_TRESTLE_AWS_SECRET_ACCESS_KEY":       daemonBudgetedKMSSecret,
		"OPEN_TRESTLE_AWS_SESSION_TOKEN":           daemonBudgetedKMSSession,
		"OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET":       daemonBudgetedGitHubWebhook,
		"OPEN_TRESTLE_GITHUB_SOURCE_BROKER_CONFIG": githubConfigPath,
		"OPEN_TRESTLE_GITHUB_APP_PRIVATE_KEY":      string(github.pem),
		"OPEN_TRESTLE_GITHUB_SETUP_TOKEN":          daemonBudgetedGitHubSetupToken,
		"OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN":    daemonBudgetedGitHubPubToken,
		daemonBudgetedModelGenerationKeyEnv:        daemonBudgetedModelGenerationKey,
		daemonBudgetedModelVerificationKeyEnv:      daemonBudgetedModelVerificationKey,
	}
	return &daemonBudgetedPipelineHarness{sql: sqlService, s3: s3, kms: kms, clock: clock, github: github, model: model, policyPath: policyPath, caPath: caPath, sqlAuthority: sqlAuthority, githubAuthority: githubAuthority, githubConfigPath: githubConfigPath, values: values, reads: map[string]int{}}
}

func (h *daemonBudgetedPipelineHarness) env(key string) string {
	h.readMu.Lock()
	defer h.readMu.Unlock()
	h.reads[key]++
	return h.values[key]
}

func (h *daemonBudgetedPipelineHarness) readCount(key string) int {
	h.readMu.Lock()
	defer h.readMu.Unlock()
	return h.reads[key]
}

func (h *daemonBudgetedPipelineHarness) args(t *testing.T) []string {
	t.Helper()
	args := []string{
		"--listen", "127.0.0.1:0",
		"--state-dir", filepath.Join(t.TempDir(), "state"),
		"--tenant", daemonBudgetedTenant,
		"--repository", daemonBudgetedRepository,
		"--metadata-store", "postgres",
		"--postgres-database-authority-identity", h.sqlAuthority,
		"--artifact-store", "s3",
		"--artifact-erasure-mode", "budgeted",
		"--erasure-policy", h.policyPath,
		"--s3-erasure-trusted-ca", h.caPath,
		"--s3-endpoint", h.s3.Endpoint(),
		"--s3-region", daemonBudgetedRegion,
		"--s3-bucket", daemonBudgetedBucket,
		"--s3-prefix", daemonBudgetedPrefix,
		"--kms-region", daemonBudgetedRegion,
		"--kms-key-arn", daemonBudgetedKMSKeyARN,
		"--kms-endpoint", h.kms.Endpoint(),
		"--github-webhook-repository", daemonBudgetedRepository,
		"--github-webhook-key-id", "key-2026-09",
		"--github-open-runs",
		"--github-local-deterministic-workers",
		"--github-repository-full-name", "owner/repo",
		"--github-review-mode", "advisory",
		"--github-review-policy-identity", daemonBudgetedPipelineReviewPolicyID,
		"--approve-github-source-broker-authority-identity", h.githubAuthority,
		"--runtime-route-inventory", h.model.inventoryPath,
		"--runtime-policy", h.model.policyPath,
	}
	return args
}

func (h *daemonBudgetedPipelineHarness) build(t *testing.T, ctx context.Context) *daemon {
	t.Helper()
	d, err := buildDaemonWithDependencies(ctx, h.args(t), h.env, io.Discard, daemonDependencies{openPostgres: h.sql.OpenPostgres, clock: h.clock})
	if err != nil {
		t.Fatalf("budgeted pipeline daemon build failed: %v", err)
	}
	return d
}

func TestDaemonBudgetedLocalSupervisorRunsModelPipelineToReadinessWithUTCMillisecondArtifacts(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fixture := newDaemonBudgetedPipelineHarness(t)
	d := fixture.build(t, ctx)
	defer d.Close()
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("startup contacted artifact providers: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}
	if calls, _, _, failures := fixture.model.generation.snapshot(); calls != 0 || len(failures) != 0 {
		t.Fatalf("startup contacted generation model: calls=%d failures=%v", calls, failures)
	}
	handlers := daemonBudgetedHandlerIdentities(t, d)
	for _, kind := range []string{"acquire_source", "build_change", "inspect_deterministic", "retrieve_context", "assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication"} {
		if handlers[kind] == "" {
			t.Fatalf("runtime status omitted local handler %s: %#v", kind, handlers)
		}
	}
	if handlers["publish_result"] != "" {
		t.Fatalf("advisory pipeline unexpectedly configured publication handler: %#v", handlers)
	}
	if fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN") != 0 {
		t.Fatalf("publication credential was read before publication was configured: %d", fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"))
	}
	supervisor := daemonBudgetedLocalSupervisor(t, d)
	scope, err := audit.NewReviewScope(daemonBudgetedTenant, daemonBudgetedRepository, "run-budgeted-pipeline-clock")
	if err != nil {
		t.Fatal(err)
	}
	repository, err := evidence.NewRepositoryIdentity("github.com", []string{"owner"}, "repo")
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := githubsource.BrokeredSourceAdapterIdentity()
	if err != nil {
		t.Fatal(err)
	}
	created := fixture.clock.UTCMS().Add(-time.Second)
	expires := fixture.clock.UTCMS().Add(time.Hour)
	baseInput := daemonBudgetedSourceInputArtifact(t, scope, repository, adapter, daemonBudgetedGitHubBaseCommit, created, expires)
	headInput := daemonBudgetedSourceInputArtifact(t, scope, repository, adapter, daemonBudgetedGitHubHeadCommit, created, expires)
	for _, value := range []artifact.Artifact{baseInput, headInput} {
		if ok, err := d.artifactStore.Put(ctx, value, fixture.clock.UTCMS()); err != nil || !ok {
			t.Fatalf("persist source input %s: created=%v err=%v", value.Identity(), ok, err)
		}
	}
	plan := daemonBudgetedPipelinePlan(t, scope, handlers, baseInput.Identity(), headInput.Identity())
	if err := d.journal.SavePlan(ctx, plan); err != nil {
		t.Fatalf("SavePlan rejected real model pipeline plan: %v", err)
	}
	coordinator, err := controlplane.NewCoordinator(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(ctx, plan, fixture.clock.UTCMS()); err != nil {
		t.Fatalf("open saved model pipeline plan: %v", err)
	}
	worked, err := supervisor.RunOnce(ctx)
	if err != nil || !worked {
		t.Fatalf("local supervisor RunOnce = (%v, %v)", worked, err)
	}
	finalizer, err := controlplane.NewRunFinalizer(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	state, finalized, err := finalizer.ReconcileRun(ctx, scope, time.Now().UTC().Truncate(time.Millisecond))
	if err != nil || !finalized || state.Status() != controlplane.ReviewRunSucceeded {
		t.Fatalf("finalize model pipeline run = (%v, %v, %v)", state.Status(), finalized, err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TaskCount() != 9 {
		t.Fatalf("task count = %d, want 9", receipt.TaskCount())
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context", "candidates", "verification", "readiness"} {
		task, ok := receipt.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeSucceeded || task.OutputIdentity() == "" {
			t.Fatalf("task %s did not succeed from actual journal: %#v", key, task)
		}
	}
	readAt := fixture.clock.UTCMS()
	baseSnapshotArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "source-base", readAt)
	headSnapshotArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "source-head", readAt)
	changeArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "change", readAt)
	analysisArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "analysis", readAt)
	memoryArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "memory", readAt)
	generationInputArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "context", readAt)
	generationArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "candidates", readAt)
	verificationArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "verification", readAt)
	readinessArtifact := daemonBudgetedTaskOutput(t, ctx, d, scope, receipt, "readiness", readAt)
	for label, value := range map[string]artifact.Artifact{"base": baseSnapshotArtifact, "head": headSnapshotArtifact, "change": changeArtifact, "analysis": analysisArtifact, "memory": memoryArtifact, "context-input": generationInputArtifact, "candidates": generationArtifact, "verification": verificationArtifact, "readiness": readinessArtifact} {
		daemonBudgetedAssertUTCMS(t, label+" created_at", value.CreatedAt(), fixture.clock.UTCMS())
		if value.Protection() != artifact.ProtectionEnvelopeEncrypted || value.Classification() != artifact.ClassificationRestricted {
			t.Fatalf("%s artifact was not budgeted protected restricted output", label)
		}
	}
	change, err := changehandler.ParseResultArtifact(changeArtifact, baseSnapshotArtifact, headSnapshotArtifact)
	if err != nil || len(change.Entries()) != 1 || change.HeadRevision().Digest() != daemonBudgetedGitHubHeadCommit {
		t.Fatalf("change result = %#v err=%v", change, err)
	}
	analysis, err := analysishandler.ParseResultArtifact(analysisArtifact, changeArtifact, baseSnapshotArtifact, headSnapshotArtifact)
	if err != nil || analysis.ChangeIdentity() != change.Identity() || len(analysis.Items()) == 0 {
		t.Fatalf("analysis result = %#v err=%v", analysis, err)
	}
	memory, err := memoryhandler.ParseResultArtifact(memoryArtifact, changeArtifact, baseSnapshotArtifact, headSnapshotArtifact)
	if err != nil || memory.ChangeArtifactIdentity() != changeArtifact.Identity() || len(memory.Queries()) != 1 || memory.PolicyIdentity() != daemonBudgetedPipelineReviewPolicyID {
		t.Fatalf("memory result = %#v err=%v", memory, err)
	}
	input, err := modelhandler.ParseGenerationInput(generationInputArtifact.Payload())
	if err != nil || input.ReviewScopeIdentity() != scope.Identity() || input.Authorization().RouteReference().ModelID() != "model-a" || input.Authorization().RouteRecordIdentity() != fixture.model.generationRoute {
		t.Fatalf("generation input route binding lost: %#v err=%v", input, err)
	}
	contextArtifact, err := d.artifactStore.Get(ctx, scope, input.ContextArtifactIdentity(), readAt)
	if err != nil {
		t.Fatal(err)
	}
	if contextArtifact.Kind() != artifact.KindContextPacket || contextArtifact.Origin() != artifact.OriginHost || !containsString(contextArtifact.Provenance(), analysisArtifact.Identity()) || !containsString(contextArtifact.Provenance(), memoryArtifact.Identity()) {
		t.Fatalf("context artifact lost host provenance or kind: %#v", contextArtifact)
	}
	generation, err := modelhandler.ParseGenerationResultArtifact(generationArtifact, generationInputArtifact, contextArtifact)
	if err != nil || generation.ContextIdentity() != input.ContextIdentity() || len(generation.Candidates().Findings()) != 1 || generation.RouteExecution().Outcome().Usage().InputTokens() != 120 || generation.RouteExecution().Outcome().Usage().OutputTokens() != 80 {
		t.Fatalf("generation result = %#v err=%v", generation, err)
	}
	verification, err := modelhandler.ParseVerificationResultArtifact(verificationArtifact, generationArtifact, generationInputArtifact, contextArtifact)
	if err != nil || verification.GenerationArtifactIdentity() != generationArtifact.Identity() || verification.Verification().Results()[0].Outcome() != review.VerificationVerified || verification.RouteExecution().Authorization().RouteReference().ModelID() != "model-b" || verification.RouteExecution().Authorization().RouteRecordIdentity() != fixture.model.verificationRoute {
		t.Fatalf("verification result = %#v err=%v", verification, err)
	}
	var readinessWire struct {
		Contract                     string `json:"contract"`
		VerificationArtifactIdentity string `json:"verification_artifact_identity"`
		VerificationResultIdentity   string `json:"verification_result_identity"`
		PublicationPolicyIdentity    string `json:"publication_policy_identity"`
		Status                       string `json:"status"`
		Verified                     uint8  `json:"verified"`
		Inline                       int    `json:"inline"`
	}
	if json.Unmarshal(readinessArtifact.Payload(), &readinessWire) != nil || readinessWire.Contract != "open-trestle/publication-readiness-result" || readinessWire.Status != "advisory_ready" || readinessWire.Verified != 1 || readinessWire.Inline != 1 || readinessWire.VerificationArtifactIdentity != verificationArtifact.Identity() || readinessWire.VerificationResultIdentity != verification.Identity() {
		t.Fatalf("readiness payload lost verified advisory gate: %#v", readinessWire)
	}
	diagnosticsSet, err := d.diagnosticStore.GetDiagnosticSet(ctx, scope)
	if err != nil || diagnosticsSet.VerifiedCount() != 1 || diagnosticsSet.SnapshotIdentity() != verification.VerifiedFindings().SnapshotIdentity() {
		t.Fatalf("diagnostic set = %#v err=%v", diagnosticsSet, err)
	}
	if findings := diagnosticsSet.Findings(); len(findings) != 1 || findings[0].Severity() != diagnostics.SeverityError || findings[0].Path() == "" || len(findings[0].EvidenceIDs()) == 0 {
		t.Fatalf("diagnostic finding lost verified source identity: %#v", findings)
	}
	generationCalls, generationBytes, generationCaptures, generationFailures := fixture.model.generation.snapshot()
	verificationCalls, verificationBytes, verificationCaptures, verificationFailures := fixture.model.verification.snapshot()
	if generationCalls != 1 || verificationCalls != 1 || len(generationCaptures) != 1 || len(verificationCaptures) != 1 || len(generationFailures)+len(verificationFailures) != 0 {
		t.Fatalf("model fixture traffic = gen(%d,%d,%d,%v) verify(%d,%d,%d,%v)", generationCalls, generationBytes, len(generationCaptures), generationFailures, verificationCalls, verificationBytes, len(verificationCaptures), verificationFailures)
	}
	if generationCaptures[0].Packet.Task != "candidate_generation" || verificationCaptures[0].Packet.Task != "candidate_verification" || verificationCaptures[0].Packet.GenerationContext != generation.ContextIdentity() || generationCaptures[0].RequestID != input.Authorization().RequestIdentity() {
		t.Fatalf("model capture lost request identities: gen=%#v verify=%#v", generationCaptures[0], verificationCaptures[0])
	}
	if fixture.readCount(daemonBudgetedModelGenerationKeyEnv) != 1 || fixture.readCount(daemonBudgetedModelVerificationKeyEnv) != 1 || fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN") != 0 {
		t.Fatalf("credential reads were not separated: gen=%d verify=%d publication=%d", fixture.readCount(daemonBudgetedModelGenerationKeyEnv), fixture.readCount(daemonBudgetedModelVerificationKeyEnv), fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"))
	}
	if failures := fixture.s3.Failures(); len(failures) != 0 {
		t.Fatalf("S3 fixture rejected pipeline requests: %v", failures)
	}
	if failures := fixture.kms.Failures(); len(failures) != 0 {
		t.Fatalf("KMS fixture rejected pipeline requests: %v", failures)
	}
	if got := fixture.s3.RawRequests(); got == 0 || got > 512 {
		t.Fatalf("S3 pipeline profile bound not honored: %d", got)
	}
	if got := fixture.kms.RawRequests(); got == 0 || got > 256 {
		t.Fatalf("KMS pipeline profile bound not honored: %d", got)
	}
	sqlSnapshot := fixture.sql.Snapshot()
	for _, id := range []string{"run_plan_insert", "run_event_insert", "audit_event_insert", "audit_events_read", "audit_event_head", "diagnostic_insert", "metadata_insert", "admission_insert", "confirmation_cas"} {
		if !daemonBudgetedTraceContains(sqlSnapshot.Events, id) {
			t.Fatalf("pipeline SQL did not execute %s", id)
		}
	}
	if len(sqlSnapshot.AuditEvents[daemonBudgetedScopeKey(daemonBudgetedTenant, daemonBudgetedRepository, scope.ReviewRunID())]) == 0 {
		t.Fatal("audit ledger did not retain model/readiness events")
	}
	if len(sqlSnapshot.Failures) != 0 {
		t.Fatalf("SQL fixture rejected model pipeline run: %v", sqlSnapshot.Failures)
	}
	t.Logf("external requests: model_generation=%d/%dB model_verification=%d/%dB S3=%d KMS=%d", generationCalls, generationBytes, verificationCalls, verificationBytes, fixture.s3.RawRequests(), fixture.kms.RawRequests())
}

func daemonBudgetedPipelinePlan(t *testing.T, scope audit.ReviewScope, handlers map[string]string, baseInput, headInput string) controlplane.ReviewRunPlan {
	t.Helper()
	mk := func(key string, kind controlplane.TaskKind, input, handler string, dependencies []string) controlplane.TaskDefinition {
		attempt, err := controlplane.DefaultTaskAttemptPolicy(kind)
		if err != nil {
			t.Fatal(err)
		}
		task, err := controlplane.NewTaskDefinition(key, kind, input, handler, dependencies, attempt.MaximumAttempts(), attempt.RetryDelayMilliseconds(), attempt.LeaseDurationMilliseconds(), true)
		if err != nil {
			t.Fatalf("task %s: %v", key, err)
		}
		return task
	}
	tasks := []controlplane.TaskDefinition{
		mk("source-base", controlplane.TaskAcquireSource, baseInput, handlers["acquire_source"], nil),
		mk("source-head", controlplane.TaskAcquireSource, headInput, handlers["acquire_source"], nil),
		mk("change", controlplane.TaskBuildChange, strings.Repeat("c", 64), handlers["build_change"], []string{"source-base", "source-head"}),
		mk("analysis", controlplane.TaskInspectDeterministic, strings.Repeat("d", 64), handlers["inspect_deterministic"], []string{"change"}),
		mk("memory", controlplane.TaskRetrieveContext, strings.Repeat("e", 64), handlers["retrieve_context"], []string{"change"}),
		mk("context", controlplane.TaskAssembleContext, strings.Repeat("f", 64), handlers["assemble_context"], []string{"analysis", "memory"}),
		mk("candidates", controlplane.TaskGenerateCandidates, strings.Repeat("1", 64), handlers["generate_candidates"], []string{"context"}),
		mk("verification", controlplane.TaskVerifyCandidates, strings.Repeat("2", 64), handlers["verify_candidates"], []string{"candidates"}),
		mk("readiness", controlplane.TaskEvaluatePublication, strings.Repeat("3", 64), handlers["evaluate_publication"], []string{"analysis", "change", "verification"}),
	}
	plan, err := controlplane.NewReviewRunPlan(scope, strings.Repeat("b", 64), daemonBudgetedPipelineReviewPolicyID, controlplane.ReviewRunAdvisory, tasks)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
