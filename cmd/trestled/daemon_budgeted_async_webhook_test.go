//go:build unix

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	githubwebhook "github.com/georgejieh/open-trestle/adapters/webhook/github"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/review"
	webhookpkg "github.com/georgejieh/open-trestle/webhook"
)

func TestDaemonBudgetedAsyncWebhookSupervisorOpensPreparedPipelineWithUTCMillisecondInputs(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	fixture := newDaemonBudgetedPipelineHarness(t)
	d := fixture.build(t, ctx)
	defer d.Close()
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("startup contacted artifact providers: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}

	supervisor := daemonBudgetedWebhookSupervisor(t, d)
	repositoryScope, err := webhookpkg.NewRepositoryScope(daemonBudgetedTenant, daemonBudgetedRepository)
	if err != nil {
		t.Fatal(err)
	}
	verifierIdentity, err := githubwebhook.VerifierConfigurationIdentity(repositoryScope, "key-2026-09")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"action":"opened","number":42,"repository":{"full_name":"owner/repo"},"pull_request":{"base":{"sha":"` + daemonBudgetedGitHubBaseCommit + `","repo":{"full_name":"owner/repo"}},"head":{"sha":"` + daemonBudgetedGitHubHeadCommit + `","repo":{"full_name":"owner/repo"}}}}`)
	deliveryID := "delivery-budgeted-async-1"
	receivedAt := fixture.clock.UTCMS()
	expectedDelivery, err := webhookpkg.NewVerifiedDelivery(repositoryScope, webhookpkg.SourceGitHub, deliveryID, "pull_request", "opened", verifierIdentity, payload, receivedAt)
	if err != nil {
		t.Fatal(err)
	}

	httpCtx, httpCancel := daemonBudgetedOperationContext(t, "webhook-async-http")
	request := httptest.NewRequest(http.MethodPost, "https://trestle.test/webhooks/github", bytes.NewReader(payload)).WithContext(httpCtx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Delivery", deliveryID)
	request.Header.Set("X-GitHub-Event", "pull_request")
	request.Header.Set("X-Hub-Signature-256", "sha256="+daemonBudgetedSignWebhook(daemonBudgetedGitHubWebhook, payload))
	response := httptest.NewRecorder()
	d.server.Handler.ServeHTTP(response, request)
	httpCancel()
	if response.Code != http.StatusAccepted {
		t.Fatalf("webhook response=%d %s", response.Code, response.Body.String())
	}
	var accepted daemonBudgetedWebhookHTTPResponse
	if err := json.Unmarshal(response.Body.Bytes(), &accepted); err != nil || accepted.Contract != "open-trestle/webhook-response" || accepted.SchemaVersion != 1 || accepted.AcceptanceIdentity == "" || accepted.Duplicate || accepted.Ignored || accepted.Error != "" {
		t.Fatalf("webhook response body=(%#v,%v)", accepted, err)
	}

	readCtx, readCancel := daemonBudgetedOperationContext(t, "webhook-async-get-before-supervisor")
	stored, found, err := d.inboxStore.Get(readCtx, repositoryScope, webhookpkg.SourceGitHub, expectedDelivery.DeduplicationKey())
	readCancel()
	if err != nil || !found {
		t.Fatalf("inbox Get before supervisor = (%#v,%t,%v)", stored, found, err)
	}
	assertBudgetedStoredWebhookMatches(t, stored, expectedDelivery, accepted.AcceptanceIdentity, payload, receivedAt)

	webhookRunScope, err := audit.NewReviewScope(repositoryScope.TenantID(), repositoryScope.RepositoryID(), webhookpkg.ReviewRunIDForDelivery(expectedDelivery))
	if err != nil {
		t.Fatal(err)
	}
	initialSnapshot := fixture.sql.Snapshot()
	mapping, ok := initialSnapshot.Webhooks[daemonBudgetedWebhookKey(repositoryScope.TenantID(), repositoryScope.RepositoryID(), webhookpkg.SourceGitHub.String(), expectedDelivery.DeduplicationKey())]
	if !ok || mapping.DeliveryIdentity != expectedDelivery.Identity() || mapping.ArtifactIdentity == "" || mapping.Run != webhookRunScope.ReviewRunID() || mapping.ReviewScopeIdentity != webhookRunScope.Identity() {
		t.Fatalf("webhook mapping was not accepted through product SQL: %#v ok=%t", mapping, ok)
	}
	assertBudgetedUTCMillisecond(t, "webhook mapping accepted_at", mapping.AcceptedAt, receivedAt)

	supervisorCtx, supervisorCancel := context.WithCancel(ctx)
	var supervisorErr error
	supervisorDone := make(chan struct{})
	go func() {
		supervisorErr = supervisor.Run(supervisorCtx)
		close(supervisorDone)
	}()
	var stopSupervisorOnce sync.Once
	stopSupervisor := func() {
		stopSupervisorOnce.Do(func() {
			supervisorCancel()
			select {
			case <-supervisorDone:
				if supervisorErr != nil {
					t.Errorf("webhook supervisor Run returned after cancellation: %v", supervisorErr)
				}
			case <-time.After(5 * time.Second):
				t.Errorf("webhook supervisor did not stop after cancellation")
			}
		})
	}
	defer stopSupervisor()

	select {
	case <-supervisor.Ready():
	case <-supervisorDone:
		t.Fatalf("webhook supervisor exited before ready: %v", supervisorErr)
	case <-ctx.Done():
		t.Fatalf("webhook supervisor was not ready before context deadline: %v", ctx.Err())
	}
	stopSupervisor()

	coordinator, err := controlplane.NewCoordinator(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	plan, state, err := coordinator.Resume(ctx, webhookRunScope)
	if err != nil {
		t.Fatalf("resume webhook-opened run: %v", err)
	}
	if plan.RequestIdentity() != expectedDelivery.Identity() || plan.PolicyIdentity() != daemonBudgetedPipelineReviewPolicyID || plan.Mode() != controlplane.ReviewRunAdvisory || plan.Scope().Identity() != webhookRunScope.Identity() || plan.TaskCount() != 9 {
		t.Fatalf("webhook generated unexpected plan: scope=%s request=%s policy=%s mode=%s tasks=%d", plan.Scope().Identity(), plan.RequestIdentity(), plan.PolicyIdentity(), plan.Mode(), plan.TaskCount())
	}
	openReceipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil || openReceipt.Status() != controlplane.ReviewRunActive || openReceipt.TaskCount() != 9 {
		t.Fatalf("opened webhook receipt=(%#v,%v)", openReceipt, err)
	}
	for _, key := range []string{"source-base", "source-head"} {
		task, ok := openReceipt.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeAvailable || !task.LeaseExpiresAt().IsZero() {
			t.Fatalf("root task %s was not opened as available without a lease: %#v", key, task)
		}
	}

	baseTask, ok := plan.Task("source-base")
	if !ok {
		t.Fatal("webhook plan omitted source-base")
	}
	headTask, ok := plan.Task("source-head")
	if !ok {
		t.Fatal("webhook plan omitted source-head")
	}
	baseInputArtifact, err := d.artifactStore.Get(ctx, webhookRunScope, baseTask.InputIdentity(), receivedAt)
	if err != nil {
		t.Fatalf("get prepared base input: %v", err)
	}
	headInputArtifact, err := d.artifactStore.Get(ctx, webhookRunScope, headTask.InputIdentity(), receivedAt)
	if err != nil {
		t.Fatalf("get prepared head input: %v", err)
	}
	daemonBudgetedAssertPreparedSourceInput(t, baseInputArtifact, webhookRunScope, expectedDelivery, daemonBudgetedGitHubBaseCommit)
	daemonBudgetedAssertPreparedSourceInput(t, headInputArtifact, webhookRunScope, expectedDelivery, daemonBudgetedGitHubHeadCommit)

	worked, err := daemonBudgetedLocalSupervisor(t, d).RunOnce(ctx)
	if err != nil || !worked {
		t.Fatalf("local supervisor RunOnce on webhook plan = (%t,%v)", worked, err)
	}
	finalizer, err := controlplane.NewRunFinalizer(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	finalState, finalized, err := finalizer.ReconcileRun(ctx, webhookRunScope, time.Now().UTC().Truncate(time.Millisecond))
	if err != nil || !finalized || finalState.Status() != controlplane.ReviewRunSucceeded {
		t.Fatalf("finalize webhook plan = (%v,%t,%v)", finalState.Status(), finalized, err)
	}
	finalReceipt, err := controlplane.NewReviewRunReceipt(finalState)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"source-base", "source-head", "change", "analysis", "memory", "context", "candidates", "verification", "readiness"} {
		task, ok := finalReceipt.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeSucceeded || task.OutputIdentity() == "" {
			t.Fatalf("webhook-generated task %s did not succeed from actual journal: %#v", key, task)
		}
	}
	readAt := fixture.clock.UTCMS()
	readinessArtifact := daemonBudgetedTaskOutput(t, ctx, d, webhookRunScope, finalReceipt, "readiness", readAt)
	daemonBudgetedAssertUTCMS(t, "webhook readiness created_at", readinessArtifact.CreatedAt(), readAt)
	var readinessWire struct {
		Contract                     string `json:"contract"`
		VerificationArtifactIdentity string `json:"verification_artifact_identity"`
		VerificationResultIdentity   string `json:"verification_result_identity"`
		Status                       string `json:"status"`
		Verified                     uint8  `json:"verified"`
		Inline                       int    `json:"inline"`
	}
	verificationArtifact := daemonBudgetedTaskOutput(t, ctx, d, webhookRunScope, finalReceipt, "verification", readAt)
	generationInputArtifact := daemonBudgetedTaskOutput(t, ctx, d, webhookRunScope, finalReceipt, "context", readAt)
	generationArtifact := daemonBudgetedTaskOutput(t, ctx, d, webhookRunScope, finalReceipt, "candidates", readAt)
	contextInput, err := modelhandler.ParseGenerationInput(generationInputArtifact.Payload())
	if err != nil || contextInput.ReviewScopeIdentity() != webhookRunScope.Identity() || contextInput.Authorization().RouteRecordIdentity() != fixture.model.generationRoute {
		t.Fatalf("webhook context task lost route lineage: %#v err=%v", contextInput, err)
	}
	contextArtifact, err := d.artifactStore.Get(ctx, webhookRunScope, contextInput.ContextArtifactIdentity(), readAt)
	if err != nil {
		t.Fatal(err)
	}
	generation, err := modelhandler.ParseGenerationResultArtifact(generationArtifact, generationInputArtifact, contextArtifact)
	if err != nil || generation.ContextIdentity() != contextInput.ContextIdentity() {
		t.Fatalf("webhook generation lineage mismatch: %#v err=%v", generation, err)
	}
	verification, err := modelhandler.ParseVerificationResultArtifact(verificationArtifact, generationArtifact, generationInputArtifact, contextArtifact)
	if err != nil || verification.GenerationArtifactIdentity() != generationArtifact.Identity() || verification.Verification().Results()[0].Outcome() != review.VerificationVerified {
		t.Fatalf("webhook verification lineage mismatch: %#v err=%v", verification, err)
	}
	if json.Unmarshal(readinessArtifact.Payload(), &readinessWire) != nil || readinessWire.Contract != "open-trestle/publication-readiness-result" || readinessWire.Status != "advisory_ready" || readinessWire.Verified != 1 || readinessWire.Inline != 1 || readinessWire.VerificationArtifactIdentity != verificationArtifact.Identity() || readinessWire.VerificationResultIdentity != verification.Identity() {
		t.Fatalf("webhook readiness payload lost verified advisory gate: %#v", readinessWire)
	}

	generationCalls, _, generationCaptures, generationFailures := fixture.model.generation.snapshot()
	verificationCalls, _, verificationCaptures, verificationFailures := fixture.model.verification.snapshot()
	if generationCalls != 1 || verificationCalls != 1 || len(generationCaptures) != 1 || len(verificationCaptures) != 1 || len(generationFailures)+len(verificationFailures) != 0 {
		t.Fatalf("webhook model traffic = gen(%d,%d,%v) verify(%d,%d,%v)", generationCalls, len(generationCaptures), generationFailures, verificationCalls, len(verificationCaptures), verificationFailures)
	}

	sqlSnapshot := fixture.sql.Snapshot()
	for _, id := range []string{"webhook_read", "webhook_count", "webhook_insert", "webhook_list", "run_plan_read", "run_plan_insert", "run_event_insert", "metadata_insert", "admission_insert", "confirmation_cas"} {
		if !daemonBudgetedTraceContains(sqlSnapshot.Events, id) {
			t.Fatalf("async webhook path did not execute %s; trace=%#v", id, sqlSnapshot.Events)
		}
	}
	for _, id := range []string{"webhook_insert", "run_plan_insert", "run_event_insert", "metadata_insert", "admission_insert"} {
		if !daemonBudgetedCommittedStatement(sqlSnapshot.Events, id) {
			t.Fatalf("async webhook path did not commit %s; trace=%#v", id, sqlSnapshot.Events)
		}
	}
	if len(sqlSnapshot.Failures) != 0 {
		t.Fatalf("SQL fixture rejected async webhook path: %v", sqlSnapshot.Failures)
	}
	if failures := fixture.s3.Failures(); len(failures) != 0 {
		t.Fatalf("S3 fixture rejected async webhook path: %v", failures)
	}
	if failures := fixture.kms.Failures(); len(failures) != 0 {
		t.Fatalf("KMS fixture rejected async webhook path: %v", failures)
	}
	if got := fixture.s3.RawRequests(); got == 0 || got > 512 {
		t.Fatalf("S3 async webhook profile bound not honored: %d", got)
	}
	if got := fixture.kms.RawRequests(); got == 0 || got > 256 {
		t.Fatalf("KMS async webhook profile bound not honored: %d", got)
	}
}

func daemonBudgetedWebhookSupervisor(t *testing.T, d *daemon) *webhookpkg.Supervisor {
	t.Helper()
	for index, name := range d.supervisorNames {
		if name != "webhook_processing" {
			continue
		}
		supervisor, ok := d.supervisors[index].(*webhookpkg.Supervisor)
		if !ok || supervisor == nil {
			t.Fatalf("webhook_processing supervisor has unexpected type %#v", d.supervisors[index])
		}
		return supervisor
	}
	t.Fatalf("webhook_processing supervisor was not registered: %#v", d.supervisorNames)
	return nil
}

func daemonBudgetedAssertPreparedSourceInput(t *testing.T, value artifact.Artifact, scope audit.ReviewScope, delivery webhookpkg.VerifiedDelivery, commit string) {
	t.Helper()
	if value.Validate() != nil || value.Scope().Identity() != scope.Identity() || value.Kind() != artifact.KindTaskInput || value.MediaType() != "application/json" || value.Classification() != artifact.ClassificationRestricted || value.Protection() != artifact.ProtectionEnvelopeEncrypted || value.Origin() != artifact.OriginHost || !containsString(value.Provenance(), delivery.Identity()) {
		t.Fatalf("prepared source input artifact lost webhook lineage: %#v", value)
	}
	daemonBudgetedAssertUTCMS(t, "prepared source input created_at", value.CreatedAt(), delivery.ReceivedAt())
	daemonBudgetedAssertUTCMS(t, "prepared source input expires_at", value.ExpiresAt(), delivery.ReceivedAt().Add(24*time.Hour))
	input, err := sourcehandler.ParseInput(value.Payload())
	if err != nil {
		t.Fatalf("parse prepared source input: %v", err)
	}
	adapter, err := githubsource.BrokeredSourceAdapterIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if input.Repository().Authority() != "github.com" || strings.Join(input.Repository().Namespace(), "/") != "owner" || input.Repository().Name() != "repo" || input.Revision().Digest() != commit || input.SourceAdapterIdentity() != adapter.Identity() {
		t.Fatalf("prepared source input payload mismatch: %#v", input)
	}
}
