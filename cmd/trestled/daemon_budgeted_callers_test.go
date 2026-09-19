package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	githubwebhook "github.com/georgejieh/open-trestle/adapters/webhook/github"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/webhook"
)

const daemonBudgetedWebhookSecret = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

func TestBuildDaemonBudgetedDiagnosticStoreUsesRealArtifactPath(t *testing.T) {
	fixture := newDaemonBudgetedHarness(t)
	d := daemonBudgetedBuildForCaller(t, fixture, fixture.args(t), fixture.env)
	defer d.Close()
	if d.diagnosticStore == nil || d.artifactStore == nil {
		t.Fatal("budgeted daemon did not expose diagnostic and artifact stores")
	}
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("startup contacted external artifact services: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}

	scope, err := audit.NewReviewScope(daemonBudgetedTenant, daemonBudgetedRepository, "run-budgeted-diagnostics")
	if err != nil {
		t.Fatal(err)
	}
	finding, err := diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Budgeted diagnostic survives protected storage", "The daemon-owned diagnostic store must persist the full verified finding set through the encrypted artifact path.", diagnostics.SeverityWarning, "cmd/trestled/main.go", 321, 323, []string{"evidence:budgeted-diagnostic"})
	if err != nil {
		t.Fatal(err)
	}
	want, err := diagnostics.NewSetWithSourceCoverage(scope, strings.Repeat("c", 64), strings.Repeat("1", 40), strings.Repeat("d", 64), strings.Repeat("e", 64), 3, 1, 1, 9, 1, 8, []diagnostics.Finding{finding})
	if err != nil {
		t.Fatal(err)
	}

	putCtx, putCancel := daemonBudgetedOperationContext(t, "diagnostic-put")
	created, err := d.diagnosticStore.PutDiagnosticSet(putCtx, want)
	putCancel()
	if err != nil || !created {
		t.Fatalf("PutDiagnosticSet = (%t,%v)", created, err)
	}
	firstReadCtx, firstReadCancel := daemonBudgetedOperationContext(t, "diagnostic-get-first")
	got, err := d.diagnosticStore.GetDiagnosticSet(firstReadCtx, scope)
	firstReadCancel()
	if err != nil {
		t.Fatalf("GetDiagnosticSet(first) = %v", err)
	}
	secondReadCtx, secondReadCancel := daemonBudgetedOperationContext(t, "diagnostic-get-second")
	gotAgain, err := d.diagnosticStore.GetDiagnosticSet(secondReadCtx, scope)
	secondReadCancel()
	if err != nil {
		t.Fatalf("GetDiagnosticSet(second) = %v", err)
	}
	assertBudgetedDiagnosticSetMatches(t, got, want)
	assertBudgetedDiagnosticSetMatches(t, gotAgain, want)

	otherScope, err := audit.NewReviewScope(daemonBudgetedTenant, daemonBudgetedRepository, "run-budgeted-diagnostics-other")
	if err != nil {
		t.Fatal(err)
	}
	missingCtx, missingCancel := daemonBudgetedOperationContext(t, "diagnostic-get-other")
	missing, err := d.diagnosticStore.GetDiagnosticSet(missingCtx, otherScope)
	missingCancel()
	if !errors.Is(err, diagnostics.ErrSetNotFound) || missing.Identity() != "" {
		t.Fatalf("other diagnostic scope was not isolated: (%#v,%v)", missing, err)
	}

	mapping, ok := daemonBudgetedDiagnosticMappingFor(t, fixture, scope)
	if !ok {
		t.Fatal("diagnostic mapping did not arise from product SQL")
	}
	if mapping.Tenant != scope.TenantID() || mapping.Repository != scope.RepositoryID() || mapping.Run != scope.ReviewRunID() || mapping.ScopeIdentity != scope.Identity() || mapping.SetIdentity != want.Identity() {
		t.Fatalf("diagnostic mapping mismatch: %#v", mapping)
	}
	metadata, ok := daemonBudgetedMetadataFor(t, fixture, scope, mapping.ArtifactIdentity)
	if !ok {
		t.Fatal("diagnostic artifact metadata did not arise from product SQL")
	}
	expectedAt := fixture.ClockUTCMS()
	expectedExpires := expectedAt.Add(30 * 24 * time.Hour)
	assertBudgetedUTCMillisecond(t, "diagnostic metadata created_at", metadata.CreatedAt, expectedAt)
	assertBudgetedUTCMillisecond(t, "diagnostic metadata expires_at", metadata.ExpiresAt, expectedExpires)
	assertBudgetedUTCMillisecond(t, "diagnostic mapping expires_at", mapping.ExpiresAt, expectedExpires)
	if metadata.Kind != "verified_finding_set" || metadata.Classification != "restricted" || metadata.Origin != "independent_verifier" || metadata.Protection != "envelope_encrypted" || metadata.ScopeIdentity != scope.Identity() || metadata.ArtifactIdentity != mapping.ArtifactIdentity {
		t.Fatalf("diagnostic artifact metadata mismatch: %#v", metadata)
	}

	snap := fixture.sql.Snapshot()
	for _, id := range []string{"diagnostic_read", "diagnostic_insert", "scope_insert", "metadata_insert", "admission_insert", "confirmation_cas", "admission_read", "operation_read"} {
		if !daemonBudgetedTraceContains(snap.Events, id) {
			t.Fatalf("diagnostic path did not execute %s; trace=%#v", id, snap.Events)
		}
	}
	if !daemonBudgetedCommittedStatement(snap.Events, "diagnostic_insert") || !daemonBudgetedCommittedStatement(snap.Events, "metadata_insert") || !daemonBudgetedCommittedStatement(snap.Events, "admission_insert") {
		t.Fatalf("diagnostic path did not commit mapping and artifact statements; trace=%#v", snap.Events)
	}
	assertBudgetedExternalArtifactTraffic(t, fixture)
}

func TestBuildDaemonBudgetedGitHubWebhookHTTPPersistsToPostgresArtifactInbox(t *testing.T) {
	fixture := newDaemonBudgetedHarness(t)
	keyID := "key-2026-09-budgeted"
	env := daemonBudgetedEnvironment(map[string]string{"OPEN_TRESTLE_GITHUB_WEBHOOK_SECRET": daemonBudgetedWebhookSecret}, map[string]string{"OPEN_TRESTLE_POSTGRES_URL": "postgres://budgeted-runtime.fixture/open_trestle"})
	args := append(append([]string(nil), fixture.args(t)...), "--github-webhook-repository", daemonBudgetedRepository, "--github-webhook-key-id", keyID)
	d := daemonBudgetedBuildForCaller(t, fixture, args, env)
	defer d.Close()
	if d.inboxStore == nil || d.artifactStore == nil {
		t.Fatal("budgeted daemon did not expose webhook inbox and artifact stores")
	}
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("startup contacted external artifact services: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}

	repositoryScope, err := webhook.NewRepositoryScope(daemonBudgetedTenant, daemonBudgetedRepository)
	if err != nil {
		t.Fatal(err)
	}
	verifierIdentity, err := githubwebhook.VerifierConfigurationIdentity(repositoryScope, keyID)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"action":"opened","number":42,"pull_request":{"base":{"sha":"0000000000000000000000000000000000000000"},"head":{"sha":"1111111111111111111111111111111111111111"}},"repository":{"full_name":"owner/repo-budgeted"}}`)
	deliveryID := "delivery-budgeted-http-1"
	receivedAt := fixture.ClockUTCMS()
	expectedDelivery, err := webhook.NewVerifiedDelivery(repositoryScope, webhook.SourceGitHub, deliveryID, "pull_request", "opened", verifierIdentity, payload, receivedAt)
	if err != nil {
		t.Fatal(err)
	}

	httpCtx, httpCancel := daemonBudgetedOperationContext(t, "webhook-http")
	request := httptest.NewRequest(http.MethodPost, "https://trestle.test/webhooks/github", bytes.NewReader(payload)).WithContext(httpCtx)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Delivery", deliveryID)
	request.Header.Set("X-GitHub-Event", "pull_request")
	request.Header.Set("X-Hub-Signature-256", "sha256="+daemonBudgetedSignWebhook(daemonBudgetedWebhookSecret, payload))
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
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("webhook response omitted safety headers: %#v", response.Header())
	}

	readCtx, readCancel := daemonBudgetedOperationContext(t, "webhook-get")
	stored, found, err := d.inboxStore.Get(readCtx, repositoryScope, webhook.SourceGitHub, expectedDelivery.DeduplicationKey())
	readCancel()
	if err != nil || !found {
		t.Fatalf("inbox Get = (%#v,%t,%v)", stored, found, err)
	}
	secondReadCtx, secondReadCancel := daemonBudgetedOperationContext(t, "webhook-get-second")
	storedAgain, found, err := d.inboxStore.Get(secondReadCtx, repositoryScope, webhook.SourceGitHub, expectedDelivery.DeduplicationKey())
	secondReadCancel()
	if err != nil || !found {
		t.Fatalf("inbox second Get = (%#v,%t,%v)", storedAgain, found, err)
	}
	assertBudgetedStoredWebhookMatches(t, stored, expectedDelivery, accepted.AcceptanceIdentity, payload, receivedAt)
	assertBudgetedStoredWebhookMatches(t, storedAgain, expectedDelivery, accepted.AcceptanceIdentity, payload, receivedAt)

	missingCtx, missingCancel := daemonBudgetedOperationContext(t, "webhook-get-other-source")
	missing, found, err := d.inboxStore.Get(missingCtx, repositoryScope, webhook.SourceGitLab, expectedDelivery.DeduplicationKey())
	missingCancel()
	if err != nil || found || missing.Delivery().Identity() != "" {
		t.Fatalf("webhook source collision was not isolated: (%#v,%t,%v)", missing, found, err)
	}

	mapping, ok := daemonBudgetedWebhookMappingFor(t, fixture, repositoryScope, webhook.SourceGitHub, expectedDelivery.DeduplicationKey())
	if !ok {
		t.Fatal("webhook mapping did not arise from product SQL")
	}
	reviewScope, err := audit.NewReviewScope(repositoryScope.TenantID(), repositoryScope.RepositoryID(), "webhook-"+expectedDelivery.DeduplicationKey())
	if err != nil {
		t.Fatal(err)
	}
	if mapping.Tenant != repositoryScope.TenantID() || mapping.Repository != repositoryScope.RepositoryID() || mapping.Run != reviewScope.ReviewRunID() || mapping.ReviewScopeIdentity != reviewScope.Identity() || mapping.RepositoryScopeIdentity != repositoryScope.Identity() || mapping.Source != webhook.SourceGitHub.String() || mapping.DeduplicationKey != expectedDelivery.DeduplicationKey() || mapping.DeliveryIdentity != expectedDelivery.Identity() {
		t.Fatalf("webhook mapping mismatch: %#v", mapping)
	}
	metadata, ok := daemonBudgetedMetadataFor(t, fixture, reviewScope, mapping.ArtifactIdentity)
	if !ok {
		t.Fatal("webhook artifact metadata did not arise from product SQL")
	}
	expectedExpires := receivedAt.Add(24 * time.Hour)
	assertBudgetedUTCMillisecond(t, "webhook mapping accepted_at", mapping.AcceptedAt, receivedAt)
	assertBudgetedUTCMillisecond(t, "webhook mapping expires_at", mapping.ExpiresAt, expectedExpires)
	assertBudgetedUTCMillisecond(t, "webhook metadata created_at", metadata.CreatedAt, receivedAt)
	assertBudgetedUTCMillisecond(t, "webhook metadata expires_at", metadata.ExpiresAt, expectedExpires)
	if metadata.Kind != "webhook_delivery" || metadata.Classification != "restricted" || metadata.Origin != "host" || metadata.Protection != "envelope_encrypted" || metadata.ScopeIdentity != reviewScope.Identity() || metadata.ArtifactIdentity != mapping.ArtifactIdentity {
		t.Fatalf("webhook artifact metadata mismatch: %#v", metadata)
	}

	snap := fixture.sql.Snapshot()
	for _, id := range []string{"webhook_read", "webhook_count", "webhook_insert", "scope_insert", "metadata_insert", "admission_insert", "confirmation_cas", "admission_read", "operation_read"} {
		if !daemonBudgetedTraceContains(snap.Events, id) {
			t.Fatalf("webhook path did not execute %s; trace=%#v", id, snap.Events)
		}
	}
	if !daemonBudgetedCommittedStatement(snap.Events, "webhook_insert") || !daemonBudgetedCommittedStatement(snap.Events, "metadata_insert") || !daemonBudgetedCommittedStatement(snap.Events, "admission_insert") {
		t.Fatalf("webhook path did not commit mapping and artifact statements; trace=%#v", snap.Events)
	}
	assertBudgetedExternalArtifactTraffic(t, fixture)
}

func daemonBudgetedBuildForCaller(t *testing.T, h *daemonBudgetedHarness, args []string, env func(string) string) *daemon {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	d, err := buildDaemonWithDependencies(ctx, args, env, io.Discard, daemonDependencies{openPostgres: h.sql.OpenPostgres, clock: h.clock})
	if err != nil {
		t.Fatalf("budgeted build failed: %v", err)
	}
	return d
}

func assertBudgetedDiagnosticSetMatches(t *testing.T, got, want diagnostics.Set) {
	t.Helper()
	gotEncoded, gotErr := diagnostics.EncodeSet(got)
	wantEncoded, wantErr := diagnostics.EncodeSet(want)
	if gotErr != nil || wantErr != nil || !bytes.Equal(gotEncoded, wantEncoded) {
		t.Fatalf("diagnostic set encoding mismatch gotErr=%v wantErr=%v got=%s want=%s", gotErr, wantErr, got.Identity(), want.Identity())
	}
	if got.Scope().Identity() != want.Scope().Identity() || got.Identity() != want.Identity() || got.SnapshotIdentity() != want.SnapshotIdentity() || got.HeadRevision() != want.HeadRevision() || got.VerifiedSetIdentity() != want.VerifiedSetIdentity() || got.VerificationContextIdentity() != want.VerificationContextIdentity() || got.CandidateCount() != want.CandidateCount() || got.VerifiedCount() != want.VerifiedCount() || got.RejectedCount() != want.RejectedCount() || got.InconclusiveCount() != want.InconclusiveCount() || got.SourceAnalyzedCount() != want.SourceAnalyzedCount() || got.SourceSelectedCount() != want.SourceSelectedCount() || got.SourceOmittedCount() != want.SourceOmittedCount() {
		t.Fatalf("diagnostic domain mismatch got=%#v want=%#v", got, want)
	}
	gotFindings, wantFindings := got.Findings(), want.Findings()
	if len(gotFindings) != len(wantFindings) {
		t.Fatalf("diagnostic findings length got=%d want=%d", len(gotFindings), len(wantFindings))
	}
	for i := range gotFindings {
		if gotFindings[i].Identity() != wantFindings[i].Identity() || gotFindings[i].SourceIdentity() != wantFindings[i].SourceIdentity() || gotFindings[i].Fingerprint() != wantFindings[i].Fingerprint() || gotFindings[i].Title() != wantFindings[i].Title() || gotFindings[i].Message() != wantFindings[i].Message() || gotFindings[i].Severity() != wantFindings[i].Severity() || gotFindings[i].Path() != wantFindings[i].Path() || gotFindings[i].StartLine() != wantFindings[i].StartLine() || gotFindings[i].EndLine() != wantFindings[i].EndLine() || !sameStringSet(gotFindings[i].EvidenceIDs(), wantFindings[i].EvidenceIDs()) {
			t.Fatalf("diagnostic finding mismatch got=%#v want=%#v", gotFindings[i], wantFindings[i])
		}
	}
}

func assertBudgetedStoredWebhookMatches(t *testing.T, got webhook.StoredDelivery, want webhook.VerifiedDelivery, acceptanceIdentity string, payload []byte, acceptedAt time.Time) {
	t.Helper()
	if got.Validate() != nil {
		t.Fatalf("stored webhook validation failed: %#v", got)
	}
	delivery := got.Delivery()
	if delivery.Identity() != want.Identity() || delivery.DeduplicationKey() != want.DeduplicationKey() || delivery.Scope().Identity() != want.Scope().Identity() || delivery.Source() != want.Source() || delivery.DeliveryID() != want.DeliveryID() || delivery.EventType() != want.EventType() || delivery.Action() != want.Action() || delivery.VerifierIdentity() != want.VerifierIdentity() || delivery.BodyDigest() != want.BodyDigest() || !bytes.Equal(delivery.Payload(), payload) || !delivery.ReceivedAt().Equal(acceptedAt) {
		t.Fatalf("webhook delivery mismatch got=%#v want=%#v", delivery, want)
	}
	receipt := got.Receipt()
	if receipt.Identity() != acceptanceIdentity || receipt.DeliveryIdentity() != want.Identity() || receipt.DeduplicationKey() != want.DeduplicationKey() || receipt.Scope().Identity() != want.Scope().Identity() || receipt.Source() != want.Source() || !receipt.AcceptedAt().Equal(acceptedAt) {
		t.Fatalf("webhook receipt mismatch: %#v", receipt)
	}
}

func daemonBudgetedDiagnosticMappingFor(t *testing.T, h *daemonBudgetedHarness, scope audit.ReviewScope) (daemonBudgetedDiagnosticRow, bool) {
	t.Helper()
	h.sql.mu.Lock()
	defer h.sql.mu.Unlock()
	row, ok := h.sql.diagnostics[daemonBudgetedDiagnosticKey(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID())]
	return row, ok
}

func daemonBudgetedWebhookMappingFor(t *testing.T, h *daemonBudgetedHarness, scope webhook.RepositoryScope, source webhook.Source, key string) (daemonBudgetedWebhookRow, bool) {
	t.Helper()
	h.sql.mu.Lock()
	defer h.sql.mu.Unlock()
	row, ok := h.sql.webhooks[daemonBudgetedWebhookKey(scope.TenantID(), scope.RepositoryID(), source.String(), key)]
	return row, ok
}

func daemonBudgetedMetadataFor(t *testing.T, h *daemonBudgetedHarness, scope audit.ReviewScope, artifactIdentity string) (daemonBudgetedMetadataRow, bool) {
	t.Helper()
	h.sql.mu.Lock()
	defer h.sql.mu.Unlock()
	row, ok := h.sql.metadata[daemonBudgetedArtifactKey(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), artifactIdentity)]
	return row, ok
}

func daemonBudgetedCommittedStatement(events []daemonBudgetedSQLTraceEvent, statement string) bool {
	for _, event := range events {
		if event.StatementID != statement || !event.Persisted || event.TransactionID == 0 {
			continue
		}
		for _, later := range events {
			if later.Sequence > event.Sequence && later.TransactionID == event.TransactionID && later.StatementID == "COMMIT" && later.Kind == "commit" && later.Persisted {
				return true
			}
		}
	}
	return false
}

func assertBudgetedUTCMillisecond(t *testing.T, label string, got, want time.Time) {
	t.Helper()
	if got.Location() != time.UTC || got.Nanosecond()%int(time.Millisecond) != 0 || !got.Equal(want) {
		t.Fatalf("%s = %s (%s, ns=%d), want %s UTC millisecond", label, got.Format(time.RFC3339Nano), got.Location(), got.Nanosecond(), want.Format(time.RFC3339Nano))
	}
}

func assertBudgetedExternalArtifactTraffic(t *testing.T, fixture *daemonBudgetedHarness) {
	t.Helper()
	s3Requests, kmsRequests := fixture.s3.Requests(), fixture.kms.Requests()
	if !daemonBudgetedS3SawArtifactWrite(s3Requests) || !daemonBudgetedS3SawMethod(s3Requests, http.MethodGet) {
		t.Fatalf("missing S3 protected create/read path: %#v", s3Requests)
	}
	if daemonBudgetedKMSTargetCount(kmsRequests, "TrentService.GenerateDataKey") == 0 || daemonBudgetedKMSTargetCount(kmsRequests, "TrentService.Decrypt") == 0 {
		t.Fatalf("missing KMS generate/decrypt path: %#v", kmsRequests)
	}
	if failures := fixture.s3.Failures(); len(failures) != 0 {
		t.Fatalf("S3 fixture rejected requests: %#v", failures)
	}
	if failures := fixture.kms.Failures(); len(failures) != 0 {
		t.Fatalf("KMS fixture rejected requests: %#v", failures)
	}
}

func daemonBudgetedSignWebhook(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

type daemonBudgetedWebhookHTTPResponse struct {
	Contract           string `json:"contract"`
	SchemaVersion      int    `json:"schema_version"`
	AcceptanceIdentity string `json:"acceptance_identity,omitempty"`
	Duplicate          bool   `json:"duplicate,omitempty"`
	Ignored            bool   `json:"ignored,omitempty"`
	Error              string `json:"error,omitempty"`
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestBuildDaemonBudgetedRuntimeStatusUsesCommittedRateLimit(t *testing.T) {
	fixture := newDaemonBudgetedHarness(t)
	d := fixture.build(t)
	defer d.Close()
	assertBudgetedRuntimeComponent(t, d)
	snapshot := fixture.sql.Snapshot()
	for _, id := range []string{"rate_limit_update", "rate_limit_advisory_lock", "rate_limit_cleanup", "rate_limit_conflict", "rate_limit_count", "rate_limit_insert"} {
		if !daemonBudgetedTraceContains(snapshot.Events, id) {
			t.Fatalf("runtime status omitted shared guard statement %s", id)
		}
	}
	if !daemonBudgetedCommittedStatement(snapshot.Events, "rate_limit_insert") {
		t.Fatal("runtime status did not commit shared guard insertion")
	}
	if len(snapshot.Failures) != 0 {
		t.Fatalf("runtime status SQL failures: %v", snapshot.Failures)
	}
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatal("runtime status contacted artifact providers")
	}
}
