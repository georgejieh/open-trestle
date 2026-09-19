//go:build unix

package main

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	githubsource "github.com/georgejieh/open-trestle/adapters/scm/github"
	postgresstore "github.com/georgejieh/open-trestle/adapters/storage/postgres"
	githubwebhook "github.com/georgejieh/open-trestle/adapters/webhook/github"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	changehandler "github.com/georgejieh/open-trestle/handlers/change"
	memoryhandler "github.com/georgejieh/open-trestle/handlers/memory"
	modelhandler "github.com/georgejieh/open-trestle/handlers/model"
	publicationhandler "github.com/georgejieh/open-trestle/handlers/publication"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/georgejieh/open-trestle/runtimeconfig"
	"github.com/georgejieh/open-trestle/webhook"
)

const (
	daemonBudgetedPublicationAuthorityID    = "9999999999999999999999999999999999999999999999999999999999999999"
	daemonBudgetedPublicationEffectPolicyID = "8888888888888888888888888888888888888888888888888888888888888888"
	daemonBudgetedPublicationPrincipalID    = "7777777777777777777777777777777777777777777777777777777777777777"
)

const daemonBudgetedPublicationAuthoritySchemaSQL = `SELECT pg_catalog.current_schema(),
(SELECT n.nspname FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = pg_catalog.to_regclass('open_trestle_publication_guard_authority'))`

const daemonBudgetedPublicationAuthorityIdentitySQL = `SELECT pg_catalog.current_database(), pg_catalog.current_schema(), database_namespace_id::text, authority_identity FROM open_trestle_publication_guard_authority WHERE singleton = true`

type daemonBudgetedPublicationHarness struct {
	*daemonBudgetedPipelineHarness
	publicationAuthority string
	effectPolicyID       string
	principalID          string
	runtimePolicyID      string
	readinessPolicyID    string
}

func newDaemonBudgetedPublicationHarness(t *testing.T) *daemonBudgetedPublicationHarness {
	t.Helper()
	base := newDaemonBudgetedPipelineHarness(t)
	base.values["OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"] = ""
	runtimePolicyID, readinessPolicyID := daemonBudgetedRewritePublicationMinimumSeverity(t, base.model.inventoryPath, base.model.policyPath, "critical")
	return &daemonBudgetedPublicationHarness{daemonBudgetedPipelineHarness: base, publicationAuthority: daemonBudgetedPublicationAuthorityID, effectPolicyID: daemonBudgetedPublicationEffectPolicyID, principalID: daemonBudgetedPublicationPrincipalID, runtimePolicyID: runtimePolicyID, readinessPolicyID: readinessPolicyID}
}

func daemonBudgetedRewritePublicationMinimumSeverity(t *testing.T, inventoryPath, policyPath, minimum string) (runtimePolicyID, readinessPolicyID string) {
	t.Helper()
	inventoryBytes, err := os.ReadFile(inventoryPath)
	if err != nil {
		t.Fatal(err)
	}
	inventory, err := runtimeconfig.DecodeRouteInventory(context.Background(), bytes.NewReader(inventoryBytes))
	if err != nil {
		t.Fatal(err)
	}
	policyBytes, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(policyBytes, &wire); err != nil {
		t.Fatal(err)
	}
	wire["publication_minimum_severity"] = minimum
	rewritten := daemonBudgetedModelJSON(t, wire)
	configuration, err := runtimeconfig.DecodeRuntimePolicy(context.Background(), bytes.NewReader(rewritten), inventory)
	if err != nil {
		t.Fatalf("rewritten runtime policy was not real-decodable: %v", err)
	}
	if configuration.ReviewPolicyIdentity() != daemonBudgetedPipelineReviewPolicyID || configuration.Publication().MinimumSeverity() != review.SeverityCritical {
		t.Fatalf("rewritten policy did not bind critical publication threshold: review=%s severity=%s", configuration.ReviewPolicyIdentity(), configuration.Publication().MinimumSeverity())
	}
	if err := os.WriteFile(policyPath, rewritten, 0o600); err != nil {
		t.Fatal(err)
	}
	return configuration.Identity(), configuration.Publication().Identity()
}

func (h *daemonBudgetedPublicationHarness) args(t *testing.T) []string {
	t.Helper()
	args := h.daemonBudgetedPipelineHarness.args(t)
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "--github-review-mode" {
			args[index+1] = "required"
		}
	}
	args = append(args,
		"--postgres-authority-identity", h.publicationAuthority,
		"--github-enable-publication",
		"--github-publication-policy-identity", h.effectPolicyID,
		"--github-publication-principal-identity", h.principalID,
	)
	return args
}

func (h *daemonBudgetedPublicationHarness) build(t *testing.T, ctx context.Context) *daemon {
	t.Helper()
	d, err := buildDaemonWithDependencies(ctx, h.args(t), h.env, io.Discard, daemonDependencies{openPostgres: h.openPostgres, clock: h.clock})
	if err != nil {
		t.Fatalf("budgeted required publication daemon build failed: %v", err)
	}
	return d
}

func (h *daemonBudgetedPublicationHarness) openPostgres(ctx context.Context, graph string, _ postgresstore.PoolOptions) (*sql.DB, error) {
	if ctx == nil || ctx.Err() != nil || strings.TrimSpace(graph) == "" {
		return nil, errors.New("invalid daemon publication SQL fixture open")
	}
	db := sql.OpenDB(daemonBudgetedPublicationConnector{service: h.sql, graph: graph, authority: h.publicationAuthority})
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	return db, nil
}

type daemonBudgetedPublicationConnector struct {
	service   *daemonBudgetedSQLService
	graph     string
	authority string
}

type daemonBudgetedPublicationConn struct {
	inner     *daemonBudgetedConn
	authority string
}

func (c daemonBudgetedPublicationConnector) Driver() driver.Driver { return daemonBudgetedDriver{} }
func (c daemonBudgetedPublicationConnector) Connect(ctx context.Context) (driver.Conn, error) {
	if ctx == nil || ctx.Err() != nil || c.service == nil || !daemonNonzeroDigest(c.authority) {
		return nil, errors.New("invalid daemon publication SQL connector")
	}
	c.service.mu.Lock()
	defer c.service.mu.Unlock()
	c.service.connections++
	return &daemonBudgetedPublicationConn{inner: &daemonBudgetedConn{service: c.service, graph: c.graph}, authority: c.authority}, nil
}

func (c *daemonBudgetedPublicationConn) Prepare(query string) (driver.Stmt, error) {
	return c.inner.Prepare(query)
}
func (c *daemonBudgetedPublicationConn) Begin() (driver.Tx, error) { return c.inner.Begin() }
func (c *daemonBudgetedPublicationConn) Close() error              { return c.inner.Close() }
func (c *daemonBudgetedPublicationConn) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	return c.inner.BeginTx(ctx, options)
}
func (c *daemonBudgetedPublicationConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.inner.ExecContext(ctx, query, args)
}
func (c *daemonBudgetedPublicationConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	switch daemonBudgetedNormalizeSQL(query) {
	case daemonBudgetedNormalizeSQL(daemonBudgetedPublicationAuthoritySchemaSQL):
		return c.publicationAuthorityRows(ctx, "publication_authority_schemas", args, [][]driver.Value{{c.inner.service.catalog.Schema, c.inner.service.catalog.Schema}})
	case daemonBudgetedNormalizeSQL(daemonBudgetedPublicationAuthorityIdentitySQL):
		catalog := c.inner.service.catalog
		return c.publicationAuthorityRows(ctx, "publication_authority_identity", args, [][]driver.Value{{catalog.Database, catalog.Schema, strings.ToLower(catalog.Namespace), c.authority}})
	default:
		return c.inner.QueryContext(ctx, query, args)
	}
}

func (c *daemonBudgetedPublicationConn) publicationAuthorityRows(ctx context.Context, id string, named []driver.NamedValue, rows [][]driver.Value) (driver.Rows, error) {
	if ctx == nil || ctx.Err() != nil || c.inner.closed || c.inner.active == nil || c.inner.active.done {
		return nil, errors.New("publication authority statement outside active transaction")
	}
	args, err := daemonBudgetedValues(named)
	if err != nil {
		return nil, err
	}
	if len(args) != 0 {
		return nil, c.inner.service.fail(id + " args")
	}
	c.inner.service.mu.Lock()
	defer c.inner.service.mu.Unlock()
	c.inner.service.event(c.inner.active, id, "query", args, false, true)
	columns := make([]string, len(rows[0]))
	for index := range columns {
		columns[index] = "c" + string(rune('0'+index))
	}
	return &daemonBudgetedRows{columns: columns, rows: daemonBudgetedCopyRows(rows)}, nil
}

func TestDaemonBudgetedRequiredPublicationBelowThresholdPersistsNoEffectReceiptWithUTCMillisecondClock(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	fixture := newDaemonBudgetedPublicationHarness(t)
	d := fixture.build(t, ctx)
	defer func() {
		if err := d.Close(); err != nil {
			t.Fatalf("daemon close: %v", err)
		}
	}()
	if fixture.s3.RawRequests() != 0 || fixture.kms.RawRequests() != 0 {
		t.Fatalf("startup contacted artifact providers: s3=%d kms=%d", fixture.s3.RawRequests(), fixture.kms.RawRequests())
	}
	if calls, _, _, failures := fixture.model.generation.snapshot(); calls != 0 || len(failures) != 0 {
		t.Fatalf("startup contacted generation model: calls=%d failures=%v", calls, failures)
	}
	if fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN") != 0 {
		t.Fatalf("startup read publication credential: %d", fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"))
	}
	handlers := daemonBudgetedHandlerIdentities(t, d)
	for _, kind := range []string{"acquire_source", "build_change", "inspect_deterministic", "retrieve_context", "assemble_context", "generate_candidates", "verify_candidates", "evaluate_publication", "publish_result"} {
		if handlers[kind] == "" {
			t.Fatalf("runtime status omitted required-mode handler %s: %#v", kind, handlers)
		}
	}
	if len(d.supervisors) == 0 || len(d.closers) == 0 || fixture.runtimePolicyID == "" || fixture.readinessPolicyID == "" {
		t.Fatal("daemon did not retain bounded runtime resources or policy identities")
	}
	supervisor := daemonBudgetedLocalSupervisor(t, d)
	plan, inputs, publicationInputArtifact := daemonBudgetedPreparedPublicationPlan(t, ctx, fixture, handlers)
	if plan.TaskCount() != 10 || plan.Mode() != controlplane.ReviewRunRequired {
		t.Fatalf("prepared plan = tasks:%d mode:%s", plan.TaskCount(), plan.Mode())
	}
	publicationTask, ok := plan.Task("publication")
	if !ok || publicationTask.Kind() != controlplane.TaskPublishResult || publicationTask.InputIdentity() != publicationInputArtifact.Identity() || publicationTask.HandlerIdentity() != handlers["publish_result"] || publicationTask.MaxAttempts() != 1 {
		t.Fatalf("publication task was not bound to real input/handler: %#v", publicationTask)
	}
	publicationInput, err := publicationhandler.ParseInput(publicationInputArtifact.Payload())
	if err != nil {
		t.Fatal(err)
	}
	publicationTarget, err := publicationInput.Target()
	if err != nil || publicationTarget.PublisherID() != githubwebhook.DefaultGitHubPublisherID || publicationTarget.ChangeID() != "42" || publicationTarget.HeadRevision().Digest() != daemonBudgetedGitHubHeadCommit {
		t.Fatalf("publication input target mismatch: %#v err=%v", publicationTarget, err)
	}
	for _, value := range inputs {
		if ok, err := d.artifactStore.Put(ctx, value, fixture.clock.UTCMS()); err != nil || !ok {
			t.Fatalf("persist prepared input %s: created=%v err=%v", value.Identity(), ok, err)
		}
	}
	if err := d.journal.SavePlan(ctx, plan); err != nil {
		t.Fatalf("SavePlan rejected real required publication plan: %v", err)
	}
	coordinator, err := controlplane.NewCoordinator(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := coordinator.Open(ctx, plan, fixture.clock.UTCMS()); err != nil {
		t.Fatalf("open saved required publication plan: %v", err)
	}
	worked, err := supervisor.RunOnce(ctx)
	if err != nil || !worked {
		t.Fatalf("local supervisor RunOnce = (%v, %v)", worked, err)
	}
	finalizer, err := controlplane.NewRunFinalizer(d.journal)
	if err != nil {
		t.Fatal(err)
	}
	state, finalized, err := finalizer.ReconcileRun(ctx, plan.Scope(), time.Now().UTC().Truncate(time.Millisecond))
	if err != nil || !finalized || state.Status() != controlplane.ReviewRunSucceeded {
		t.Fatalf("finalize required publication run = (%v, %v, %v)", state.Status(), finalized, err)
	}
	receipt, err := controlplane.NewReviewRunReceipt(state)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.TaskCount() != 10 || state.OutputIdentity() == "" {
		t.Fatalf("terminal receipt/task count mismatch: count=%d output=%s", receipt.TaskCount(), state.OutputIdentity())
	}
	keys := []string{"source-base", "source-head", "change", "analysis", "memory", "context", "candidates", "verification", "readiness", "publication"}
	outputs := map[string]artifact.Artifact{}
	for _, key := range keys {
		task, ok := receipt.Task(key)
		if !ok || task.Status() != controlplane.TaskRuntimeSucceeded || task.OutputIdentity() == "" {
			t.Fatalf("task %s did not succeed from actual journal: %#v", key, task)
		}
		outputs[key] = daemonBudgetedTaskOutput(t, ctx, d, plan.Scope(), receipt, key, fixture.clock.UTCMS())
	}
	if state.OutputIdentity() != outputs["publication"].Identity() {
		t.Fatalf("run output = %s, publication output = %s", state.OutputIdentity(), outputs["publication"].Identity())
	}
	wantKinds := map[string]artifact.Kind{"source-base": artifact.KindSourceSnapshot, "source-head": artifact.KindSourceSnapshot, "change": artifact.KindChangeModel, "analysis": artifact.KindDeterministicEvidence, "memory": artifact.KindRetrievalResult, "context": artifact.KindTaskInput, "candidates": artifact.KindCandidateBatch, "verification": artifact.KindVerifiedFindingSet, "readiness": artifact.KindPublicationPlan, "publication": artifact.KindPublicationReceipt}
	for key, value := range outputs {
		if value.Validate() != nil || value.Kind() != wantKinds[key] || value.Protection() != artifact.ProtectionEnvelopeEncrypted || value.Classification() != artifact.ClassificationRestricted {
			t.Fatalf("%s artifact lost kind/protection/classification: kind=%s protection=%s class=%s", key, value.Kind(), value.Protection(), value.Classification())
		}
		daemonBudgetedAssertUTCMS(t, key+" created_at", value.CreatedAt(), fixture.clock.UTCMS())
	}
	baseSnapshot, err := sourcehandler.ParseSnapshotArtifact(outputs["source-base"])
	if err != nil {
		t.Fatal(err)
	}
	headSnapshot, err := sourcehandler.ParseSnapshotArtifact(outputs["source-head"])
	if err != nil {
		t.Fatal(err)
	}
	daemonBudgetedAssertSnapshotContent(t, ctx, d, plan.Scope(), outputs["source-base"], baseSnapshot, fixture.github.revisions[daemonBudgetedGitHubBaseCommit].content, fixture.clock.UTCMS())
	daemonBudgetedAssertSnapshotContent(t, ctx, d, plan.Scope(), outputs["source-head"], headSnapshot, fixture.github.revisions[daemonBudgetedGitHubHeadCommit].content, fixture.clock.UTCMS())
	change, err := changehandler.ParseResultArtifact(outputs["change"], outputs["source-base"], outputs["source-head"])
	if err != nil || len(change.Entries()) != 1 || change.HeadRevision().Digest() != daemonBudgetedGitHubHeadCommit {
		t.Fatalf("change result = %#v err=%v", change, err)
	}
	analysis, err := analysishandler.ParseResultArtifact(outputs["analysis"], outputs["change"], outputs["source-base"], outputs["source-head"])
	if err != nil || analysis.ChangeIdentity() != change.Identity() || len(analysis.Items()) == 0 {
		t.Fatalf("analysis result = %#v err=%v", analysis, err)
	}
	memory, err := memoryhandler.ParseResultArtifact(outputs["memory"], outputs["change"], outputs["source-base"], outputs["source-head"])
	if err != nil || memory.ChangeArtifactIdentity() != outputs["change"].Identity() || memory.PolicyIdentity() != daemonBudgetedPipelineReviewPolicyID {
		t.Fatalf("memory result = %#v err=%v", memory, err)
	}
	generationInput, err := modelhandler.ParseGenerationInput(outputs["context"].Payload())
	if err != nil || generationInput.ReviewScopeIdentity() != plan.Scope().Identity() || generationInput.Authorization().RouteReference().ModelID() != "model-a" || generationInput.Authorization().RouteRecordIdentity() != fixture.model.generationRoute {
		t.Fatalf("generation input route binding lost: %#v err=%v", generationInput, err)
	}
	contextArtifact, err := d.artifactStore.Get(ctx, plan.Scope(), generationInput.ContextArtifactIdentity(), fixture.clock.UTCMS())
	if err != nil {
		t.Fatal(err)
	}
	generation, err := modelhandler.ParseGenerationResultArtifact(outputs["candidates"], outputs["context"], contextArtifact)
	if err != nil || generation.ContextIdentity() != generationInput.ContextIdentity() || len(generation.Candidates().Findings()) != 1 {
		t.Fatalf("generation result = %#v err=%v", generation, err)
	}
	verification, err := modelhandler.ParseVerificationResultArtifact(outputs["verification"], outputs["candidates"], outputs["context"], contextArtifact)
	if err != nil || verification.GenerationArtifactIdentity() != outputs["candidates"].Identity() || verification.Verification().Results()[0].Outcome() != review.VerificationVerified || verification.VerifiedFindings().Findings()[0].Severity() != review.SeverityHigh || verification.RouteExecution().Authorization().RouteReference().ModelID() != "model-b" {
		t.Fatalf("verification result = %#v err=%v", verification, err)
	}
	var readinessWire struct {
		Contract                     string `json:"contract"`
		VerificationArtifactIdentity string `json:"verification_artifact_identity"`
		VerificationResultIdentity   string `json:"verification_result_identity"`
		PublicationPolicyIdentity    string `json:"publication_policy_identity"`
		ReadinessIdentity            string `json:"readiness_identity"`
		Status                       string `json:"status"`
		Verified                     uint8  `json:"verified"`
		BelowThreshold               uint8  `json:"below_threshold"`
		Inline                       int    `json:"inline"`
	}
	if json.Unmarshal(outputs["readiness"].Payload(), &readinessWire) != nil || readinessWire.Contract != "open-trestle/publication-readiness-result" || readinessWire.Status != "below_threshold" || readinessWire.Verified != 1 || readinessWire.BelowThreshold != 1 || readinessWire.Inline != 0 || readinessWire.VerificationArtifactIdentity != outputs["verification"].Identity() || readinessWire.VerificationResultIdentity != verification.Identity() || readinessWire.PublicationPolicyIdentity != fixture.readinessPolicyID {
		t.Fatalf("readiness payload did not bind below-threshold verification: %#v", readinessWire)
	}
	publicationReceipt := outputs["publication"]
	var receiptWire struct {
		Contract                   string `json:"contract"`
		SchemaVersion              int    `json:"schema_version"`
		Status                     string `json:"status"`
		ReadinessIdentity          string `json:"readiness_identity"`
		SourceBindingIdentity      string `json:"source_binding_identity"`
		AuthorizationIdentity      string `json:"authorization_identity"`
		ClaimIdentity              string `json:"claim_identity"`
		HeadReconciliationIdentity string `json:"head_reconciliation_identity"`
		ResultIdentity             string `json:"result_identity"`
		ExternalReferenceIdentity  string `json:"external_reference_identity"`
	}
	if json.Unmarshal(publicationReceipt.Payload(), &receiptWire) != nil || receiptWire.Contract != "open-trestle/publication-receipt" || receiptWire.SchemaVersion != 1 || receiptWire.Status != "not_required" || receiptWire.ReadinessIdentity != readinessWire.ReadinessIdentity {
		t.Fatalf("publication no-effect receipt lost readiness binding: %#v", receiptWire)
	}
	if receiptWire.SourceBindingIdentity != "" || receiptWire.AuthorizationIdentity != "" || receiptWire.ClaimIdentity != "" || receiptWire.HeadReconciliationIdentity != "" || receiptWire.ResultIdentity != "" || receiptWire.ExternalReferenceIdentity != "" {
		t.Fatalf("no-effect receipt unexpectedly carried publication effect identities: %#v", receiptWire)
	}
	for _, id := range []string{outputs["readiness"].Identity(), publicationInputArtifact.Identity(), readinessWire.ReadinessIdentity} {
		if !containsString(publicationReceipt.Provenance(), id) {
			t.Fatalf("publication receipt provenance omitted %s: %#v", id, publicationReceipt.Provenance())
		}
	}
	if _, err := d.artifactStore.Put(ctx, publicationReceipt, fixture.clock.Now()); !errors.Is(err, artifact.ErrInvalidErasureContract) {
		t.Fatalf("public Store accepted or normalized non-UTC/sub-ms publication Put: %v", err)
	}
	diagnosticsSet, err := d.diagnosticStore.GetDiagnosticSet(ctx, plan.Scope())
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
	if fixture.readCount(daemonBudgetedModelGenerationKeyEnv) != 1 || fixture.readCount(daemonBudgetedModelVerificationKeyEnv) != 1 || fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN") != 0 {
		t.Fatalf("credential reads were not separated: gen=%d verify=%d publication=%d", fixture.readCount(daemonBudgetedModelGenerationKeyEnv), fixture.readCount(daemonBudgetedModelVerificationKeyEnv), fixture.readCount("OPEN_TRESTLE_GITHUB_PUBLICATION_TOKEN"))
	}
	apiPaths, archivePaths, sourceHeaders, archiveHeaders, githubFailures := fixture.github.snapshot()
	if len(githubFailures) != 0 || sourceHeaders == 0 || archiveHeaders == 0 {
		t.Fatalf("GitHub source fixture traffic failed: api=%v archive=%v headers=(%d,%d) failures=%v", apiPaths, archivePaths, sourceHeaders, archiveHeaders, githubFailures)
	}
	for _, path := range apiPaths {
		if strings.Contains(path, "/pulls/") || strings.Contains(path, "/reviews") {
			t.Fatalf("publication head or review route reached a provider fixture: %v", apiPaths)
		}
	}
	if failures := fixture.s3.Failures(); len(failures) != 0 {
		t.Fatalf("S3 fixture rejected publication pipeline requests: %v", failures)
	}
	if failures := fixture.kms.Failures(); len(failures) != 0 {
		t.Fatalf("KMS fixture rejected publication pipeline requests: %v", failures)
	}
	if got := fixture.s3.RawRequests(); got == 0 || got > 512 {
		t.Fatalf("S3 pipeline profile bound not honored: %d", got)
	}
	if got := fixture.kms.RawRequests(); got == 0 || got > 256 {
		t.Fatalf("KMS pipeline profile bound not honored: %d", got)
	}
	sqlSnapshot := fixture.sql.Snapshot()
	for _, id := range []string{"publication_authority_schemas", "publication_authority_identity", "run_plan_insert", "run_event_insert", "audit_event_insert", "audit_events_read", "audit_event_head", "diagnostic_insert", "metadata_insert", "admission_insert", "confirmation_cas"} {
		if !daemonBudgetedTraceContains(sqlSnapshot.Events, id) {
			t.Fatalf("publication pipeline SQL did not execute %s", id)
		}
	}
	if daemonBudgetedTraceCount(sqlSnapshot.Events, "metadata_insert") < len(inputs)+len(keys) {
		t.Fatalf("metadata commits too few for inputs and task outputs: got=%d inputs=%d outputs=%d", daemonBudgetedTraceCount(sqlSnapshot.Events, "metadata_insert"), len(inputs), len(keys))
	}
	auditRows := sqlSnapshot.AuditEvents[daemonBudgetedScopeKey(daemonBudgetedTenant, daemonBudgetedRepository, plan.Scope().ReviewRunID())]
	if len(auditRows) == 0 {
		t.Fatal("audit ledger did not retain model/readiness events")
	}
	for _, row := range auditRows {
		event, err := audit.ParseEvent(row.CanonicalEvent)
		if err != nil {
			t.Fatal(err)
		}
		switch event.Kind() {
		case audit.EventPublicationAuthorized, audit.EventPublicationClaimed, audit.EventPublicationHeadReconciled, audit.EventPublicationCompleted, audit.EventPublicationRetryAuthorized:
			t.Fatalf("no-effect branch recorded forbidden publication effect audit event: %s", event.Kind())
		}
	}
	if len(sqlSnapshot.Failures) != 0 {
		t.Fatalf("SQL fixture rejected publication no-effect run: %v", sqlSnapshot.Failures)
	}
}

func daemonBudgetedPreparedPublicationPlan(t *testing.T, ctx context.Context, fixture *daemonBudgetedPublicationHarness, handlers map[string]string) (controlplane.ReviewRunPlan, []artifact.Artifact, artifact.Artifact) {
	t.Helper()
	bindings := []githubwebhook.TaskHandlerBinding{
		{Kind: controlplane.TaskAcquireSource, HandlerIdentity: handlers["acquire_source"]},
		{Kind: controlplane.TaskBuildChange, HandlerIdentity: handlers["build_change"]},
		{Kind: controlplane.TaskInspectDeterministic, HandlerIdentity: handlers["inspect_deterministic"]},
		{Kind: controlplane.TaskRetrieveContext, HandlerIdentity: handlers["retrieve_context"]},
		{Kind: controlplane.TaskAssembleContext, HandlerIdentity: handlers["assemble_context"]},
		{Kind: controlplane.TaskGenerateCandidates, HandlerIdentity: handlers["generate_candidates"]},
		{Kind: controlplane.TaskVerifyCandidates, HandlerIdentity: handlers["verify_candidates"]},
		{Kind: controlplane.TaskEvaluatePublication, HandlerIdentity: handlers["evaluate_publication"]},
		{Kind: controlplane.TaskPublishResult, HandlerIdentity: handlers["publish_result"]},
	}
	adapter, err := githubsource.BrokeredSourceAdapterIdentity()
	if err != nil {
		t.Fatal(err)
	}
	planner, err := githubwebhook.NewPreparedPullRequestPlanner("github.com", "owner/repo", daemonBudgetedPipelineReviewPolicyID, githubwebhook.DefaultGitHubPublisherID, controlplane.ReviewRunRequired, bindings, adapter, artifact.ClassificationRestricted, artifact.ProtectionEnvelopeEncrypted, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	scope, err := webhook.NewRepositoryScope(daemonBudgetedTenant, daemonBudgetedRepository)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"action":"synchronize","number":42,"repository":{"full_name":"owner/repo"},"pull_request":{"base":{"sha":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repo":{"full_name":"owner/repo"}},"head":{"sha":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","repo":{"full_name":"owner/repo"}}}}`)
	payload = bytes.ReplaceAll(payload, []byte(`\"`), []byte(`"`))
	delivery, err := webhook.NewVerifiedDelivery(scope, webhook.SourceGitHub, "delivery-budgeted-publication-noeffect", "pull_request", "synchronize", daemonBudgetedModelDigest([]byte("publication-noeffect-webhook-secret")), payload, fixture.clock.UTCMS().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	inbox := webhook.NewMemoryStore()
	stored, _, err := inbox.Put(ctx, delivery, fixture.clock.UTCMS().Add(-time.Second))
	if err != nil {
		t.Fatal(err)
	}
	plan, inputs, err := planner.Prepare(ctx, stored)
	if err != nil {
		t.Fatal(err)
	}
	var publication artifact.Artifact
	for _, input := range inputs {
		if parsed, err := publicationhandler.ParseInput(input.Payload()); err == nil && parsed.Identity() != "" {
			publication = input
		}
	}
	if publication.Identity() == "" || len(inputs) != 3 {
		t.Fatalf("prepared planner did not return source+publication inputs: inputs=%d publication=%s", len(inputs), publication.Identity())
	}
	return plan, inputs, publication
}
