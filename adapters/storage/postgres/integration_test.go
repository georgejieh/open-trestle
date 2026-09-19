package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
)

func TestPostgresIntegration(t *testing.T) {
	dataSource := os.Getenv("OPEN_TRESTLE_TEST_POSTGRES_URL")
	if dataSource == "" {
		t.Skip("OPEN_TRESTLE_TEST_POSTGRES_URL is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	database, err := Open(ctx, dataSource, PoolOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if err := ApplyMigrations(ctx, database); err != nil {
		t.Fatal(err)
	}
	runID := fmt.Sprintf("integration-%d", time.Now().UTC().UnixNano())
	scope, _ := audit.NewReviewScope("integration-tenant", "integration-repository", runID)
	task, _ := controlplane.NewTaskDefinition("source", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, 2, 100, 1000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("c", 64), strings.Repeat("d", 64), controlplane.ReviewRunAdvisory, []controlplane.TaskDefinition{task})
	store, _ := New(database)
	coordinator, err := controlplane.NewCoordinator(store)
	if err != nil {
		t.Fatal(err)
	}
	state, err := coordinator.Open(ctx, plan, time.Now().UTC())
	if err != nil || state.Revision() == 0 {
		t.Fatalf("open=(%#v,%v)", state, err)
	}
	reloadedPlan, reloaded, err := coordinator.Resume(ctx, scope)
	if err != nil || reloadedPlan.Identity() != plan.Identity() || reloaded.HeadIdentity() != state.HeadIdentity() {
		t.Fatalf("resume=(%#v,%v)", reloaded, err)
	}
	ledger, _ := NewAuditLedger(database)
	event, _ := audit.NewEvent(scope, 1, "", audit.EventRouteSelected, strings.Repeat("e", 64), []string{strings.Repeat("f", 64)}, time.Now().UTC())
	if err := ledger.Append(ctx, "", event); err != nil {
		t.Fatal(err)
	}
	head, found, err := ledger.Head(ctx, scope)
	if err != nil || !found || head.Identity() != event.Identity() {
		t.Fatalf("audit head=(%#v,%v,%v)", head, found, err)
	}
	verifiedAuthority, err := VerifyDatabaseStorageAuthority(ctx, database)
	if err != nil {
		t.Fatal(err)
	}
	observation, err := VerifySharedRateLimitConformance(ctx, database, verifiedAuthority.Identity(), strings.Repeat("9", 64), strings.Repeat("8", 64))
	if err != nil || observation.Validate() != nil {
		t.Fatalf("rate-limit conformance=(%#v,%v)", observation, err)
	}
	replicaObservation, err := VerifyReplicaReconciliationConformance(ctx, database, verifiedAuthority.Identity(), strings.Repeat("7", 64), strings.Repeat("6", 64))
	if err != nil || replicaObservation.Validate() != nil {
		t.Fatalf("replica reconciliation conformance=(%#v,%v)", replicaObservation, err)
	}
	requestLimiter, principalLimiter, err := NewRuntimeAPIRateLimiters(database, verifiedAuthority.Identity())
	if err != nil || requestLimiter.ConfigurationIdentity() == principalLimiter.ConfigurationIdentity() {
		t.Fatalf("runtime limiters=(%#v,%#v,%v)", requestLimiter, principalLimiter, err)
	}

	tx, err := database.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT set_config('open_trestle.tenant_id', $1, true)", "another-tenant"); err != nil {
		t.Fatal(err)
	}
	var visible int
	if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM open_trestle_run_plans WHERE tenant_id = $1", scope.TenantID()).Scan(&visible); err != nil {
		t.Fatal(err)
	}
	if visible != 0 {
		t.Fatalf("row-level security exposed %d foreign rows; use a non-superuser application role", visible)
	}
}
