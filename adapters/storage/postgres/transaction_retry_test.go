package postgres

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSerializableMutationsRetryKnownAborts(t *testing.T) {
	for _, operation := range []string{"save-plan", "append-run", "append-audit"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, stage := range mutationRetryStages(operation) {
				t.Run(operation+"/"+code+"/"+stage, func(t *testing.T) {
					fixture := newMutationRetryFixture(t, operation)
					database, mock, observed := newObservedRetryDatabase(t)
					failure := fmt.Errorf("driver wrapper: %w", &pgconn.PgError{Code: code, Message: "private SQL detail"})
					fixture.expectAttempt(mock, stage, failure)
					fixture.expectAttempt(mock, "", nil)
					if err := fixture.invoke(context.Background(), database); err != nil {
						t.Errorf("retry returned %v", err)
					}
					assertObservedRetryTransactions(t, mock, observed, 2)
				})
			}
		}
	}
}

func TestSerializableMutationsDoNotRetryUnclassifiedFailures(t *testing.T) {
	failures := []struct {
		name string
		err  error
	}{
		{"unique-violation", &pgconn.PgError{Code: "23505", Message: "private SQL detail"}},
		{"permission", &pgconn.PgError{Code: "42501", Message: "private SQL detail"}},
		{"query-canceled", &pgconn.PgError{Code: "57014", Message: "private SQL detail"}},
		{"connection-failure", &pgconn.PgError{Code: "08006", Message: "private SQL detail"}},
		{"completion-unknown", &pgconn.PgError{Code: "40003", Message: "private SQL detail"}},
		{"internal-error", &pgconn.PgError{Code: "XX000", Message: "private SQL detail"}},
		{"network", &net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}},
		{"ambiguous-eof", io.ErrUnexpectedEOF},
		{"text-is-not-sqlstate", errors.New("private SQL detail: SQLSTATE 40001 / 40P01")},
	}
	for _, operation := range []string{"save-plan", "append-run", "append-audit"} {
		for _, failure := range failures {
			for _, stage := range mutationRetryStages(operation) {
				t.Run(operation+"/"+failure.name+"/"+stage, func(t *testing.T) {
					fixture := newMutationRetryFixture(t, operation)
					database, mock, observed := newObservedRetryDatabase(t)
					fixture.expectAttempt(mock, stage, failure.err)
					if err := fixture.invoke(context.Background(), database); err != ErrDatabaseUnavailable {
						t.Errorf("error = %v, want closed unavailable sentinel", err)
					}
					assertObservedRetryTransactions(t, mock, observed, 1)
				})
			}
		}
	}
}

func TestSerializableMutationsBoundConflictAttempts(t *testing.T) {
	for _, operation := range []string{"save-plan", "append-run", "append-audit"} {
		for _, stage := range []string{"insert", "commit"} {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				fixture := newMutationRetryFixture(t, operation)
				database, mock, observed := newObservedRetryDatabase(t)
				for _, code := range []string{"40001", "40P01", "40001"} {
					fixture.expectAttempt(mock, stage, &pgconn.PgError{Code: code, Message: "private SQL detail"})
				}
				if err := fixture.invoke(context.Background(), database); err != ErrDatabaseUnavailable {
					t.Errorf("exhaustion error = %v, want closed unavailable sentinel", err)
				}
				assertObservedRetryTransactions(t, mock, observed, 3)
			})
		}
	}
}

func TestSerializableMutationsDoNotRetryFailedRollback(t *testing.T) {
	for _, operation := range []string{"save-plan", "append-run", "append-audit"} {
		for _, tenantFailure := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/tenant=%v", operation, tenantFailure), func(t *testing.T) {
				fixture := newMutationRetryFixture(t, operation)
				database, mock, observed := newObservedRetryDatabase(t)
				failure := &pgconn.PgError{Code: "40001"}
				if tenantFailure {
					mock.ExpectBegin()
					mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('open_trestle.tenant_id', $1, true)")).WithArgs(fixture.plan.Scope().TenantID()).WillReturnError(failure)
				} else {
					expectTenantTransaction(mock, fixture.plan.Scope().TenantID())
					mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs(fixture.lockIdentity()).WillReturnError(failure)
				}
				mock.ExpectRollback().WillReturnError(io.ErrUnexpectedEOF)
				if err := fixture.invoke(context.Background(), database); err != ErrDatabaseUnavailable {
					t.Errorf("rollback failure = %v, want closed unavailable sentinel", err)
				}
				assertObservedRetryTransactions(t, mock, observed, 1)
			})
		}
	}
}

func TestTransactionHelpersKeepLegacyClosedErrors(t *testing.T) {
	for _, code := range []string{"40001", "40P01"} {
		for _, stage := range []string{"begin", "tenant", "lock", "scope-insert", "scope-read", "run-head", "audit-head", "commit"} {
			t.Run(code+"/"+stage, func(t *testing.T) {
				fixture := newMutationRetryFixture(t, "append-run")
				database, mock, observed := newObservedRetryDatabase(t)
				store, _ := New(database)
				scope := fixture.plan.Scope()
				failure := &pgconn.PgError{Code: code, Message: "private SQL detail"}
				var result error
				if stage == "begin" || stage == "tenant" {
					fixture.expectAttempt(mock, stage, failure)
					_, result = store.beginTenant(context.Background(), scope.TenantID(), sql.LevelSerializable)
				} else {
					expectTenantTransaction(mock, scope.TenantID())
					tx, err := store.beginTenant(context.Background(), scope.TenantID(), sql.LevelSerializable)
					if err != nil {
						t.Fatal(err)
					}
					switch stage {
					case "lock":
						mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs(scope.Identity()).WillReturnError(failure)
						result = lockScope(context.Background(), tx, scope.Identity())
					case "scope-insert", "scope-read":
						expected := mock.ExpectExec("INSERT INTO open_trestle_review_scopes").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity())
						if stage == "scope-insert" {
							expected.WillReturnError(failure)
						} else {
							expected.WillReturnResult(sqlmock.NewResult(0, 1))
							mock.ExpectQuery("SELECT scope_identity").WithArgs(fixture.scopeArgs()...).WillReturnError(failure)
						}
						result = ensureScope(context.Background(), tx, scope)
					case "run-head", "audit-head":
						mock.ExpectQuery("SELECT sequence, event_identity, canonical_event").WithArgs(fixture.scopeArgs()...).WillReturnError(failure)
						if stage == "run-head" {
							_, _, result = queryRunHead(context.Background(), tx, scope)
						} else {
							_, _, result = queryAuditHead(context.Background(), tx, scope)
						}
					case "commit":
						mock.ExpectCommit().WillReturnError(failure)
						result = commit(tx)
					}
					if stage != "commit" {
						mock.ExpectRollback()
						if err := tx.Rollback(); err != nil {
							t.Fatal(err)
						}
					}
				}
				if result != ErrDatabaseUnavailable {
					t.Errorf("legacy helper error = %v, want closed unavailable sentinel", result)
				}
				assertObservedRetryTransactions(t, mock, observed, 1)
			})
		}
	}
}

func TestSerializableMutationsStopWhenContextCanceledAfterAbort(t *testing.T) {
	for _, operation := range []string{"save-plan", "append-run", "append-audit"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, stage := range []string{"insert", "commit"} {
				t.Run(operation+"/"+code+"/"+stage, func(t *testing.T) {
					fixture := newMutationRetryFixture(t, operation)
					database, mock, observed := newObservedRetryDatabase(t)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					observed.afterClose = cancel
					fixture.expectAttempt(mock, stage, &pgconn.PgError{Code: code})
					if err := fixture.invoke(ctx, database); err != fixture.contextDoneError() {
						t.Errorf("canceled retry = %v, want %v", err, fixture.contextDoneError())
					}
					assertObservedRetryTransactions(t, mock, observed, 1)
				})
			}
		}
	}
}

func TestSerializableMutationsRejectDoneContextBeforeBegin(t *testing.T) {
	for _, operation := range []string{"save-plan", "append-run", "append-audit"} {
		for _, deadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deadline=%v", operation, deadline), func(t *testing.T) {
				fixture := newMutationRetryFixture(t, operation)
				database, mock, observed := newObservedRetryDatabase(t)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if deadline {
					ctx, cancel = context.WithDeadline(context.Background(), time.Unix(1, 0))
					defer cancel()
				}
				if err := fixture.invoke(ctx, database); err != fixture.contextDoneError() {
					t.Errorf("done context = %v, want %v", err, fixture.contextDoneError())
				}
				assertObservedRetryTransactions(t, mock, observed, 0)
			})
		}
	}
}

func TestRunAppendRetryRechecksHeadAndPreservesIdempotency(t *testing.T) {
	for _, identical := range []bool{false, true} {
		t.Run(fmt.Sprintf("identical=%v", identical), func(t *testing.T) {
			fixture := newMutationRetryFixture(t, "append-run")
			database, mock, observed := newObservedRetryDatabase(t)
			fixture.expectAttempt(mock, "commit", &pgconn.PgError{Code: "40001"})
			fixture.expectPrefix(mock)
			mock.ExpectQuery("SELECT plan_identity").WithArgs(fixture.scopeArgs()...).WillReturnError(sql.ErrNoRows)
			winner := fixture.runEvent
			if !identical {
				var err error
				winner, err = controlplane.NewRunEvent(fixture.plan, 1, "", controlplane.RunEventOpened, controlplane.TaskDefinition{}, 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(1001))
				if err != nil {
					t.Fatal(err)
				}
			}
			encoded, err := controlplane.EncodeRunEvent(winner)
			if err != nil {
				t.Fatal(err)
			}
			mock.ExpectQuery("SELECT sequence, event_identity, canonical_event").WithArgs(fixture.scopeArgs()...).WillReturnRows(sqlmock.NewRows([]string{"sequence", "event_identity", "canonical_event", "count"}).AddRow(1, winner.Identity(), encoded, 1))
			var want error
			if identical {
				mock.ExpectCommit()
			} else {
				mock.ExpectRollback()
				want = controlplane.ErrRunJournalHeadConflict
			}
			if err := fixture.invoke(context.Background(), database); err != want {
				t.Errorf("fresh head result = %v, want %v", err, want)
			}
			assertObservedRetryTransactions(t, mock, observed, 2)
		})
	}
}

func TestAuditAppendRetryReturnsFreshHeadConflict(t *testing.T) {
	fixture := newMutationRetryFixture(t, "append-audit")
	database, mock, observed := newObservedRetryDatabase(t)
	fixture.expectAttempt(mock, "insert", &pgconn.PgError{Code: "40P01"})
	fixture.expectPrefix(mock)
	encoded, err := audit.EncodeEvent(fixture.auditEvent)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT sequence, event_identity, canonical_event").WithArgs(fixture.scopeArgs()...).WillReturnRows(sqlmock.NewRows([]string{"sequence", "event_identity", "canonical_event", "count"}).AddRow(1, fixture.auditEvent.Identity(), encoded, 1))
	mock.ExpectRollback()
	if err := fixture.invoke(context.Background(), database); err != audit.ErrAuditHeadConflict {
		t.Errorf("fresh head result = %v, want audit head conflict", err)
	}
	assertObservedRetryTransactions(t, mock, observed, 2)
}

func TestSavePlanRetryRecognizesExistingCanonicalPlan(t *testing.T) {
	fixture := newMutationRetryFixture(t, "save-plan")
	database, mock, observed := newObservedRetryDatabase(t)
	fixture.expectAttempt(mock, "commit", &pgconn.PgError{Code: "40P01"})
	fixture.expectPrefix(mock)
	encoded, err := controlplane.EncodeReviewRunPlan(fixture.plan)
	if err != nil {
		t.Fatal(err)
	}
	mock.ExpectQuery("SELECT plan_identity, canonical_plan").WithArgs(fixture.scopeArgs()...).WillReturnRows(sqlmock.NewRows([]string{"plan_identity", "canonical_plan"}).AddRow(fixture.plan.Identity(), encoded))
	mock.ExpectCommit()
	if err := fixture.invoke(context.Background(), database); err != nil {
		t.Errorf("existing plan retry = %v", err)
	}
	assertObservedRetryTransactions(t, mock, observed, 2)
}

type mutationRetryFixture struct {
	operation  string
	plan       controlplane.ReviewRunPlan
	runEvent   controlplane.RunEvent
	auditEvent audit.Event
}

func newMutationRetryFixture(t *testing.T, operation string) mutationRetryFixture {
	t.Helper()
	plan, runEvent := postgresRunFixture(t)
	auditEvent, err := audit.NewEvent(plan.Scope(), 1, "", audit.EventRouteSelected, strings.Repeat("e", 64), []string{strings.Repeat("f", 64)}, time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	return mutationRetryFixture{operation, plan, runEvent, auditEvent}
}

func (f mutationRetryFixture) invoke(ctx context.Context, database *sql.DB) error {
	store, err := New(database)
	if err != nil {
		return err
	}
	switch f.operation {
	case "save-plan":
		return store.SavePlan(ctx, f.plan)
	case "append-run":
		return store.Append(ctx, "", f.runEvent)
	default:
		ledger, err := NewAuditLedger(database)
		if err != nil {
			return err
		}
		return ledger.Append(ctx, "", f.auditEvent)
	}
}

func (f mutationRetryFixture) contextDoneError() error {
	if f.operation == "append-audit" {
		return audit.ErrAuditContextDone
	}
	return controlplane.ErrRunJournalContextDone
}

func mutationRetryStages(operation string) []string {
	stages := []string{"begin", "tenant", "lock", "scope-insert", "scope-read"}
	if operation != "append-audit" {
		stages = append(stages, "plan-read")
	}
	return append(stages, "event-read", "insert", "commit")
}

func (f mutationRetryFixture) scopeArgs() []driver.Value {
	scope := f.plan.Scope()
	return []driver.Value{scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()}
}

func (f mutationRetryFixture) lockIdentity() string {
	if f.operation == "append-audit" {
		return "audit:" + f.plan.Scope().Identity()
	}
	return f.plan.Scope().Identity()
}

func (f mutationRetryFixture) expectPrefix(mock sqlmock.Sqlmock) {
	expectTenantTransaction(mock, f.plan.Scope().TenantID())
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs(f.lockIdentity()).WillReturnResult(sqlmock.NewResult(0, 1))
	expectScope(mock, f.plan.Scope())
}

func (f mutationRetryFixture) expectAttempt(mock sqlmock.Sqlmock, stage string, failure error) {
	scope := f.plan.Scope()
	begin := mock.ExpectBegin()
	if stage == "begin" {
		begin.WillReturnError(failure)
		return
	}
	exec := func(name, query string, args ...driver.Value) bool {
		expected := mock.ExpectExec(query).WithArgs(args...)
		if stage == name {
			expected.WillReturnError(failure)
			mock.ExpectRollback()
			return false
		}
		expected.WillReturnResult(sqlmock.NewResult(1, 1))
		return true
	}
	query := func(name, statement string, rows *sqlmock.Rows) bool {
		expected := mock.ExpectQuery(statement).WithArgs(f.scopeArgs()...)
		if stage == name {
			expected.WillReturnError(failure)
			mock.ExpectRollback()
			return false
		}
		if rows == nil {
			expected.WillReturnError(sql.ErrNoRows)
		} else {
			expected.WillReturnRows(rows)
		}
		return true
	}
	if !exec("tenant", regexp.QuoteMeta("SELECT set_config('open_trestle.tenant_id', $1, true)"), scope.TenantID()) ||
		!exec("lock", regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"), f.lockIdentity()) ||
		!exec("scope-insert", "INSERT INTO open_trestle_review_scopes", scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity()) ||
		!query("scope-read", "SELECT scope_identity", sqlmock.NewRows([]string{"scope_identity"}).AddRow(scope.Identity())) {
		return
	}
	switch f.operation {
	case "save-plan":
		if !query("plan-read", "SELECT plan_identity, canonical_plan", nil) || !query("event-read", "SELECT plan_identity", nil) {
			return
		}
		encoded, _ := controlplane.EncodeReviewRunPlan(f.plan)
		if !exec("insert", "INSERT INTO open_trestle_run_plans", scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), f.plan.Identity(), encoded) {
			return
		}
	case "append-run":
		if !query("plan-read", "SELECT plan_identity", nil) || !query("event-read", "SELECT sequence, event_identity, canonical_event", nil) {
			return
		}
		event := f.runEvent
		encoded, _ := controlplane.EncodeRunEvent(event)
		if !exec("insert", "INSERT INTO open_trestle_run_events", scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), event.PlanIdentity(), event.Sequence(), event.Identity(), event.PreviousIdentity(), encoded, event.OccurredAt()) {
			return
		}
	case "append-audit":
		if !query("event-read", "SELECT sequence, event_identity, canonical_event", nil) {
			return
		}
		event := f.auditEvent
		encoded, _ := audit.EncodeEvent(event)
		if !exec("insert", "INSERT INTO open_trestle_audit_events", scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), event.Sequence(), event.Identity(), event.PreviousIdentity(), encoded, time.UnixMilli(event.OccurredAtUnixMilliseconds()).UTC()) {
			return
		}
	}
	committed := mock.ExpectCommit()
	if stage == "commit" {
		committed.WillReturnError(failure)
	}
}

// Count driver calls because sqlmock can return an unexpected Begin error that production redacts.
type retryTransactionObserver struct {
	begins     atomic.Int32
	active     atomic.Int32
	invalid    atomic.Bool
	afterClose func()
}

type retryObservedConnector struct {
	driver   driver.Driver
	dsn      string
	observed *retryTransactionObserver
}

func (c retryObservedConnector) Driver() driver.Driver { return c.driver }
func (c retryObservedConnector) Connect(context.Context) (driver.Conn, error) {
	connection, err := c.driver.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &retryObservedConnection{connection, c.observed}, nil
}

type retryObservedConnection struct {
	driver.Conn
	observed *retryTransactionObserver
}

func (c *retryObservedConnection) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	c.observed.begins.Add(1)
	if options.Isolation != driver.IsolationLevel(sql.LevelSerializable) || options.ReadOnly || c.observed.active.Load() != 0 {
		c.observed.invalid.Store(true)
	}
	tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	c.observed.active.Add(1)
	return &retryObservedTransaction{tx, c.observed}, nil
}

func (c *retryObservedConnection) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	return c.Conn.(driver.ExecerContext).ExecContext(ctx, query, args)
}

func (c *retryObservedConnection) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	return c.Conn.(driver.QueryerContext).QueryContext(ctx, query, args)
}

type retryObservedTransaction struct {
	driver.Tx
	observed *retryTransactionObserver
}

func (tx *retryObservedTransaction) Commit() error {
	err := tx.Tx.Commit()
	tx.closed()
	return err
}

func (tx *retryObservedTransaction) Rollback() error {
	err := tx.Tx.Rollback()
	tx.closed()
	return err
}

func (tx *retryObservedTransaction) closed() {
	if tx.observed.active.Add(-1) != 0 {
		tx.observed.invalid.Store(true)
	}
	if tx.observed.afterClose != nil {
		tx.observed.afterClose()
	}
}

func newObservedRetryDatabase(t *testing.T) (*sql.DB, sqlmock.Sqlmock, *retryTransactionObserver) {
	t.Helper()
	original, mock, err := sqlmock.NewWithDSN(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	observed := &retryTransactionObserver{}
	database := sql.OpenDB(retryObservedConnector{original.Driver(), t.Name(), observed})
	t.Cleanup(func() {
		_ = database.Close()
		_ = original.Close()
	})
	return database, mock, observed
}

func assertObservedRetryTransactions(t *testing.T, mock sqlmock.Sqlmock, observed *retryTransactionObserver, begins int32) {
	t.Helper()
	if actual := observed.begins.Load(); actual != begins {
		t.Errorf("transaction attempts = %d, want %d", actual, begins)
	}
	if observed.invalid.Load() || observed.active.Load() != 0 {
		t.Error("transaction isolation changed or transaction was not closed before retry/return")
	}
	assertMock(t, mock)
}
