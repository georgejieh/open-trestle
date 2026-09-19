package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/webhook"
)

type metadataRetryClock struct{ at time.Time }

func (c *metadataRetryClock) Now() time.Time { return c.at }

type metadataRetryConnector struct {
	retryObservedConnector
	preReads *atomic.Int32
}

func (c metadataRetryConnector) Connect(context.Context) (driver.Conn, error) {
	connection, err := c.driver.Open(c.dsn)
	if err != nil {
		return nil, err
	}
	return &metadataRetryConnection{retryObservedConnection{connection, c.observed}, c.preReads}, nil
}

type metadataRetryConnection struct {
	retryObservedConnection
	preReads *atomic.Int32
}

func (c *metadataRetryConnection) BeginTx(ctx context.Context, options driver.TxOptions) (driver.Tx, error) {
	// The public pre-read is READ COMMITTED; metadata attempts must remain SERIALIZABLE.
	if c.preReads.CompareAndSwap(0, 1) {
		if options.Isolation != driver.IsolationLevel(sql.LevelReadCommitted) || options.ReadOnly || c.observed.active.Load() != 0 {
			c.observed.invalid.Store(true)
		}
		tx, err := c.Conn.(driver.ConnBeginTx).BeginTx(ctx, options)
		if err != nil {
			return nil, err
		}
		c.observed.active.Add(1)
		return &retryObservedTransaction{tx, c.observed}, nil
	}
	return c.retryObservedConnection.BeginTx(ctx, options)
}

type metadataRetryArtifacts struct {
	*artifact.MemoryStore
	t          *testing.T
	database   *sql.DB
	puts, gets int
	putError   error
	getError   error
	values     []artifact.Artifact
	putTimes   []time.Time
	getIDs     []string
	getTimes   []time.Time
	afterPut   func()
}

func (s *metadataRetryArtifacts) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	s.puts++
	s.values = append(s.values, value)
	s.putTimes = append(s.putTimes, at)
	if s.database.Stats().InUse != 0 {
		s.t.Error("artifact Put retained a metadata transaction connection")
	}
	if s.putError != nil {
		return false, s.putError
	}
	created, err := s.MemoryStore.Put(ctx, value, at)
	if err == nil && s.afterPut != nil {
		s.afterPut()
	}
	return created, err
}

func (s *metadataRetryArtifacts) Get(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (artifact.Artifact, error) {
	s.gets++
	s.getIDs = append(s.getIDs, identity)
	s.getTimes = append(s.getTimes, at)
	if s.database.Stats().InUse != 0 {
		s.t.Error("artifact Get retained a metadata transaction connection")
	}
	if s.getError != nil {
		return artifact.Artifact{}, s.getError
	}
	return (artifactStoreUsingMetadataPool{Store: s.MemoryStore, database: s.database}).Get(ctx, scope, identity, at)
}

type metadataRetryFixture struct {
	t          *testing.T
	operation  string
	database   *sql.DB
	mock       sqlmock.Sqlmock
	observed   *retryTransactionObserver
	preReads   *atomic.Int32
	artifacts  *metadataRetryArtifacts
	clock      *metadataRetryClock
	diagnostic *DiagnosticStore
	webhook    *WebhookStore
	set        diagnostics.Set
	delivery   webhook.VerifiedDelivery
	stored     webhook.StoredDelivery
	scope      audit.ReviewScope
	value      artifact.Artifact
	at         time.Time
}

func newMetadataRetryFixture(t *testing.T, operation string) *metadataRetryFixture {
	t.Helper()
	original, mock, err := sqlmock.NewWithDSN(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	observed := &retryTransactionObserver{}
	preReads := &atomic.Int32{}
	database := sql.OpenDB(metadataRetryConnector{retryObservedConnector{original.Driver(), t.Name(), observed}, preReads})
	database.SetMaxOpenConns(1)
	t.Cleanup(func() {
		_ = database.Close()
		_ = original.Close()
	})
	memory, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	if err != nil {
		t.Fatal(err)
	}
	at := time.UnixMilli(2000).UTC()
	bodies := &metadataRetryArtifacts{MemoryStore: memory, t: t, database: database}
	f := &metadataRetryFixture{t: t, operation: operation, database: database, mock: mock, observed: observed, preReads: preReads, artifacts: bodies, clock: &metadataRetryClock{at}, at: at}
	if operation == "diagnostic" {
		f.scope, err = audit.NewReviewScope("tenant-a", "repo-a", "metadata-retry")
		if err != nil {
			t.Fatal(err)
		}
		finding, err := diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Bounded title", "Untrusted detail", diagnostics.SeverityWarning, "src/main.go", 2, 3, []string{"evidence:one"})
		if err != nil {
			t.Fatal(err)
		}
		f.set, err = diagnostics.NewSet(f.scope, strings.Repeat("c", 64), strings.Repeat("d", 40), strings.Repeat("e", 64), []diagnostics.Finding{finding})
		if err != nil {
			t.Fatal(err)
		}
		f.diagnostic, err = NewDiagnosticStore(database, bodies, DiagnosticStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Clock: f.clock})
		if err != nil {
			t.Fatal(err)
		}
		f.value, err = f.diagnostic.newDiagnosticArtifact(f.set, at)
	} else {
		scope, scopeErr := webhook.NewRepositoryScope("tenant-a", "repo-a")
		if scopeErr != nil {
			t.Fatal(scopeErr)
		}
		f.delivery, err = webhook.NewVerifiedDelivery(scope, webhook.SourceGitHub, "delivery-1", "pull_request", "opened", strings.Repeat("a", 64), []byte(`{"action":"opened","number":1}`), at.Add(-time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		f.stored, err = webhook.NewStoredDelivery(f.delivery, at)
		if err != nil {
			t.Fatal(err)
		}
		f.webhook, err = NewWebhookStore(database, bodies, WebhookStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Clock: f.clock})
		if err != nil {
			t.Fatal(err)
		}
		f.value, f.scope, err = f.webhook.newWebhookArtifact(f.stored)
	}
	if err != nil {
		t.Fatal(err)
	}
	return f
}

type metadataRetryAttempt struct {
	stage        string
	failure      error
	rollback     error
	rows         *sqlmock.Rows
	domainError  error
	scopeCorrupt bool
	count        int
	readAt       time.Time
}

func metadataRetryStages(operation string) []string {
	stages := []string{"begin", "tenant", "lock", "scope-write", "scope-read", "mapping"}
	if operation == "webhook" {
		stages = append(stages, "capacity")
	}
	return append(stages, "insert", "commit")
}

func (f *metadataRetryFixture) mappingQuery() string {
	if f.operation == "diagnostic" {
		return "SELECT set_identity, artifact_identity, expires_at"
	}
	return "SELECT review_run_id, review_scope_identity, repository_scope_identity"
}

func (f *metadataRetryFixture) mappingArgs() []driver.Value {
	if f.operation == "diagnostic" {
		return []driver.Value{f.scope.TenantID(), f.scope.RepositoryID(), f.scope.ReviewRunID()}
	}
	return []driver.Value{f.scope.TenantID(), f.scope.RepositoryID(), f.delivery.Source().String(), f.delivery.DeduplicationKey()}
}

func (f *metadataRetryFixture) expectPreRead(a metadataRetryAttempt) {
	begin := f.mock.ExpectBegin()
	if a.stage == "begin" {
		begin.WillReturnError(a.failure)
		return
	}
	tenant := f.mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('open_trestle.tenant_id', $1, true)")).WithArgs(f.scope.TenantID())
	if a.stage == "tenant" {
		tenant.WillReturnError(a.failure)
		f.mock.ExpectRollback()
		return
	}
	tenant.WillReturnResult(sqlmock.NewResult(0, 1))
	query := f.mock.ExpectQuery(f.mappingQuery()).WithArgs(f.mappingArgs()...)
	if a.stage == "mapping" {
		query.WillReturnError(a.failure)
		f.mock.ExpectRollback()
		return
	}
	if a.rows == nil {
		query.WillReturnError(sql.ErrNoRows)
	} else {
		query.WillReturnRows(a.rows)
	}
	if a.domainError != nil {
		f.mock.ExpectRollback()
		return
	}
	ending := f.mock.ExpectCommit()
	if a.stage == "commit" {
		ending.WillReturnError(a.failure)
	}
}

func (f *metadataRetryFixture) expectAttempt(a metadataRetryAttempt) {
	failedExec := func(query string, args ...driver.Value) bool {
		expected := f.mock.ExpectExec(query).WithArgs(args...)
		if a.failure != nil {
			expected.WillReturnError(a.failure)
			rollback := f.mock.ExpectRollback()
			if a.rollback != nil {
				rollback.WillReturnError(a.rollback)
			}
			return true
		}
		expected.WillReturnResult(sqlmock.NewResult(0, 1))
		return false
	}
	begin := f.mock.ExpectBegin()
	if a.stage == "begin" {
		begin.WillReturnError(a.failure)
		return
	}
	failure := a.failure
	a.failure = nil
	if a.stage == "tenant" {
		a.failure = failure
	}
	if failedExec(regexp.QuoteMeta("SELECT set_config('open_trestle.tenant_id', $1, true)"), f.scope.TenantID()) {
		return
	}
	lock := "diagnostics:" + f.scope.Identity()
	if f.operation == "webhook" {
		lock = "webhook:" + f.delivery.Scope().Identity() + ":" + f.delivery.Source().String()
	}
	if a.stage == "lock" {
		a.failure = failure
	}
	if failedExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"), lock) {
		return
	}
	if a.stage == "scope-write" {
		a.failure = failure
	}
	if failedExec("INSERT INTO open_trestle_review_scopes", f.scope.TenantID(), f.scope.RepositoryID(), f.scope.ReviewRunID(), f.scope.Identity()) {
		return
	}
	scopeRead := f.mock.ExpectQuery("SELECT scope_identity").WithArgs(f.scope.TenantID(), f.scope.RepositoryID(), f.scope.ReviewRunID())
	if a.stage == "scope-read" {
		scopeRead.WillReturnError(failure)
		f.expectRollback(a.rollback)
		return
	}
	identity := f.scope.Identity()
	if a.scopeCorrupt {
		identity = strings.Repeat("f", 64)
	}
	scopeRead.WillReturnRows(sqlmock.NewRows([]string{"scope_identity"}).AddRow(identity))
	if a.scopeCorrupt {
		f.expectRollback(a.rollback)
		return
	}
	mapping := f.mock.ExpectQuery(f.mappingQuery()).WithArgs(f.mappingArgs()...)
	if a.stage == "mapping" {
		mapping.WillReturnError(failure)
		f.expectRollback(a.rollback)
		return
	}
	if a.rows != nil {
		mapping.WillReturnRows(a.rows)
		if a.domainError != nil {
			f.expectRollback(a.rollback)
			return
		}
	} else {
		mapping.WillReturnError(sql.ErrNoRows)
		if f.operation == "webhook" {
			readAt := a.readAt
			if readAt.IsZero() {
				readAt = f.at
			}
			count := f.mock.ExpectQuery("SELECT count\\(\\*\\)").WithArgs(f.scope.TenantID(), f.scope.RepositoryID(), f.delivery.Source().String(), readAt)
			if a.stage == "capacity" {
				count.WillReturnError(failure)
				f.expectRollback(a.rollback)
				return
			}
			count.WillReturnRows(sqlmock.NewRows([]string{"count"}).AddRow(a.count))
			if a.count >= maximumWebhookEntries {
				f.expectRollback(a.rollback)
				return
			}
		}
		if a.stage == "insert" {
			a.failure = failure
		}
		var failed bool
		if f.operation == "diagnostic" {
			failed = failedExec("INSERT INTO open_trestle_diagnostic_sets", f.scope.TenantID(), f.scope.RepositoryID(), f.scope.ReviewRunID(), f.scope.Identity(), f.set.Identity(), f.value.Identity(), f.value.ExpiresAt())
		} else {
			failed = failedExec("INSERT INTO open_trestle_webhook_deliveries", f.scope.TenantID(), f.scope.RepositoryID(), f.scope.ReviewRunID(), f.scope.Identity(), f.delivery.Scope().Identity(), f.delivery.Source().String(), f.delivery.DeduplicationKey(), f.delivery.Identity(), f.value.Identity(), f.stored.Receipt().AcceptedAt(), f.value.ExpiresAt())
		}
		if failed {
			return
		}
	}
	ending := f.mock.ExpectCommit()
	if a.stage == "commit" {
		ending.WillReturnError(failure)
	}
}

func (f *metadataRetryFixture) expectRollback(failure error) {
	rollback := f.mock.ExpectRollback()
	if failure != nil {
		rollback.WillReturnError(failure)
	}
}

func (f *metadataRetryFixture) diagnosticRows(setIdentity, artifactIdentity string, expiry time.Time) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"set_identity", "artifact_identity", "expires_at"}).AddRow(setIdentity, artifactIdentity, expiry)
}

func (f *metadataRetryFixture) webhookRows(stored webhook.StoredDelivery, value artifact.Artifact, expiry time.Time) *sqlmock.Rows {
	delivery := stored.Delivery()
	return sqlmock.NewRows([]string{"review_run_id", "review_scope_identity", "repository_scope_identity", "deduplication_key", "delivery_identity", "artifact_identity", "accepted_at", "expires_at"}).AddRow(f.scope.ReviewRunID(), f.scope.Identity(), delivery.Scope().Identity(), delivery.DeduplicationKey(), delivery.Identity(), value.Identity(), stored.Receipt().AcceptedAt(), expiry)
}

func (f *metadataRetryFixture) rows(value artifact.Artifact, stored webhook.StoredDelivery) *sqlmock.Rows {
	if f.operation == "diagnostic" {
		return f.diagnosticRows(f.set.Identity(), value.Identity(), value.ExpiresAt())
	}
	return f.webhookRows(stored, value, value.ExpiresAt())
}

func (f *metadataRetryFixture) seed(value artifact.Artifact) {
	f.t.Helper()
	if _, err := f.artifacts.MemoryStore.Put(context.Background(), value, value.CreatedAt()); err != nil {
		f.t.Fatal(err)
	}
}

func (f *metadataRetryFixture) check(ctx context.Context, created bool, want error, attempts, preReads int32, puts, gets int, expected webhook.StoredDelivery) {
	f.t.Helper()
	if f.operation == "diagnostic" {
		got, err := f.diagnostic.PutDiagnosticSet(ctx, f.set)
		if got != created || err != want {
			f.t.Errorf("PutDiagnosticSet=(%v,%v), want (%v,%v)", got, err, created, want)
		}
	} else {
		got, inserted, err := f.webhook.Put(ctx, f.delivery, f.at)
		if inserted != created || err != want {
			f.t.Errorf("Put=(%v,%v), want (%v,%v)", inserted, err, created, want)
		}
		if want != nil {
			if got.Validate() == nil || got.Receipt().Identity() != "" || got.Delivery().Identity() != "" {
				f.t.Error("failed metadata call returned an accepted delivery")
			}
		} else {
			encoded, err := webhook.EncodeStoredDelivery(got)
			wantEncoded, wantErr := webhook.EncodeStoredDelivery(expected)
			if err != nil || wantErr != nil || !bytes.Equal(encoded, wantEncoded) {
				f.t.Error("returned delivery changed canonical body, original receipt, or receive time")
			}
		}
	}
	assertObservedRetryTransactions(f.t, f.mock, f.observed, attempts)
	if f.preReads.Load() != preReads {
		f.t.Errorf("pre-read attempts=%d, want %d", f.preReads.Load(), preReads)
	}
	if f.database.Stats().InUse != 0 || f.artifacts.puts != puts || f.artifacts.gets != gets {
		f.t.Errorf("connection/artifact boundary: in-use=%d put=%d get=%d; want 0/%d/%d", f.database.Stats().InUse, f.artifacts.puts, f.artifacts.gets, puts, gets)
	}
	for i, value := range f.artifacts.values {
		if value.Identity() != f.value.Identity() || !bytes.Equal(value.Payload(), f.value.Payload()) || !value.CreatedAt().Equal(f.value.CreatedAt()) || !value.ExpiresAt().Equal(f.value.ExpiresAt()) || !f.artifacts.putTimes[i].Equal(f.at) {
			f.t.Error("speculative artifact changed canonical bytes, identity, creation, expiry, or Put time")
		}
	}
}
