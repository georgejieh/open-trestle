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
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestArtifactIndexMutationsRetryKnownAborts(t *testing.T) {
	for _, operation := range []string{"register", "authorization", "receipt"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, stage := range artifactIndexRetryStages(operation) {
				t.Run(operation+"/"+code+"/"+stage, func(t *testing.T) {
					fixture := newArtifactIndexRetryFixture(t, operation)
					database, mock, observed := newObservedRetryDatabase(t)
					failure := fmt.Errorf("driver wrapper: %w", &pgconn.PgError{Code: code, Message: "private SQL detail"})
					state := ""
					if stage == "existing-commit" {
						state = "identical"
					}
					fixture.expectAttempt(mock, stage, failure, state)
					fixture.expectAttempt(mock, "", nil, state)
					created, err := fixture.invoke(context.Background(), database)
					if err != nil || created != (state == "") {
						t.Errorf("retry = (%t, %v), want (%t, nil)", created, err, state == "")
					}
					assertObservedRetryTransactions(t, mock, observed, 2)
				})
			}
		}
	}
}

func TestArtifactIndexMutationsDoNotRetryUnclassifiedFailures(t *testing.T) {
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
	for _, operation := range []string{"register", "authorization", "receipt"} {
		for _, failure := range failures {
			for _, stage := range artifactIndexRetryStages(operation) {
				t.Run(operation+"/"+failure.name+"/"+stage, func(t *testing.T) {
					fixture := newArtifactIndexRetryFixture(t, operation)
					database, mock, observed := newObservedRetryDatabase(t)
					state := ""
					if stage == "existing-commit" {
						state = "identical"
					}
					fixture.expectAttempt(mock, stage, failure.err, state)
					created, err := fixture.invoke(context.Background(), database)
					if created || err != ErrDatabaseUnavailable {
						t.Errorf("failure = (%t, %v), want (false, closed unavailable sentinel)", created, err)
					}
					assertObservedRetryTransactions(t, mock, observed, 1)
				})
			}
		}
	}
}

func TestArtifactIndexMutationsBoundConflictAttempts(t *testing.T) {
	for _, operation := range []string{"register", "authorization", "receipt"} {
		for _, stage := range artifactIndexRetryStages(operation) {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				fixture := newArtifactIndexRetryFixture(t, operation)
				database, mock, observed := newObservedRetryDatabase(t)
				state := ""
				if stage == "existing-commit" {
					state = "identical"
				}
				for _, code := range []string{"40001", "40P01", "40001"} {
					fixture.expectAttempt(mock, stage, &pgconn.PgError{Code: code, Message: "private SQL detail"}, state)
				}
				created, err := fixture.invoke(context.Background(), database)
				if created || err != ErrDatabaseUnavailable {
					t.Errorf("exhaustion = (%t, %v), want (false, closed unavailable sentinel)", created, err)
				}
				assertObservedRetryTransactions(t, mock, observed, 3)
			})
		}
	}
}

func TestArtifactIndexMutationsDoNotRetryFailedRollback(t *testing.T) {
	for _, operation := range []string{"register", "authorization", "receipt"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, stage := range []string{"tenant", "lock"} {
				t.Run(operation+"/"+code+"/"+stage, func(t *testing.T) {
					fixture := newArtifactIndexRetryFixture(t, operation)
					database, mock, observed := newObservedRetryDatabase(t)
					failure := &pgconn.PgError{Code: code}
					if stage == "tenant" {
						mock.ExpectBegin()
						mock.ExpectExec(regexp.QuoteMeta("SELECT set_config('open_trestle.tenant_id', $1, true)")).WithArgs(fixture.value.Scope().TenantID()).WillReturnError(failure)
					} else {
						expectTenantTransaction(mock, fixture.value.Scope().TenantID())
						mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs(fixture.lockIdentity()).WillReturnError(failure)
					}
					mock.ExpectRollback().WillReturnError(io.ErrUnexpectedEOF)
					created, err := fixture.invoke(context.Background(), database)
					if created || err != ErrDatabaseUnavailable {
						t.Errorf("rollback failure = (%t, %v), want (false, closed unavailable sentinel)", created, err)
					}
					assertObservedRetryTransactions(t, mock, observed, 1)
				})
			}
		}
	}
}

func TestArtifactIndexMutationsStopWhenContextCanceledAfterAbort(t *testing.T) {
	for _, operation := range []string{"register", "authorization", "receipt"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, stage := range []string{"tenant", "insert", "commit", "existing-commit"} {
				t.Run(operation+"/"+code+"/"+stage, func(t *testing.T) {
					fixture := newArtifactIndexRetryFixture(t, operation)
					database, mock, observed := newObservedRetryDatabase(t)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					observed.afterClose = cancel
					state := ""
					if stage == "existing-commit" {
						state = "identical"
					}
					fixture.expectAttempt(mock, stage, &pgconn.PgError{Code: code}, state)
					created, err := fixture.invoke(ctx, database)
					if created || err != ErrDatabaseUnavailable {
						t.Errorf("canceled retry = (%t, %v), want (false, unavailable)", created, err)
					}
					assertObservedRetryTransactions(t, mock, observed, 1)
				})
			}
		}
	}
}

func TestArtifactIndexMutationsRejectDoneContextBeforeBegin(t *testing.T) {
	for _, operation := range []string{"register", "authorization", "receipt"} {
		for _, deadline := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/deadline=%v", operation, deadline), func(t *testing.T) {
				fixture := newArtifactIndexRetryFixture(t, operation)
				database, mock, observed := newObservedRetryDatabase(t)
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				if deadline {
					ctx, cancel = context.WithDeadline(context.Background(), time.Unix(1, 0))
					defer cancel()
				}
				created, err := fixture.invoke(ctx, database)
				if created || err != ErrDatabaseUnavailable {
					t.Errorf("done context = (%t, %v), want (false, unavailable)", created, err)
				}
				assertObservedRetryTransactions(t, mock, observed, 0)
			})
		}
	}
}

func TestArtifactIndexMutationsRetryRechecksCanonicalState(t *testing.T) {
	for _, operation := range []string{"register", "authorization", "receipt"} {
		states := []string{"identical", "existing-conflict", "metadata-corrupt"}
		if operation != "register" {
			states = append(states, "metadata-missing")
		}
		if operation == "receipt" {
			states = append(states, "payload-conflict", "authorization-missing", "authorization-foreign")
		}
		for _, code := range []string{"40001", "40P01"} {
			for _, stage := range []string{"insert", "commit"} {
				for _, state := range states {
					t.Run(operation+"/"+code+"/"+stage+"/"+state, func(t *testing.T) {
						fixture := newArtifactIndexRetryFixture(t, operation)
						database, mock, observed := newObservedRetryDatabase(t)
						fixture.expectAttempt(mock, stage, &pgconn.PgError{Code: code}, "")
						fixture.expectAttempt(mock, "", nil, state)
						var want error
						switch state {
						case "identical":
						case "metadata-missing":
							want = ErrArtifactMetadataNotFound
						case "metadata-corrupt":
							want = ErrCorruptRecord
						case "authorization-missing":
							want = artifact.ErrDeletionNotAllowed
						default:
							want = ErrArtifactIndexConflict
						}
						created, err := fixture.invoke(context.Background(), database)
						if created || err != want {
							t.Errorf("fresh state = (%t, %v), want (false, %v)", created, err, want)
						}
						assertObservedRetryTransactions(t, mock, observed, 2)
					})
				}
			}
		}
	}
}

type artifactIndexRetryFixture struct {
	operation     string
	value         artifact.Artifact
	authorization artifact.DeletionAuthorization
	receipt       artifact.DeletionReceipt
}

func newArtifactIndexRetryFixture(t *testing.T, operation string) artifactIndexRetryFixture {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-a")
	if err != nil {
		t.Fatal(err)
	}
	value, err := artifact.New(scope, artifact.KindContextPacket, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate, []string{strings.Repeat("a", 64)}, []byte(`{"value":1}`), time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := artifact.NewDeletionAuthorization(scope, value.Identity(), strings.Repeat("b", 64), "operator-a", strings.Repeat("c", 64), artifact.DeletionExpired, time.UnixMilli(1000), time.UnixMilli(2000))
	if err != nil {
		t.Fatal(err)
	}
	// Build completion evidence once, outside the database-only operation under test.
	memory, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := memory.Put(context.Background(), value, time.UnixMilli(200)); err != nil {
		t.Fatal(err)
	}
	receipt, err := memory.Delete(context.Background(), authorization, time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	return artifactIndexRetryFixture{operation, value, authorization, receipt}
}

func (f artifactIndexRetryFixture) invoke(ctx context.Context, database *sql.DB) (bool, error) {
	index, err := NewArtifactIndex(database)
	if err != nil {
		return false, err
	}
	switch f.operation {
	case "register":
		return index.RegisterArtifact(ctx, f.value)
	case "authorization":
		return index.RecordDeletionAuthorization(ctx, f.authorization)
	default:
		return index.RecordDeletionReceipt(ctx, f.receipt)
	}
}

func artifactIndexRetryStages(operation string) []string {
	stages := []string{"begin", "tenant", "lock"}
	if operation == "register" {
		stages = append(stages, "scope-insert", "scope-read")
	}
	stages = append(stages, "metadata-read")
	if operation == "receipt" {
		stages = append(stages, "authorization-read")
	}
	if operation != "register" {
		stages = append(stages, "existing-read")
	}
	return append(stages, "insert", "commit", "existing-commit")
}

func (f artifactIndexRetryFixture) lockIdentity() string {
	switch f.operation {
	case "register":
		return "artifact:" + f.value.Scope().Identity() + ":" + f.value.Identity()
	case "authorization":
		return "artifact-auth:" + f.authorization.Identity()
	default:
		return "artifact-delete:" + f.receipt.ArtifactIdentity()
	}
}

func (f artifactIndexRetryFixture) expectAttempt(mock sqlmock.Sqlmock, stage string, failure error, state string) {
	scope := f.value.Scope()
	scopeArgs := []driver.Value{scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()}
	artifactArgs := append(append([]driver.Value{}, scopeArgs...), f.value.Identity())
	authorizationArgs := append(append([]driver.Value{}, scopeArgs...), f.authorization.Identity())
	begin := mock.ExpectBegin()
	if stage == "begin" {
		begin.WillReturnError(failure)
		return
	}
	exec := func(name, statement string, args ...driver.Value) bool {
		expected := mock.ExpectExec(statement).WithArgs(args...)
		if stage == name {
			expected.WillReturnError(failure)
			mock.ExpectRollback()
			return false
		}
		expected.WillReturnResult(sqlmock.NewResult(1, 1))
		return true
	}
	query := func(name, statement string, rows *sqlmock.Rows, args ...driver.Value) bool {
		expected := mock.ExpectQuery(statement).WithArgs(args...)
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
		!exec("lock", regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))"), f.lockIdentity()) {
		return
	}
	if f.operation == "register" {
		if !exec("scope-insert", "INSERT INTO open_trestle_review_scopes", scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity()) ||
			!query("scope-read", "SELECT scope_identity", sqlmock.NewRows([]string{"scope_identity"}).AddRow(scope.Identity()), scopeArgs...) {
			return
		}
	}
	value := f.value
	payload := value.PayloadDigest()
	kind := value.Kind().String()
	if state == "payload-conflict" || f.operation == "register" && state == "existing-conflict" {
		payload = strings.Repeat("d", 64)
	}
	if state == "metadata-corrupt" {
		kind = "unknown"
	}
	metadata := sqlmock.NewRows([]string{"payload_digest", "kind", "classification", "origin", "protection", "created_at", "expires_at"}).AddRow(payload, kind, value.Classification().String(), value.Origin().String(), value.Protection().String(), value.CreatedAt(), value.ExpiresAt())
	if state == "metadata-missing" || f.operation == "register" && state == "" {
		metadata = nil
	}
	if !query("metadata-read", "SELECT payload_digest, kind, classification, origin, protection, created_at, expires_at", metadata, artifactArgs...) {
		return
	}
	if state == "metadata-missing" || state == "metadata-corrupt" || state == "payload-conflict" || f.operation == "register" && state == "existing-conflict" {
		mock.ExpectRollback()
		return
	}
	authorization := f.authorization
	receipt := f.receipt
	if f.operation == "receipt" {
		identity := value.Identity()
		if state == "authorization-foreign" {
			identity = strings.Repeat("d", 64)
		}
		rows := sqlmock.NewRows([]string{"artifact_identity"}).AddRow(identity)
		if state == "authorization-missing" {
			rows = nil
		}
		if !query("authorization-read", "SELECT artifact_identity", rows, authorizationArgs...) {
			return
		}
		if state == "authorization-missing" || state == "authorization-foreign" {
			mock.ExpectRollback()
			return
		}
	}
	if f.operation != "register" {
		var rows *sqlmock.Rows
		if f.operation == "authorization" {
			principal := authorization.PrincipalIdentity()
			if state == "existing-conflict" {
				principal = "operator-b"
			}
			if state != "" {
				rows = sqlmock.NewRows([]string{"authorization_identity", "artifact_identity", "policy_identity", "principal_identity", "hold_clearance_identity", "reason", "issued_at", "expires_at"}).AddRow(authorization.Identity(), authorization.ArtifactIdentity(), authorization.PolicyIdentity(), principal, authorization.HoldClearanceIdentity(), authorization.Reason().String(), authorization.IssuedAt(), authorization.ExpiresAt())
			}
			if !query("existing-read", "SELECT authorization_identity, artifact_identity, policy_identity, principal_identity, hold_clearance_identity, reason, issued_at, expires_at", rows, authorizationArgs...) {
				return
			}
		} else {
			deletedAt := receipt.DeletedAt()
			if state == "existing-conflict" {
				deletedAt = deletedAt.Add(time.Millisecond)
			}
			if state != "" {
				rows = sqlmock.NewRows([]string{"receipt_identity", "payload_digest", "authorization_identity", "deleted_at"}).AddRow(receipt.Identity(), receipt.PayloadDigest(), receipt.AuthorizationIdentity(), deletedAt)
			}
			if !query("existing-read", "SELECT receipt_identity, payload_digest, authorization_identity, deleted_at", rows, artifactArgs...) {
				return
			}
		}
		if state == "existing-conflict" {
			mock.ExpectRollback()
			return
		}
	}
	if state == "" {
		switch f.operation {
		case "register":
			if !exec("insert", "INSERT INTO open_trestle_artifacts", scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), value.Identity(), value.PayloadDigest(), value.Kind().String(), value.Classification().String(), value.Origin().String(), value.Protection().String(), value.CreatedAt(), value.ExpiresAt()) {
				return
			}
		case "authorization":
			if !exec("insert", "INSERT INTO open_trestle_artifact_deletion_authorizations", scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), authorization.Identity(), authorization.ArtifactIdentity(), authorization.PolicyIdentity(), authorization.PrincipalIdentity(), authorization.HoldClearanceIdentity(), authorization.Reason().String(), authorization.IssuedAt(), authorization.ExpiresAt()) {
				return
			}
		case "receipt":
			if !exec("insert", "INSERT INTO open_trestle_artifact_deletion_receipts", scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), receipt.Identity(), receipt.ArtifactIdentity(), receipt.PayloadDigest(), receipt.AuthorizationIdentity(), receipt.DeletedAt()) {
				return
			}
		}
	}
	commit := mock.ExpectCommit()
	if stage == "commit" || stage == "existing-commit" {
		commit.WillReturnError(failure)
	}
}
