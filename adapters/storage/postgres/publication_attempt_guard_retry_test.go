package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/internal/review"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestPublicationGuardRetryKnownAborts(t *testing.T) {
	for _, operation := range []string{"claim", "complete"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, wrapped := range []bool{false, true} {
				for _, stage := range publicationGuardRetryStages(operation) {
					t.Run(fmt.Sprintf("%s/%s/wrapped=%v/%s", operation, code, wrapped, stage), func(t *testing.T) {
						f := newPublicationGuardRetryFixture(t, operation)
						failure := publicationGuardAbort(code, wrapped)
						f.expectAttempt(publicationGuardAttempt{stage: stage, failure: failure})
						f.expectAttempt(publicationGuardAttempt{})
						f.check(t, context.Background(), operation == "claim", nil, 2)
					})
				}
			}
		}
	}
}

func TestPublicationGuardRetryStopsAtThreeAttempts(t *testing.T) {
	for _, operation := range []string{"claim", "complete"} {
		for _, stage := range publicationGuardRetryStages(operation) {
			for _, succeeds := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/third-succeeds=%v", operation, stage, succeeds), func(t *testing.T) {
					f := newPublicationGuardRetryFixture(t, operation)
					f.expectAttempt(publicationGuardAttempt{stage: stage, failure: publicationGuardAbort("40001", false)})
					f.expectAttempt(publicationGuardAttempt{stage: stage, failure: publicationGuardAbort("40P01", true)})
					want := review.ErrPublicationAttemptGuardUnavailable
					if succeeds {
						f.expectAttempt(publicationGuardAttempt{})
						want = nil
					} else {
						f.expectAttempt(publicationGuardAttempt{stage: stage, failure: publicationGuardAbort("40001", true)})
					}
					f.check(t, context.Background(), succeeds && operation == "claim", want, 3)
				})
			}
		}
	}
}

func TestPublicationGuardRetryRejectsUncertainErrors(t *testing.T) {
	failures := []struct {
		name string
		err  error
	}{
		{"unique", &pgconn.PgError{Code: "23505"}},
		{"permission", &pgconn.PgError{Code: "42501"}},
		{"canceled-query", &pgconn.PgError{Code: "57014"}},
		{"connection", &pgconn.PgError{Code: "08006"}},
		{"unknown-completion", &pgconn.PgError{Code: "40003"}},
		{"internal", &pgconn.PgError{Code: "XX000"}},
		{"network", &net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}},
		{"eof", io.ErrUnexpectedEOF},
		{"text-only", errors.New("private SQLSTATE 40001 / 40P01")},
		{"sqlstate-interface-only", publicationGuardSQLStateImpostor{}},
	}
	for _, operation := range []string{"claim", "complete"} {
		for _, failure := range failures {
			for _, stage := range publicationGuardRetryStages(operation) {
				t.Run(operation+"/"+failure.name+"/"+stage, func(t *testing.T) {
					f := newPublicationGuardRetryFixture(t, operation)
					f.expectAttempt(publicationGuardAttempt{stage: stage, failure: failure.err})
					f.check(t, context.Background(), false, review.ErrPublicationAttemptGuardUnavailable, 1)
				})
			}
		}
	}
}

func TestPublicationGuardRetryStopsOnRollbackFailure(t *testing.T) {
	for _, operation := range []string{"claim", "complete"} {
		for _, stage := range []string{"tenant", "lock", "row", "write"} {
			for _, rollbackCode := range []string{"network", "40001", "40P01"} {
				t.Run(operation+"/"+stage+"/"+rollbackCode, func(t *testing.T) {
					f := newPublicationGuardRetryFixture(t, operation)
					var rollback error = io.ErrUnexpectedEOF
					if rollbackCode != "network" {
						rollback = publicationGuardAbort(rollbackCode, true)
					}
					f.expectAttempt(publicationGuardAttempt{stage: stage, failure: publicationGuardAbort("40001", true), rollback: rollback})
					f.check(t, context.Background(), false, review.ErrPublicationAttemptGuardUnavailable, 1)
				})
			}
		}
	}
}

func TestPublicationGuardRetryCancellationIsClosed(t *testing.T) {
	for _, operation := range []string{"claim", "complete"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, stage := range []string{"tenant", "write", "commit"} {
				t.Run(operation+"/"+code+"/"+stage, func(t *testing.T) {
					f := newPublicationGuardRetryFixture(t, operation)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					f.observed.afterClose = cancel
					f.expectAttempt(publicationGuardAttempt{stage: stage, failure: publicationGuardAbort(code, true)})
					f.check(t, ctx, false, review.ErrPublicationAttemptGuardUnavailable, 1)
				})
			}
		}
		for _, kind := range []string{"canceled", "deadline", "nil", "typed-nil"} {
			t.Run(operation+"/before-begin/"+kind, func(t *testing.T) {
				f := newPublicationGuardRetryFixture(t, operation)
				var ctx context.Context
				switch kind {
				case "canceled":
					canceled, cancel := context.WithCancel(context.Background())
					cancel()
					ctx = canceled
				case "deadline":
					deadline, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
					defer cancel()
					ctx = deadline
				case "typed-nil":
					var typedNil *publicationGuardNilContext
					ctx = typedNil
				}
				f.check(t, ctx, false, review.ErrPublicationAttemptGuardUnavailable, 0)
			})
		}
	}
}

func TestPublicationGuardRetryClaimRechecksAuthoritativeRow(t *testing.T) {
	for _, stage := range []string{"initial", "write", "commit"} {
		for _, status := range []string{"claimed", "completed", "invalid"} {
			for _, change := range []string{"same", "attempt", "request"} {
				t.Run(stage+"/"+status+"/"+change, func(t *testing.T) {
					f := newPublicationGuardRetryFixture(t, "claim")
					var begins int32 = 1
					if stage != "initial" {
						f.expectAttempt(publicationGuardAttempt{stage: stage, failure: publicationGuardAbort("40001", true)})
						begins++
					}
					attempt, request := f.attempt, f.request
					if change == "attempt" {
						attempt = strings.Repeat("e", 64)
					}
					if change == "request" {
						request = strings.Repeat("e", 64)
					}
					conflict := change != "same" || status == "invalid"
					f.expectAttempt(publicationGuardAttempt{rows: publicationGuardClaimRows(attempt, request, status), noWrite: true, conflict: conflict})
					var want error
					if conflict {
						want = review.ErrPublicationAttemptGuardConflict
					}
					f.check(t, context.Background(), false, want, begins)
				})
			}
		}
	}
}

func TestPublicationGuardRetryClaimResetsAcquiredOnEveryAttempt(t *testing.T) {
	for _, last := range []string{"absent", "claimed", "completed", "uncertain"} {
		t.Run(last, func(t *testing.T) {
			f := newPublicationGuardRetryFixture(t, "claim")
			f.expectAttempt(publicationGuardAttempt{stage: "commit", failure: publicationGuardAbort("40001", false)})
			f.expectAttempt(publicationGuardAttempt{rows: publicationGuardClaimRows(f.attempt, f.request, "claimed"), noWrite: true, stage: "commit", failure: publicationGuardAbort("40P01", true)})
			var want error
			switch last {
			case "absent":
				f.expectAttempt(publicationGuardAttempt{})
			case "uncertain":
				f.expectAttempt(publicationGuardAttempt{stage: "commit", failure: io.ErrUnexpectedEOF})
				want = review.ErrPublicationAttemptGuardUnavailable
			default:
				f.expectAttempt(publicationGuardAttempt{rows: publicationGuardClaimRows(f.attempt, f.request, last), noWrite: true})
			}
			f.check(t, context.Background(), last == "absent", want, 3)
		})
	}
}

func TestPublicationGuardRetryCompletionRechecksResultAndClaimedAt(t *testing.T) {
	for _, stage := range []string{"initial", "write", "commit"} {
		for _, state := range []string{"claimed", "equal-time", "future-claim", "submillisecond-future", "claimed-with-result", "completed-same", "completed-other", "completed-null", "future-completed", "invalid", "absent", "bad-time"} {
			t.Run(stage+"/"+state, func(t *testing.T) {
				f := newPublicationGuardRetryFixture(t, "complete")
				var begins int32 = 1
				if stage != "initial" {
					f.expectAttempt(publicationGuardAttempt{stage: stage, failure: publicationGuardAbort("40P01", true)})
					begins++
				}
				next := publicationGuardAttempt{}
				want := review.ErrPublicationAttemptGuardConflict
				switch state {
				case "claimed":
					next.rows = publicationGuardCompleteRows("claimed", nil, f.at.Add(-2*time.Second))
					want = nil
				case "equal-time":
					next.rows = publicationGuardCompleteRows("claimed", nil, f.canonicalAt())
					want = nil
				case "future-claim":
					next.rows = publicationGuardCompleteRows("claimed", nil, f.canonicalAt().Add(time.Millisecond))
				case "submillisecond-future":
					next.rows = publicationGuardCompleteRows("claimed", nil, f.canonicalAt().Add(time.Nanosecond))
				case "claimed-with-result":
					next.rows = publicationGuardCompleteRows("claimed", f.result, f.claimedAt)
				case "completed-same":
					next.rows = publicationGuardCompleteRows("completed", f.result, f.claimedAt)
					next.noWrite = true
					want = nil
				case "completed-other":
					next.rows = publicationGuardCompleteRows("completed", strings.Repeat("e", 64), f.claimedAt)
				case "completed-null":
					next.rows = publicationGuardCompleteRows("completed", nil, f.claimedAt)
				case "future-completed":
					next.rows = publicationGuardCompleteRows("completed", f.result, f.canonicalAt().Add(time.Millisecond))
				case "invalid":
					next.rows = publicationGuardCompleteRows("invalid", nil, f.claimedAt)
				case "absent":
					next.stage, next.failure = "row", sql.ErrNoRows
				case "bad-time":
					next.rows = publicationGuardCompleteRows("claimed", nil, "not a time")
					want = review.ErrPublicationAttemptGuardUnavailable
				}
				next.conflict = want != nil
				f.expectAttempt(next)
				f.check(t, context.Background(), false, want, begins)
			})
		}
	}
}

func TestPublicationGuardRetryCompletionClearsPreviousReadState(t *testing.T) {
	f := newPublicationGuardRetryFixture(t, "complete")
	f.expectAttempt(publicationGuardAttempt{rows: publicationGuardCompleteRows("completed", f.result, f.claimedAt), noWrite: true, stage: "commit", failure: publicationGuardAbort("40001", true)})
	f.expectAttempt(publicationGuardAttempt{rows: publicationGuardCompleteRows("claimed", nil, f.claimedAt.Add(time.Millisecond))})
	f.check(t, context.Background(), false, nil, 2)
}

func TestPublicationGuardRetryCompletionRowsAffectedIsTerminal(t *testing.T) {
	cases := []struct {
		name   string
		result driver.Result
	}{
		{"zero", sqlmock.NewResult(0, 0)},
		{"multiple", sqlmock.NewResult(0, 2)},
		{"negative", sqlmock.NewResult(0, -1)},
		{"network", sqlmock.NewErrorResult(io.ErrUnexpectedEOF)},
		{"serialization", sqlmock.NewErrorResult(publicationGuardAbort("40001", false))},
		{"wrapped-serialization", sqlmock.NewErrorResult(publicationGuardAbort("40001", true))},
		{"deadlock", sqlmock.NewErrorResult(publicationGuardAbort("40P01", false))},
		{"wrapped-deadlock", sqlmock.NewErrorResult(publicationGuardAbort("40P01", true))},
	}
	for _, test := range cases {
		for _, priorAbort := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/prior-abort=%v", test.name, priorAbort), func(t *testing.T) {
				f := newPublicationGuardRetryFixture(t, "complete")
				var begins int32 = 1
				if priorAbort {
					f.expectAttempt(publicationGuardAttempt{stage: "commit", failure: publicationGuardAbort("40001", false)})
					begins++
				}
				f.expectAttempt(publicationGuardAttempt{writeResult: test.result, badResult: true})
				f.check(t, context.Background(), false, review.ErrPublicationAttemptGuardUnavailable, begins)
			})
		}
	}
}

func TestPublicationGuardRetryDuplicateCommitMustBeKnown(t *testing.T) {
	for _, operation := range []string{"claim", "complete"} {
		for _, status := range []string{"claimed", "completed"} {
			if operation == "complete" && status != "completed" {
				continue
			}
			t.Run(operation+"/"+status, func(t *testing.T) {
				f := newPublicationGuardRetryFixture(t, operation)
				rows := publicationGuardClaimRows(f.attempt, f.request, status)
				if operation == "complete" {
					rows = publicationGuardCompleteRows(status, f.result, f.claimedAt)
				}
				f.expectAttempt(publicationGuardAttempt{rows: rows, noWrite: true, stage: "commit", failure: io.ErrUnexpectedEOF})
				f.check(t, context.Background(), false, review.ErrPublicationAttemptGuardUnavailable, 1)
			})
		}
	}
}

func TestPublicationGuardRetryScopeCorruptionStaysClosed(t *testing.T) {
	for _, kind := range []string{"missing", "changed", "null"} {
		for _, priorAbort := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/prior-abort=%v", kind, priorAbort), func(t *testing.T) {
				f := newPublicationGuardRetryFixture(t, "claim")
				var begins int32 = 1
				if priorAbort {
					f.expectAttempt(publicationGuardAttempt{stage: "commit", failure: publicationGuardAbort("40001", true)})
					begins++
				}
				rows := sqlmock.NewRows([]string{"scope_identity"})
				if kind == "changed" {
					rows.AddRow(strings.Repeat("e", 64))
				} else if kind == "null" {
					rows.AddRow(nil)
				}
				f.expectAttempt(publicationGuardAttempt{scopeRows: rows})
				f.check(t, context.Background(), false, review.ErrPublicationAttemptGuardUnavailable, begins)
			})
		}
	}
}

func TestPublicationGuardRetryClaimScanCorruptionIsUnavailable(t *testing.T) {
	for _, column := range []string{"attempt", "request", "status"} {
		t.Run(column, func(t *testing.T) {
			f := newPublicationGuardRetryFixture(t, "claim")
			var attempt, request, status driver.Value = f.attempt, f.request, "claimed"
			switch column {
			case "attempt":
				attempt = nil
			case "request":
				request = nil
			case "status":
				status = nil
			}
			f.expectAttempt(publicationGuardAttempt{rows: publicationGuardClaimRows(attempt, request, status), conflict: true})
			f.check(t, context.Background(), false, review.ErrPublicationAttemptGuardUnavailable, 1)
		})
	}
}

func TestPublicationGuardRetryPreservesIdempotencyIdentity(t *testing.T) {
	f := newPublicationGuardRetryFixture(t, "claim")
	digest := sha256.Sum256([]byte("open-trestle/postgresql-publication-attempt-guard/v3/" + f.store.publicationAuthority.Identity()))
	identity := hex.EncodeToString(digest[:])
	if f.store.Identity() != identity || f.store.IdempotencyGuarantee() != review.PublisherExactOperationKey {
		t.Fatal("database-only retries changed publication authority semantics")
	}
	f.expectAttempt(publicationGuardAttempt{stage: "commit", failure: publicationGuardAbort("40001", true)})
	f.expectAttempt(publicationGuardAttempt{})
	f.check(t, context.Background(), true, nil, 2)
	if f.store.Identity() != identity || f.store.IdempotencyGuarantee() != review.PublisherExactOperationKey {
		t.Fatal("retry changed publication identity or guarantee")
	}
}

const publicationGuardScopeInsertSQL = `INSERT INTO open_trestle_review_scopes
(tenant_id, repository_id, review_run_id, scope_identity)
VALUES ($1, $2, $3, $4)
ON CONFLICT DO NOTHING`

const publicationGuardScopeReadSQL = `SELECT scope_identity
FROM open_trestle_review_scopes
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3`

const publicationGuardClaimReadSQL = `SELECT attempt_identity, request_identity, status
FROM open_trestle_publication_attempts
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND operation_key = $4`

const publicationGuardCompleteReadSQL = `SELECT status, result_identity, claimed_at
FROM open_trestle_publication_attempts
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND attempt_identity = $4`

const publicationGuardInsertSQL = `INSERT INTO open_trestle_publication_attempts
(tenant_id, repository_id, review_run_id, scope_identity, operation_key, attempt_identity, request_identity, status, claimed_at)
VALUES ($1, $2, $3, $4, $5, $6, $7, 'claimed', $8)`

const publicationGuardUpdateSQL = `UPDATE open_trestle_publication_attempts
SET status = 'completed', result_identity = $1, completed_at = $2
WHERE tenant_id = $3 AND repository_id = $4 AND review_run_id = $5 AND attempt_identity = $6 AND status = 'claimed' AND result_identity IS NULL`

type publicationGuardRetryFixture struct {
	operation string
	store     *Store
	mock      sqlmock.Sqlmock
	observed  *retryTransactionObserver
	scope     audit.ReviewScope
	key       string
	attempt   string
	request   string
	result    string
	at        time.Time
	claimedAt time.Time
}

func newPublicationGuardRetryFixture(t *testing.T, operation string) publicationGuardRetryFixture {
	t.Helper()
	original, mock, err := sqlmock.NewWithDSN(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = original.Close() })
	authority := strings.Repeat("f", 64)
	expectPublicationAuthorityVerification(mock, authority, testPublicationNamespace)
	store, err := NewWithPublicationAuthority(context.Background(), original, authority)
	if err != nil {
		t.Fatal(err)
	}
	assertMock(t, mock)
	// Observe guard transactions on the same mock database, not the READ COMMITTED authority check.
	observed := &retryTransactionObserver{}
	database := sql.OpenDB(retryObservedConnector{original.Driver(), t.Name(), observed})
	t.Cleanup(func() { _ = database.Close() })
	store.database = database
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-publication-retry")
	if err != nil {
		t.Fatal(err)
	}
	return publicationGuardRetryFixture{
		operation: operation, store: store, mock: mock, observed: observed, scope: scope,
		key: strings.Repeat("a", 64), attempt: strings.Repeat("b", 64),
		request: strings.Repeat("c", 64), result: strings.Repeat("d", 64),
		at:        time.Unix(1700000000, 123456789).In(time.FixedZone("fixture", 3600)),
		claimedAt: time.Unix(1699999999, 123000000).UTC(),
	}
}

func (f publicationGuardRetryFixture) canonicalAt() time.Time {
	return time.UnixMilli(f.at.UnixMilli()).UTC()
}

func (f publicationGuardRetryFixture) check(t *testing.T, ctx context.Context, wantAcquired bool, want error, begins int32) {
	t.Helper()
	var acquired bool
	var err error
	if f.operation == "claim" {
		acquired, err = f.store.ClaimPublicationAttempt(ctx, f.scope, f.key, f.attempt, f.request, f.at)
	} else {
		err = f.store.CompletePublicationAttempt(ctx, f.scope, f.attempt, f.result, f.at)
	}
	if err != want || acquired != wantAcquired {
		t.Errorf("%s = (%v, %v), want (%v, %v)", f.operation, acquired, err, wantAcquired, want)
	}
	assertObservedRetryTransactions(t, f.mock, f.observed, begins)
}

type publicationGuardAttempt struct {
	stage       string
	failure     error
	rollback    error
	rows        *sqlmock.Rows
	scopeRows   *sqlmock.Rows
	noWrite     bool
	conflict    bool
	writeResult driver.Result
	badResult   bool
}

func (f publicationGuardRetryFixture) expectAttempt(a publicationGuardAttempt) {
	mock, scope := f.mock, f.scope
	rollback := func() {
		expected := mock.ExpectRollback()
		if a.rollback != nil {
			expected.WillReturnError(a.rollback)
		}
	}
	begin := mock.ExpectBegin()
	if a.stage == "begin" {
		begin.WillReturnError(a.failure)
		return
	}
	exec := func(stage, statement string, args ...driver.Value) bool {
		expected := mock.ExpectExec(publicationGuardExactSQL(statement)).WithArgs(args...)
		if a.stage == stage {
			expected.WillReturnError(a.failure)
			rollback()
			return false
		}
		if stage == "write" && a.writeResult != nil {
			expected.WillReturnResult(a.writeResult)
		} else {
			expected.WillReturnResult(sqlmock.NewResult(0, 1))
		}
		return true
	}
	query := func(stage, statement string, rows *sqlmock.Rows, args ...driver.Value) bool {
		expected := mock.ExpectQuery(publicationGuardExactSQL(statement)).WithArgs(args...)
		if a.stage == stage {
			expected.WillReturnError(a.failure)
			rollback()
			return false
		}
		if a.stage == "row-scan" && stage == "row" {
			if rows == nil {
				rows = publicationGuardClaimRows(f.attempt, f.request, "claimed")
			}
			expected.WillReturnRows(rows.RowError(0, a.failure))
			rollback()
			return false
		}
		if rows == nil {
			expected.WillReturnError(sql.ErrNoRows)
		} else {
			expected.WillReturnRows(rows)
		}
		return true
	}
	lock := "publication-operation:" + f.key
	if f.operation == "complete" {
		lock = "publication-attempt:" + f.attempt
	}
	if !exec("tenant", "SELECT set_config('open_trestle.tenant_id', $1, true)", scope.TenantID()) ||
		!exec("lock", "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", lock) {
		return
	}
	scopeArgs := []driver.Value{scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()}
	if f.operation == "claim" {
		if !exec("scope-insert", publicationGuardScopeInsertSQL, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity()) {
			return
		}
		rows := a.scopeRows
		if rows == nil {
			rows = sqlmock.NewRows([]string{"scope_identity"}).AddRow(scope.Identity())
		}
		if !query("scope-read", publicationGuardScopeReadSQL, rows, scopeArgs...) {
			return
		}
		if a.scopeRows != nil {
			rollback()
			return
		}
	}
	rows := a.rows
	statement, identity := publicationGuardClaimReadSQL, f.key
	if f.operation == "complete" {
		statement, identity = publicationGuardCompleteReadSQL, f.attempt
		if rows == nil {
			rows = publicationGuardCompleteRows("claimed", nil, f.claimedAt)
		}
	}
	if !query("row", statement, rows, append(scopeArgs, identity)...) {
		return
	}
	if a.conflict {
		rollback()
		return
	}
	if !a.noWrite {
		if f.operation == "claim" {
			if !exec("write", publicationGuardInsertSQL, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), f.key, f.attempt, f.request, f.canonicalAt()) {
				return
			}
		} else if !exec("write", publicationGuardUpdateSQL, f.result, f.canonicalAt(), scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), f.attempt) {
			return
		}
		if a.badResult {
			rollback()
			return
		}
	}
	commit := mock.ExpectCommit()
	if a.stage == "commit" {
		commit.WillReturnError(a.failure)
	}
}

func publicationGuardExactSQL(statement string) string {
	return "^" + regexp.QuoteMeta(statement) + "$"
}

func publicationGuardRetryStages(operation string) []string {
	stages := []string{"begin", "tenant", "lock"}
	if operation == "claim" {
		stages = append(stages, "scope-insert", "scope-read")
	}
	return append(stages, "row", "row-scan", "write", "commit")
}

func publicationGuardAbort(code string, wrapped bool) error {
	var err error = &pgconn.PgError{Code: code, Message: "private SQL detail"}
	if wrapped {
		err = fmt.Errorf("driver wrapper: %w", err)
	}
	return err
}

func publicationGuardClaimRows(attempt, request, status driver.Value) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"attempt_identity", "request_identity", "status"}).AddRow(attempt, request, status)
}

func publicationGuardCompleteRows(status, result, claimedAt driver.Value) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"status", "result_identity", "claimed_at"}).AddRow(status, result, claimedAt)
}

type publicationGuardNilContext struct{ context.Context }

type publicationGuardSQLStateImpostor struct{}

func (publicationGuardSQLStateImpostor) Error() string    { return "SQLSTATE 40001" }
func (publicationGuardSQLStateImpostor) SQLState() string { return "40001" }
