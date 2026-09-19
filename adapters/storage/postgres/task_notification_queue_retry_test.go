package postgres

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestTaskNotificationQueueRetryKnownAborts(t *testing.T) {
	for _, operation := range []string{"enqueue", "claim", "acknowledge"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, wrapped := range []bool{false, true} {
				for _, stage := range notificationRetryStages(operation) {
					t.Run(fmt.Sprintf("%s/%s/wrapped=%v/%s", operation, code, wrapped, stage), func(t *testing.T) {
						f, store, mock, observed, entropy := newNotificationRetryFixture(t)
						var failure error = &pgconn.PgError{Code: code, Message: "private SQL detail"}
						if wrapped {
							failure = fmt.Errorf("driver wrapper: %w", failure)
						}
						f.expectAttempt(mock, operation, notificationRetryAttempt{stage: stage, failure: failure})
						f.expectAttempt(mock, operation, notificationRetryAttempt{})
						f.invoke(t, context.Background(), store, operation, true, f.lease(t, f.notice, 1), nil)
						assertObservedRetryTransactions(t, mock, observed, 2)
						wantReads := 0
						if operation == "claim" {
							wantReads = 1
						}
						entropy.assertReads(t, wantReads)
					})
				}
			}
		}
	}
}

func TestTaskNotificationQueueRetryNeverReplaysUnclassifiedFailures(t *testing.T) {
	failures := []struct {
		name string
		err  error
	}{
		{"unique", &pgconn.PgError{Code: "23505"}},
		{"permission", &pgconn.PgError{Code: "42501"}},
		{"query-canceled", &pgconn.PgError{Code: "57014"}},
		{"connection-failure", &pgconn.PgError{Code: "08006"}},
		{"completion-unknown", &pgconn.PgError{Code: "40003"}},
		{"internal", &pgconn.PgError{Code: "XX000"}},
		{"network", &net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}},
		{"ambiguous-eof", io.ErrUnexpectedEOF},
		{"sqlstate-text", errors.New("private SQLSTATE 40001 / 40P01")},
		{"context-canceled", context.Canceled},
		{"context-deadline", context.DeadlineExceeded},
	}
	for _, operation := range []string{"enqueue", "claim", "acknowledge"} {
		for _, failure := range failures {
			for _, stage := range notificationRetryStages(operation) {
				t.Run(operation+"/"+failure.name+"/"+stage, func(t *testing.T) {
					f, store, mock, observed, _ := newNotificationRetryFixture(t)
					f.expectAttempt(mock, operation, notificationRetryAttempt{stage: stage, failure: fmt.Errorf("driver: %w", failure.err)})
					f.invoke(t, context.Background(), store, operation, false, controlplane.TaskNotificationLease{}, ErrDatabaseUnavailable)
					assertObservedRetryTransactions(t, mock, observed, 1)
				})
			}
		}
	}
}

func TestTaskNotificationQueueRetryStopsAfterThreeAttempts(t *testing.T) {
	for _, operation := range []string{"enqueue", "claim", "acknowledge"} {
		for _, stage := range notificationRetryStages(operation) {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				f, store, mock, observed, entropy := newNotificationRetryFixture(t)
				for _, code := range []string{"40001", "40P01", "40001"} {
					f.expectAttempt(mock, operation, notificationRetryAttempt{stage: stage, failure: &pgconn.PgError{Code: code}})
				}
				f.invoke(t, context.Background(), store, operation, false, controlplane.TaskNotificationLease{}, ErrDatabaseUnavailable)
				assertObservedRetryTransactions(t, mock, observed, 3)
				wantReads := 0
				if operation == "claim" && (stage == "write" || stage == "commit") {
					wantReads = 1
				}
				entropy.assertReads(t, wantReads)
			})
		}
	}
}

func TestTaskNotificationQueueRetryStopsOnRollbackFailure(t *testing.T) {
	for _, operation := range []string{"enqueue", "claim", "acknowledge"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, stage := range []string{"tenant", "write"} {
				t.Run(operation+"/"+code+"/"+stage, func(t *testing.T) {
					f, store, mock, observed, _ := newNotificationRetryFixture(t)
					f.expectAttempt(mock, operation, notificationRetryAttempt{stage: stage, failure: &pgconn.PgError{Code: code}, rollbackFailure: io.ErrUnexpectedEOF})
					f.invoke(t, context.Background(), store, operation, false, controlplane.TaskNotificationLease{}, ErrDatabaseUnavailable)
					assertObservedRetryTransactions(t, mock, observed, 1)
				})
			}
		}
	}
}

func TestTaskNotificationQueueRetryPreservesDoneContextContract(t *testing.T) {
	for _, operation := range []string{"enqueue", "claim", "acknowledge"} {
		for _, mode := range []string{"nil", "canceled", "deadline"} {
			t.Run(operation+"/"+mode, func(t *testing.T) {
				f, store, mock, observed, entropy := newNotificationRetryFixture(t)
				var ctx context.Context
				if mode == "canceled" {
					canceled, cancel := context.WithCancel(context.Background())
					cancel()
					ctx = canceled
				} else if mode == "deadline" {
					expired, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
					defer cancel()
					ctx = expired
				}
				f.invoke(t, ctx, store, operation, false, controlplane.TaskNotificationLease{}, controlplane.ErrInvalidTaskNotificationQueue)
				assertObservedRetryTransactions(t, mock, observed, 0)
				entropy.assertReads(t, 0)
			})
		}
	}
}

func TestTaskNotificationQueueRetryStopsWhenCanceledAfterAbort(t *testing.T) {
	for _, operation := range []string{"enqueue", "claim", "acknowledge"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, stage := range []string{"tenant", "write", "commit"} {
				t.Run(operation+"/"+code+"/"+stage, func(t *testing.T) {
					f, store, mock, observed, _ := newNotificationRetryFixture(t)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					observed.afterClose = cancel
					f.expectAttempt(mock, operation, notificationRetryAttempt{stage: stage, failure: &pgconn.PgError{Code: code}})
					f.invoke(t, ctx, store, operation, false, controlplane.TaskNotificationLease{}, ErrDatabaseUnavailable)
					assertObservedRetryTransactions(t, mock, observed, 1)
				})
			}
		}
	}
}

func TestTaskNotificationQueueRetryEnqueueRechecksCanonicalNotice(t *testing.T) {
	for _, stage := range []string{"write", "commit"} {
		for _, final := range []string{"absent", "identical", "identity-conflict", "bytes-conflict", "checksum-conflict"} {
			t.Run(stage+"/"+final, func(t *testing.T) {
				f, store, mock, observed, entropy := newNotificationRetryFixture(t)
				f.expectAttempt(mock, "enqueue", notificationRetryAttempt{stage: stage, failure: &pgconn.PgError{Code: "40001"}})
				attempt := notificationRetryAttempt{}
				var want error
				if final != "absent" {
					encoded, checksum := notificationRetryEncoding(t, f.notice)
					identity := f.notice.Identity()
					switch final {
					case "identity-conflict":
						identity = f.otherNotice.Identity()
					case "bytes-conflict":
						encoded = append(encoded, '\n')
					case "checksum-conflict":
						checksum = "wrong-checksum"
					}
					attempt.existing = sqlmock.NewRows([]string{"notice_identity", "canonical_notice", "canonical_checksum"}).AddRow(identity, encoded, checksum)
					if final != "identical" {
						attempt.domainFailure = true
						want = controlplane.ErrTaskNotificationConflict
					}
				}
				f.expectAttempt(mock, "enqueue", attempt)
				f.invoke(t, context.Background(), store, "enqueue", final == "absent", controlplane.TaskNotificationLease{}, want)
				assertObservedRetryTransactions(t, mock, observed, 2)
				entropy.assertReads(t, 0)
			})
		}
	}
}

func TestTaskNotificationQueueRetryEnqueueExistingCommitMustBeKnown(t *testing.T) {
	for _, retryable := range []bool{false, true} {
		t.Run(fmt.Sprintf("retryable=%v", retryable), func(t *testing.T) {
			f, store, mock, observed, _ := newNotificationRetryFixture(t)
			encoded, checksum := notificationRetryEncoding(t, f.notice)
			rows := func() *sqlmock.Rows {
				return sqlmock.NewRows([]string{"notice_identity", "canonical_notice", "canonical_checksum"}).AddRow(f.notice.Identity(), encoded, checksum)
			}
			var failure error = io.ErrUnexpectedEOF
			want, begins := ErrDatabaseUnavailable, int32(1)
			if retryable {
				failure = &pgconn.PgError{Code: "40P01"}
				want, begins = nil, 2
			}
			f.expectAttempt(mock, "enqueue", notificationRetryAttempt{existing: rows(), stage: "commit", failure: failure})
			if retryable {
				f.expectAttempt(mock, "enqueue", notificationRetryAttempt{existing: rows()})
			}
			f.invoke(t, context.Background(), store, "enqueue", false, controlplane.TaskNotificationLease{}, want)
			assertObservedRetryTransactions(t, mock, observed, begins)
		})
	}
}

func TestTaskNotificationQueueRetryClaimReselectsNoticeAndDelivery(t *testing.T) {
	for _, stage := range []string{"write", "commit"} {
		for _, differentNotice := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/different-notice=%v", stage, differentNotice), func(t *testing.T) {
				f, store, mock, observed, entropy := newNotificationRetryFixture(t)
				f.expectAttempt(mock, "claim", notificationRetryAttempt{delivery: 2, stage: stage, failure: &pgconn.PgError{Code: "40P01"}})
				selected := f.notice
				if differentNotice {
					selected = f.otherNotice
				}
				f.expectAttempt(mock, "claim", notificationRetryAttempt{candidate: &selected, delivery: 7})
				f.invoke(t, context.Background(), store, "claim", true, f.lease(t, selected, 8), nil)
				assertObservedRetryTransactions(t, mock, observed, 2)
				entropy.assertReads(t, 1)
			})
		}
	}
}

func TestTaskNotificationQueueRetryClaimNoRowsClearsAbortedCapability(t *testing.T) {
	for _, stage := range []string{"write", "commit"} {
		for _, emptyCommit := range []string{"success", "ambiguous", "aborted-again"} {
			t.Run(stage+"/"+emptyCommit, func(t *testing.T) {
				f, store, mock, observed, entropy := newNotificationRetryFixture(t)
				f.expectAttempt(mock, "claim", notificationRetryAttempt{stage: stage, failure: &pgconn.PgError{Code: "40001"}, delivery: 4})
				attempt := notificationRetryAttempt{noRows: true}
				var want error
				begins := int32(2)
				if emptyCommit == "ambiguous" {
					attempt.stage, attempt.failure = "commit", io.ErrUnexpectedEOF
					want = ErrDatabaseUnavailable
				} else if emptyCommit == "aborted-again" {
					attempt.stage, attempt.failure = "commit", &pgconn.PgError{Code: "40P01"}
					begins = 3
				}
				f.expectAttempt(mock, "claim", attempt)
				if emptyCommit == "aborted-again" {
					f.expectAttempt(mock, "claim", notificationRetryAttempt{noRows: true})
				}
				f.invoke(t, context.Background(), store, "claim", false, controlplane.TaskNotificationLease{}, want)
				assertObservedRetryTransactions(t, mock, observed, begins)
				entropy.assertReads(t, 1)
			})
		}
	}
}

func TestTaskNotificationQueueRetryClaimEmptyDoesNotRequireEntropy(t *testing.T) {
	for _, final := range []string{"empty", "candidate", "ambiguous"} {
		t.Run(final, func(t *testing.T) {
			f, store, mock, observed, entropy := newNotificationRetryFixture(t)
			f.expectAttempt(mock, "claim", notificationRetryAttempt{noRows: true, stage: "commit", failure: &pgconn.PgError{Code: "40P01"}})
			attempt := notificationRetryAttempt{noRows: final != "candidate"}
			var want error
			var lease controlplane.TaskNotificationLease
			reads := 0
			if final == "candidate" {
				attempt.delivery = 9
				lease = f.lease(t, f.notice, 10)
				reads = 1
			} else {
				entropy.reader = bytes.NewReader(nil)
			}
			if final == "ambiguous" {
				attempt.stage, attempt.failure = "commit", io.ErrUnexpectedEOF
				want = ErrDatabaseUnavailable
			}
			f.expectAttempt(mock, "claim", attempt)
			f.invoke(t, context.Background(), store, "claim", final == "candidate", lease, want)
			assertObservedRetryTransactions(t, mock, observed, 2)
			entropy.assertReads(t, reads)
		})
	}
}

func TestTaskNotificationQueueRetryClaimEntropyFailureIsTerminal(t *testing.T) {
	for _, mode := range []string{"eof", "zeros", "short"} {
		t.Run(mode, func(t *testing.T) {
			f, store, mock, observed, entropy := newNotificationRetryFixture(t)
			data := []byte(nil)
			if mode == "zeros" {
				data = make([]byte, 32)
			} else if mode == "short" {
				data = bytes.Repeat([]byte{1}, 16)
			}
			entropy.reader = bytes.NewReader(data)
			f.expectAttempt(mock, "claim", notificationRetryAttempt{stage: "read", failure: &pgconn.PgError{Code: "40001"}})
			f.expectAttempt(mock, "claim", notificationRetryAttempt{domainFailure: true})
			f.invoke(t, context.Background(), store, "claim", false, controlplane.TaskNotificationLease{}, ErrDatabaseUnavailable)
			assertObservedRetryTransactions(t, mock, observed, 2)
		})
	}
}

func TestTaskNotificationQueueRetryClaimEntropySQLStateIsNotDatabaseAbort(t *testing.T) {
	for _, code := range []string{"40001", "40P01"} {
		for _, wrapped := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/wrapped=%v", code, wrapped), func(t *testing.T) {
				f, store, mock, observed, entropy := newNotificationRetryFixture(t)
				var failure error = &pgconn.PgError{Code: code}
				if wrapped {
					failure = fmt.Errorf("entropy wrapper: %w", failure)
				}
				entropy.reader = notificationRetryErrorReader{err: failure}
				f.expectAttempt(mock, "claim", notificationRetryAttempt{stage: "read", failure: &pgconn.PgError{Code: "40001"}})
				f.expectAttempt(mock, "claim", notificationRetryAttempt{domainFailure: true})
				f.invoke(t, context.Background(), store, "claim", false, controlplane.TaskNotificationLease{}, ErrDatabaseUnavailable)
				assertObservedRetryTransactions(t, mock, observed, 2)
				entropy.assertReads(t, 1)
			})
		}
	}
}

func TestTaskNotificationQueueRetryClaimRejectsFreshCorruption(t *testing.T) {
	for _, corruption := range []string{"negative-delivery", "exhausted-delivery", "canonical", "identity", "checksum", "plan", "revision", "head", "task-key", "task", "handler", "attempt", "available"} {
		t.Run(corruption, func(t *testing.T) {
			f, store, mock, observed, entropy := newNotificationRetryFixture(t)
			f.expectAttempt(mock, "claim", notificationRetryAttempt{stage: "commit", failure: &pgconn.PgError{Code: "40001"}})
			values := notificationRetryClaimValues(t, f.notice, 3)
			switch corruption {
			case "negative-delivery":
				values[11] = int64(-1)
			case "exhausted-delivery":
				values[11] = int64(10)
			case "canonical":
				values[9] = []byte("{}")
			case "identity":
				values[0] = f.otherNotice.Identity()
			case "checksum":
				values[10] = "wrong-checksum"
			case "plan":
				values[1] = "wrong-plan"
			case "revision":
				values[2] = int64(999)
			case "head":
				values[3] = "wrong-head"
			case "task-key":
				values[4] = "other-task"
			case "task":
				values[5] = "wrong-task"
			case "handler":
				values[6] = "wrong-handler"
			case "attempt":
				values[7] = int64(2)
			case "available":
				values[8] = f.notice.AvailableAt().Add(time.Millisecond)
			}
			f.expectAttempt(mock, "claim", notificationRetryAttempt{claimRows: sqlmock.NewRows(notificationRetryClaimColumns).AddRow(values...), domainFailure: true})
			f.invoke(t, context.Background(), store, "claim", false, controlplane.TaskNotificationLease{}, ErrCorruptRecord)
			assertObservedRetryTransactions(t, mock, observed, 2)
			entropy.assertReads(t, 1)
		})
	}
}

func TestTaskNotificationQueueRetryRowsAffectedFailuresAreTerminal(t *testing.T) {
	for _, operation := range []string{"claim", "acknowledge"} {
		for _, resultCase := range []string{"zero", "multiple", "error", "typed-abort-error"} {
			for _, afterAbort := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/after-abort=%v", operation, resultCase, afterAbort), func(t *testing.T) {
					f, store, mock, observed, _ := newNotificationRetryFixture(t)
					begins := int32(1)
					if afterAbort {
						f.expectAttempt(mock, operation, notificationRetryAttempt{stage: "commit", failure: &pgconn.PgError{Code: "40P01"}})
						begins = 2
					}
					var result driver.Result = sqlmock.NewResult(0, 0)
					want := ErrDatabaseUnavailable
					switch resultCase {
					case "multiple":
						result = sqlmock.NewResult(0, 2)
					case "error":
						result = sqlmock.NewErrorResult(io.ErrUnexpectedEOF)
					case "typed-abort-error":
						result = sqlmock.NewErrorResult(&pgconn.PgError{Code: "40001"})
					}
					if operation == "acknowledge" && (resultCase == "zero" || resultCase == "multiple") {
						want = controlplane.ErrTaskNotificationLeaseMismatch
					}
					f.expectAttempt(mock, operation, notificationRetryAttempt{result: result})
					f.invoke(t, context.Background(), store, operation, false, controlplane.TaskNotificationLease{}, want)
					assertObservedRetryTransactions(t, mock, observed, begins)
				})
			}
		}
	}
}

func TestTaskNotificationQueueRetryCanCommitThirdAttempt(t *testing.T) {
	for _, operation := range []string{"enqueue", "claim", "acknowledge"} {
		t.Run(operation, func(t *testing.T) {
			f, store, mock, observed, entropy := newNotificationRetryFixture(t)
			f.expectAttempt(mock, operation, notificationRetryAttempt{stage: "write", failure: &pgconn.PgError{Code: "40001"}})
			f.expectAttempt(mock, operation, notificationRetryAttempt{stage: "commit", failure: &pgconn.PgError{Code: "40P01"}})
			f.expectAttempt(mock, operation, notificationRetryAttempt{})
			f.invoke(t, context.Background(), store, operation, true, f.lease(t, f.notice, 1), nil)
			assertObservedRetryTransactions(t, mock, observed, 3)
			reads := 0
			if operation == "claim" {
				reads = 1
			}
			entropy.assertReads(t, reads)
		})
	}
}

func TestTaskNotificationQueueRetryAmbiguousFailureAfterAbortIsTerminal(t *testing.T) {
	for _, operation := range []string{"enqueue", "claim", "acknowledge"} {
		for _, stage := range []string{"write", "commit"} {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				f, store, mock, observed, entropy := newNotificationRetryFixture(t)
				f.expectAttempt(mock, operation, notificationRetryAttempt{stage: "commit", failure: &pgconn.PgError{Code: "40001"}})
				f.expectAttempt(mock, operation, notificationRetryAttempt{stage: stage, failure: io.ErrUnexpectedEOF})
				f.invoke(t, context.Background(), store, operation, false, controlplane.TaskNotificationLease{}, ErrDatabaseUnavailable)
				assertObservedRetryTransactions(t, mock, observed, 2)
				reads := 0
				if operation == "claim" {
					reads = 1
				}
				entropy.assertReads(t, reads)
			})
		}
	}
}

func TestTaskNotificationQueueRetryKnownCommitSurvivesLaterCancellation(t *testing.T) {
	for _, operation := range []string{"enqueue", "claim", "acknowledge"} {
		t.Run(operation, func(t *testing.T) {
			f, store, mock, observed, _ := newNotificationRetryFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			observed.afterClose = cancel
			f.expectAttempt(mock, operation, notificationRetryAttempt{})
			f.invoke(t, ctx, store, operation, true, f.lease(t, f.notice, 1), nil)
			assertObservedRetryTransactions(t, mock, observed, 1)
		})
	}
}

func TestTaskNotificationQueueRetryClaimTokenIsLocalToOneOperation(t *testing.T) {
	f, store, mock, observed, entropy := newNotificationRetryFixture(t)
	first := bytes.Repeat([]byte{0x5a}, 32)
	second := bytes.Repeat([]byte{0x6b}, 32)
	entropy.reader = bytes.NewReader(append(first, second...))
	f.expectAttempt(mock, "claim", notificationRetryAttempt{stage: "commit", failure: &pgconn.PgError{Code: "40001"}})
	f.expectAttempt(mock, "claim", notificationRetryAttempt{})
	f.invoke(t, context.Background(), store, "claim", true, f.lease(t, f.notice, 1), nil)
	entropy.assertReads(t, 1)
	f.token = hex.EncodeToString(second)
	f.at = f.at.Add(f.duration)
	f.expectAttempt(mock, "claim", notificationRetryAttempt{delivery: 1})
	f.invoke(t, context.Background(), store, "claim", true, f.lease(t, f.notice, 2), nil)
	assertObservedRetryTransactions(t, mock, observed, 3)
	entropy.assertReads(t, 2)
}

func TestTaskNotificationQueueRetryAcknowledgeRejectsOutsideLeaseWindow(t *testing.T) {
	for _, when := range []string{"zero", "before", "after"} {
		t.Run(when, func(t *testing.T) {
			f, store, mock, observed, entropy := newNotificationRetryFixture(t)
			lease := f.lease(t, f.notice, 3)
			var at time.Time
			if when == "before" {
				at = lease.LeasedAt().Add(-time.Millisecond)
			} else if when == "after" {
				at = lease.ExpiresAt().Add(time.Millisecond)
			}
			if err := store.AcknowledgeTaskNotification(context.Background(), lease, at); err != controlplane.ErrInvalidTaskNotificationQueue {
				t.Errorf("acknowledge outside lease window = %v, want invalid queue", err)
			}
			assertObservedRetryTransactions(t, mock, observed, 0)
			entropy.assertReads(t, 0)
		})
	}
}

// Full predicates keep retry tests sensitive to lost scope, availability and lease fences.
const notificationRetryInsertSQL = `INSERT INTO open_trestle_task_notifications
(tenant_id, repository_id, review_run_id, scope_identity, notice_identity, plan_identity, task_state_revision, task_state_event_identity, task_key, task_identity, handler_identity, attempt, available_at, canonical_notice, canonical_checksum)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`

const notificationRetryReadSQL = `SELECT notice_identity, canonical_notice, canonical_checksum
FROM open_trestle_task_notifications
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3 AND notice_identity = $4`

const notificationRetryClaimSQL = `SELECT notice_identity, plan_identity, task_state_revision, task_state_event_identity, task_key, task_identity, handler_identity, attempt, available_at, canonical_notice, canonical_checksum, delivery_count
FROM open_trestle_task_notifications
WHERE tenant_id = $1 AND repository_id = $2 AND review_run_id = $3
  AND acknowledged_at IS NULL AND delivery_count < 10 AND available_at <= $4
  AND (lease_expires_at IS NULL OR lease_expires_at <= $4)
ORDER BY available_at ASC, notice_identity ASC
FOR UPDATE SKIP LOCKED LIMIT 1`

const notificationRetryClaimUpdateSQL = `UPDATE open_trestle_task_notifications
SET delivery_count = delivery_count + 1, lease_worker_identity = $1, lease_token_identity = $2, leased_at = $3, lease_expires_at = $4
WHERE tenant_id = $5 AND repository_id = $6 AND review_run_id = $7 AND notice_identity = $8 AND delivery_count = $9`

const notificationRetryAckSQL = `UPDATE open_trestle_task_notifications
SET acknowledged_at = $1, lease_worker_identity = NULL, lease_token_identity = NULL, leased_at = NULL, lease_expires_at = NULL
WHERE tenant_id = $2 AND repository_id = $3 AND review_run_id = $4 AND notice_identity = $5
  AND acknowledged_at IS NULL AND delivery_count = $6 AND lease_worker_identity = $7
  AND lease_token_identity = $8 AND leased_at = $9 AND lease_expires_at = $10 AND lease_expires_at >= $1`

var notificationRetryClaimColumns = []string{"notice_identity", "plan_identity", "task_state_revision", "task_state_event_identity", "task_key", "task_identity", "handler_identity", "attempt", "available_at", "canonical_notice", "canonical_checksum", "delivery_count"}

type notificationRetryFixture struct {
	t           *testing.T
	notice      controlplane.TaskNotification
	otherNotice controlplane.TaskNotification
	at          time.Time
	duration    time.Duration
	worker      string
	token       string
}

type notificationRetryAttempt struct {
	stage           string
	failure         error
	rollbackFailure error
	existing        *sqlmock.Rows
	candidate       *controlplane.TaskNotification
	delivery        int64
	noRows          bool
	claimRows       *sqlmock.Rows
	domainFailure   bool
	result          driver.Result
}

type notificationRetryEntropy struct {
	reader io.Reader
	reads  int
}

type notificationRetryErrorReader struct{ err error }

func (r notificationRetryErrorReader) Read([]byte) (int, error) { return 0, r.err }

func (r *notificationRetryEntropy) Read(p []byte) (int, error) {
	r.reads++
	return r.reader.Read(p)
}

func (r *notificationRetryEntropy) assertReads(t *testing.T, want int) {
	t.Helper()
	if r.reads != want {
		t.Errorf("entropy reads = %d, want %d", r.reads, want)
	}
}

func newNotificationRetryFixture(t *testing.T) (notificationRetryFixture, *Store, sqlmock.Sqlmock, *retryTransactionObserver, *notificationRetryEntropy) {
	t.Helper()
	plan, _ := postgresRunFixture(t)
	makeNotice := func(at time.Time) controlplane.TaskNotification {
		journal := controlplane.NewMemoryRunJournal()
		coordinator, err := controlplane.NewCoordinator(journal)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := coordinator.Open(context.Background(), plan, at); err != nil {
			t.Fatal(err)
		}
		state, err := coordinator.Advance(context.Background(), plan, at.Add(time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		runtime, ok := state.Task("source")
		if !ok {
			t.Fatal("fixture task missing")
		}
		notice, err := controlplane.NewTaskNotification(state, runtime, at.Add(time.Millisecond))
		if err != nil {
			t.Fatal(err)
		}
		return notice
	}
	data := bytes.Repeat([]byte{0x5a}, 32)
	f := notificationRetryFixture{
		t: t, notice: makeNotice(time.UnixMilli(1000)), otherNotice: makeNotice(time.UnixMilli(2000)),
		at:       time.UnixMilli(3000).Add(123456 * time.Nanosecond).In(time.FixedZone("caller", 3600)),
		duration: 2500 * time.Millisecond, worker: "worker-a", token: hex.EncodeToString(data),
	}
	if f.notice.Identity() == f.otherNotice.Identity() {
		t.Fatal("fixture needs distinct selectable notices")
	}
	database, mock, observed := newObservedRetryDatabase(t)
	store, err := New(database)
	if err != nil {
		t.Fatal(err)
	}
	// Only one token is available per operation; an empty claim must not read it.
	entropy := &notificationRetryEntropy{reader: bytes.NewReader(data)}
	store.notificationRandom = entropy
	return f, store, mock, observed, entropy
}

func notificationRetryEncoding(t *testing.T, notice controlplane.TaskNotification) ([]byte, string) {
	t.Helper()
	encoded, err := controlplane.EncodeTaskNotification(notice)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return encoded, hex.EncodeToString(digest[:])
}

func notificationRetryClaimValues(t *testing.T, notice controlplane.TaskNotification, delivery int64) []driver.Value {
	t.Helper()
	encoded, checksum := notificationRetryEncoding(t, notice)
	return []driver.Value{notice.Identity(), notice.PlanIdentity(), int64(notice.TaskStateRevision()), notice.TaskStateEventIdentity(), notice.TaskKey(), notice.TaskIdentity(), notice.HandlerIdentity(), int64(notice.Attempt()), notice.AvailableAt(), encoded, checksum, delivery}
}

func (f notificationRetryFixture) lease(t *testing.T, notice controlplane.TaskNotification, delivery uint8) controlplane.TaskNotificationLease {
	t.Helper()
	at := time.UnixMilli(f.at.UnixMilli()).UTC()
	lease, err := controlplane.NewTaskNotificationLease(notice, f.worker, f.token, delivery, at, at.Add(f.duration))
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func (f notificationRetryFixture) invoke(t *testing.T, ctx context.Context, store *Store, operation string, wantSuccess bool, wantLease controlplane.TaskNotificationLease, wantError error) {
	t.Helper()
	switch operation {
	case "enqueue":
		created, err := store.EnqueueTaskNotification(ctx, f.notice)
		if err != wantError || created != wantSuccess {
			t.Errorf("enqueue = (%v, %v), want (%v, %v)", created, err, wantSuccess, wantError)
		}
	case "claim":
		lease, found, err := store.ClaimTaskNotification(ctx, f.notice.Scope(), f.worker, f.at, f.duration)
		if err != wantError || found != wantSuccess || !reflect.DeepEqual(lease, wantLease) {
			t.Errorf("claim found=%v error=%v lease-matches=%v, want found=%v error=%v", found, err, reflect.DeepEqual(lease, wantLease), wantSuccess, wantError)
		}
	case "acknowledge":
		if err := store.AcknowledgeTaskNotification(ctx, f.lease(t, f.notice, 3), f.at.Add(time.Second)); err != wantError {
			t.Errorf("acknowledge = %v, want %v", err, wantError)
		}
	default:
		t.Fatalf("unknown operation %q", operation)
	}
}

func notificationRetryStages(operation string) []string {
	stages := []string{"begin", "tenant"}
	if operation == "enqueue" {
		stages = append(stages, "lock", "scope-insert", "scope-read")
	}
	if operation != "acknowledge" {
		stages = append(stages, "read")
	}
	return append(stages, "write", "commit")
}

func (f notificationRetryFixture) expectAttempt(mock sqlmock.Sqlmock, operation string, a notificationRetryAttempt) {
	f.t.Helper()
	scope := f.notice.Scope()
	at := time.UnixMilli(f.at.UnixMilli()).UTC()
	rollback := func() {
		expected := mock.ExpectRollback()
		if a.rollbackFailure != nil {
			expected.WillReturnError(a.rollbackFailure)
		}
	}
	begin := mock.ExpectBegin()
	if a.stage == "begin" {
		begin.WillReturnError(a.failure)
		return
	}
	exec := func(stage, statement string, args ...driver.Value) bool {
		expected := mock.ExpectExec(regexp.QuoteMeta(statement)).WithArgs(args...)
		if a.stage == stage {
			expected.WillReturnError(a.failure)
			rollback()
			return false
		}
		if stage == "write" && a.result != nil {
			expected.WillReturnResult(a.result)
			rollback()
			return false
		}
		expected.WillReturnResult(sqlmock.NewResult(1, 1))
		return true
	}
	query := func(stage, statement string, rows *sqlmock.Rows, args ...driver.Value) bool {
		expected := mock.ExpectQuery(regexp.QuoteMeta(statement)).WithArgs(args...)
		if a.stage == stage {
			expected.WillReturnError(a.failure)
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
	if !exec("tenant", "SELECT set_config('open_trestle.tenant_id', $1, true)", scope.TenantID()) {
		return
	}
	switch operation {
	case "enqueue":
		if !exec("lock", "SELECT pg_advisory_xact_lock(hashtextextended($1, 0))", "task-notification:"+f.notice.Identity()) ||
			!exec("scope-insert", "INSERT INTO open_trestle_review_scopes", scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity()) ||
			!query("scope-read", "SELECT scope_identity", sqlmock.NewRows([]string{"scope_identity"}).AddRow(scope.Identity()), scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()) ||
			!query("read", notificationRetryReadSQL, a.existing, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), f.notice.Identity()) {
			return
		}
		if a.domainFailure {
			rollback()
			return
		}
		if a.existing == nil {
			n := f.notice
			encoded, checksum := notificationRetryEncoding(f.t, n)
			if !exec("write", notificationRetryInsertSQL, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), n.Identity(), n.PlanIdentity(), n.TaskStateRevision(), n.TaskStateEventIdentity(), n.TaskKey(), n.TaskIdentity(), n.HandlerIdentity(), n.Attempt(), n.AvailableAt(), encoded, checksum) {
				return
			}
		}
	case "claim":
		n := f.notice
		if a.candidate != nil {
			n = *a.candidate
		}
		rows := a.claimRows
		if rows == nil && !a.noRows {
			rows = sqlmock.NewRows(notificationRetryClaimColumns).AddRow(notificationRetryClaimValues(f.t, n, a.delivery)...)
		}
		if !query("read", notificationRetryClaimSQL, rows, scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), at) {
			return
		}
		if a.domainFailure {
			rollback()
			return
		}
		if !a.noRows {
			lease := f.lease(f.t, n, uint8(a.delivery+1))
			if !exec("write", notificationRetryClaimUpdateSQL, f.worker, lease.TokenIdentity(), at, at.Add(f.duration), scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), n.Identity(), a.delivery) {
				return
			}
		}
	case "acknowledge":
		lease := f.lease(f.t, f.notice, 3)
		if !exec("write", notificationRetryAckSQL, at.Add(time.Second), scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), lease.Notification().Identity(), lease.Delivery(), lease.WorkerIdentity(), lease.TokenIdentity(), lease.LeasedAt(), lease.ExpiresAt()) {
			return
		}
	default:
		f.t.Fatalf("unknown operation %q", operation)
	}
	committed := mock.ExpectCommit()
	if a.stage == "commit" {
		committed.WillReturnError(a.failure)
	}
}
