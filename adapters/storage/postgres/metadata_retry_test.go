package postgres

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/webhook"
	"github.com/jackc/pgx/v5/pgconn"
)

func metadataRetryAbort(code string, wrapped bool) error {
	var err error = &pgconn.PgError{Code: code, Message: "private SQL detail"}
	if wrapped {
		err = fmt.Errorf("driver wrapper: %w", err)
	}
	return err
}

func TestMetadataRetryKnownAborts(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, code := range []string{"40001", "40P01"} {
			for _, wrapped := range []bool{false, true} {
				for _, stage := range metadataRetryStages(operation) {
					t.Run(fmt.Sprintf("%s/%s/wrapped=%v/%s", operation, code, wrapped, stage), func(t *testing.T) {
						f := newMetadataRetryFixture(t, operation)
						f.expectPreRead(metadataRetryAttempt{})
						f.expectAttempt(metadataRetryAttempt{stage: stage, failure: metadataRetryAbort(code, wrapped)})
						f.expectAttempt(metadataRetryAttempt{})
						f.check(context.Background(), true, nil, 2, 1, 1, 0, f.stored)
					})
				}
			}
		}
	}
}

func TestMetadataRetryBoundedAtThreeAttempts(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, stage := range metadataRetryStages(operation) {
			for _, succeeds := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/third-succeeds=%v", operation, stage, succeeds), func(t *testing.T) {
					f := newMetadataRetryFixture(t, operation)
					f.expectPreRead(metadataRetryAttempt{})
					f.expectAttempt(metadataRetryAttempt{stage: stage, failure: metadataRetryAbort("40001", false)})
					f.expectAttempt(metadataRetryAttempt{stage: stage, failure: metadataRetryAbort("40P01", true)})
					var want error = ErrDatabaseUnavailable
					if succeeds {
						f.expectAttempt(metadataRetryAttempt{})
						want = nil
					} else {
						f.expectAttempt(metadataRetryAttempt{stage: stage, failure: metadataRetryAbort("40001", true)})
					}
					f.check(context.Background(), succeeds, want, 3, 1, 1, 0, f.stored)
				})
			}
		}
	}
}

type metadataSQLStateOnly struct{}

func (metadataSQLStateOnly) Error() string    { return "private SQLSTATE 40001" }
func (metadataSQLStateOnly) SQLState() string { return "40001" }

func TestMetadataRetryNeverReplaysUncertainFailures(t *testing.T) {
	failures := []struct {
		name string
		err  error
	}{
		{"unique", &pgconn.PgError{Code: "23505"}},
		{"permission", &pgconn.PgError{Code: "42501"}},
		{"query-canceled", &pgconn.PgError{Code: "57014"}},
		{"connection", &pgconn.PgError{Code: "08006"}},
		{"completion-unknown", &pgconn.PgError{Code: "40003"}},
		{"internal", &pgconn.PgError{Code: "XX000"}},
		{"network", &net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}},
		{"eof", io.ErrUnexpectedEOF},
		{"text-only", errors.New("private SQLSTATE 40001 / 40P01")},
		{"interface-only", metadataSQLStateOnly{}},
		{"context-canceled", context.Canceled},
		{"context-deadline", context.DeadlineExceeded},
	}
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, failure := range failures {
			for _, stage := range metadataRetryStages(operation) {
				t.Run(operation+"/"+failure.name+"/"+stage, func(t *testing.T) {
					f := newMetadataRetryFixture(t, operation)
					f.expectPreRead(metadataRetryAttempt{})
					f.expectAttempt(metadataRetryAttempt{stage: stage, failure: fmt.Errorf("driver: %w", failure.err)})
					f.check(context.Background(), false, ErrDatabaseUnavailable, 1, 1, 1, 0, webhook.StoredDelivery{})
				})
			}
		}
	}
}

func TestMetadataRetryStopsOnRollbackFailure(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, stage := range []string{"tenant", "lock", "mapping", "insert"} {
			for _, code := range []string{"40001", "40P01"} {
				for _, rollback := range []string{"network", "40001", "40P01"} {
					t.Run(operation+"/"+stage+"/"+code+"/"+rollback, func(t *testing.T) {
						f := newMetadataRetryFixture(t, operation)
						var failure error = io.ErrUnexpectedEOF
						if rollback != "network" {
							failure = metadataRetryAbort(rollback, true)
						}
						f.expectPreRead(metadataRetryAttempt{})
						f.expectAttempt(metadataRetryAttempt{stage: stage, failure: metadataRetryAbort(code, true), rollback: failure})
						f.check(context.Background(), false, ErrDatabaseUnavailable, 1, 1, 1, 0, webhook.StoredDelivery{})
					})
				}
			}
		}
	}
}

func TestMetadataRetryPreReadRemainsSeparateAndTerminal(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, stage := range []string{"begin", "tenant", "mapping", "commit"} {
			for _, code := range []string{"40001", "40P01", "08006"} {
				t.Run(operation+"/"+stage+"/"+code, func(t *testing.T) {
					f := newMetadataRetryFixture(t, operation)
					f.expectPreRead(metadataRetryAttempt{stage: stage, failure: metadataRetryAbort(code, true)})
					f.check(context.Background(), false, ErrDatabaseUnavailable, 0, 1, 0, 0, webhook.StoredDelivery{})
				})
			}
		}
	}
}

type metadataNilContext struct{ context.Context }

func TestMetadataRetryPreservesInitialContextErrors(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, kind := range []string{"nil", "typed-nil", "canceled", "deadline"} {
			t.Run(operation+"/"+kind, func(t *testing.T) {
				f := newMetadataRetryFixture(t, operation)
				var ctx context.Context
				switch kind {
				case "typed-nil":
					var typedNil *metadataNilContext
					ctx = typedNil
				case "canceled":
					canceled, cancel := context.WithCancel(context.Background())
					cancel()
					ctx = canceled
				case "deadline":
					deadline, cancel := context.WithDeadline(context.Background(), time.Unix(1, 0))
					defer cancel()
					ctx = deadline
				}
				var want error = diagnostics.ErrInvalidStoreContext
				if operation == "webhook" {
					want = webhook.ErrInvalidInboxContext
				}
				if kind == "canceled" || kind == "deadline" {
					want = diagnostics.ErrStoreContextDone
					if operation == "webhook" {
						want = webhook.ErrInboxContextDone
					}
				}
				f.check(ctx, false, want, 0, 0, 0, 0, webhook.StoredDelivery{})
			})
		}
	}
}

func TestMetadataRetryCancellationAfterAbortStaysClosed(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, stage := range []string{"tenant", "insert", "commit"} {
			for _, code := range []string{"40001", "40P01"} {
				t.Run(operation+"/"+stage+"/"+code, func(t *testing.T) {
					f := newMetadataRetryFixture(t, operation)
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					f.observed.afterClose = func() {
						if f.observed.begins.Load() > 0 {
							cancel()
						}
					}
					f.expectPreRead(metadataRetryAttempt{})
					f.expectAttempt(metadataRetryAttempt{stage: stage, failure: metadataRetryAbort(code, true)})
					f.check(ctx, false, ErrDatabaseUnavailable, 1, 1, 1, 0, webhook.StoredDelivery{})
				})
			}
		}
	}
}

func TestMetadataRetryDoesNotReplayArtifactFailures(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, phase := range []string{"put", "initial-get", "concurrent-get", "retried-get"} {
			for _, code := range []string{"40001", "40P01", "network", "corruption"} {
				t.Run(operation+"/"+phase+"/"+code, func(t *testing.T) {
					f := newMetadataRetryFixture(t, operation)
					var failure error = metadataRetryAbort(code, true)
					if code == "network" {
						failure = io.ErrUnexpectedEOF
					} else if code == "corruption" {
						failure = artifact.ErrCorruptArtifact
					}
					var attempts int32
					puts, gets := 1, 0
					if phase == "put" {
						f.artifacts.putError = failure
						f.expectPreRead(metadataRetryAttempt{})
					} else {
						f.artifacts.getError = failure
						gets = 1
						if phase == "initial-get" {
							puts = 0
							f.expectPreRead(metadataRetryAttempt{rows: f.rows(f.value, f.stored)})
						} else {
							f.expectPreRead(metadataRetryAttempt{})
							if phase == "retried-get" {
								f.expectAttempt(metadataRetryAttempt{stage: "commit", failure: metadataRetryAbort("40001", false)})
								attempts++
							}
							f.expectAttempt(metadataRetryAttempt{rows: f.rows(f.value, f.stored)})
							attempts++
						}
					}
					f.check(context.Background(), false, failure, attempts, 1, puts, gets, webhook.StoredDelivery{})
				})
			}
		}
	}
}

func TestMetadataRetryRechecksScopeAndMappingCorruption(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, stage := range []string{"initial", "insert", "commit"} {
			for _, corrupt := range []string{"scope", "mapping"} {
				t.Run(operation+"/"+stage+"/"+corrupt, func(t *testing.T) {
					f := newMetadataRetryFixture(t, operation)
					f.expectPreRead(metadataRetryAttempt{})
					var attempts int32 = 1
					if stage != "initial" {
						f.expectAttempt(metadataRetryAttempt{stage: stage, failure: metadataRetryAbort("40001", true)})
						attempts++
					}
					a := metadataRetryAttempt{scopeCorrupt: corrupt == "scope", domainError: ErrCorruptRecord}
					if corrupt == "mapping" {
						if operation == "diagnostic" {
							a.rows = f.diagnosticRows(f.set.Identity(), "not-a-digest", f.value.ExpiresAt())
						} else {
							a.rows = f.webhookRows(f.stored, f.value, f.stored.Receipt().AcceptedAt())
						}
					}
					f.expectAttempt(a)
					f.check(context.Background(), false, ErrCorruptRecord, attempts, 1, 1, 0, webhook.StoredDelivery{})
				})
			}
		}
	}
}

func TestMetadataRetryFreshCapacityAndExpiryClockKeepArtifactFixed(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, final := range []string{"insert", "duplicate", "capacity"} {
			if operation == "diagnostic" && final == "capacity" {
				continue
			}
			t.Run(operation+"/"+final, func(t *testing.T) {
				f := newMetadataRetryFixture(t, operation)
				later := f.at.Add(time.Second)
				f.observed.afterClose = func() {
					if f.observed.begins.Load() > 0 {
						f.clock.at = later
					}
				}
				f.expectPreRead(metadataRetryAttempt{})
				f.expectAttempt(metadataRetryAttempt{stage: "commit", failure: metadataRetryAbort("40001", false)})
				a := metadataRetryAttempt{readAt: later}
				gets := 0
				var want error
				if final == "duplicate" {
					a.rows = f.rows(f.value, f.stored)
					gets = 1
				} else if final == "capacity" {
					a.count = maximumWebhookEntries
					want = webhook.ErrInboxStoreCapacity
				}
				f.expectAttempt(a)
				f.check(context.Background(), final == "insert", want, 2, 1, 1, gets, f.stored)
				if gets == 1 && (len(f.artifacts.getTimes) != 1 || !f.artifacts.getTimes[0].Equal(later)) {
					t.Error("duplicate validation reused stale expiry time")
				}
			})
		}
	}
}

func TestMetadataRetryResetsInsertedAndCapturedMapping(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, last := range []string{"absent", "duplicate", "unknown-insert", "unknown-duplicate"} {
			t.Run(operation+"/"+last, func(t *testing.T) {
				f := newMetadataRetryFixture(t, operation)
				old, original := f.originalMapping(false)
				f.seed(old)
				f.expectPreRead(metadataRetryAttempt{})
				f.expectAttempt(metadataRetryAttempt{stage: "commit", failure: metadataRetryAbort("40001", false)})
				f.expectAttempt(metadataRetryAttempt{rows: f.rows(old, original), stage: "commit", failure: metadataRetryAbort("40P01", true)})
				a := metadataRetryAttempt{}
				if last == "duplicate" || last == "unknown-duplicate" {
					a.rows = f.rows(f.value, f.stored)
				}
				var want error
				gets := 0
				if strings.HasPrefix(last, "unknown-") {
					a.stage, a.failure = "commit", io.ErrUnexpectedEOF
					want = ErrDatabaseUnavailable
				} else if last == "duplicate" {
					gets = 1
				}
				f.expectAttempt(a)
				f.check(context.Background(), last == "absent", want, 3, 1, 1, gets, f.stored)
				if gets == 1 && (len(f.artifacts.getIDs) != 1 || f.artifacts.getIDs[0] != f.value.Identity()) {
					t.Error("validated a mapping captured by an aborted transaction")
				}
			})
		}
	}
}

func (f *metadataRetryFixture) originalMapping(changedBody bool) (artifact.Artifact, webhook.StoredDelivery) {
	f.t.Helper()
	if f.operation == "diagnostic" {
		value, err := f.diagnostic.newDiagnosticArtifact(f.set, f.at.Add(-time.Millisecond))
		if err != nil {
			f.t.Fatal(err)
		}
		return value, webhook.StoredDelivery{}
	}
	body := f.delivery.Payload()
	if changedBody {
		body = []byte(`{"action":"opened","number":2}`)
	}
	delivery, err := webhook.NewVerifiedDelivery(f.delivery.Scope(), f.delivery.Source(), f.delivery.DeliveryID(), f.delivery.EventType(), f.delivery.Action(), f.delivery.VerifierIdentity(), body, f.at.Add(-time.Second))
	if err != nil {
		f.t.Fatal(err)
	}
	stored, err := webhook.NewStoredDelivery(delivery, f.at.Add(-time.Second+time.Millisecond))
	if err != nil {
		f.t.Fatal(err)
	}
	value, _, err := f.webhook.newWebhookArtifact(stored)
	if err != nil {
		f.t.Fatal(err)
	}
	if value.Identity() == f.value.Identity() || stored.Delivery().DeduplicationKey() != f.delivery.DeduplicationKey() {
		f.t.Fatal("original mapping fixture must differ from speculative artifact for the same key")
	}
	return value, stored
}

func TestMetadataRetryFreshDuplicateValidatesOriginalAfterClose(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, stage := range []string{"initial", "concurrent", "insert", "commit"} {
			for _, state := range []string{"valid", "missing", "expired", "expiry-mismatch", "payload-corrupt", "conflict"} {
				t.Run(operation+"/"+stage+"/"+state, func(t *testing.T) {
					f := newMetadataRetryFixture(t, operation)
					value, original := f.originalMapping(state == "conflict")
					var want error
					gets := 1
					if state == "payload-corrupt" {
						var err error
						value, err = artifact.New(value.Scope(), value.Kind(), value.MediaType(), value.Classification(), value.Origin(), value.Protection(), value.Provenance(), []byte(`{"broken":true}`), value.CreatedAt(), value.ExpiresAt())
						if err != nil {
							t.Fatal(err)
						}
						want = ErrCorruptRecord
					}
					if state != "missing" {
						f.seed(value)
					} else {
						want = artifact.ErrArtifactNotFound
					}
					rows := f.rows(value, original)
					domain := error(nil)
					if state == "expiry-mismatch" {
						if operation == "diagnostic" {
							rows = f.diagnosticRows(f.set.Identity(), value.Identity(), value.ExpiresAt().Add(time.Second))
						} else {
							rows = f.webhookRows(original, value, value.ExpiresAt().Add(time.Second))
						}
						want = ErrCorruptRecord
					} else if state == "conflict" {
						want = webhook.ErrDeliveryConflict
						if operation == "diagnostic" {
							rows = f.diagnosticRows(strings.Repeat("f", 64), value.Identity(), value.ExpiresAt())
							want, domain, gets = diagnostics.ErrSetConflict, diagnostics.ErrSetConflict, 0
						}
					} else if state == "expired" {
						// Expiry advances after the speculative Put, not its immutable creation time.
						if stage == "initial" {
							f.clock.at = value.ExpiresAt()
						} else {
							f.artifacts.afterPut = func() { f.clock.at = value.ExpiresAt() }
						}
						want = artifact.ErrArtifactExpired
						if operation == "webhook" {
							want, gets = webhook.ErrDeliveryExpired, 0
						}
					}
					var attempts int32
					puts := 0
					if stage == "initial" {
						f.expectPreRead(metadataRetryAttempt{rows: rows})
					} else {
						puts, attempts = 1, 1
						f.expectPreRead(metadataRetryAttempt{})
						if stage != "concurrent" {
							readAt := f.at
							if state == "expired" {
								readAt = value.ExpiresAt()
							}
							f.expectAttempt(metadataRetryAttempt{stage: stage, failure: metadataRetryAbort("40001", true), readAt: readAt})
							attempts++
						}
						f.expectAttempt(metadataRetryAttempt{rows: rows, domainError: domain})
					}
					f.check(context.Background(), false, want, attempts, 1, puts, gets, original)
					if gets == 1 && (len(f.artifacts.getIDs) != 1 || f.artifacts.getIDs[0] != value.Identity()) {
						t.Error("did not validate the captured original artifact exactly once")
					}
				})
			}
		}
	}
}

func TestMetadataRetryUnknownDuplicateCommitDoesNotReadArtifact(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		for _, stage := range []string{"initial", "concurrent", "retried"} {
			t.Run(operation+"/"+stage, func(t *testing.T) {
				f := newMetadataRetryFixture(t, operation)
				value, original := f.originalMapping(false)
				f.seed(value)
				a := metadataRetryAttempt{rows: f.rows(value, original), stage: "commit", failure: io.ErrUnexpectedEOF}
				var attempts int32
				puts := 0
				if stage == "initial" {
					f.expectPreRead(a)
				} else {
					puts, attempts = 1, 1
					f.expectPreRead(metadataRetryAttempt{})
					if stage == "retried" {
						f.expectAttempt(metadataRetryAttempt{stage: "commit", failure: metadataRetryAbort("40001", false)})
						attempts++
					}
					f.expectAttempt(a)
				}
				f.check(context.Background(), false, ErrDatabaseUnavailable, attempts, 1, puts, 0, webhook.StoredDelivery{})
			})
		}
	}
}

func TestMetadataRetryPreReadCorruptMappingNeverWritesArtifact(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		t.Run(operation, func(t *testing.T) {
			f := newMetadataRetryFixture(t, operation)
			var rows *sqlmock.Rows
			if operation == "diagnostic" {
				rows = f.diagnosticRows("bad-identity", f.value.Identity(), f.value.ExpiresAt())
			} else {
				rows = f.webhookRows(f.stored, f.value, f.at)
			}
			f.expectPreRead(metadataRetryAttempt{rows: rows, domainError: ErrCorruptRecord})
			f.check(context.Background(), false, ErrCorruptRecord, 0, 1, 0, 0, webhook.StoredDelivery{})
		})
	}
}

func TestMetadataRetryCancellationBetweenArtifactAndMetadataKeepsExistingError(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		t.Run(operation, func(t *testing.T) {
			f := newMetadataRetryFixture(t, operation)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			f.artifacts.afterPut = cancel
			f.expectPreRead(metadataRetryAttempt{})
			f.check(ctx, false, ErrInvalidDatabase, 0, 1, 1, 0, webhook.StoredDelivery{})
		})
	}
}

func TestMetadataRetryExpiryIsReevaluatedAfterAbortedAttempt(t *testing.T) {
	for _, operation := range []string{"diagnostic", "webhook"} {
		t.Run(operation, func(t *testing.T) {
			f := newMetadataRetryFixture(t, operation)
			value, original := f.originalMapping(false)
			f.seed(value)
			f.observed.afterClose = func() {
				if f.observed.begins.Load() > 0 {
					f.clock.at = value.ExpiresAt()
				}
			}
			f.expectPreRead(metadataRetryAttempt{})
			f.expectAttempt(metadataRetryAttempt{rows: f.rows(value, original), stage: "commit", failure: metadataRetryAbort("40001", true)})
			f.expectAttempt(metadataRetryAttempt{rows: f.rows(value, original)})
			var want error = artifact.ErrArtifactExpired
			gets := 1
			if operation == "webhook" {
				want, gets = webhook.ErrDeliveryExpired, 0
			}
			f.check(context.Background(), false, want, 2, 1, 1, gets, webhook.StoredDelivery{})
		})
	}
}
