package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestErasureJournalKnownAbortRetriesHaveNoExternalEffects(t *testing.T) {
	stages := []string{"BEGIN", "tenant_guc", "artifact_lock", "scope_insert", "scope_read", "metadata_read", "key_occupancy", "legacy_lineage", "metadata_insert", "admission_insert", "COMMIT"}
	for _, stage := range stages {
		for _, code := range []string{"40001", "40P01"} {
			for failures := 1; failures <= 3; failures++ {
				t.Run(stage+"/"+code+"/"+string(rune('0'+failures)), func(t *testing.T) {
					f := newErasureFixture(t)
					j := f.journal()
					candidate, _ := artifact.NewArtifactAdmission(f.value, f.policy.NamespaceIdentity(), time.UnixMilli(1000).UTC())
					for n := 0; n < failures; n++ {
						fault := erasureSQLFault{StatementID: stage, Occurrence: 1, OperationLabel: "work", Err: &pgconn.PgError{Code: code}}
						if stage == "COMMIT" {
							fault.CommitMode = erasureTestKnownAbort
						}
						if err := f.s.Inject(fault); err != nil {
							t.Fatal(err)
						}
					}
					a, inserted, err := j.AdmitArtifact(f.ctx, candidate)
					if failures == 3 {
						erasureRequireError(t, err, artifact.ErrErasureJournalUnavailable)
						if inserted || !reflect.DeepEqual(a, artifact.ArtifactAdmission{}) {
							t.Fatal("exhaustion released callback output")
						}
						if len(f.s.Snapshot().Rows[erasureAdmissions]) != 0 {
							t.Fatal("abort persisted canonical row")
						}
					} else {
						if err != nil || !inserted || a.Identity() != candidate.Identity() {
							t.Fatal("known abort did not retry exact candidate", err)
						}
					}
					if f.s.beginCount("work") != min(failures+1, 3) {
						t.Fatal("attempt count", f.s.beginCount("work"))
					}
					if f.external.Counts() != (erasureExternalCounts{}) {
						t.Fatal("DB retry effects")
					}
				})
			}
		}
	}
}
func TestErasureJournalNonAbortErrorsNeverReplay(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{{"EOF", io.EOF}, {"generic", errors.New("private I/O detail")}, {"text40001", errors.New("SQLSTATE40001 serialization failure")}, {"in-doubt", &pgconn.PgError{Code: "40003"}}, {"unique", &pgconn.PgError{Code: "23505"}}, {"cancel", context.Canceled}, {"deadline", context.DeadlineExceeded}}
	for _, stage := range []string{"BEGIN", "tenant_guc", "admission_insert", "COMMIT"} {
		for _, tc := range cases {
			t.Run(stage+"/"+tc.name, func(t *testing.T) {
				f := newErasureFixture(t)
				j := f.journal()
				candidate, _ := artifact.NewArtifactAdmission(f.value, f.policy.NamespaceIdentity(), time.UnixMilli(1000).UTC())
				if err := f.s.Inject(erasureSQLFault{StatementID: stage, Occurrence: 1, OperationLabel: "work", Err: tc.err}); err != nil {
					t.Fatal(err)
				}
				a, inserted, err := j.AdmitArtifact(f.ctx, candidate)
				if err == nil || inserted || !reflect.DeepEqual(a, artifact.ArtifactAdmission{}) {
					t.Fatal("non-abort released success")
				}
				if f.s.beginCount("work") != 1 {
					t.Fatal("non-abort replay")
				}
				if f.external.Counts() != (erasureExternalCounts{}) {
					t.Fatal("failure effects")
				}
				if stage == "COMMIT" {
					erasureRequireError(t, err, artifact.ErrErasureUnknownOutcome)
				}
			})
		}
	}
	for _, stage := range []string{"tenant_guc", "admission_insert"} {
		t.Run(stage+"/rollback failure", func(t *testing.T) {
			f := newErasureFixture(t)
			j := f.journal()
			candidate, _ := artifact.NewArtifactAdmission(f.value, f.policy.NamespaceIdentity(), time.UnixMilli(1000).UTC())
			if err := f.s.Inject(erasureSQLFault{StatementID: stage, Occurrence: 1, OperationLabel: "work", Err: &pgconn.PgError{Code: "40001"}, RollbackErr: io.ErrClosedPipe}); err != nil {
				t.Fatal(err)
			}
			a, inserted, err := j.AdmitArtifact(f.ctx, candidate)
			if err == nil || inserted || !reflect.DeepEqual(a, artifact.ArtifactAdmission{}) || f.s.beginCount("work") != 1 {
				t.Fatal("failed rollback replayed or released output")
			}
		})
	}
}
func TestErasureRetryResetsSuccessfulCallbackOutput(t *testing.T) {
	f := newErasureFixture(t)
	f.clock.Set(time.UnixMilli(1100).UTC())
	j := f.journal()
	candidate, _ := artifact.NewArtifactAdmission(f.value, f.policy.NamespaceIdentity(), time.UnixMilli(1100).UTC())
	entered, release := make(chan struct{}), make(chan struct{})
	if err := f.s.Inject(erasureSQLFault{StatementID: "COMMIT", Occurrence: 1, OperationLabel: "work", Err: &pgconn.PgError{Code: "40001"}, CommitMode: erasureTestKnownAbort}); err != nil {
		t.Fatal(err)
	}
	if err := f.s.Inject(erasureSQLFault{StatementID: "BEGIN", Occurrence: 2, OperationLabel: "work", Entered: entered, Release: release}); err != nil {
		t.Fatal(err)
	}
	type result struct {
		a        artifact.ArtifactAdmission
		inserted bool
		err      error
	}
	out := make(chan result, 1)
	ctxWorker, cancelWorker := context.WithCancel(f.ctx)
	done := make(chan struct{})
	erasureJoinOnCleanup(t, cancelWorker, done)
	go func() { defer close(done); a, b, e := j.AdmitArtifact(ctxWorker, candidate); out <- result{a, b, e} }()
	erasureWait(t, f.ctx, entered)
	clock := &erasureClock{at: time.UnixMilli(1000).UTC()}
	index, _ := newErasureGraph(t, f.s, f.external, f.policy, clock, "winner")
	ctx, cancel := erasureOperationContext(t, "winner")
	defer cancel()
	w, err := VerifyArtifactErasureIndex(ctx, index)
	if err != nil {
		t.Fatal(err)
	}
	other, err := newArtifactAdmissionJournal(index, w, f.policy, clock)
	if err != nil {
		t.Fatal(err)
	}
	earlier, _ := artifact.NewArtifactAdmission(f.value, f.policy.NamespaceIdentity(), time.UnixMilli(1000).UTC())
	winner, inserted, err := other.AdmitArtifact(ctx, earlier)
	if err != nil || !inserted {
		t.Fatal("competing actual winner", err)
	}
	close(release)
	select {
	case r := <-out:
		if r.err != nil || r.inserted || r.a.Identity() != winner.Identity() || !r.a.AdmittedAt().Equal(winner.AdmittedAt()) {
			t.Fatal("stale successful callback output", r.err)
		}
	case <-f.ctx.Done():
		t.Fatal("retry did not finish")
	}
	if f.external.Counts() != (erasureExternalCounts{}) {
		t.Fatal("retry or winner dispatched")
	}
}
func TestErasurePrepareKnownAbortRetryStages(t *testing.T) {
	for _, stage := range []string{"BEGIN", "tenant_guc", "artifact_lock", "key_occupancy", "admission_lock_read", "legacy_lineage", "operation_read", "operation_insert", "COMMIT"} {
		t.Run(stage, func(t *testing.T) {
			f := newErasureFixture(t)
			f.put()
			a := f.admission()
			grant := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
			before := f.external.Counts()
			start := f.s.beginCount("work")
			fault := erasureSQLFault{StatementID: stage, Occurrence: 1, OperationLabel: "work", Err: &pgconn.PgError{Code: "40P01"}}
			if stage == "COMMIT" {
				fault.CommitMode = erasureTestKnownAbort
			}
			if err := f.s.Inject(fault); err != nil {
				t.Fatal(err)
			}
			op, err := f.store.PrepareErasure(f.ctx, grant, time.UnixMilli(1000).UTC())
			if err != nil || op.Validate() != nil {
				t.Fatal("Prepare retry", err)
			}
			if f.s.beginCount("work")-start != 2 {
				t.Fatal("Prepare attempts")
			}
			if f.external.Counts() != before || len(f.s.Snapshot().Rows[erasureOperations]) != 1 {
				t.Fatal("Prepare retry duplicated effects/row")
			}
		})
	}
}
func TestErasureConfirmationRetryHasOnePhysicalDispatch(t *testing.T) {
	for _, code := range []string{"40001", "40P01"} {
		t.Run(code, func(t *testing.T) {
			f := newErasureFixture(t)
			if err := f.s.Inject(erasureSQLFault{StatementID: "confirmation_cas", Occurrence: 1, OperationLabel: "work", Err: &pgconn.PgError{Code: code}}); err != nil {
				t.Fatal(err)
			}
			f.put()
			row := erasureOnlyRow(t, f.s, erasureAdmissions)
			if row["confirmed_version"] == nil {
				t.Fatal("confirmation not committed")
			}
			c := f.external.Counts()
			if c.Generates != 1 || c.Creates != 1 {
				t.Fatal("confirmation retry replayed Put")
			}
		})
	}
}
func TestErasureDecisionClockRefusesWithoutEffects(t *testing.T) {
	for _, at := range []time.Time{time.Time{}, time.UnixMilli(0).UTC(), time.UnixMilli(99).UTC(), time.UnixMilli(1000).UTC().Add(time.Nanosecond), time.UnixMilli(1000).In(time.FixedZone("nonUTC", 3600)), time.UnixMilli(10000).UTC()} {
		t.Run(at.String(), func(t *testing.T) {
			f := newErasureFixture(t)
			f.clock.Set(at)
			before := len(f.s.Snapshot().Events)
			created, err := f.store.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
			if created || err == nil {
				t.Fatal("invalid/expired clock accepted")
			}
			if len(f.s.Snapshot().Events) != before || f.external.Counts() != (erasureExternalCounts{}) {
				t.Fatal("invalid decision clock effects")
			}
		})
	}
	t.Run("future caller at", func(t *testing.T) {
		f := newErasureFixture(t)
		before := len(f.s.Snapshot().Events)
		created, err := f.store.Put(f.ctx, f.value, time.UnixMilli(1001).UTC())
		if created || err == nil || len(f.s.Snapshot().Events) != before || f.external.Counts() != (erasureExternalCounts{}) {
			t.Fatal("future at authorized work")
		}
	})
	t.Run("grant backdating cannot revive", func(t *testing.T) {
		f := newErasureFixture(t)
		f.put()
		a := f.admission()
		g := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
		f.clock.Set(time.UnixMilli(8000).UTC())
		before := len(f.s.Snapshot().Events)
		external := f.external.Counts()
		op, err := f.store.PrepareErasure(f.ctx, g, time.UnixMilli(1000).UTC())
		if err == nil {
			t.Fatal("expired grant revived by old at")
		}
		erasureRequireZeroOperation(t, op)
		if len(f.s.Snapshot().Events) != before || f.external.Counts() != external {
			t.Fatal("backdated Prepare effects")
		}
	})
}
func TestErasureHistoricalReadbackDoesNotReviveExpiredWork(t *testing.T) {
	f := newErasureFixture(t)
	f.put()
	a := f.admission()
	grant := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
	op, err := f.store.PrepareErasure(f.ctx, grant, time.UnixMilli(1000).UTC())
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Set(time.UnixMilli(11000).UTC())
	before := f.external.Counts()
	_, fresh := newErasureGraph(t, f.s, f.external, f.policy, f.clock, "expired-restart")
	got, found, err := fresh.ReadPreparedErasure(f.ctx, op.Ref())
	if err != nil || !found || got.Identity() != op.Identity() {
		t.Fatal("expired snapshot readback refused", err)
	}
	_, found, err = fresh.ReadAdmission(f.ctx, a.Scope(), a.NamespaceIdentity(), a.ArtifactIdentity())
	if err != nil || !found {
		t.Fatal("historical admission refused", err)
	}
	if before != f.external.Counts() {
		t.Fatal("historical reads effects")
	}
	work, err := fresh.PrepareErasure(f.ctx, grant, time.UnixMilli(1000).UTC())
	if err == nil {
		t.Fatal("expired authority revived")
	}
	erasureRequireZeroOperation(t, work)
}
func TestErasurePreparedReadbackValidatesWholeRows(t *testing.T) {
	for _, table := range []string{erasureScopes, erasureMetadata, erasureAdmissions, erasureOperations} {
		var descriptor map[string]erasureTableDescriptor
		if err := json.Unmarshal([]byte(erasureDescriptorJSON), &descriptor); err != nil {
			t.Fatal(err)
		}
		for _, col := range descriptor[table].Columns {
			if col.Name == "registered_at" {
				continue
			}
			t.Run(table+"/"+col.Name, func(t *testing.T) {
				f := newErasureFixture(t)
				f.put()
				a := f.admission()
				g := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
				op, err := f.store.PrepareErasure(f.ctx, g, time.UnixMilli(1000).UTC())
				if err != nil {
					t.Fatal(err)
				}
				row := erasureOnlyRow(t, f.s, table)
				var key []driver.Value
				for _, k := range descriptor[table].Constraints {
					if k.Kind == "PRIMARY KEY" {
						key = erasureTuple(row, k.Columns)
					}
				}
				var replacement driver.Value
				switch col.Type {
				case "text":
					replacement = strings.Repeat("d", 64)
					if replacement == row[col.Name] {
						replacement = strings.Repeat("e", 64)
					}
					if col.Name == "confirmed_version" {
						replacement = "version:null"
					}
					if col.Name == "confirmed_ciphertext_digest" {
						replacement = "not-a-digest"
					}
				case "bytea":
					replacement = []byte("{}")
				case "int8":
					replacement = int64(1)
				case "timestamptz":
					replacement = time.UnixMilli(1).UTC()
				}
				if err = f.s.CorruptExistingRow(table, key, col.Name, replacement); err != nil {
					t.Fatal(err)
				}
				before := f.external.Counts()
				got, found, err := f.store.ReadPreparedErasure(f.ctx, op.Ref())
				if err == nil && found {
					t.Fatal("corrupt full joined row accepted", table, col.Name)
				}
				erasureRequireZeroOperation(t, got)
				if before != f.external.Counts() {
					t.Fatal("corruption readback contacted provider")
				}
			})
		}
	}
}
func TestErasureReadbackChecksCanonicalMediaProvenanceAndBounds(t *testing.T) {
	for _, field := range []string{"media_type", "provenance", "scope_identity", "artifact_identity", "namespace_identity", "admitted_at_milliseconds"} {
		t.Run(field, func(t *testing.T) {
			f := newErasureFixture(t)
			f.put()
			a := f.admission()
			row := erasureOnlyRow(t, f.s, erasureAdmissions)
			var fields map[string]any
			if err := json.Unmarshal(row["canonical_admission"].([]byte), &fields); err != nil {
				t.Fatal(err)
			}
			switch field {
			case "media_type":
				fields[field] = "application/json"
			case "provenance":
				fields[field] = []string{strings.Repeat("e", 64)}
			case "admitted_at_milliseconds":
				fields[field] = int64(1100)
			default:
				fields[field] = strings.Repeat("c", 64)
			}
			if field == "media_type" || field == "provenance" {
				originalOrder := strings.Fields("scope_identity kind media_type classification origin protection provenance payload_digest created_at_milliseconds expires_at_milliseconds")
				original := map[string]any{}
				for _, k := range originalOrder {
					original[k] = fields[k]
				}
				fields["artifact_identity"] = erasureHash(erasureOrdered(t, original, originalOrder, ""))
			}
			order := strings.Fields("contract schema_version identity namespace_identity scope_identity tenant_id repository_id review_run_id artifact_identity kind media_type classification origin protection provenance payload_digest created_at_milliseconds expires_at_milliseconds admitted_at_milliseconds")
			wire := erasureOrdered(t, fields, order, "open-trestle/artifact-admission/v1\x00")
			if field == "media_type" || field == "provenance" || field == "namespace_identity" || field == "admitted_at_milliseconds" {
				if _, parseErr := artifact.ParseArtifactAdmission(wire); parseErr != nil {
					t.Fatal("rehashed metadata-shape positive control", parseErr)
				}
			}
			if err := f.s.CorruptExistingRow(erasureAdmissions, erasureRowKey(row), "canonical_admission", wire); err != nil {
				t.Fatal(err)
			}
			got, found, err := f.store.ReadAdmission(f.ctx, a.Scope(), a.NamespaceIdentity(), a.ArtifactIdentity())
			if err == nil && found {
				t.Fatal("rehashed changed canonical preimage accepted")
			}
			if !reflect.DeepEqual(got, artifact.ArtifactAdmission{}) {
				t.Fatal("corruption leaked admission")
			}
		})
	}
	for _, wire := range [][]byte{nil, {}, []byte("{} trailing"), bytes.Repeat([]byte{'x'}, 16385), []byte(`{"identity":"a","identity":"a"}`)} {
		t.Run("wire", func(t *testing.T) {
			f := newErasureFixture(t)
			f.put()
			a := f.admission()
			r := erasureOnlyRow(t, f.s, erasureAdmissions)
			if err := f.s.CorruptExistingRow(erasureAdmissions, erasureRowKey(r), "canonical_admission", wire); err != nil {
				t.Fatal(err)
			}
			got, found, err := f.store.ReadAdmission(f.ctx, a.Scope(), a.NamespaceIdentity(), a.ArtifactIdentity())
			if err == nil && found {
				t.Fatal("malformed bytes accepted")
			}
			if !reflect.DeepEqual(got, artifact.ArtifactAdmission{}) {
				t.Fatal("malformed read retained identity")
			}
		})
	}
}
func TestErasureConfirmationTokensAndFirstTimeAreExact(t *testing.T) {
	f := newErasureFixture(t)
	f.put()
	a := f.admission()
	j := f.journal()
	r := erasureOnlyRow(t, f.s, erasureAdmissions)
	digest := r["confirmed_ciphertext_digest"].(string)
	before := f.external.Counts()
	for _, token := range []string{"", "version:", "version:null", "unqualified", "version:bad token", "version:bad\n", "version:" + strings.Repeat("a", 505), "version:\xff"} {
		if err := j.ConfirmAdmission(f.ctx, a, token, digest, time.UnixMilli(1000).UTC()); err == nil {
			t.Fatal("invalid confirmation token", token)
		}
	}
	if err := j.ConfirmAdmission(f.ctx, a, "version:different", digest, time.UnixMilli(1000).UTC()); !errors.Is(err, artifact.ErrErasureConflict) {
		t.Fatal("confirmation token conflict", err)
	}
	f.clock.Set(time.UnixMilli(1100).UTC())
	if err := j.ConfirmAdmission(f.ctx, a, r["confirmed_version"].(string), digest, time.UnixMilli(1100).UTC()); err != nil {
		t.Fatal(err)
	}
	after := erasureOnlyRow(t, f.s, erasureAdmissions)
	if after["confirmed_at_milliseconds"] != r["confirmed_at_milliseconds"] {
		t.Fatal("idempotent confirm changed first time")
	}
	if f.external.Counts() != before {
		t.Fatal("database Confirm effects")
	}
}

func TestErasureLoadedAuthorityAndAdmittedPolicyCannotBeReplaced(t *testing.T) {
	f := newErasureFixture(t)
	f.put()
	a := f.admission()
	grant := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
	b, err := artifact.EncodeErasureAuthorizationV2(grant)
	if err != nil {
		t.Fatal(err)
	}
	shape, err := artifact.ParseErasureAuthorizationV2(b)
	if err != nil {
		t.Fatal(err)
	}
	before := f.external.Counts()
	op, err := f.store.PrepareErasure(f.ctx, shape, time.UnixMilli(1000).UTC())
	erasureRequireError(t, err, artifact.ErrErasureAuthorityRequired)
	erasureRequireZeroOperation(t, op)
	policy := erasurePolicy(t, f.s.catalog, f.external.Backend(t, "first", f.clock), map[string]any{"configuration_evidence_identity": strings.Repeat("e", 64)})
	w, err := VerifyArtifactErasureIndex(f.ctx, f.index)
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewIndexedEnvelopeStore(f.index, EnvelopeDependencies{Backend: f.external.Backend(t, "first", f.clock), Keys: f.external.Keys(t, "first"), Clock: f.clock, IndexAuthority: w}, policy)
	if err != nil {
		t.Fatal("valid local constructor must not query stored policy", err)
	}
	changedGrant := erasureGrant(t, policy, a, strings.Repeat("8", 64))
	op, err = other.PrepareErasure(f.ctx, changedGrant, time.UnixMilli(1000).UTC())
	if err == nil {
		t.Fatal("different admitted protected policy accepted")
	}
	erasureRequireZeroOperation(t, op)
	created, err := other.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
	if err == nil || created {
		t.Fatal("different policy gained a Put permit")
	}
	if before != f.external.Counts() {
		t.Fatal("denied authority work performed remote effects")
	}
}
func TestErasureNonNullRemoteVersionIsMandatory(t *testing.T) {
	f := newErasureFixture(t)
	f.external.mu.Lock()
	f.external.version = "null"
	f.external.mu.Unlock()
	created, err := f.store.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
	if created {
		t.Fatal("null remote version confirmed")
	}
	erasureRequireError(t, err, artifact.ErrRemoteStoreConflict)
	r := erasureOnlyRow(t, f.s, erasureAdmissions)
	if r["confirmed_version"] != nil {
		t.Fatal("inferred non-null confirmation from Create bool")
	}
	if f.external.Counts().Generates != 1 || f.external.Counts().Creates != 1 {
		t.Fatal("null version retransmission")
	}
}
func TestErasureNewDMLChecksAffectedCounts(t *testing.T) {
	for _, stage := range []string{"scope_insert", "metadata_insert", "admission_insert"} {
		for _, count := range []int64{-1, 2} {
			t.Run(stage+"/count", func(t *testing.T) {
				f := newErasureFixture(t)
				if err := f.s.Inject(erasureSQLFault{StatementID: stage, Occurrence: 1, OperationLabel: "work", AffectedRows: &count}); err != nil {
					t.Fatal(err)
				}
				created, err := f.store.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
				if err == nil || created {
					t.Fatal("invalid affected row count accepted")
				}
				if f.external.Counts() != (erasureExternalCounts{}) {
					t.Fatal("malformed DML result dispatched")
				}
			})
		}
	}
	for _, stage := range []string{"metadata_insert", "admission_insert"} {
		t.Run(stage+"/zero", func(t *testing.T) {
			f := newErasureFixture(t)
			count := int64(0)
			if err := f.s.Inject(erasureSQLFault{StatementID: stage, Occurrence: 1, OperationLabel: "work", AffectedRows: &count}); err != nil {
				t.Fatal(err)
			}
			created, err := f.store.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
			if err == nil || created || f.external.Counts() != (erasureExternalCounts{}) {
				t.Fatal("zero INSERT result granted permit")
			}
		})
	}
	for _, count := range []int64{-1, 0, 2} {
		t.Run("operation/count", func(t *testing.T) {
			f := newErasureFixture(t)
			f.put()
			a := f.admission()
			g := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
			before := f.external.Counts()
			if err := f.s.Inject(erasureSQLFault{StatementID: "operation_insert", Occurrence: 1, OperationLabel: "work", AffectedRows: &count}); err != nil {
				t.Fatal(err)
			}
			op, err := f.store.PrepareErasure(f.ctx, g, time.UnixMilli(1000).UTC())
			if err == nil {
				t.Fatal("invalid operation INSERT count")
			}
			erasureRequireZeroOperation(t, op)
			if before != f.external.Counts() {
				t.Fatal("invalid operation DML effects")
			}
		})
	}
}

func TestErasureConfirmationAffectedCountNeverInventsSuccess(t *testing.T) {
	for _, count := range []int64{-1, 0, 2} {
		t.Run("count", func(t *testing.T) {
			f := newErasureFixture(t)
			if err := f.s.Inject(erasureSQLFault{StatementID: "confirmation_cas", Occurrence: 1, OperationLabel: "work", AffectedRows: &count}); err != nil {
				t.Fatal(err)
			}
			created, err := f.store.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
			if created || err == nil {
				t.Fatal("invalid/zero confirmation CAS reported success")
			}
			if f.external.Counts().Generates != 1 || f.external.Counts().Creates != 1 {
				t.Fatal("CAS count failure replayed physical work")
			}
		})
	}
}
func TestErasurePrepareDefinitiveAbortRetainsNoOperation(t *testing.T) {
	f := newErasureFixture(t)
	f.put()
	a := f.admission()
	g := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
	before := f.external.Counts()
	for i := 0; i < 3; i++ {
		if err := f.s.Inject(erasureSQLFault{StatementID: "COMMIT", Occurrence: 1, OperationLabel: "work", Err: &pgconn.PgError{Code: "40001"}, CommitMode: erasureTestKnownAbort}); err != nil {
			t.Fatal(err)
		}
	}
	op, err := f.store.PrepareErasure(f.ctx, g, time.UnixMilli(1000).UTC())
	erasureRequireError(t, err, artifact.ErrErasureJournalUnavailable)
	erasureRequireZeroOperation(t, op)
	if len(f.s.Snapshot().Rows[erasureOperations]) != 0 || before != f.external.Counts() {
		t.Fatal("aborted Prepare retained mutation/effects")
	}
	_, fresh := newErasureGraph(t, f.s, f.external, f.policy, f.clock, "abort-restart")
	op, found, err := fresh.FindPreparedErasure(f.ctx, a.Scope(), a.NamespaceIdentity(), a.ArtifactIdentity())
	if err != nil || found {
		t.Fatal("aborted operation discovered", err)
	}
	erasureRequireZeroOperation(t, op)
}
func TestErasureConfirmCommitKnownAbortRetries(t *testing.T) {
	for failures := 1; failures <= 3; failures++ {
		t.Run("attempts", func(t *testing.T) {
			f := newErasureFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			if err := f.s.Inject(erasureSQLFault{StatementID: "confirmation_cas", Occurrence: 1, OperationLabel: "work", Entered: entered, Release: release}); err != nil {
				t.Fatal(err)
			}
			out := erasureStartPut(t, f)
			erasureWait(t, f.ctx, entered)
			for i := 0; i < failures; i++ {
				if err := f.s.Inject(erasureSQLFault{StatementID: "COMMIT", Occurrence: 1, OperationLabel: "work", Err: &pgconn.PgError{Code: "40P01"}, CommitMode: erasureTestKnownAbort}); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			r := erasurePutWait(t, f.ctx, out)
			if failures == 3 {
				if r.created {
					t.Fatal("exhausted confirmation success")
				}
				erasureRequireError(t, r.err, artifact.ErrErasureJournalUnavailable)
				if erasureOnlyRow(t, f.s, erasureAdmissions)["confirmed_version"] != nil {
					t.Fatal("aborted confirmation persisted")
				}
			} else if r.err != nil || !r.created {
				t.Fatal("confirmation retry did not succeed", r.err)
			}
			if f.external.Counts().Generates != 1 || f.external.Counts().Creates != 1 {
				t.Fatal("commit retry repeated Create/Generate")
			}
		})
	}
}

var _ func(*Store, context.Context, string, func(*sql.Tx) error) (erasureCommitOutcome, error) = (*Store).retryErasureMutation
var _ func(context.Context, *sql.Tx, audit.ReviewScope) error = ensureErasureScopeTransaction

func TestErasureWrappedAbortClassification(t *testing.T) {
	for _, code := range []string{"40001", "40P01"} {
		for _, stage := range []string{"admission_insert", "COMMIT"} {
			t.Run(stage+"/"+code, func(t *testing.T) {
				f := newErasureFixture(t)
				j := f.journal()
				candidate, _ := artifact.NewArtifactAdmission(f.value, f.policy.NamespaceIdentity(), time.UnixMilli(1000).UTC())
				fault := erasureSQLFault{StatementID: stage, Occurrence: 1, OperationLabel: "work", Err: errors.Join(errors.New("synthetic wrapper"), &pgconn.PgError{Code: code})}
				if stage == "COMMIT" {
					fault.CommitMode = erasureTestKnownAbort
				}
				if err := f.s.Inject(fault); err != nil {
					t.Fatal(err)
				}
				a, inserted, err := j.AdmitArtifact(f.ctx, candidate)
				if err != nil || !inserted || a.Identity() != candidate.Identity() || f.s.beginCount("work") != 2 {
					t.Fatal("wrapped exact SQLSTATE was not retried", err)
				}
				if f.external.Counts() != (erasureExternalCounts{}) {
					t.Fatal("wrapped abort effects")
				}
			})
		}
	}
}

func TestErasureRowAndCloseErrorsDiscardOutputs(t *testing.T) {
	for _, phase := range []string{"next", "close"} {
		t.Run("read/"+phase, func(t *testing.T) {
			f := newErasureFixture(t)
			f.put()
			a := f.admission()
			fault := erasureSQLFault{StatementID: "admission_read", Occurrence: 1, OperationLabel: "work"}
			if phase == "next" {
				fault.NextErr = io.ErrUnexpectedEOF
			} else {
				fault.CloseErr = io.ErrClosedPipe
			}
			if err := f.s.Inject(fault); err != nil {
				t.Fatal(err)
			}
			before := f.external.Counts()
			got, found, err := f.store.ReadAdmission(f.ctx, a.Scope(), a.NamespaceIdentity(), a.ArtifactIdentity())
			if err == nil || found || !reflect.DeepEqual(got, artifact.ArtifactAdmission{}) {
				t.Fatal("failed read retained callback metadata")
			}
			if f.external.Counts() != before {
				t.Fatal("failed read effects")
			}
		})
		for _, code := range []string{"40001", "40P01"} {
			t.Run("mutation/"+phase+"/"+code, func(t *testing.T) {
				f := newErasureFixture(t)
				j := f.journal()
				candidate, _ := artifact.NewArtifactAdmission(f.value, f.policy.NamespaceIdentity(), time.UnixMilli(1000).UTC())
				fault := erasureSQLFault{StatementID: "scope_read", Occurrence: 1, OperationLabel: "work"}
				if phase == "next" {
					fault.NextErr = &pgconn.PgError{Code: code}
				} else {
					fault.CloseErr = &pgconn.PgError{Code: code}
				}
				if err := f.s.Inject(fault); err != nil {
					t.Fatal(err)
				}
				a, inserted, err := j.AdmitArtifact(f.ctx, candidate)
				if err != nil || !inserted || a.Identity() != candidate.Identity() || f.s.beginCount("work") != 2 {
					t.Fatal("row/close known abort retry", err)
				}
				if f.external.Counts() != (erasureExternalCounts{}) {
					t.Fatal("row/close retry effects")
				}
			})
		}
	}
}
