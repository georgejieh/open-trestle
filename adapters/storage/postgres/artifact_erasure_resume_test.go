package postgres

import (
	"bytes"
	"context"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestResumeJournalSixMethodsAndExactIdempotence(t *testing.T) {
	g := newResumeJournalFixture(t)
	_, op, _ := g.Prepared()
	a, _, raw := resumeAllowance(t, g.policy, op, g.clock.Value(), "first", resumeMaximum())
	before := len(g.peer.Events())
	usage, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value())
	if err != nil || usage != (artifact.AllowanceUsage{AllowanceIdentity: a.Identity(), NextSequence: 1}) {
		t.Fatal("zero-spent allowance", err)
	}
	if len(g.peer.Events()) != before {
		t.Fatal("journal admission dispatched")
	}
	rows := g.sql.Snapshot().Rows[resumeAllowances]
	if len(rows) != 1 || !bytes.Equal(rows[0]["canonical_allowance"].([]byte), raw) || rows[0]["allowance_document_digest"] != resumeHash(raw) {
		t.Fatal("independent allowance canonical bytes")
	}
	r := resumeCurrentRequest(t, g, op, a, "request-one")
	at := g.clock.Value()
	attempt, inserted, err := g.journal.ReserveErasureAttempt(g.Context("reserve"), op.Ref(), a, r, at)
	if err != nil || !inserted {
		t.Fatal(err)
	}
	resumeAssertAttempt(t, attempt, r, 1, at)
	revision := g.sql.Snapshot().Revision
	again, inserted, err := g.journal.ReserveErasureAttempt(g.Context("duplicate"), op.Ref(), a, r, at)
	if err != nil || inserted || again.Identity() != attempt.Identity() || g.sql.Snapshot().Revision != revision {
		t.Fatal("duplicate changed spending or attempt", err)
	}
	changed, err := artifact.NewAttemptRequest(artifact.AttemptRequestOptions{ReservationIdentity: r.ReservationIdentity(), Operation: op, Allowance: a, Kind: artifact.AttemptCurrentRead, Key: g.Key(), MaximumResponseBytes: 8192})
	if err != nil {
		t.Fatal(err)
	}
	out, inserted, err := g.journal.ReserveErasureAttempt(g.Context("conflicting"), op.Ref(), a, changed, at)
	if !errors.Is(err, artifact.ErrErasureConflict) || inserted || out.Identity() != "" {
		t.Fatal("reservation bytes conflict", err)
	}
	usage, err = g.journal.AdmitResumeAllowance(g.Context("read-usage"), op.Ref(), a, at)
	if err != nil || usage.Spent != resumeCost(r) || usage.NextSequence != 2 {
		t.Fatal("spent usage", err)
	}
	got, evidence, found, err := g.journal.ReadErasureAttempt(g.Context("read-attempt"), op.Ref(), r.ReservationIdentity())
	if err != nil || !found || len(evidence) != 0 {
		t.Fatal(err)
	}
	resumeAssertAttempt(t, got, r, 1, at)
	page, err := g.journal.ReadAllowanceAttempts(g.Context("page"), op.Ref(), a.Identity(), 0, 1)
	if err != nil || len(page.Attempts) != 1 || page.After != 1 || page.More {
		t.Fatal("attempt page", err)
	}
	unknown, err := artifact.NewAttemptUnknownEvidence(attempt, at)
	if err != nil {
		t.Fatal(err)
	}
	recorded, inserted, err := g.journal.RecordErasureEvidence(g.Context("record-unknown"), op.Ref(), unknown)
	if err != nil || !inserted {
		t.Fatal(err)
	}
	encoded, err := artifact.EncodeErasureEvidence(recorded)
	if err != nil || !bytes.Equal(encoded, resumeExpectedUnknown(t, attempt, at)) {
		t.Fatal("canonical unknown output", err)
	}
	later, err := artifact.NewAttemptUnknownEvidence(attempt, at.Add(time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	g.clock.Set(at.Add(time.Millisecond))
	adopted, inserted, err := g.journal.RecordErasureEvidence(g.Context("first-unknown-wins"), op.Ref(), later)
	if err != nil || inserted || adopted.Identity() != recorded.Identity() || !adopted.ObservedAt().Equal(at) {
		t.Fatal("unknown winner overwritten", err)
	}
	progress, found, err := g.journal.ReadErasureProgress(g.Context("progress"), op.Ref(), a.Identity())
	if err != nil || !found || progress.Validate() != nil || !progress.HasUnknownHistory() || !progress.HasUnresolvedAttempts() || len(progress.UnrecordedUncertainty()) != 0 || progress.UncertaintyBookkeepingMore() {
		t.Fatal("progress", err)
	}
	usages := progress.AllowanceUsages()
	if len(usages) != 1 || usages[0] != usage {
		t.Fatal("requested usage")
	}
	usages[0].NextSequence = 99
	if progress.AllowanceUsages()[0] != usage {
		t.Fatal("usage aliases progress")
	}
	if len(g.peer.Events()) != before {
		t.Fatal("six journal methods touched object service")
	}
	bad, found, err := g.journal.ReadErasureProgress(g.Context("missing-allowance"), op.Ref(), strings.Repeat("f", 64))
	if !errors.Is(err, artifact.ErrErasureConflict) || found || bad.Operation().Identity() != "" {
		t.Fatal("missing requested allowance", err)
	}
	empty, err := g.journal.ReadAllowanceAttempts(g.Context("empty-page"), op.Ref(), a.Identity(), 19, 64)
	if err != nil || len(empty.Attempts) != 0 || empty.After != 19 || empty.More {
		t.Fatal("empty cursor preserved", err)
	}
	g.sql.AssertClean(t)
}
func TestResumeJournalLoadedAuthorityAndIndependentBudgetDimensions(t *testing.T) {
	for dimension := 0; dimension < 11; dimension++ {
		t.Run(resumeDimensions[dimension], func(t *testing.T) {
			g := newResumeJournalFixture(t)
			_, op, _ := g.Prepared()
			max := resumeBudgetVector(resumeMaximum())
			max[dimension] = 0
			if dimension == 0 {
				max[0] = 1
				max[1] = 1
			}
			a, _, raw := resumeAllowance(t, g.policy, op, g.clock.Value(), "bounded", resumeBudgetFrom(max))
			ctx := g.Context("admit")
			if _, err := g.journal.AdmitResumeAllowance(ctx, op.Ref(), a, g.clock.Value()); err != nil {
				t.Fatal(err)
			}
			parsed, err := artifact.ParseResumeAllowance(raw, g.scope)
			if err != nil {
				t.Fatal(err)
			}
			r := resumeCurrentRequest(t, g, op, a, "parsed-refusal")
			before := g.sql.Snapshot().Revision
			out, inserted, err := g.journal.ReserveErasureAttempt(g.Context("parsed"), op.Ref(), parsed, r, g.clock.Value())
			if err == nil || inserted || out.Identity() != "" || g.sql.Snapshot().Revision != before {
				t.Fatal("metadata acquired fresh allowance authority")
			}
			// A read spends only Requests, Reads and ResponseBytes.
			if dimension == 0 || dimension == 2 || dimension == 8 {
				r = resumeCurrentRequest(t, g, op, a, "budgeted-read")
				attempt, inserted, err := g.journal.ReserveErasureAttempt(g.Context("read-one"), op.Ref(), a, r, g.clock.Value())
				if dimension == 0 {
					if err != nil || !inserted {
						t.Fatal(err)
					}
					resumeAssertAttempt(t, attempt, r, 1, g.clock.Value())
					r = resumeCurrentRequest(t, g, op, a, "budgeted-read-two")
					attempt, inserted, err = g.journal.ReserveErasureAttempt(g.Context("read-two"), op.Ref(), a, r, g.clock.Value())
				}
				if !errors.Is(err, artifact.ErrErasureAllowanceExhausted) || inserted || attempt.Identity() != "" {
					t.Fatal("independent exhausted dimension", err)
				}
			}
			usage, err := g.journal.AdmitResumeAllowance(g.Context("unchanged"), op.Ref(), a, g.clock.Value())
			if err != nil {
				t.Fatal(err)
			}
			if dimension != 0 && usage.Spent != (artifact.ResumeBudget{}) {
				t.Fatal("denied request spent or refunded another dimension")
			}
		})
	}
}
func TestResumeJournalKnownAbortRetriesAndUnknownOutputs(t *testing.T) {
	for _, point := range []string{"tenant_guc", "artifact_lock", "operation_ref_read", "legacy_lineage", "allowance_lock", "allowance_totals", "attempt_read", "allowance_spend", "attempt_insert", "COMMIT"} {
		for _, code := range []string{"40001", "40P01"} {
			t.Run(point+"/"+code, func(t *testing.T) {
				g := newResumeJournalFixture(t)
				_, op, _ := g.Prepared()
				a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "retry", resumeMaximum())
				if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
					t.Fatal(err)
				}
				if err := g.sql.Inject(resumeFixtureSQLFault{StatementID: point, OperationLabel: "reserve", Occurrence: 1, Err: &pgconn.PgError{Code: code}, CommitMode: resumeFixtureTestKnownAbort}); err != nil {
					t.Fatal(err)
				}
				r := resumeCurrentRequest(t, g, op, a, "retry-request")
				attempt, inserted, err := g.journal.ReserveErasureAttempt(g.Context("reserve"), op.Ref(), a, r, g.clock.Value())
				if err != nil || !inserted {
					t.Fatal("known abort did not retry", err)
				}
				resumeAssertAttempt(t, attempt, r, 1, g.clock.Value())
				if n := g.sql.beginCount("reserve"); n < 2 || n > 3 {
					t.Fatal("retry bound", n)
				}
				snap := g.sql.Snapshot()
				if len(snap.Rows[resumeAttempts]) != 1 || resumeFixtureSQLInt(snap.Rows[resumeAllowances][0], "spent_requests") != 1 {
					t.Fatal("retry duplicate spend")
				}
				g.sql.AssertClean(t)
			})
		}
	}
	for _, mode := range []string{"persist-lost", "not-persisted", "rollback-lost", "retry-exhausted"} {
		t.Run(mode, func(t *testing.T) {
			g := newResumeJournalFixture(t)
			_, op, _ := g.Prepared()
			a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "outcome", resumeMaximum())
			if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
				t.Fatal(err)
			}
			fault := resumeFixtureSQLFault{StatementID: "COMMIT", OperationLabel: "reserve", Occurrence: 1, Err: io.EOF, CommitMode: resumeFixtureTestPersistThenLose}
			switch mode {
			case "not-persisted":
				fault.CommitMode = resumeFixtureTestLoseWithoutPersist
			case "rollback-lost":
				fault.StatementID = "attempt_insert"
				fault.Err = &pgconn.PgError{Code: "40001"}
				fault.RollbackErr = io.EOF
			case "retry-exhausted":
				fault.Err = &pgconn.PgError{Code: "40P01"}
				fault.CommitMode = resumeFixtureTestKnownAbort
			}
			repeats := 1
			if mode == "retry-exhausted" {
				repeats = 3
			}
			for i := 0; i < repeats; i++ {
				if err := g.sql.Inject(fault); err != nil {
					t.Fatal(err)
				}
			}
			r := resumeCurrentRequest(t, g, op, a, "uncertain-reservation")
			out, inserted, err := g.journal.ReserveErasureAttempt(g.Context("reserve"), op.Ref(), a, r, g.clock.Value())
			if err == nil || inserted || out.Identity() != "" {
				t.Fatal("unknown/aborted reservation returned output")
			}
			if mode != "retry-exhausted" && !errors.Is(err, artifact.ErrErasureUnknownOutcome) {
				t.Fatal("uncertain outcome classification", err)
			}
			if g.sql.beginCount("reserve") > 3 {
				t.Fatal("unbounded retry")
			}
			before := len(g.peer.Events())
			got, _, found, readErr := g.journal.ReadErasureAttempt(g.Context("readback"), op.Ref(), r.ReservationIdentity())
			if readErr != nil {
				t.Fatal(readErr)
			}
			if (mode == "persist-lost") != found {
				t.Fatal("durable lost-commit state")
			}
			if found {
				resumeAssertAttempt(t, got, r, 1, g.clock.Value())
				again, inserted, err := g.journal.ReserveErasureAttempt(g.Context("no-replay"), op.Ref(), a, r, g.clock.Value())
				if err != nil || inserted || again.Identity() != got.Identity() {
					t.Fatal("readback revived insertion", err)
				}
			}
			if len(g.peer.Events()) != before {
				t.Fatal("reservation or readback dispatched")
			}
		})
	}
}
func TestResumeJournalAtomicUncertaintyAndRetainedHistory(t *testing.T) {
	for _, code := range []artifact.AttemptResponseCode{artifact.AttemptResponseUnavailable, artifact.AttemptResponseMalformed} {
		for _, mode := range []string{"known", "unknown-first-fails", "response-fails", "persist-lost", "earlier-unknown"} {
			t.Run(code.String()+"/"+mode, func(t *testing.T) {
				g := newResumeJournalFixture(t)
				_, op, _ := g.Prepared()
				a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "atomic", resumeMaximum())
				if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
					t.Fatal(err)
				}
				r := resumeCurrentRequest(t, g, op, a, "response")
				attempt, inserted, err := g.journal.ReserveErasureAttempt(g.Context("reserve"), op.Ref(), a, r, g.clock.Value())
				if err != nil || !inserted {
					t.Fatal(err)
				}
				at := g.clock.Value()
				var earlier artifact.ErasureEvidence
				if mode == "earlier-unknown" {
					earlier, err = artifact.NewAttemptUnknownEvidence(attempt, at)
					if err != nil {
						t.Fatal(err)
					}
					if _, _, err := g.journal.RecordErasureEvidence(g.Context("earlier"), op.Ref(), earlier); err != nil {
						t.Fatal(err)
					}
					at = at.Add(time.Millisecond)
					g.clock.Set(at)
				}
				response, err := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: attempt, Code: code, ObservedAt: at})
				if err != nil {
					t.Fatal(err)
				}
				if mode == "unknown-first-fails" || mode == "response-fails" {
					n := 1
					if mode == "response-fails" {
						n = 2
					}
					if err := g.sql.Inject(resumeFixtureSQLFault{StatementID: "evidence_insert", OperationLabel: "record", Occurrence: n, Err: errors.New("synthetic insert failure")}); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "persist-lost" {
					if err := g.sql.Inject(resumeFixtureSQLFault{StatementID: "COMMIT", OperationLabel: "record", Occurrence: 1, Err: io.EOF, CommitMode: resumeFixtureTestPersistThenLose}); err != nil {
						t.Fatal(err)
					}
				}
				got, inserted, err := g.journal.RecordErasureEvidence(g.Context("record"), op.Ref(), response)
				success := mode == "known" || mode == "earlier-unknown"
				if success {
					if err != nil || !inserted || got.Identity() != response.Identity() {
						t.Fatal(err)
					}
				} else if err == nil || inserted || got.Identity() != "" {
					t.Fatal("failed evidence record released output")
				}
				rows := g.sql.Snapshot().Rows[resumeEvidence]
				durable := success || mode == "persist-lost"
				if durable && len(rows) != 2 || !durable && len(rows) != 0 {
					t.Fatal("uncertain response not atomic")
				}
				if durable {
					_, ev, found, err := g.journal.ReadErasureAttempt(g.Context("read"), op.Ref(), r.ReservationIdentity())
					if err != nil || !found || len(ev) != 2 {
						t.Fatal("full uncertainty closure", err)
					}
					if mode == "earlier-unknown" {
						kept := false
						for _, e := range ev {
							kept = kept || e.Identity() == earlier.Identity()
						}
						if !kept {
							t.Fatal("earlier unknown overwritten")
						}
					}
					result, inserted, err := g.journal.RecordErasureEvidence(g.Context("duplicate"), op.Ref(), response)
					if err != nil || inserted || result.Identity() != response.Identity() {
						t.Fatal("duplicate uncertain response", err)
					}
					if err := g.sql.DropExistingForFault(resumeEvidence, "kind", "unknown", "uncertain response missing counterpart"); err != nil {
						t.Fatal(err)
					}
					out, ev, found, err := g.journal.ReadErasureAttempt(g.Context("corrupt"), op.Ref(), r.ReservationIdentity())
					if err == nil || found || len(ev) != 0 || out.Identity() != "" {
						t.Fatal("uncertain response alone accepted")
					}
				}
			})
		}
	}
}
func TestResumeJournalLookaheadClosureAndPointBounds(t *testing.T) {
	for _, distinct := range []bool{false, true} {
		for _, count := range []int{65, 129} {
			t.Run(fmt.Sprintf("distinct=%t/count=%d", distinct, count), func(t *testing.T) {
				g := newResumeJournalFixture(t)
				_, op, _ := g.Prepared()
				a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "shared", resumeMaximum())
				if !distinct {
					if _, err := g.journal.AdmitResumeAllowance(g.Context("admit-shared"), op.Ref(), a, g.clock.Value()); err != nil {
						t.Fatal(err)
					}
				}
				for i := 0; i < count; i++ {
					active := g
					allowance := a
					if distinct {
						policy := resumePolicy(t, g.sql.catalog, g.backend, g.clock.Value(), map[string]any{"configuration_evidence_identity": resumeHash([]byte(fmt.Sprintf("policy-%03d", i)))})
						active = newResumeJournalGraph(t, g.sql, g.peer, g.value, policy, g.clock.Value(), fmt.Sprintf("graph-%03d", i))
						allowance, _, _ = resumeAllowance(t, policy, op, g.clock.Value(), fmt.Sprintf("allowance-%03d", i), resumeMaximum())
						if _, err := active.journal.AdmitResumeAllowance(active.Context("admit"), op.Ref(), allowance, active.clock.Value()); err != nil {
							t.Fatal(err)
						}
					}
					r := resumeCurrentRequest(t, active, op, allowance, fmt.Sprintf("unrecorded-%03d", i))
					attempt, inserted, err := active.journal.ReserveErasureAttempt(active.Context("reserve"), op.Ref(), allowance, r, active.clock.Value())
					if err != nil || !inserted || attempt.Identity() == "" {
						t.Fatal("actual reservation", err)
					}
				}
				before := len(g.sql.Snapshot().Events)
				revision := g.sql.Snapshot().Revision
				wire := len(g.peer.Events())
				p, found, err := g.journal.ReadErasureProgress(g.Context("bounded-progress"), op.Ref(), "")
				if err != nil || !found || p.Validate() != nil || len(p.UnrecordedUncertainty()) != 64 || !p.UncertaintyBookkeepingMore() {
					t.Fatal("65th lookahead rejected", err)
				}
				if g.sql.Snapshot().Revision != revision || len(g.peer.Events()) != wire {
					t.Fatal("progress performed bookkeeping or remote work")
				}
				points := 0
				perAttemptAbsence := 0
				for _, e := range g.sql.Snapshot().Events[before:] {
					if e.Kind == "statement" && strings.HasPrefix(g.sql.registry[e.StatementID].SQL, "SELECT ") && e.StatementID != "tenant_guc" && e.StatementID != "unrecorded_uncertainty_page" {
						points++
					}
					if e.StatementID == "evidence_attempt_read" {
						perAttemptAbsence++
					}
				}
				if points > 192 || perAttemptAbsence != 0 {
					t.Fatal("point lookup budget or redundant negative-selection reads", points, perAttemptAbsence)
				}
				if distinct && 2*len(p.Attempts())+len(p.Allowances())+len(p.AcceptedPolicyBytes()) <= 192 {
					t.Fatal("distinct policies and requests were omitted from closure")
				}
				for _, a := range p.Attempts() {
					if a.Request().Validate() != nil {
						t.Fatal("request preimage missing")
					}
				}
				// Row65 must be validated before it is dropped from the returned carrier.
				rows := g.sql.Snapshot().Rows[resumeAttempts]
				sortResumeRows(rows, "attempt_identity")
				lookahead := rows[64]
				pk := resumeFixtureTuple(lookahead, []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "reservation_identity"})
				if err := g.sql.CorruptExistingRow(resumeAttempts, pk, "canonical_request", []byte("invalid lookahead request")); err != nil {
					t.Fatal(err)
				}
				invalid, found, err := g.journal.ReadErasureProgress(g.Context("corrupt-lookahead"), op.Ref(), "")
				if err == nil || found || invalid.Operation().Identity() != "" {
					t.Fatal("unvalidated row65")
				}
			})
		}
	}
}
func sortResumeRows(rows []resumeFixtureRow, column string) {
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && resumeFixtureSQLText(rows[j], column) < resumeFixtureSQLText(rows[j-1], column); j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
}
func TestResumeJournalImmutableColumnsAndReadFailures(t *testing.T) {
	for _, column := range []string{"scope_identity", "namespace_identity", "artifact_identity", "admission_identity", "operation_identity", "allowance_identity", "request_identity", "canonical_request", "canonical_attempt", "sequence", "reserved_at_milliseconds", "cost_requests", "cost_response_bytes"} {
		t.Run(column, func(t *testing.T) {
			g := newResumeJournalFixture(t)
			_, op, _ := g.Prepared()
			a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "corrupt", resumeMaximum())
			if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
				t.Fatal(err)
			}
			r := resumeCurrentRequest(t, g, op, a, "corrupt-request")
			if _, inserted, err := g.journal.ReserveErasureAttempt(g.Context("reserve"), op.Ref(), a, r, g.clock.Value()); err != nil || !inserted {
				t.Fatal(err)
			}
			row := g.sql.Snapshot().Rows[resumeAttempts][0]
			pk := resumeFixtureTuple(row, []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "reservation_identity"})
			var replacement driver.Value
			switch v := row[column].(type) {
			case string:
				replacement = strings.Repeat("f", 64)
			case []byte:
				replacement = []byte("invalid canonical record")
			case int64:
				replacement = v + 1
			}
			if err := g.sql.CorruptExistingRow(resumeAttempts, pk, column, replacement); err != nil {
				t.Fatal(err)
			}
			p, found, err := g.journal.ReadErasureProgress(g.Context("read-corrupt"), op.Ref(), a.Identity())
			if err == nil || found || p.Operation().Identity() != "" {
				t.Fatal("corrupt dependency produced metadata")
			}
		})
	}
	for _, mode := range []string{"Next", "Close", "COMMIT"} {
		t.Run(mode, func(t *testing.T) {
			g := newResumeJournalFixture(t)
			_, op, _ := g.Prepared()
			fault := resumeFixtureSQLFault{StatementID: "operation_ref_read", OperationLabel: "read", Occurrence: 1}
			switch mode {
			case "Next":
				fault.NextErr = io.ErrUnexpectedEOF
			case "Close":
				fault.CloseErr = io.ErrClosedPipe
			case "COMMIT":
				fault.StatementID = "COMMIT"
				fault.Err = io.EOF
			}
			if err := g.sql.Inject(fault); err != nil {
				t.Fatal(err)
			}
			p, found, err := g.journal.ReadErasureProgress(g.Context("read"), op.Ref(), "")
			if err == nil || found || p.Operation().Identity() != "" {
				t.Fatal("failed snapshot released progress")
			}
		})
	}
}

func TestResumeJournalRealFenceCandidateCASAndPublicationClosure(t *testing.T) {
	g := newResumeJournalFixture(t)
	admission, op, _ := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "journal-protocol", resumeMaximum())
	if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
		t.Fatal(err)
	}
	intentKey, err := artifact.NewExactObjectKey(op.NamespaceIdentity(), resumePrefix+"/deletions/"+op.Scope().Identity()+"/"+op.ArtifactIdentity()+".intent-v2")
	if err != nil {
		t.Fatal(err)
	}
	_, intentAbsent := resumeJournalRead(t, g, op, a, artifact.AttemptIntentRead, intentKey, "intent-absent")
	resumeJournalCreate(t, g, op, a, artifact.AttemptIntentCreate, intentKey, resumeOperationBytes(t, op), intentAbsent, "intent-create")
	resumeJournalRead(t, g, op, a, artifact.AttemptIntentRead, intentKey, "intent-full")
	readAttempt, current := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "current-payload")
	currentOptions, err := artifact.ParseAttemptResponseEvidence(current, readAttempt)
	if err != nil {
		t.Fatal(err)
	}
	deletion := resumeJournalReserve(t, g, op, a, artifact.AttemptRequestOptions{Kind: artifact.AttemptVersionDelete, Key: g.Key(), Version: currentOptions.Version, ObservationIdentity: current.Identity(), MaximumResponseBytes: 4096}, "delete-payload")
	outcome, err := g.backend.DeleteObjectVersion(g.Context("delete-payload"), g.Key(), resumeOwner, currentOptions.Version)
	if err != nil || outcome != artifact.VersionDeleteDeleted {
		t.Fatal("owned exact-version deletion", err)
	}
	deleted, err := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: deletion, Code: artifact.AttemptResponseDeleted, ObservedAt: g.clock.Value()})
	if err != nil {
		t.Fatal(err)
	}
	resumeJournalRecord(t, g, op, deleted)
	_, absent := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "current-absent")
	resumeJournalCreate(t, g, op, a, artifact.AttemptFenceCreate, g.Key(), resumeFenceBytes(t, op), absent, "create-fence")
	_, observed := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "read-fence")
	fence, err := artifact.NewFenceObservationEvidence(op, g.Key(), observed, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	wrongKey, err := artifact.NewExactObjectKey(op.NamespaceIdentity(), g.Key().Key()+".wrong")
	if err != nil {
		t.Fatal(err)
	}
	wrongFence, err := artifact.NewFenceObservationEvidence(op, wrongKey, observed, g.clock.Value())
	if err != nil {
		t.Fatal("valid metadata wrong-key fixture", err)
	}
	refused, inserted, err := g.journal.RecordErasureEvidence(g.Context("wrong-fence-key"), op.Ref(), wrongFence)
	if err == nil || inserted || refused.Identity() != "" {
		t.Fatal("fence record key differed from current request and derived key")
	}
	fence = resumeJournalRecord(t, g, op, fence)
	g.clock.Set(g.clock.Value().Add(time.Millisecond))
	laterFence, err := artifact.NewFenceObservationEvidence(op, g.Key(), observed, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	winner, inserted, err := g.journal.RecordErasureEvidence(g.Context("fence-cas"), op.Ref(), laterFence)
	if err != nil || inserted || winner.Identity() != fence.Identity() || !winner.ObservedAt().Equal(fence.ObservedAt()) {
		t.Fatal("same token fence did not adopt original winner", err)
	}
	_, list := resumeJournalList(t, g, op, a, "terminal-list", 2, artifact.VersionCursor{})
	_, full := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "terminal-current")
	verification, err := artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{list}, full, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	verified, err := artifact.NewVerificationEvidence(verification)
	if err != nil {
		t.Fatal(err)
	}
	resumeJournalRecord(t, g, op, verified)
	candidate, err := artifact.NewAttestationCandidateEvidence(op, admission, g.policy, verification)
	if err != nil {
		t.Fatal(err)
	}
	candidate = resumeJournalRecord(t, g, op, candidate)
	g.clock.Set(g.clock.Value().Add(time.Millisecond))
	_, list2 := resumeJournalList(t, g, op, a, "second-terminal-list", 2, artifact.VersionCursor{})
	_, full2 := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "second-terminal-current")
	secondVerification, err := artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{list2}, full2, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	secondVerified, err := artifact.NewVerificationEvidence(secondVerification)
	if err != nil {
		t.Fatal(err)
	}
	resumeJournalRecord(t, g, op, secondVerified)
	secondCandidate, err := artifact.NewAttestationCandidateEvidence(op, admission, g.policy, secondVerification)
	if err != nil {
		t.Fatal(err)
	}
	winner, inserted, err = g.journal.RecordErasureEvidence(g.Context("candidate-cas"), op.Ref(), secondCandidate)
	if err != nil || inserted || winner.Identity() != candidate.Identity() || !bytes.Equal(winner.RecordBytes(), candidate.RecordBytes()) {
		t.Fatal("candidate winner changed", err)
	}
	key, err := artifact.NewExactObjectKey(g.policy.NamespaceIdentity(), resumePrefix+"/deletions/"+g.scope.Identity()+"/"+g.value.Identity()+".attestation-v2")
	if err != nil {
		t.Fatal(err)
	}
	_, proofAbsent := resumeJournalRead(t, g, op, a, artifact.AttemptAttestationRead, key, "proof-absent")
	resumeJournalCreate(t, g, op, a, artifact.AttemptAttestationCreate, key, candidate.RecordBytes(), proofAbsent, "proof-create")
	_, proof := resumeJournalRead(t, g, op, a, artifact.AttemptAttestationRead, key, "proof-full-read")
	publication, err := artifact.NewAttestationPublicationEvidence(candidate, proof, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	publication = resumeJournalRecord(t, g, op, publication)
	progress, found, err := g.journal.ReadErasureProgress(g.Context("complete-closure"), op.Ref(), a.Identity())
	if err != nil || !found || progress.Validate() != nil {
		t.Fatal("durable publication closure", err)
	}
	got, ok := progress.Published()
	if !ok || got.Identity() != publication.Identity() {
		t.Fatal("publication preimage missing")
	}
	got, ok = progress.Candidate()
	if !ok || got.Identity() != candidate.Identity() {
		t.Fatal("original candidate missing")
	}
	for _, response := range []artifact.ErasureEvidence{observed, list, full, proof} {
		present := false
		for _, e := range progress.Evidence() {
			present = present || e.Identity() == response.Identity()
		}
		if !present {
			t.Fatal("mandatory evidence dependency omitted")
		}
	}
}

func TestResumeJournalEscapedXMLResponseAdoptionIsAtomic(t *testing.T) {
	g := newResumeJournalFixture(t)
	_, op, _ := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "escaped-xml", resumeMaximum())
	if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		g.peer.AddOpaqueHistory(t, g.Key().Key(), strings.Repeat("&", 496)+fmt.Sprintf("%08d", i), false, []byte("synthetic historical ciphertext"))
	}
	attempt := resumeJournalReserve(t, g, op, a, artifact.AttemptRequestOptions{Kind: artifact.AttemptVersionList, Key: g.Key(), PageLimit: 256, MaximumResponseBytes: 1 << 20}, "large-list")
	page, err := g.backend.ListObjectVersions(g.Context("large-list"), g.Key(), resumeOwner, artifact.VersionCursor{}, 256, 1<<20)
	if err != nil || len(page.Entries) != 256 || page.ResponseBytes > 1<<20 {
		t.Fatal("valid bounded owned XML page", err)
	}
	events := g.peer.Events()
	wire := events[len(events)-1]
	independent := resumePageFromWire(t, g.Key(), wire.ResponseBody)
	if !reflect.DeepEqual(page, independent) || len(wire.ResponseBody) != int(page.ResponseBytes) {
		t.Fatal("independent page observations differ")
	}
	expected := resumeIndependentResponse(t, op, attempt, independent, g.clock.Value())
	if len(expected) <= 262144 {
		t.Fatal("fixture did not exceed inner canonical cap")
	}
	refused, err := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: attempt, Code: artifact.AttemptResponsePresent, ObservedAt: g.clock.Value(), Page: page, ResponseBytes: page.ResponseBytes})
	if err == nil || refused.Identity() != "" {
		t.Fatal("unencodable page was truncated or accepted")
	}
	before := resumeFixtureCopyTables(g.sql.Snapshot().Rows)
	malformed, err := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: attempt, Code: artifact.AttemptResponseMalformed, ObservedAt: g.clock.Value()})
	if err != nil {
		t.Fatal(err)
	}
	resumeJournalRecord(t, g, op, malformed)
	_, evidence, found, err := g.journal.ReadErasureAttempt(g.Context("read-uncertainty"), op.Ref(), attempt.Request().ReservationIdentity())
	if err != nil || !found || len(evidence) != 2 {
		t.Fatal("atomic malformed and unknown", err)
	}
	kinds := map[string]bool{}
	for _, e := range evidence {
		kinds[e.Kind()] = true
	}
	if !kinds["unknown"] || !kinds["response"] {
		t.Fatal("uncertain response missing counterpart")
	}
	after := g.sql.Snapshot().Rows
	if !reflect.DeepEqual(before[resumeAllowances], after[resumeAllowances]) || !reflect.DeepEqual(before[resumeAttempts], after[resumeAttempts]) {
		t.Fatal("response encoding failure refunded spending")
	}
	if len(g.peer.Events()) != len(events) || len(g.peer.History(g.Key().Key())) != 257 {
		t.Fatal("refused page caused mutation")
	}
}

func TestResumeJournalConcurrentAllowanceCannotOverspend(t *testing.T) {
	first := newResumeJournalFixture(t)
	_, op, _ := first.Prepared()
	maximum := artifact.ResumeBudget{Requests: 1, Reads: 1, ResponseBytes: 4097}
	a, path, _ := resumeAllowance(t, first.policy, op, first.clock.Value(), "shared-race", maximum)
	if _, err := first.journal.AdmitResumeAllowance(first.Context("admit"), op.Ref(), a, first.clock.Value()); err != nil {
		t.Fatal(err)
	}
	second := newResumeJournalGraph(t, first.sql, first.peer, first.value, first.policy, first.clock.Value(), "second")
	b, err := artifact.LoadResumeAllowance(context.Background(), path, second.policy, second.scope)
	if err != nil {
		t.Fatal(err)
	}
	entered, release, competing := make(chan struct{}), make(chan struct{}), make(chan struct{})
	if err := first.sql.Inject(resumeFixtureSQLFault{StatementID: "allowance_spend", OperationLabel: "reserve-first", Occurrence: 1, Entered: entered, Release: release}); err != nil {
		t.Fatal(err)
	}
	if err := first.sql.Inject(resumeFixtureSQLFault{StatementID: "artifact_lock", OperationLabel: "reserve-second", Occurrence: 1, Entered: competing}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	type reply struct {
		attempt  artifact.ErasureAttempt
		inserted bool
		err      error
	}
	one, two := make(chan reply, 1), make(chan reply, 1)
	workers := newResumeWorkers(t)
	r1 := resumeCurrentRequest(t, first, op, a, "concurrent-one")
	r2 := resumeCurrentRequest(t, second, op, b, "concurrent-two")
	c1, c2 := first.Context("reserve-first"), second.Context("reserve-second")
	workers.Start(c1, func(ctx context.Context) {
		a, inserted, err := first.journal.ReserveErasureAttempt(ctx, op.Ref(), a, r1, first.clock.Value())
		one <- reply{a, inserted, err}
	})
	wait := func(ch <-chan struct{}) {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case <-ch:
		case <-timer.C:
			t.Fatal("SQL barrier")
		}
	}
	wait(entered)
	workers.Start(c2, func(ctx context.Context) {
		a, inserted, err := second.journal.ReserveErasureAttempt(ctx, op.Ref(), b, r2, second.clock.Value())
		two <- reply{a, inserted, err}
	})
	wait(competing)
	close(release)
	receive := func(ch <-chan reply) reply {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		select {
		case r := <-ch:
			return r
		case <-timer.C:
			t.Fatal("SQL worker did not join")
			return reply{}
		}
	}
	winner, loser := receive(one), receive(two)
	if winner.err != nil || !winner.inserted {
		t.Fatal("first reservation", winner.err)
	}
	if !errors.Is(loser.err, artifact.ErrErasureAllowanceExhausted) || loser.inserted || loser.attempt.Identity() != "" {
		t.Fatal("concurrent overspend", loser.err)
	}
	snapshot := first.sql.Snapshot()
	if len(snapshot.Rows[resumeAttempts]) != 1 || resumeFixtureSQLInt(snapshot.Rows[resumeAllowances][0], "spent_requests") != 1 {
		t.Fatal("concurrent spending not serialized")
	}
	first.sql.AssertClean(t)
}
func TestResumeJournalMissingReadsAndAlternateKeys(t *testing.T) {
	g := newResumeJournalFixture(t)
	_, op, _ := g.Prepared()
	missing, err := artifact.NewErasureOperationRef(op.Scope(), op.NamespaceIdentity(), strings.Repeat("f", 64))
	if err != nil {
		t.Fatal(err)
	}
	p, found, err := g.journal.ReadErasureProgress(g.Context("missing-operation"), missing, "")
	if err != nil || found || p.Operation().Identity() != "" {
		t.Fatal("missing operation output", err)
	}
	out, evidence, found, err := g.journal.ReadErasureAttempt(g.Context("missing-attempt"), op.Ref(), strings.Repeat("f", 64))
	if err != nil || found || out.Identity() != "" || evidence != nil {
		t.Fatal("missing attempt output", err)
	}
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "alternate-keys", resumeMaximum())
	if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []artifact.AttemptKind{artifact.AttemptCurrentRead, artifact.AttemptIntentRead, artifact.AttemptAttestationRead, artifact.AttemptVersionList} {
		key, err := artifact.NewExactObjectKey(op.NamespaceIdentity(), "resume-fixture/unauthorized")
		if err != nil {
			t.Fatal(err)
		}
		options := artifact.AttemptRequestOptions{ReservationIdentity: resumeHash([]byte(kind.String())), Operation: op, Allowance: a, Kind: kind, Key: key, MaximumResponseBytes: 4096}
		if kind == artifact.AttemptVersionList {
			options.PageLimit = 2
		}
		request, err := artifact.NewAttemptRequest(options)
		if err != nil {
			t.Fatal(err)
		}
		before := g.sql.Snapshot().Revision
		out, inserted, err := g.journal.ReserveErasureAttempt(g.Context(kind.String()), op.Ref(), a, request, g.clock.Value())
		if err == nil || inserted || out.Identity() != "" || g.sql.Snapshot().Revision != before {
			t.Fatal("alternate key acquired reservation")
		}
	}
}

func TestResumeJournalEveryCostDimensionExactAndOneShort(t *testing.T) {
	for dimension, name := range resumeDimensions {
		for _, short := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/one-short=%t", name, short), func(t *testing.T) {
				g := newResumeJournalFixture(t)
				_, op, _ := g.Prepared()
				options := artifact.AttemptRequestOptions{Kind: artifact.AttemptCurrentRead, Key: g.Key(), MaximumResponseBytes: 4096}
				if dimension == 3 || dimension == 6 || dimension == 7 || dimension == 9 {
					options.Kind = artifact.AttemptVersionList
					options.PageLimit = 2
				}
				if dimension == 1 || dimension == 4 || dimension == 10 {
					observer, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "observation-budget", resumeMaximum())
					if _, err := g.journal.AdmitResumeAllowance(g.Context("admit-observer"), op.Ref(), observer, g.clock.Value()); err != nil {
						t.Fatal(err)
					}
					key, err := artifact.NewExactObjectKey(op.NamespaceIdentity(), resumePrefix+"/deletions/"+g.scope.Identity()+"/"+g.value.Identity()+".intent-v2")
					if err != nil {
						t.Fatal(err)
					}
					_, observation := resumeJournalRead(t, g, op, observer, artifact.AttemptIntentRead, key, "observe-absence")
					body := resumeOperationBytes(t, op)
					options.Kind = artifact.AttemptIntentCreate
					options.Key = key
					options.BodyBytes = uint32(len(body))
					options.BodyDigest = resumeHash(body)
					options.ObservationIdentity = observation.Identity()
				}
				if dimension == 5 {
					observer, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "deletion-observation", resumeMaximum())
					if _, err := g.journal.AdmitResumeAllowance(g.Context("admit-observer"), op.Ref(), observer, g.clock.Value()); err != nil {
						t.Fatal(err)
					}
					attempt, observation := resumeJournalRead(t, g, op, observer, artifact.AttemptCurrentRead, g.Key(), "observe-current")
					decoded, err := artifact.ParseAttemptResponseEvidence(observation, attempt)
					if err != nil {
						t.Fatal(err)
					}
					options.Kind = artifact.AttemptVersionDelete
					options.Version = decoded.Version
					options.ObservationIdentity = observation.Identity()
				}
				// The expected request price comes from the frozen eleven-component cost equation.
				price := artifact.ResumeBudget{Requests: 1, Reads: 1, ResponseBytes: 4097}
				switch options.Kind {
				case artifact.AttemptVersionList:
					price = artifact.ResumeBudget{Requests: 1, Lists: 1, Pages: 1, Versions: 2, ResponseBytes: 4097, ListBytes: 4097}
				case artifact.AttemptIntentCreate:
					price = artifact.ResumeBudget{Requests: 1, Mutations: 1, Creates: 1, ResponseBytes: 4097, WriteBytes: uint64(options.BodyBytes)}
				case artifact.AttemptVersionDelete:
					price = artifact.ResumeBudget{Requests: 1, Mutations: 1, Deletes: 1, ResponseBytes: 4097}
				}
				wanted := resumeBudgetVector(price)[dimension]
				maximum := resumeBudgetVector(resumeMaximum())
				maximum[dimension] = wanted
				if short && dimension != 0 {
					maximum[dimension]--
				}
				if dimension == 0 {
					maximum[1] = 1
				}
				allowance, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "exact-price", resumeBudgetFrom(maximum))
				if _, err := g.journal.AdmitResumeAllowance(g.Context("admit-priced"), op.Ref(), allowance, g.clock.Value()); err != nil {
					t.Fatal(err)
				}
				options.Operation = op
				options.Allowance = allowance
				options.ReservationIdentity = resumeHash([]byte("priced-request"))
				request, err := artifact.NewAttemptRequest(options)
				if err != nil {
					t.Fatal(err)
				}
				attempt, inserted, err := g.journal.ReserveErasureAttempt(g.Context("reserve-priced"), op.Ref(), allowance, request, g.clock.Value())
				if short && dimension != 0 {
					if !errors.Is(err, artifact.ErrErasureAllowanceExhausted) || inserted || attempt.Identity() != "" {
						t.Fatal("request one unit above independent ceiling", err)
					}
				} else {
					if err != nil || !inserted {
						t.Fatal("exact boundary refused", err)
					}
					resumeAssertAttempt(t, attempt, request, 1, g.clock.Value())
					if short {
						options.ReservationIdentity = resumeHash([]byte("second-priced-request"))
						next, err := artifact.NewAttemptRequest(options)
						if err != nil {
							t.Fatal(err)
						}
						out, inserted, err := g.journal.ReserveErasureAttempt(g.Context("one-request-over"), op.Ref(), allowance, next, g.clock.Value())
						if !errors.Is(err, artifact.ErrErasureAllowanceExhausted) || inserted || out.Identity() != "" {
							t.Fatal("request ceiling plus one", err)
						}
					}
				}
				usage, err := g.journal.AdmitResumeAllowance(g.Context("priced-usage"), op.Ref(), allowance, g.clock.Value())
				if err != nil {
					t.Fatal(err)
				}
				expected := price
				if short && dimension != 0 {
					expected = artifact.ResumeBudget{}
				}
				if usage.Spent != expected {
					t.Fatal("independent eleven-vector spending or no-refund mismatch")
				}
			})
		}
	}
}

func TestResumeJournalPointBudgetRefusesCompleteWideObservationClosure(t *testing.T) {
	g := newResumeJournalFixture(t)
	_, op, _ := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "mutation-closure", resumeMaximum())
	if _, err := g.journal.AdmitResumeAllowance(g.Context("admit-mutations"), op.Ref(), a, g.clock.Value()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 64; i++ {
		policy := resumePolicy(t, g.sql.catalog, g.backend, g.clock.Value(), map[string]any{"configuration_evidence_identity": resumeHash([]byte(fmt.Sprintf("observation-policy-%d", i)))})
		observer := newResumeJournalGraph(t, g.sql, g.peer, g.value, policy, g.clock.Value(), fmt.Sprintf("observation-graph-%d", i))
		allowance, _, _ := resumeAllowance(t, policy, op, g.clock.Value(), fmt.Sprintf("observation-allowance-%d", i), resumeMaximum())
		if _, err := observer.journal.AdmitResumeAllowance(observer.Context("admit"), op.Ref(), allowance, observer.clock.Value()); err != nil {
			t.Fatal(err)
		}
		observedAttempt, response := resumeJournalRead(t, observer, op, allowance, artifact.AttemptCurrentRead, observer.Key(), fmt.Sprintf("observe-%d", i))
		options, err := artifact.ParseAttemptResponseEvidence(response, observedAttempt)
		if err != nil {
			t.Fatal(err)
		}
		resumeJournalReserve(t, g, op, a, artifact.AttemptRequestOptions{Kind: artifact.AttemptVersionDelete, Key: g.Key(), Version: options.Version, ObservationIdentity: response.Identity(), MaximumResponseBytes: 4096}, fmt.Sprintf("unrecorded-delete-%d", i))
		if i == 7 {
			p, found, err := g.journal.ReadErasureProgress(g.Context("small-complete-closure"), op.Ref(), "")
			if err != nil || !found || len(p.UnrecordedUncertainty()) != 8 {
				t.Fatal("small valid observation closure", err)
			}
		}
	}
	before := len(g.sql.Snapshot().Events)
	wire := len(g.peer.Events())
	revision := g.sql.Snapshot().Revision
	p, found, err := g.journal.ReadErasureProgress(g.Context("wide-closure"), op.Ref(), "")
	if err == nil || found || p.Operation().Identity() != "" {
		t.Fatal("wide closure returned partial metadata")
	}
	points := 0
	for _, e := range g.sql.Snapshot().Events[before:] {
		if e.Kind == "statement" && strings.HasPrefix(g.sql.registry[e.StatementID].SQL, "SELECT ") && e.StatementID != "tenant_guc" && e.StatementID != "unrecorded_uncertainty_page" {
			points++
		}
	}
	if points > 192 || g.sql.Snapshot().Revision != revision || len(g.peer.Events()) != wire {
		t.Fatal("point limit released work or exceeded query ceiling", points)
	}
}
func TestResumeJournalCanonicalByteBudgetIsNotACollectionLimit(t *testing.T) {
	g := newResumeJournalFixture(t)
	_, op, _ := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "large-closure", resumeMaximum())
	if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 256; i++ {
		g.peer.AddOpaqueHistory(t, g.Key().Key(), fmt.Sprintf("%08d%s", i, strings.Repeat("v", 482)), false, []byte("synthetic historical payload"))
	}
	g.peer.AddHistory(t, g.Key().Key(), true, nil)
	_, marker := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "marker")
	resumeJournalCreate(t, g, op, a, artifact.AttemptFenceCreate, g.Key(), resumeFenceBytes(t, op), marker, "fence")
	_, current := resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "fence-read")
	fence, err := artifact.NewFenceObservationEvidence(op, g.Key(), current, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	resumeJournalRecord(t, g, op, fence)
	for i := 0; i < 32; i++ {
		label := fmt.Sprintf("large-observation-%d", i)
		attempt := resumeJournalReserve(t, g, op, a, artifact.AttemptRequestOptions{Kind: artifact.AttemptVersionList, Key: g.Key(), PageLimit: 256, MaximumResponseBytes: 1 << 20}, label)
		page, err := g.backend.ListObjectVersions(g.Context(label), g.Key(), resumeOwner, artifact.VersionCursor{}, 256, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		expected := resumeIndependentResponse(t, op, attempt, page, g.clock.Value())
		if len(expected) > 262144 {
			t.Fatal("individual canonical response must fit")
		}
		response, err := artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: attempt, Code: artifact.AttemptResponsePresent, ObservedAt: g.clock.Value(), Page: page, ResponseBytes: page.ResponseBytes})
		if err != nil {
			t.Fatal(err)
		}
		response = resumeJournalRecord(t, g, op, response)
		target := page.Entries[2].Version
		resumeJournalReserve(t, g, op, a, artifact.AttemptRequestOptions{Kind: artifact.AttemptVersionDelete, Key: g.Key(), Version: target, ObservationIdentity: response.Identity(), MaximumResponseBytes: 4096}, fmt.Sprintf("pending-delete-%d", i))
		if i == 23 {
			p, found, err := g.journal.ReadErasureProgress(g.Context("bounded-large-closure"), op.Ref(), "")
			if err != nil || !found || len(p.UnrecordedUncertainty()) != 24 {
				t.Fatal("valid sub8MiB closure refused", err)
			}
		}
	}
	before := len(g.peer.Events())
	p, found, err := g.journal.ReadErasureProgress(g.Context("over8MiB-closure"), op.Ref(), "")
	if err == nil || found || p.Operation().Identity() != "" || len(g.peer.Events()) != before {
		t.Fatal("over8MiB closure produced partial metadata or work")
	}
}

func TestResumeJournalTerminalRequestInputsAreNotResponseShape(t *testing.T) {
	for _, mode := range []string{"fresh", "limit-three", "nonempty-cursor", "list-reserved-before-fence", "current-reserved-before-list"} {
		t.Run(mode, func(t *testing.T) {
			g, admission, op, a, fenceRead := resumeJournalFenceInput(t)
			at := g.clock.Value()
			var fence, list, current artifact.ErasureEvidence
			var err error
			var earlyCurrent artifact.ErasureAttempt
			var object artifact.ErasureObjectRead
			if mode == "list-reserved-before-fence" {
				attempt := resumeJournalReserve(t, g, op, a, artifact.AttemptRequestOptions{Kind: artifact.AttemptVersionList, Key: g.Key(), PageLimit: 2, MaximumResponseBytes: 4096}, "early-list")
				page, err := g.backend.ListObjectVersions(g.Context("early-list"), g.Key(), resumeOwner, artifact.VersionCursor{}, 2, 4096)
				if err != nil {
					t.Fatal(err)
				}
				g.clock.Set(at.Add(time.Millisecond))
				fence, err = artifact.NewFenceObservationEvidence(op, g.Key(), fenceRead, g.clock.Value())
				if err != nil {
					t.Fatal(err)
				}
				fence = resumeJournalRecord(t, g, op, fence)
				g.clock.Set(at.Add(2 * time.Millisecond))
				list, err = artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: attempt, Code: artifact.AttemptResponsePresent, ObservedAt: g.clock.Value(), Page: page, ResponseBytes: page.ResponseBytes})
				if err != nil {
					t.Fatal(err)
				}
				list = resumeJournalRecord(t, g, op, list)
			} else {
				fence, err = artifact.NewFenceObservationEvidence(op, g.Key(), fenceRead, at)
				if err != nil {
					t.Fatal(err)
				}
				fence = resumeJournalRecord(t, g, op, fence)
				if mode == "current-reserved-before-list" {
					earlyCurrent = resumeJournalReserve(t, g, op, a, artifact.AttemptRequestOptions{Kind: artifact.AttemptCurrentRead, Key: g.Key(), MaximumResponseBytes: 4096}, "early-current")
					object, err = g.backend.ReadErasureObject(g.Context("early-current"), g.Key(), resumeOwner, 4096)
					if err != nil {
						t.Fatal(err)
					}
					g.clock.Set(at.Add(time.Millisecond))
				}
				limit := uint16(2)
				cursor := artifact.VersionCursor{}
				if mode == "limit-three" {
					limit = 3
				}
				if mode == "nonempty-cursor" {
					cursor = artifact.VersionCursor{KeyMarker: g.Key().Key(), VersionIDMarker: "synthetic-previous-cursor"}
					history := g.peer.History(g.Key().Key())
					if len(history) != 1 {
						t.Fatal("singleton fence fixture")
					}
					body := []byte(fmt.Sprintf("<ListVersionsResult><Name>%s</Name><Prefix>%s</Prefix><KeyMarker>%s</KeyMarker><VersionIdMarker>%s</VersionIdMarker><MaxKeys>2</MaxKeys><IsTruncated>false</IsTruncated><Version><Key>%s</Key><VersionId>%s</VersionId><IsLatest>true</IsLatest><Size>%d</Size></Version></ListVersionsResult>", resumeBucket, resumeXML(g.Key().Key()), resumeXML(cursor.KeyMarker), resumeXML(cursor.VersionIDMarker), resumeXML(g.Key().Key()), resumeXML(history[0].ID), len(history[0].Body)))
					g.peer.Fault(resumePeerFault{Graph: g.name, Method: "GET", Key: g.Key().Key(), ListOnly: true, Occurrence: 1, Body: body})
				}
				_, list = resumeJournalList(t, g, op, a, "list", limit, cursor)
			}
			if mode == "current-reserved-before-list" {
				g.clock.Set(at.Add(2 * time.Millisecond))
				version, err := artifact.NewObjectVersion(g.Key().NamespaceIdentity(), g.Key().Key(), artifact.ObjectVersionData, strings.TrimPrefix(object.Object.Version, "version:"))
				if err != nil {
					t.Fatal(err)
				}
				current, err = artifact.NewAttemptResponseEvidence(artifact.AttemptResponseOptions{Attempt: earlyCurrent, Code: artifact.AttemptResponsePresent, ObservedAt: g.clock.Value(), Version: version, ContentKind: "fence", ContentDigest: object.Object.Digest, CanonicalRecord: object.Object.Content, ResponseBytes: uint32(len(object.Object.Content))})
				if err != nil {
					t.Fatal(err)
				}
				current = resumeJournalRecord(t, g, op, current)
			} else {
				_, current = resumeJournalRead(t, g, op, a, artifact.AttemptCurrentRead, g.Key(), "fresh-current")
			}
			verification, err := artifact.NewErasureVerification(op, fence, []artifact.ErasureEvidence{list}, current, g.clock.Value())
			if err != nil {
				t.Fatal("valid response-shaped metadata", err)
			}
			evidence, err := artifact.NewVerificationEvidence(verification)
			if err != nil {
				t.Fatal(err)
			}
			got, inserted, err := g.journal.RecordErasureEvidence(g.Context("verify-inputs"), op.Ref(), evidence)
			if mode == "fresh" {
				if err != nil || !inserted || got.Identity() != evidence.Identity() {
					t.Fatal("fresh terminal verification", err)
				}
				candidate, err := artifact.NewAttestationCandidateEvidence(op, admission, g.policy, verification)
				if err != nil {
					t.Fatal(err)
				}
				resumeJournalRecord(t, g, op, candidate)
			} else if err == nil || inserted || got.Identity() != "" {
				t.Fatal("response shape hid invalid terminal request", mode)
			}
		})
	}
}

func TestResumeJournalAffectedCountsAndUncertainAllowanceAdmission(t *testing.T) {
	for _, statement := range []string{"allowance_spend", "attempt_insert"} {
		for _, count := range []int64{0, 2} {
			t.Run(fmt.Sprintf("%s/rows=%d", statement, count), func(t *testing.T) {
				g := newResumeJournalFixture(t)
				_, op, _ := g.Prepared()
				a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "affected", resumeMaximum())
				if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
					t.Fatal(err)
				}
				if err := g.sql.Inject(resumeFixtureSQLFault{StatementID: statement, OperationLabel: "reserve", Occurrence: 1, AffectedRows: &count}); err != nil {
					t.Fatal(err)
				}
				request := resumeCurrentRequest(t, g, op, a, "count-refusal")
				out, inserted, err := g.journal.ReserveErasureAttempt(g.Context("reserve"), op.Ref(), a, request, g.clock.Value())
				if err == nil || inserted || out.Identity() != "" {
					t.Fatal("non-one affected count released reservation")
				}
				snapshot := g.sql.Snapshot()
				if len(snapshot.Rows[resumeAttempts]) != 0 || resumeFixtureSQLInt(snapshot.Rows[resumeAllowances][0], "spent_requests") != 0 {
					t.Fatal("affected count failure committed staged spending")
				}
			})
		}
	}
	g := newResumeJournalFixture(t)
	_, op, _ := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "admission-unknown", resumeMaximum())
	if err := g.sql.Inject(resumeFixtureSQLFault{StatementID: "COMMIT", OperationLabel: "admit", Occurrence: 1, Err: io.EOF, CommitMode: resumeFixtureTestPersistThenLose}); err != nil {
		t.Fatal(err)
	}
	usage, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value())
	if !errors.Is(err, artifact.ErrErasureUnknownOutcome) || usage != (artifact.AllowanceUsage{}) {
		t.Fatal("uncertain allowance admission returned usage", err)
	}
	snapshot := g.sql.Snapshot()
	if len(snapshot.Rows[resumeAllowances]) != 1 || resumeFixtureSQLInt(snapshot.Rows[resumeAllowances][0], "spent_requests") != 0 {
		t.Fatal("persisted allowance admission state")
	}
	usage, err = g.journal.AdmitResumeAllowance(g.Context("reconcile-admission"), op.Ref(), a, g.clock.Value())
	if err != nil || usage != (artifact.AllowanceUsage{AllowanceIdentity: a.Identity(), NextSequence: 1}) || g.sql.Snapshot().Revision != snapshot.Revision {
		t.Fatal("admission reconciliation changed original row", err)
	}
}

func TestResumeJournalAllPublicErrorsResetOutputsAndRedactDriverText(t *testing.T) {
	for _, method := range []string{"admit", "reserve", "attempt", "page", "progress", "record"} {
		t.Run(method, func(t *testing.T) {
			g := newResumeJournalFixture(t)
			_, op, _ := g.Prepared()
			a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "redaction", resumeMaximum())
			var attempt artifact.ErasureAttempt
			if method != "admit" {
				if _, err := g.journal.AdmitResumeAllowance(g.Context("setup-admit"), op.Ref(), a, g.clock.Value()); err != nil {
					t.Fatal(err)
				}
			}
			request := resumeCurrentRequest(t, g, op, a, "redaction-request")
			if method != "admit" && method != "reserve" {
				var inserted bool
				var err error
				attempt, inserted, err = g.journal.ReserveErasureAttempt(g.Context("setup-reserve"), op.Ref(), a, request, g.clock.Value())
				if err != nil || !inserted {
					t.Fatal(err)
				}
			}
			statement := map[string]string{"admit": "allowance_insert", "reserve": "attempt_insert", "attempt": "attempt_read", "page": "attempt_page", "progress": "unrecorded_uncertainty_page", "record": "evidence_insert"}[method]
			if err := g.sql.Inject(resumeFixtureSQLFault{StatementID: statement, OperationLabel: "failure", Occurrence: 1, Err: errors.New("SYNTHETIC-DRIVER-SECRET must not escape")}); err != nil {
				t.Fatal(err)
			}
			ctx := g.Context("failure")
			var got error
			switch method {
			case "admit":
				usage, err := g.journal.AdmitResumeAllowance(ctx, op.Ref(), a, g.clock.Value())
				got = err
				if usage != (artifact.AllowanceUsage{}) {
					t.Fatal("admission failure output")
				}
			case "reserve":
				out, inserted, err := g.journal.ReserveErasureAttempt(ctx, op.Ref(), a, request, g.clock.Value())
				got = err
				if out.Identity() != "" || inserted {
					t.Fatal("reserve failure output")
				}
			case "attempt":
				out, evidence, found, err := g.journal.ReadErasureAttempt(ctx, op.Ref(), request.ReservationIdentity())
				got = err
				if out.Identity() != "" || evidence != nil || found {
					t.Fatal("attempt failure output")
				}
			case "page":
				out, err := g.journal.ReadAllowanceAttempts(ctx, op.Ref(), a.Identity(), 19, 1)
				got = err
				if out.Attempts != nil || out.After != 0 || out.More {
					t.Fatal("page failure output")
				}
			case "progress":
				out, found, err := g.journal.ReadErasureProgress(ctx, op.Ref(), "")
				got = err
				if out.Operation().Identity() != "" || found {
					t.Fatal("progress failure output")
				}
			case "record":
				unknown, err := artifact.NewAttemptUnknownEvidence(attempt, g.clock.Value())
				if err != nil {
					t.Fatal(err)
				}
				out, inserted, err := g.journal.RecordErasureEvidence(ctx, op.Ref(), unknown)
				got = err
				if out.Identity() != "" || inserted {
					t.Fatal("record failure output")
				}
			}
			if got != artifact.ErrErasureJournalUnavailable {
				t.Fatal("public journal returned a wrapped or non-fixed driver error", got)
			}
		})
	}
}

func TestResumeProgressMetadataCarrierCannotRestoreLoadedAllowance(t *testing.T) {
	g := newResumeJournalFixture(t)
	admission, op, grant := g.Prepared()
	a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "metadata-carrier", resumeMaximum())
	usage, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value())
	if err != nil {
		t.Fatal(err)
	}
	namespace, err := artifact.NewStorageNamespace(g.backend.ConfigurationIdentity(), g.policy.Prefix(), g.policy.NamespaceEpochIdentity())
	if err != nil {
		t.Fatal(err)
	}
	row := g.sql.Snapshot().Rows[erasureAdmissions][0]
	options := artifact.ErasureProgressOptions{Operation: op, Admission: admission, Namespace: namespace, OriginalAuthorization: grant, AdmissionPolicyBytes: g.policy.Bytes(), OperationPolicyBytes: g.policy.Bytes(), OperationAcceptedAt: g.clock.Value(), ConfirmedVersion: row["confirmed_version"].(string), ConfirmedCiphertextDigest: row["confirmed_ciphertext_digest"].(string), ConfirmedAt: time.UnixMilli(row["confirmed_at_milliseconds"].(int64)).UTC(), RequestedAllowanceIdentity: a.Identity(), AllowanceSnapshots: []artifact.ErasureAllowanceSnapshot{{Allowance: a, AcceptedPolicyBytes: g.policy.Bytes(), AcceptedAt: g.clock.Value(), Usage: usage}}}
	progress, err := artifact.NewErasureProgress(options)
	if err != nil || progress.Validate() != nil || len(progress.Allowances()) != 1 {
		t.Fatal("complete metadata carrier", err)
	}
	historical := progress.Allowances()[0]
	if historical.ProtectedDocumentDigest() != "" || historical.ValidateProtected(g.policy) == nil {
		t.Fatal("metadata carrier retained live allowance authority")
	}
	before := g.sql.Snapshot().Revision
	out, err := g.journal.AdmitResumeAllowance(g.Context("metadata-is-not-authority"), op.Ref(), historical, g.clock.Value())
	if !errors.Is(err, artifact.ErrErasureAuthorityRequired) || out != (artifact.AllowanceUsage{}) || g.sql.Snapshot().Revision != before {
		t.Fatal("progress metadata reissued authority", err)
	}
}

func TestResumeJournalProtectedAllowanceMustMatchOriginalPreimages(t *testing.T) {
	for _, field := range []string{"principal_identity", "original_authorization_identity", "authorization_document_digest", "artifact_identity", "admission_identity", "operation_identity"} {
		t.Run(field, func(t *testing.T) {
			g := newResumeJournalFixture(t)
			_, op, _ := g.Prepared()
			_, _, raw := resumeAllowance(t, g.policy, op, g.clock.Value(), "wrong-binding", resumeMaximum())
			record := resumeDecodeObject(t, raw)
			fields := map[string]any{}
			for k, v := range record {
				fields[k] = v
			}
			fields[field] = strings.Repeat("e", 64)
			changed := resumeOrdered(t, fields, "contract schema_version identity namespace_identity scope_identity artifact_identity admission_identity operation_identity original_authorization_identity authorization_document_digest recovery_policy_identity protected_policy_identity principal_identity issuance_identity expected_bucket_owner not_before_milliseconds not_after_milliseconds maximum", "open-trestle/artifact-erasure-resume-allowance/v1\x00")
			loaded, err := artifact.LoadResumeAllowance(context.Background(), erasureProtectedFile(t, changed), g.policy, g.scope)
			if err != nil {
				t.Fatal("valid protected metadata fixture", err)
			}
			before := g.sql.Snapshot().Revision
			usage, err := g.journal.AdmitResumeAllowance(g.Context("wrong-original"), op.Ref(), loaded, g.clock.Value())
			if !errors.Is(err, artifact.ErrErasureBindingMismatch) || usage != (artifact.AllowanceUsage{}) || g.sql.Snapshot().Revision != before {
				t.Fatal("protected file bypassed full durable original binding", err)
			}
		})
	}
}
func TestResumeJournalEveryAllowanceColumnIsRevalidated(t *testing.T) {
	catalog := newResumeCatalog(t)
	for _, column := range catalog.Tables[resumeAllowances].Columns {
		t.Run(column.Name, func(t *testing.T) {
			g := newResumeJournalFixture(t)
			_, op, _ := g.Prepared()
			a, _, _ := resumeAllowance(t, g.policy, op, g.clock.Value(), "snapshot-column", resumeMaximum())
			if _, err := g.journal.AdmitResumeAllowance(g.Context("admit"), op.Ref(), a, g.clock.Value()); err != nil {
				t.Fatal(err)
			}
			request := resumeCurrentRequest(t, g, op, a, "snapshot-request")
			if _, inserted, err := g.journal.ReserveErasureAttempt(g.Context("reserve"), op.Ref(), a, request, g.clock.Value()); err != nil || !inserted {
				t.Fatal(err)
			}
			row := g.sql.Snapshot().Rows[resumeAllowances][0]
			pk := resumeFixtureTuple(row, []string{"tenant_id", "repository_id", "review_run_id", "namespace_identity", "operation_identity", "allowance_identity"})
			var replacement driver.Value
			switch value := row[column.Name].(type) {
			case string:
				replacement = strings.Repeat("f", 64)
			case []byte:
				replacement = []byte("invalid full canonical allowance or accepted policy")
			case int64:
				replacement = value + 1
			}
			if err := g.sql.CorruptExistingRow(resumeAllowances, pk, column.Name, replacement); err != nil {
				t.Fatal(err)
			}
			p, found, err := g.journal.ReadErasureProgress(g.Context("corrupt-snapshot"), op.Ref(), a.Identity())
			if err == nil || found || p.Operation().Identity() != "" {
				t.Fatal("corrupt allowance projection was trusted", column.Name)
			}
		})
	}
}
