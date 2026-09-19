package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

var _ artifact.AdmissionPreparationStore = (*IndexedArtifactStore)(nil)
var _ artifact.AdmissionPreparationStore = (*artifact.EnvelopeStore)(nil)

func TestIndexedEnvelopeAdmissionBeforeAnyRemoteEffect(t *testing.T) {
	f := newErasureFixture(t)
	f.put()
	got, err := f.store.Get(f.ctx, f.value.Scope(), f.value.Identity(), time.UnixMilli(1000).UTC())
	if err != nil {
		t.Fatal(err)
	}
	wantBytes, _ := artifact.Encode(f.value)
	gotBytes, _ := artifact.Encode(got)
	if !bytes.Equal(wantBytes, gotBytes) || !reflect.DeepEqual(got.Provenance(), f.value.Provenance()) || got.MediaType() != f.value.MediaType() {
		t.Fatal("full artifact preimage changed")
	}
	a := f.admission()
	encoded, _ := artifact.EncodeArtifactAdmission(a)
	row := erasureOnlyRow(t, f.s, erasureAdmissions)
	if !bytes.Equal(row["canonical_admission"].([]byte), encoded) || row["confirmed_version"] != "version:synthetic-version-1" || row["confirmed_at_milliseconds"] == nil {
		t.Fatal("canonical admission/confirmation not persisted")
	}
	objects := f.external.Snapshot()
	if len(objects) != 1 {
		t.Fatal("unexpected object keys")
	}
	for _, versions := range objects {
		if len(versions) != 1 || row["confirmed_ciphertext_digest"] != versions[0].Digest {
			t.Fatal("confirmation not exact observed ciphertext")
		}
	}
	counts := f.external.Counts()
	if counts.Generates != 1 || counts.Creates != 1 || counts.Decrypts < 2 || counts.Deletes != 0 {
		t.Fatalf("actual external calls %+v", counts)
	}
	admissionTx := uint64(0)
	knownSequence := uint64(0)
	scopeInserts, metadataInserts := 0, 0
	for _, e := range f.s.Snapshot().Events {
		if e.StatementID == "scope_insert" {
			scopeInserts++
		}
		if e.StatementID == "metadata_insert" {
			metadataInserts++
		}
		if e.StatementID == "admission_insert" {
			admissionTx = e.TransactionID
		}
		if e.TransactionID == admissionTx && admissionTx != 0 && e.StatementID == "COMMIT" && e.ReplyKnown {
			knownSequence = e.Sequence
		}
		if strings.HasPrefix(e.Kind, "external:") && (knownSequence == 0 || e.Sequence <= knownSequence) {
			t.Fatal("external call preceded known metadata/admission commit")
		}
	}
	if scopeInserts != 1 || metadataInserts != 1 {
		t.Fatal("second RegisterArtifact or missing atomic metadata insertion", scopeInserts, metadataInserts)
	}
}
func TestIndexedEnvelopePositiveAdmissionPrepareComposition(t *testing.T) {
	f := newErasureFixture(t)
	f.put()
	a := f.admission()
	grant := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
	before := f.external.Counts()
	op, err := f.store.PrepareErasure(f.ctx, grant, time.UnixMilli(1000).UTC())
	if err != nil || op.Validate() != nil {
		t.Fatal("database-only Prepare", err)
	}
	if f.external.Counts() != before {
		t.Fatal("Prepare performed external I/O")
	}
	if op.AdmissionIdentity() != a.Identity() || op.AuthorizationDocumentDigest() != grant.ProtectedDocumentDigest() || op.ProtectedPolicyIdentity() != f.policy.Identity() {
		t.Fatal("winning canonical authority differs")
	}
	row := erasureOnlyRow(t, f.s, erasureOperations)
	opBytes, _ := artifact.EncodeErasureOperation(op)
	grantBytes, _ := artifact.EncodeErasureAuthorizationV2(grant)
	if !bytes.Equal(row["canonical_operation"].([]byte), opBytes) || !bytes.Equal(row["canonical_authorization"].([]byte), grantBytes) || !bytes.Equal(row["accepted_policy"].([]byte), f.policy.Bytes()) || row["authorization_document_digest"] != erasureHash(grantBytes) {
		t.Fatal("SQL rows did not retain exact originals")
	}
	_, fresh := newErasureGraph(t, f.s, f.external, f.policy, &erasureClock{at: time.UnixMilli(1001).UTC()}, "restart")
	read, found, err := fresh.ReadPreparedErasure(f.ctx, op.Ref())
	if err != nil || !found {
		t.Fatal("restart read", found, err)
	}
	find, found, err := fresh.FindPreparedErasure(f.ctx, a.Scope(), a.NamespaceIdentity(), a.ArtifactIdentity())
	if err != nil || !found {
		t.Fatal("restart find", found, err)
	}
	for _, v := range []artifact.ErasureOperation{read, find} {
		b, _ := artifact.EncodeErasureOperation(v)
		if !bytes.Equal(b, opBytes) {
			t.Fatal("restart changed winning operation")
		}
	}
	if f.external.Counts() != before {
		t.Fatal("factory/readback contacted provider")
	}
}
func TestErasureAdmissionFirstWinnerAndOneUsePermit(t *testing.T) {
	t.Run("positive duplicates and restart", func(t *testing.T) {
		f := newErasureFixture(t)
		f.put()
		original := f.admission()
		f.clock.Set(time.UnixMilli(1100).UTC())
		counts := f.external.Counts()
		created, err := f.store.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
		if err != nil || created {
			t.Fatal("confirmed duplicate", created, err)
		}
		a := f.admission()
		if a.Identity() != original.Identity() || !a.AdmittedAt().Equal(original.AdmittedAt()) {
			t.Fatal("duplicate changed first decision time")
		}
		_, fresh := newErasureGraph(t, f.s, f.external, f.policy, &erasureClock{at: time.UnixMilli(1200).UTC()}, "restart")
		created, err = fresh.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
		if err != nil || created {
			t.Fatal("restart duplicate", created, err)
		}
		after := f.external.Counts()
		if after.Generates != counts.Generates || after.Creates != counts.Creates {
			t.Fatal("duplicate recreated a permit")
		}
	})
	t.Run("shape has no acceptance", func(t *testing.T) {
		f := newErasureFixture(t)
		shape, err := artifact.NewArtifactAdmission(f.value, f.policy.NamespaceIdentity(), time.UnixMilli(1000).UTC())
		if err != nil {
			t.Fatal(err)
		}
		a, found, err := f.store.ReadAdmission(f.ctx, shape.Scope(), shape.NamespaceIdentity(), shape.ArtifactIdentity())
		if err != nil || found || !reflect.DeepEqual(a, artifact.ArtifactAdmission{}) {
			t.Fatal("candidate became database acceptance")
		}
		grant := erasureGrant(t, f.policy, shape, strings.Repeat("8", 64))
		candidate, err := artifact.NewErasureOperationCandidate(grant, shape, f.policy, time.UnixMilli(1000).UTC())
		if err != nil {
			t.Fatal(err)
		}
		op, found, err := f.store.ReadPreparedErasure(f.ctx, candidate.Ref())
		if err != nil || found {
			t.Fatal("candidate became prepared")
		}
		erasureRequireZeroOperation(t, op)
		if f.external.Counts() != (erasureExternalCounts{}) {
			t.Fatal("shape/readback effects")
		}
	})
	t.Run("different time direct admission never permits Put", func(t *testing.T) {
		f := newErasureFixture(t)
		j := f.journal()
		first, _ := artifact.NewArtifactAdmission(f.value, f.policy.NamespaceIdentity(), time.UnixMilli(1000).UTC())
		a, inserted, err := j.AdmitArtifact(f.ctx, first)
		if err != nil || !inserted {
			t.Fatal(err)
		}
		later, _ := artifact.NewArtifactAdmission(f.value, f.policy.NamespaceIdentity(), time.UnixMilli(1100).UTC())
		f.clock.Set(time.UnixMilli(1100).UTC())
		winner, inserted, err := j.AdmitArtifact(f.ctx, later)
		if err != nil || inserted || winner.Identity() != a.Identity() {
			t.Fatal("first winner not retained", err)
		}
		created, err := f.store.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
		if created {
			t.Fatal("readback minted permit")
		}
		erasureRequireError(t, err, artifact.ErrErasureUnknownOutcome)
		after := f.external.Counts()
		if after.Generates != 0 || after.Creates != 0 {
			t.Fatal("unconfirmed absent key recreated")
		}
		_, fresh := newErasureGraph(t, f.s, f.external, f.policy, f.clock, "restart")
		created, err = fresh.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
		if created {
			t.Fatal("restart minted permit")
		}
		erasureRequireError(t, err, artifact.ErrErasureUnknownOutcome)
		if f.external.Counts().Generates != 0 || f.external.Counts().Creates != 0 {
			t.Fatal("restart replayed abandoned Put")
		}
	})
}
func TestErasureAdmissionUnknownCommitNeverDispatches(t *testing.T) {
	for _, persist := range []bool{false, true} {
		t.Run(map[bool]string{false: "no persistence", true: "persisted lost reply"}[persist], func(t *testing.T) {
			f := newErasureFixture(t)
			mode := erasureTestLoseWithoutPersist
			if persist {
				mode = erasureTestPersistThenLose
			}
			if err := f.s.Inject(erasureSQLFault{StatementID: "COMMIT", Occurrence: 1, OperationLabel: "work", Err: io.EOF, CommitMode: mode}); err != nil {
				t.Fatal(err)
			}
			created, err := f.store.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
			if created {
				t.Fatal("unknown admission returned success")
			}
			erasureRequireError(t, err, artifact.ErrErasureUnknownOutcome)
			if f.external.Counts() != (erasureExternalCounts{}) {
				t.Fatal("unknown admission dispatched")
			}
			snapshot := f.s.Snapshot()
			if (len(snapshot.Rows[erasureAdmissions]) == 1) != persist || (len(snapshot.Rows[erasureMetadata]) == 1) != persist {
				t.Fatal("raw commit persistence branch differs")
			}
			_, fresh := newErasureGraph(t, f.s, f.external, f.policy, f.clock, "restart")
			a, found, err := fresh.ReadAdmission(f.ctx, f.value.Scope(), f.policy.NamespaceIdentity(), f.value.Identity())
			if err != nil || found != persist {
				t.Fatal("fresh actual graph discovery", found, err)
			}
			if !persist && !reflect.DeepEqual(a, artifact.ArtifactAdmission{}) {
				t.Fatal("absent branch leaked admission")
			}
		})
	}
}
func TestErasurePrepareUnknownCommitRetainsOnlyCommittedWinner(t *testing.T) {
	for _, persist := range []bool{false, true} {
		t.Run(fmtBool(persist), func(t *testing.T) {
			f := newErasureFixture(t)
			f.put()
			a := f.admission()
			grant := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
			before := f.external.Counts()
			mode := erasureTestLoseWithoutPersist
			if persist {
				mode = erasureTestPersistThenLose
			}
			if err := f.s.Inject(erasureSQLFault{StatementID: "COMMIT", Occurrence: 1, OperationLabel: "work", Err: io.EOF, CommitMode: mode}); err != nil {
				t.Fatal(err)
			}
			op, err := f.store.PrepareErasure(f.ctx, grant, time.UnixMilli(1000).UTC())
			erasureRequireError(t, err, artifact.ErrErasureUnknownOutcome)
			erasureRequireZeroOperation(t, op)
			if before != f.external.Counts() {
				t.Fatal("Prepare effects")
			}
			_, fresh := newErasureGraph(t, f.s, f.external, f.policy, f.clock, "restart")
			winner, found, err := fresh.FindPreparedErasure(f.ctx, a.Scope(), a.NamespaceIdentity(), a.ArtifactIdentity())
			if err != nil || found != persist {
				t.Fatal("unknown Prepare discovery", found, err)
			}
			if persist {
				row := erasureOnlyRow(t, f.s, erasureOperations)
				b, _ := artifact.EncodeErasureOperation(winner)
				if !bytes.Equal(b, row["canonical_operation"].([]byte)) {
					t.Fatal("readback invented winner")
				}
			} else {
				erasureRequireZeroOperation(t, winner)
			}
		})
	}
}
func fmtBool(v bool) string {
	if v {
		return "persisted"
	}
	return "not-persisted"
}

type erasurePutResult struct {
	created bool
	err     error
}

func erasureWait(t *testing.T, ctx context.Context, ch <-chan struct{}) {
	t.Helper()
	select {
	case <-ch:
	case <-ctx.Done():
		t.Fatal("bounded synchronization", ctx.Err())
	}
}
func erasurePutWait(t *testing.T, ctx context.Context, ch <-chan erasurePutResult) erasurePutResult {
	t.Helper()
	select {
	case r := <-ch:
		return r
	case <-ctx.Done():
		t.Fatal("bounded Put completion", ctx.Err())
		return erasurePutResult{}
	}
}
func TestErasureConfirmUnknownCommitNeverReportsSuccess(t *testing.T) {
	for _, persist := range []bool{false, true} {
		t.Run(fmtBool(persist), func(t *testing.T) {
			f := newErasureFixture(t)
			entered, release := make(chan struct{}), make(chan struct{})
			if err := f.s.Inject(erasureSQLFault{StatementID: "confirmation_cas", Occurrence: 1, OperationLabel: "work", Entered: entered, Release: release}); err != nil {
				t.Fatal(err)
			}
			result := erasureStartPut(t, f)
			erasureWait(t, f.ctx, entered)
			mode := erasureTestLoseWithoutPersist
			if persist {
				mode = erasureTestPersistThenLose
			}
			if err := f.s.Inject(erasureSQLFault{StatementID: "COMMIT", Occurrence: 1, OperationLabel: "work", Err: io.EOF, CommitMode: mode}); err != nil {
				t.Fatal(err)
			}
			close(release)
			r := erasurePutWait(t, f.ctx, result)
			if r.created {
				t.Fatal("unknown Confirm returned success")
			}
			erasureRequireError(t, r.err, artifact.ErrErasureUnknownOutcome)
			row := erasureOnlyRow(t, f.s, erasureAdmissions)
			if (row["confirmed_version"] != nil) != persist {
				t.Fatal("confirmation persistence mismatch")
			}
			counts := f.external.Counts()
			if counts.Creates != 1 || counts.Generates != 1 {
				t.Fatal("confirmation replayed physical work")
			}
			_, fresh := newErasureGraph(t, f.s, f.external, f.policy, f.clock, "restart")
			_, found, err := fresh.ReadAdmission(f.ctx, f.value.Scope(), f.policy.NamespaceIdentity(), f.value.Identity())
			if err != nil || !found {
				t.Fatal("admission retained after confirmation outcome", err)
			}
			if f.external.Counts() != counts {
				t.Fatal("readback performed effects")
			}
		})
	}
}
func TestErasurePrepareAndConfirmCAS(t *testing.T) {
	t.Run("confirmation then preparation", func(t *testing.T) {
		f := newErasureFixture(t)
		f.put()
		a := f.admission()
		j := f.journal()
		grant := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
		op, inserted, err := j.AcceptErasure(f.ctx, grant, time.UnixMilli(1000).UTC())
		if err != nil || !inserted {
			t.Fatal(err)
		}
		f.clock.Set(time.UnixMilli(1100).UTC())
		same, inserted, err := j.AcceptErasure(f.ctx, grant, time.UnixMilli(1100).UTC())
		if err != nil || inserted || same.Identity() != op.Identity() || !same.PreparedAt().Equal(op.PreparedAt()) {
			t.Fatal("original CAS winner changed", err)
		}
		different := erasureGrant(t, f.policy, a, strings.Repeat("c", 64))
		conflict, inserted, err := j.AcceptErasure(f.ctx, different, time.UnixMilli(1100).UTC())
		if inserted {
			t.Fatal("second authority won")
		}
		erasureRequireZeroOperation(t, conflict)
		erasureRequireError(t, err, artifact.ErrErasureConflict)
		row := erasureOnlyRow(t, f.s, erasureAdmissions)
		err = j.ConfirmAdmission(f.ctx, a, row["confirmed_version"].(string), row["confirmed_ciphertext_digest"].(string), time.UnixMilli(1100).UTC())
		erasureRequireError(t, err, artifact.ErrArtifactDeleted)
		got, err := f.store.Get(f.ctx, f.value.Scope(), f.value.Identity(), time.UnixMilli(1100).UTC())
		erasureRequireError(t, err, artifact.ErrArtifactDeleted)
		if !reflect.DeepEqual(got, artifact.Artifact{}) {
			t.Fatal("prepared Get returned payload")
		}
		created, err := f.store.Put(f.ctx, f.value, time.UnixMilli(1000).UTC())
		if created {
			t.Fatal("prepared Put succeeded")
		}
		erasureRequireError(t, err, artifact.ErrArtifactDeleted)
	})
	t.Run("prepare before duplicate admission", func(t *testing.T) {
		f := newErasureFixture(t)
		j := f.journal()
		shape, _ := artifact.NewArtifactAdmission(f.value, f.policy.NamespaceIdentity(), time.UnixMilli(1000).UTC())
		a, inserted, err := j.AdmitArtifact(f.ctx, shape)
		if err != nil || !inserted {
			t.Fatal(err)
		}
		grant := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
		_, _, err = j.AcceptErasure(f.ctx, grant, time.UnixMilli(1000).UTC())
		if err != nil {
			t.Fatal(err)
		}
		winner, inserted, err := j.AdmitArtifact(f.ctx, shape)
		if inserted || !reflect.DeepEqual(winner, artifact.ArtifactAdmission{}) {
			t.Fatal("prepared admission resurrected")
		}
		erasureRequireError(t, err, artifact.ErrArtifactDeleted)
		if f.external.Counts() != (erasureExternalCounts{}) {
			t.Fatal("database phases dispatched")
		}
	})
	t.Run("late preadmitted Create can retain ciphertext", func(t *testing.T) {
		f := newErasureFixture(t)
		entered, release := f.external.BlockNextCreate()
		result := erasureStartPut(t, f)
		erasureWait(t, f.ctx, entered)
		_, other := newErasureGraph(t, f.s, f.external, f.policy, &erasureClock{at: time.UnixMilli(1001).UTC()}, "preparer")
		ctx, cancel := erasureOperationContext(t, "prepare-other")
		defer cancel()
		a, found, err := other.ReadAdmission(ctx, f.value.Scope(), f.policy.NamespaceIdentity(), f.value.Identity())
		if err != nil || !found {
			t.Fatal("live admission not committed", err)
		}
		grant := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
		before := f.external.Counts()
		op, err := other.PrepareErasure(ctx, grant, time.UnixMilli(1001).UTC())
		if err != nil || op.Validate() != nil {
			t.Fatal("concurrent Prepare", err)
		}
		if before != f.external.Counts() {
			t.Fatal("Prepare external calls")
		}
		close(release)
		r := erasurePutWait(t, f.ctx, result)
		if r.created {
			t.Fatal("late Put returned success")
		}
		erasureRequireError(t, r.err, artifact.ErrArtifactDeleted)
		snapshot := f.external.Snapshot()
		retained := 0
		for _, v := range snapshot {
			for _, o := range v {
				retained += len(o.Content)
			}
		}
		if retained == 0 {
			t.Fatal("fixture concealed late ciphertext")
		}
		row := erasureOnlyRow(t, f.s, erasureAdmissions)
		if row["confirmed_version"] != nil {
			t.Fatal("prepared row confirmed/resurrected")
		}
		if len(f.s.Snapshot().Rows[erasureOperations]) != 1 {
			t.Fatal("preparation lost")
		}
		if f.external.Counts().Deletes != 0 {
			t.Fatal("unadmitted cleanup used as erasure proof")
		}
	})
}

func erasureJoinOnCleanup(t *testing.T, cancel context.CancelFunc, done <-chan struct{}) {
	t.Helper()
	t.Cleanup(func() {
		cancel()
		ctx, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		select {
		case <-done:
		case <-ctx.Done():
			t.Error("product goroutine failed bounded join")
		}
	})
}
func erasureStartPut(t *testing.T, f *erasureFixture) <-chan erasurePutResult {
	t.Helper()
	ctx, cancel := context.WithCancel(f.ctx)
	done := make(chan struct{})
	out := make(chan erasurePutResult, 1)
	erasureJoinOnCleanup(t, cancel, done)
	go func() {
		defer close(done)
		c, e := f.store.Put(ctx, f.value, time.UnixMilli(1000).UTC())
		out <- erasurePutResult{c, e}
	}()
	return out
}

func TestErasureReadAPIsUseNoWriteRepeatableSnapshots(t *testing.T) {
	f := newErasureFixture(t)
	f.put()
	a := f.admission()
	grant := erasureGrant(t, f.policy, a, strings.Repeat("8", 64))
	op, err := f.store.PrepareErasure(f.ctx, grant, time.UnixMilli(1000).UTC())
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"admission", "prepared", "find"} {
		t.Run(name, func(t *testing.T) {
			start := len(f.s.Snapshot().Events)
			external := f.external.Counts()
			switch name {
			case "admission":
				_, found, err := f.store.ReadAdmission(f.ctx, a.Scope(), a.NamespaceIdentity(), a.ArtifactIdentity())
				if err != nil || !found {
					t.Fatal(err)
				}
			case "prepared":
				_, found, err := f.store.ReadPreparedErasure(f.ctx, op.Ref())
				if err != nil || !found {
					t.Fatal(err)
				}
			case "find":
				_, found, err := f.store.FindPreparedErasure(f.ctx, a.Scope(), a.NamespaceIdentity(), a.ArtifactIdentity())
				if err != nil || !found {
					t.Fatal(err)
				}
			}
			events := f.s.Snapshot().Events[start:]
			begins := 0
			for _, e := range events {
				if e.StatementID == "BEGIN" {
					begins++
					if e.ReadOnly || e.Isolation != driver.IsolationLevel(sql.LevelRepeatableRead) {
						t.Fatal("journal read transaction changed frozen options")
					}
				}
				switch e.StatementID {
				case "artifact_lock", "scope_insert", "metadata_insert", "admission_insert", "admission_lock_read", "operation_insert", "confirmation_cas":
					t.Fatal("read API performed mutation/lock", e.StatementID)
				}
			}
			if begins != 1 || external != f.external.Counts() {
				t.Fatal("read API transaction/effect boundary")
			}
		})
	}
}
