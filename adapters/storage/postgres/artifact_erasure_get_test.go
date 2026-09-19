package postgres

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/artifact"
)

func TestErasureGetRequiresOriginalAdmissionInFinalSnapshot(t *testing.T) {
	for _, indexed := range []bool{false, true} {
		for _, missing := range []bool{false, true} {
			name := "envelope/replaced"
			if indexed {
				name = "indexed/replaced"
			}
			if missing {
				name = strings.TrimSuffix(name, "replaced") + "missing"
			}
			t.Run(name, func(t *testing.T) {
				f := newErasureFixture(t)
				f.put()
				original := f.admission()
				get := f.store.artifacts.(*artifact.EnvelopeStore).Get
				if indexed {
					get = f.store.Get
				}
				before := f.external.Counts()
				entered, release := make(chan struct{}), make(chan struct{})
				if err := f.s.Inject(erasureSQLFault{StatementID: "BEGIN", Occurrence: 3, OperationLabel: "get-final-check", Entered: entered, Release: release}); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := erasureOperationContext(t, "get-final-check")
				defer cancel()
				type result struct {
					value artifact.Artifact
					err   error
				}
				out := make(chan result, 1)
				done := make(chan struct{})
				erasureJoinOnCleanup(t, cancel, done)
				go func() {
					defer close(done)
					v, e := get(ctx, f.value.Scope(), f.value.Identity(), time.UnixMilli(1000).UTC())
					out <- result{v, e}
				}()
				erasureWait(t, ctx, entered)
				during := f.external.Counts()
				if during.Decrypts != before.Decrypts+1 || f.s.Snapshot().Active != 0 {
					t.Fatal("barrier is not after actual decryption and before final read snapshot")
				}
				row := erasureOnlyRow(t, f.s, erasureAdmissions)
				key := erasureRowKey(row)
				if missing {
					if err := f.s.CorruptExistingRow(erasureAdmissions, key, "artifact_identity", strings.Repeat("f", 64)); err != nil {
						t.Fatal(err)
					}
				} else {
					replacement, err := artifact.NewArtifactAdmission(f.value, original.NamespaceIdentity(), time.UnixMilli(900).UTC())
					if err != nil || replacement.Identity() == original.Identity() {
						t.Fatal("valid distinct admission control", err)
					}
					encoded, err := artifact.EncodeArtifactAdmission(replacement)
					if err != nil {
						t.Fatal(err)
					}
					if err := f.s.CorruptExistingRow(erasureAdmissions, key, "canonical_admission", encoded); err != nil {
						t.Fatal(err)
					}
					if err := f.s.CorruptExistingRow(erasureAdmissions, key, "admission_identity", replacement.Identity()); err != nil {
						t.Fatal(err)
					}
					if err := f.s.CorruptExistingRow(erasureAdmissions, key, "admitted_at_milliseconds", replacement.AdmittedAt().UnixMilli()); err != nil {
						t.Fatal(err)
					}
				}
				close(release)
				select {
				case got := <-out:
					if got.err == nil || !reflect.DeepEqual(got.value, artifact.Artifact{}) {
						t.Fatal("final Get released payload without its original required admission")
					}
				case <-ctx.Done():
					t.Fatal("Get failed bounded completion", ctx.Err())
				}
				after := f.external.Counts()
				if after.Generates != before.Generates || after.Creates != before.Creates || after.Deletes != before.Deletes {
					t.Fatal("read check performed new physical mutation")
				}
			})
		}
	}
}

func TestErasureFindAllowsUnadmittedScopedAbsence(t *testing.T) {
	f := newErasureFixture(t)
	value, found, err := f.store.FindPreparedErasure(f.ctx, f.value.Scope(), f.policy.NamespaceIdentity(), f.value.Identity())
	if err != nil || found || !reflect.DeepEqual(value, artifact.ErasureOperation{}) {
		t.Fatal("ordinary missing Find is not scoped absence", err)
	}
	if f.external.Counts() != (erasureExternalCounts{}) {
		t.Fatal("missing Find contacted remote service")
	}
}
