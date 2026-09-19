package postgres

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
)

type diagnosticDuplicateArtifactStore struct {
	*artifact.MemoryStore
	database   *sql.DB
	t          *testing.T
	puts, gets int
}

func (s *diagnosticDuplicateArtifactStore) Put(ctx context.Context, value artifact.Artifact, at time.Time) (bool, error) {
	s.puts++
	return s.MemoryStore.Put(ctx, value, at)
}
func (s *diagnosticDuplicateArtifactStore) Get(ctx context.Context, scope audit.ReviewScope, identity string, at time.Time) (artifact.Artifact, error) {
	s.gets++
	if s.database.Stats().InUse != 0 {
		s.t.Error("artifact load retained metadata transaction connection")
	}
	return s.MemoryStore.Get(ctx, scope, identity, at)
}

func TestDiagnosticStoreConcurrentDuplicateRequiresStoredArtifact(t *testing.T) {
	for _, test := range []struct{ concurrent, present bool }{{false, false}, {true, false}, {false, true}, {true, true}} {
		concurrent := test.concurrent
		name := "initial-duplicate"
		if concurrent {
			name = "concurrent-duplicate"
		}
		if test.present {
			name += "/present"
		} else {
			name += "/missing"
		}
		t.Run(name, func(t *testing.T) {
			scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "diagnostic-duplicate")
			finding, err := diagnostics.NewFinding(strings.Repeat("a", 64), strings.Repeat("b", 64), "Bounded title", "Untrusted detail", diagnostics.SeverityWarning, "src/main.go", 2, 3, []string{"evidence:one"})
			if err != nil {
				t.Fatal(err)
			}
			set, err := diagnostics.NewSet(scope, strings.Repeat("c", 64), strings.Repeat("d", 40), strings.Repeat("e", 64), []diagnostics.Finding{finding})
			if err != nil {
				t.Fatal(err)
			}
			memory, err := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
			if err != nil {
				t.Fatal(err)
			}
			database, mock := newMockDatabase(t)
			database.SetMaxOpenConns(1)
			artifacts := &diagnosticDuplicateArtifactStore{MemoryStore: memory, database: database, t: t}
			at := time.UnixMilli(100)
			store, err := NewDiagnosticStore(database, artifacts, DiagnosticStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Clock: diagnosticFixedClock{at: at}})
			if err != nil {
				t.Fatal(err)
			}
			mapped, err := store.newDiagnosticArtifact(set, at.Add(-time.Millisecond))
			if err != nil {
				t.Fatal(err)
			}
			if test.present {
				if _, err := memory.Put(context.Background(), mapped, at); err != nil {
					t.Fatal(err)
				}
			}
			// Any speculative Put uses a different creation time and cannot repair
			// the mapping when its original artifact is absent.
			rows := func() *sqlmock.Rows {
				return sqlmock.NewRows([]string{"set_identity", "artifact_identity", "expires_at"}).AddRow(set.Identity(), mapped.Identity(), mapped.ExpiresAt())
			}
			expectTenantTransaction(mock, scope.TenantID())
			first := mock.ExpectQuery("SELECT set_identity, artifact_identity, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID())
			if concurrent {
				first.WillReturnError(sql.ErrNoRows)
			} else {
				first.WillReturnRows(rows())
			}
			mock.ExpectCommit()
			if concurrent {
				expectTenantTransaction(mock, scope.TenantID())
				mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("diagnostics:" + scope.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
				expectScope(mock, scope)
				mock.ExpectQuery("SELECT set_identity, artifact_identity, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnRows(rows())
				mock.ExpectCommit()
			}
			created, err := store.PutDiagnosticSet(context.Background(), set)
			if test.present {
				if created || err != nil {
					t.Errorf("valid duplicate rejected: created=%v error=%v", created, err)
				}
			} else if created || !errors.Is(err, artifact.ErrArtifactNotFound) {
				t.Errorf("missing mapped artifact accepted: created=%v error=%v", created, err)
			}
			expectedPuts := 0
			if concurrent {
				expectedPuts = 1
			}
			if artifacts.puts != expectedPuts || artifacts.gets != 1 {
				t.Errorf("artifact calls put=%d get=%d; want put=%d get=1", artifacts.puts, artifacts.gets, expectedPuts)
			}
			assertMock(t, mock)
		})
	}
}
