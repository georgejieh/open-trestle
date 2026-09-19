package postgres

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
)

func investigationMetadataFixture(t *testing.T, token string) artifact.Artifact {
	t.Helper()
	kind := parseArtifactKind(token)
	if kind == 0 || kind.String() != token {
		t.Fatalf("metadata kind decoder does not recognize %q", token)
	}
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-token")
	if err != nil {
		t.Fatal(err)
	}
	value, err := artifact.New(scope, kind, "application/json", artifact.ClassificationConfidential, artifact.OriginHost, artifact.ProtectionProcessPrivate,
		[]string{strings.Repeat("a", 64)}, []byte(`{"fixture":"inert token metadata"}`), time.UnixMilli(100), time.UnixMilli(1000))
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func investigationMetadataRows(value artifact.Artifact, kind string) *sqlmock.Rows {
	return sqlmock.NewRows([]string{"payload_digest", "kind", "classification", "origin", "protection", "created_at", "expires_at"}).AddRow(
		value.PayloadDigest(), kind, value.Classification().String(), value.Origin().String(), value.Protection().String(), value.CreatedAt(), value.ExpiresAt())
}

func TestInvestigationArtifactMetadataRegistersAndReadsExactKinds(t *testing.T) {
	for _, token := range []string{"investigation_turn", "investigation_tool_result"} {
		t.Run(token, func(t *testing.T) {
			value := investigationMetadataFixture(t, token)
			scope := value.Scope()
			database, mock := newMockDatabase(t)
			index, err := NewArtifactIndex(database)
			if err != nil {
				t.Fatal(err)
			}
			for _, existing := range []bool{false, true} {
				expectTenantTransaction(mock, scope.TenantID())
				mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("artifact:" + scope.Identity() + ":" + value.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
				expectScope(mock, scope)
				query := mock.ExpectQuery("SELECT payload_digest, kind, classification, origin, protection, created_at, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), value.Identity())
				if existing {
					query.WillReturnRows(investigationMetadataRows(value, token))
				} else {
					query.WillReturnError(sql.ErrNoRows)
					mock.ExpectExec("INSERT INTO open_trestle_artifacts").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), value.Identity(), value.PayloadDigest(), token, value.Classification().String(), value.Origin().String(), value.Protection().String(), value.CreatedAt(), value.ExpiresAt()).WillReturnResult(sqlmock.NewResult(0, 1))
				}
				mock.ExpectCommit()
				if inserted, err := index.RegisterArtifact(context.Background(), value); err != nil || inserted == existing {
					t.Fatal("metadata registration lost exact token or idempotence")
				}
			}
			expectTenantTransaction(mock, scope.TenantID())
			mock.ExpectQuery("SELECT payload_digest, kind, classification, origin, protection, created_at, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), value.Identity()).WillReturnRows(investigationMetadataRows(value, token))
			mock.ExpectCommit()
			metadata, err := index.GetArtifactMetadata(context.Background(), scope, value.Identity())
			if err != nil || metadata.Validate() != nil || !metadata.matches(value) || metadata.Kind().String() != token {
				t.Fatal("actual metadata readback lost scoped artifact binding")
			}
			expectTenantTransaction(mock, scope.TenantID())
			mock.ExpectQuery("SELECT payload_digest, kind, classification, origin, protection, created_at, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), value.Identity()).WillReturnRows(investigationMetadataRows(value, token+" "))
			mock.ExpectRollback()
			if _, err := index.GetArtifactMetadata(context.Background(), scope, value.Identity()); !errors.Is(err, ErrCorruptRecord) {
				t.Fatal("metadata readback accepted a near-miss stored kind")
			}
			other, err := audit.NewReviewScope("tenant-b", "repo-a", "run-token")
			if err != nil {
				t.Fatal(err)
			}
			expectTenantTransaction(mock, other.TenantID())
			mock.ExpectQuery("SELECT payload_digest, kind, classification, origin, protection, created_at, expires_at").WithArgs(other.TenantID(), other.RepositoryID(), other.ReviewRunID(), value.Identity()).WillReturnError(sql.ErrNoRows)
			mock.ExpectRollback()
			if _, err := index.GetArtifactMetadata(context.Background(), other, value.Identity()); !errors.Is(err, ErrArtifactMetadataNotFound) {
				t.Fatal("metadata lookup ignored exact requested tenant scope")
			}
			assertMock(t, mock)
		})
	}
}

func TestInvestigationArtifactMetadataKindsPreserveOldValuesAndRefuseAliases(t *testing.T) {
	tokens := []string{"source_snapshot", "change_model", "deterministic_evidence", "retrieval_result", "context_packet", "candidate_batch", "verification_batch", "verified_finding_set", "publication_plan", "run_export", "task_input", "webhook_delivery", "source_file", "publication_receipt", "investigation_turn", "investigation_tool_result"}
	for i, token := range tokens {
		if kind := parseArtifactKind(token); kind != artifact.Kind(i+1) || kind.String() != token {
			t.Fatal("metadata decoder changed an enum value or omitted appended kind")
		}
	}
	for _, token := range []string{"", "investigation_turns", "Investigation_turn", "investigation-turn", " investigation_turn", "investigation_tool_result\n", "investigation_tool_completed"} {
		if parseArtifactKind(token) != 0 {
			t.Fatal("metadata decoder admitted an alias or audit token")
		}
	}
}

func investigationMigrationHistory() []struct{ path, checksum string } {
	return []struct{ path, checksum string }{
		{"migrations/0001_core.sql", "0851e0f67a9e743b341f3ee6ec7f9fa76b8e357be760288babb343c02c97c875"},
		{"migrations/0002_diagnostic_metadata.sql", "c366087870ef9b9473ce36b0226e51b20d5909ecd9bde2c7d4c2b6af5cffb197"},
		{"migrations/0003_webhook_metadata.sql", "a0c7db325849510df8067ef84ae4ed3ad0e8fe4863902161163a91ce578a218f"},
		{"migrations/0004_artifact_metadata.sql", "966735c8949937700a2324107520977159a371314085cc1e3340da613a9e7c20"},
		{"migrations/0005_task_notifications.sql", "57c661e7233d925905d2b67583594777cf929e38d91863fbbc1270dcb55b4476"},
		{"migrations/0006_publication_attempts.sql", "054802bf6a6d8f43fbd688d56a11bd7dcfd5aff1c54f7efc466452b6df103f9e"},
		{"migrations/0007_publication_guard_authority.sql", "1f5022dccb073081833f7190e7f5feab1ee956f32ebcd69eb9c4d7ff355f97d8"},
		{"migrations/0008_database_authority.sql", "39457b6ccb1932e6af18d5dca4ce1ad701a3d9021bb607224aac6b13293dc78f"},
		{"migrations/0009_shared_rate_limits.sql", "cf4f73b98666478a3749895189011eed9e4da9ae3f216cd1e1da47e9490143f1"},
		{"migrations/0010_artifact_kinds_and_origins.sql", "b681d2cf121d9e72e5f7343e66ae27cff7488ecdeb5618ba6b24686edee135fb"},
	}
}

func TestInvestigationArtifactMigrationIsAdditiveAndPreservesHistory(t *testing.T) {
	history := investigationMigrationHistory()
	wantOrder := make([]string, 0, 11)
	for _, old := range history {
		encoded, err := migrationFiles.ReadFile(old.path)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(encoded)
		if hex.EncodeToString(digest[:]) != old.checksum {
			t.Fatal("historical migration bytes changed")
		}
		wantOrder = append(wantOrder, old.path)
	}
	const path = "migrations/0011_investigation_artifact_kinds.sql"
	wantOrder = append(wantOrder, path)
	if len(orderedMigrations) < len(wantOrder) || !reflect.DeepEqual(orderedMigrations[:len(wantOrder)], wantOrder) {
		t.Fatal("migration registration did not preserve the version-eleven history prefix")
	}
	encoded, err := migrationFiles.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "ALTER TABLE open_trestle_artifacts DROP CONSTRAINT open_trestle_artifacts_kind_check, ADD CONSTRAINT open_trestle_artifacts_kind_check CHECK (kind IN ( 'source_snapshot', 'change_model', 'deterministic_evidence', 'retrieval_result', 'context_packet', 'candidate_batch', 'verification_batch', 'verified_finding_set', 'publication_plan', 'run_export', 'task_input', 'webhook_delivery', 'source_file', 'publication_receipt', 'investigation_turn', 'investigation_tool_result' ));"
	if strings.Join(strings.Fields(string(encoded)), " ") != want {
		t.Fatal("new migration changes more than the append-only artifact kind constraint")
	}
}

func TestInvestigationArtifactMigrationVerificationRequiresCurrentVersions(t *testing.T) {
	for _, count := range []int{10, 11, len(orderedMigrations)} {
		database, mock := newMockDatabase(t)
		mock.ExpectBegin()
		tx, err := database.Begin()
		if err != nil {
			t.Fatal(err)
		}
		rows := sqlmock.NewRows([]string{"version", "checksum"})
		for i := 0; i < count; i++ {
			if i >= len(orderedMigrations) {
				t.Fatal("new migration is not registered")
			}
			checksum, err := migrationChecksum(orderedMigrations[i])
			if err != nil {
				t.Fatal(err)
			}
			rows.AddRow(i+1, checksum)
		}
		mock.ExpectQuery("SELECT version, checksum FROM open_trestle_schema_migrations ORDER BY version ASC").WillReturnRows(rows)
		mock.ExpectRollback()
		err = verifyMigrationsTransaction(context.Background(), tx)
		if count < len(orderedMigrations) && !errors.Is(err, ErrMigrationConflict) || count == len(orderedMigrations) && err != nil {
			t.Error("runtime migration verification did not require the additive version")
		}
		if err := tx.Rollback(); err != nil {
			t.Fatal(err)
		}
		assertMock(t, mock)
	}
}
