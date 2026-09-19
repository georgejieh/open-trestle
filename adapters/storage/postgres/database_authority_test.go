package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func expectDatabaseAuthoritySchemas(mock sqlmock.Sqlmock, migrationSchema, authoritySchema string) {
	mock.ExpectQuery("SELECT pg_catalog.current_schema").WillReturnRows(sqlmock.NewRows([]string{"current_schema", "migration_schema", "authority_schema"}).AddRow("public", migrationSchema, authoritySchema))
}

func TestVerifyDatabaseAuthorityBindsNamespaceDatabaseSchemaAndRole(t *testing.T) {
	database, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	mock.ExpectBegin()
	expectDatabaseAuthoritySchemas(mock, "public", "public")
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pg_catalog.current_database(), pg_catalog.current_schema(), CURRENT_USER, database_namespace_id::text FROM open_trestle_database_authority WHERE singleton = true")).WillReturnRows(sqlmock.NewRows([]string{"database", "schema", "role", "namespace"}).AddRow("trestle", "public", "runtime_role", "123e4567-e89b-12d3-a456-426614174000"))
	mock.ExpectCommit()
	authority, err := VerifyDatabaseAuthority(context.Background(), database)
	if err != nil || authority.Validate() != nil || authority.Identity() == "" || authority.DatabaseNamespaceID() != "123e4567-e89b-12d3-a456-426614174000" {
		t.Fatalf("authority=%#v err=%v", authority, err)
	}
	if strings.Contains(fmt.Sprintf("%#v", authority), "runtime_role") || strings.Contains(fmt.Sprint(authority), "trestle") {
		t.Fatal("authority formatter leaked")
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
func TestVerifyDatabaseAuthorityFailsClosed(t *testing.T) {
	for _, test := range []struct {
		name     string
		row      *sqlmock.Rows
		queryErr error
	}{{"missing", nil, sql.ErrNoRows}, {"invalid namespace", sqlmock.NewRows([]string{"database", "schema", "role", "namespace"}).AddRow("trestle", "public", "runtime_role", "not-a-uuid"), nil}, {"invalid role", sqlmock.NewRows([]string{"database", "schema", "role", "namespace"}).AddRow("trestle", "public", strings.Repeat("r", 64), "123e4567-e89b-12d3-a456-426614174000"), nil}} {
		t.Run(test.name, func(t *testing.T) {
			database, mock, _ := sqlmock.New()
			defer database.Close()
			mock.ExpectBegin()
			expectDatabaseAuthoritySchemas(mock, "public", "public")
			expect := mock.ExpectQuery("SELECT pg_catalog.current_database")
			if test.queryErr != nil {
				expect.WillReturnError(test.queryErr)
			} else {
				expect.WillReturnRows(test.row)
			}
			mock.ExpectRollback()
			authority, err := VerifyDatabaseAuthority(context.Background(), database)
			if !errors.Is(err, ErrDatabaseAuthorityMismatch) || authority.Identity() != "" {
				t.Fatalf("authority=%#v err=%v", authority, err)
			}
			_ = mock.ExpectationsWereMet()
		})
	}
}

func TestVerifyDatabaseStorageAuthorityUsesOneExactSnapshot(t *testing.T) {
	database, mock, _ := sqlmock.New()
	defer database.Close()
	mock.ExpectBegin()
	expectDatabaseAuthoritySchemas(mock, "public", "public")
	rows := sqlmock.NewRows([]string{"version", "checksum"})
	for index, name := range orderedMigrations {
		checksum, err := migrationChecksum(name)
		if err != nil {
			t.Fatal(err)
		}
		rows.AddRow(index+1, checksum)
	}
	mock.ExpectQuery("SELECT version, checksum FROM open_trestle_schema_migrations").WillReturnRows(rows)
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pg_catalog.current_database(), pg_catalog.current_schema(), CURRENT_USER, database_namespace_id::text FROM open_trestle_database_authority WHERE singleton = true")).WillReturnRows(sqlmock.NewRows([]string{"database", "schema", "role", "namespace"}).AddRow("trestle", "public", "runtime_role", "123e4567-e89b-12d3-a456-426614174000"))
	mock.ExpectCommit()
	authority, err := VerifyDatabaseStorageAuthority(context.Background(), database)
	if err != nil || authority.Validate() != nil {
		t.Fatalf("authority=%#v err=%v", authority, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDatabaseAuthoritySeparatesUnavailableQuery(t *testing.T) {
	database, mock, _ := sqlmock.New()
	defer database.Close()
	mock.ExpectBegin()
	expectDatabaseAuthoritySchemas(mock, "public", "public")
	mock.ExpectQuery("SELECT pg_catalog.current_database").WillReturnError(errors.New("connection lost"))
	mock.ExpectRollback()
	authority, err := VerifyDatabaseAuthority(context.Background(), database)
	if !errors.Is(err, ErrDatabaseUnavailable) || authority.Identity() != "" {
		t.Fatalf("authority=%#v err=%v", authority, err)
	}
	_ = mock.ExpectationsWereMet()
}

func TestVerifyDatabaseStorageAuthorityRejectsSearchPathSubstitution(t *testing.T) {
	database, mock, _ := sqlmock.New()
	defer database.Close()
	mock.ExpectBegin()
	expectDatabaseAuthoritySchemas(mock, "shadow", "public")
	mock.ExpectRollback()
	authority, err := VerifyDatabaseStorageAuthority(context.Background(), database)
	if !errors.Is(err, ErrDatabaseAuthorityMismatch) || authority.Identity() != "" {
		t.Fatalf("authority=%#v err=%v", authority, err)
	}
	_ = mock.ExpectationsWereMet()
}
