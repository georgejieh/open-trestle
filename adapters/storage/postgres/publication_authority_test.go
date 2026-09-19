package postgres

import (
	"context"
	"errors"
	"github.com/DATA-DOG/go-sqlmock"
	"regexp"
	"strings"
	"testing"
)

const testPublicationNamespace = "11111111-1111-4111-8111-111111111111"

func TestVerifyPublicationAuthorityBindsDatabaseNamespace(t *testing.T) {
	database, mock := newMockDatabase(t)
	authority := strings.Repeat("a", 64)
	expectPublicationAuthorityVerification(mock, authority, testPublicationNamespace)
	verified, err := VerifyPublicationAuthority(context.Background(), database, authority)
	if err != nil || verified.Validate() != nil || verified.AuthorityIdentity() != authority || verified.DatabaseNamespaceID() != testPublicationNamespace {
		t.Fatalf("verified=(%#v,%v)", verified, err)
	}
	assertMock(t, mock)
}
func TestVerifyPublicationAuthorityRejectsMissingOrMismatchedRow(t *testing.T) {
	database, mock := newMockDatabase(t)
	authority := strings.Repeat("a", 64)
	mock.ExpectBegin()
	expectPublicationAuthoritySchema(mock, "public")
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pg_catalog.current_database(), pg_catalog.current_schema(), database_namespace_id::text, authority_identity FROM open_trestle_publication_guard_authority WHERE singleton = true")).WillReturnRows(sqlmock.NewRows([]string{"database", "schema", "namespace", "authority"}).AddRow("trestle", "public", testPublicationNamespace, strings.Repeat("b", 64)))
	mock.ExpectRollback()
	verified, err := VerifyPublicationAuthority(context.Background(), database, authority)
	if !errors.Is(err, ErrPublicationAuthorityMismatch) || verified.Identity() != "" {
		t.Fatalf("verified=(%#v,%v)", verified, err)
	}
	assertMock(t, mock)
}
func TestInitializePublicationAuthorityCreatesOnceAndVerifies(t *testing.T) {
	database, mock := newMockDatabase(t)
	authority := strings.Repeat("a", 64)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock($1)")).WithArgs(migrationLockID).WillReturnResult(sqlmock.NewResult(0, 1))
	expectPublicationAuthoritySchema(mock, "public")
	mock.ExpectExec("INSERT INTO open_trestle_publication_guard_authority").WithArgs(authority).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery(regexp.QuoteMeta("SELECT pg_catalog.current_database(), pg_catalog.current_schema(), database_namespace_id::text, authority_identity FROM open_trestle_publication_guard_authority WHERE singleton = true")).WillReturnRows(sqlmock.NewRows([]string{"database", "schema", "namespace", "authority"}).AddRow("trestle", "public", testPublicationNamespace, authority))
	mock.ExpectCommit()
	verified, err := InitializePublicationAuthority(context.Background(), database, authority)
	if err != nil || verified.Validate() != nil {
		t.Fatalf("verified=(%#v,%v)", verified, err)
	}
	assertMock(t, mock)
}

func expectPublicationAuthoritySchema(mock sqlmock.Sqlmock, schema string) {
	mock.ExpectQuery("SELECT pg_catalog.current_schema").WillReturnRows(sqlmock.NewRows([]string{"current_schema", "authority_schema"}).AddRow("public", schema))
}
func TestPublicationAuthorityRejectsRelationSubstitution(t *testing.T) {
	authority := strings.Repeat("a", 64)
	t.Run("verify", func(t *testing.T) {
		database, mock := newMockDatabase(t)
		mock.ExpectBegin()
		expectPublicationAuthoritySchema(mock, "shadow")
		mock.ExpectRollback()
		verified, err := VerifyPublicationAuthority(context.Background(), database, authority)
		if !errors.Is(err, ErrPublicationAuthorityMismatch) || verified.Identity() != "" {
			t.Fatalf("verified=%#v err=%v", verified, err)
		}
		assertMock(t, mock)
	})
	t.Run("initialize", func(t *testing.T) {
		database, mock := newMockDatabase(t)
		mock.ExpectBegin()
		mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock($1)")).WithArgs(migrationLockID).WillReturnResult(sqlmock.NewResult(0, 1))
		expectPublicationAuthoritySchema(mock, "shadow")
		mock.ExpectRollback()
		verified, err := InitializePublicationAuthority(context.Background(), database, authority)
		if !errors.Is(err, ErrPublicationAuthorityMismatch) || verified.Identity() != "" {
			t.Fatalf("verified=%#v err=%v", verified, err)
		}
		assertMock(t, mock)
	})
	t.Run("store", func(t *testing.T) {
		database, mock := newMockDatabase(t)
		mock.ExpectBegin()
		expectPublicationAuthoritySchema(mock, "shadow")
		mock.ExpectRollback()
		store, err := NewWithPublicationAuthority(context.Background(), database, authority)
		if !errors.Is(err, ErrPublicationAuthorityMismatch) || store != nil {
			t.Fatalf("store=%#v err=%v", store, err)
		}
		assertMock(t, mock)
	})
}
func TestPublicationAuthoritySeparatesUnavailableRead(t *testing.T) {
	authority := strings.Repeat("a", 64)
	database, mock := newMockDatabase(t)
	mock.ExpectBegin()
	expectPublicationAuthoritySchema(mock, "public")
	mock.ExpectQuery("SELECT pg_catalog.current_database").WillReturnError(errors.New("connection lost"))
	mock.ExpectRollback()
	verified, err := VerifyPublicationAuthority(context.Background(), database, authority)
	if !errors.Is(err, ErrDatabaseUnavailable) || verified.Identity() != "" {
		t.Fatalf("verified=%#v err=%v", verified, err)
	}
	assertMock(t, mock)
}

func TestInitializePublicationAuthoritySeparatesUnavailableReadback(t *testing.T) {
	authority := strings.Repeat("a", 64)
	database, mock := newMockDatabase(t)
	mock.ExpectBegin()
	mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock($1)")).WithArgs(migrationLockID).WillReturnResult(sqlmock.NewResult(0, 1))
	expectPublicationAuthoritySchema(mock, "public")
	mock.ExpectExec("INSERT INTO open_trestle_publication_guard_authority").WithArgs(authority).WillReturnResult(sqlmock.NewResult(1, 1))
	mock.ExpectQuery("SELECT pg_catalog.current_database").WillReturnError(errors.New("connection lost"))
	mock.ExpectRollback()
	verified, err := InitializePublicationAuthority(context.Background(), database, authority)
	if !errors.Is(err, ErrDatabaseUnavailable) || verified.Identity() != "" {
		t.Fatalf("verified=%#v err=%v", verified, err)
	}
	assertMock(t, mock)
}
