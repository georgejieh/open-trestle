package postgres

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/georgejieh/open-trestle/artifact"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/diagnostics"
)

func postgresFinalFixture(t *testing.T, withVerification bool) diagnostics.Set {
	t.Helper()
	scope, err := audit.NewReviewScope("tenant-a", "repo-a", "run-final")
	if err != nil {
		t.Fatal(err)
	}
	analysis := strings.Repeat("8", 64)
	check, err := diagnostics.NewDeterministicCheck("3f01f93e51003eb3a0deca04719a3957d6e367c97c33bdfea105174d95698092", analysis, strings.Repeat("7", 64), diagnostics.CheckPassed, 1, 2, 1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	deterministic, err := diagnostics.NewSetWithDeterministicObservations(scope, strings.Repeat("c", 64), strings.Repeat("d", 40), analysis, []diagnostics.DeterministicCheck{check}, nil)
	if err != nil {
		t.Fatal(err)
	}
	var verified diagnostics.Set
	outcome := diagnostics.FinalOutcomeFailed
	if withVerification {
		outcome = diagnostics.FinalOutcomeCompleted
		verified, err = diagnostics.NewSetWithDeterministicChecks(scope, strings.Repeat("b", 64), deterministic.HeadRevision(), strings.Repeat("e", 64), strings.Repeat("f", 64), 0, 0, 0, 1, 1, 0, nil, deterministic.DeterministicChecks(), nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	final, err := diagnostics.NewFinalReviewSet(scope, deterministic.SnapshotIdentity(), deterministic.HeadRevision(), outcome, deterministic, verified)
	if err != nil {
		t.Fatal(err)
	}
	return final
}

func TestDiagnosticStoreFinalV7RoundTripAndAuthority(t *testing.T) {
	for _, verified := range []bool{false, true} {
		t.Run(map[bool]string{false: "failed-deterministic", true: "completed-verified"}[verified], func(t *testing.T) {
			set := postgresFinalFixture(t, verified)
			artifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
			database, mock := newMockDatabase(t)
			at := time.UnixMilli(100)
			store, err := NewDiagnosticStore(database, artifacts, DiagnosticStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Clock: diagnosticFixedClock{at}})
			if err != nil {
				t.Fatal(err)
			}
			value, err := store.newDiagnosticArtifact(set, at)
			if err != nil {
				t.Fatal(err)
			}
			expected := []string{set.Identity(), set.SnapshotIdentity(), set.AnalysisResultIdentity()}
			if verified {
				expected = append(expected, set.VerifiedSetIdentity(), set.ReviewSnapshotIdentity())
			}
			slices.Sort(expected)
			if value.Kind() != artifact.KindRunExport || value.Origin() != artifact.OriginHost || !slices.Equal(value.Provenance(), expected) {
				t.Fatalf("v7 authority kind=%s origin=%s provenance=%v want=%v", value.Kind(), value.Origin(), value.Provenance(), expected)
			}
			scope := set.Scope()
			expectTenantTransaction(mock, scope.TenantID())
			mock.ExpectQuery("SELECT set_identity, artifact_identity, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnError(sql.ErrNoRows)
			mock.ExpectCommit()
			expectTenantTransaction(mock, scope.TenantID())
			mock.ExpectExec(regexp.QuoteMeta("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")).WithArgs("diagnostics:" + scope.Identity()).WillReturnResult(sqlmock.NewResult(0, 1))
			expectScope(mock, scope)
			mock.ExpectQuery("SELECT set_identity, artifact_identity, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnError(sql.ErrNoRows)
			mock.ExpectExec("INSERT INTO open_trestle_diagnostic_sets").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID(), scope.Identity(), set.Identity(), value.Identity(), value.ExpiresAt()).WillReturnResult(sqlmock.NewResult(1, 1))
			mock.ExpectCommit()
			if created, err := store.PutDiagnosticSet(context.Background(), set); err != nil || !created {
				t.Fatalf("put=(%v,%v)", created, err)
			}
			expectTenantTransaction(mock, scope.TenantID())
			mock.ExpectQuery("SELECT set_identity, artifact_identity, expires_at").WithArgs(scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()).WillReturnRows(sqlmock.NewRows([]string{"set_identity", "artifact_identity", "expires_at"}).AddRow(set.Identity(), value.Identity(), value.ExpiresAt()))
			mock.ExpectCommit()
			loaded, err := store.GetDiagnosticSet(context.Background(), scope)
			if err != nil || loaded.Identity() != set.Identity() || loaded.SchemaVersion() != 7 || loaded.Outcome() != set.Outcome() {
				t.Fatalf("get=(%#v,%v)", loaded, err)
			}
			assertMock(t, mock)
		})
	}
}

func TestDiagnosticStoreFinalV7RejectsLegacyAuthorityAndImmutableCollision(t *testing.T) {
	set := postgresFinalFixture(t, true)
	at := time.UnixMilli(100)
	artifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	database, mock := newMockDatabase(t)
	store, _ := NewDiagnosticStore(database, artifacts, DiagnosticStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Clock: diagnosticFixedClock{at}})
	value, err := store.newDiagnosticArtifact(set, at)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := diagnostics.EncodeSet(set)
	if err != nil {
		t.Fatal(err)
	}
	mapping := diagnosticMapping{setIdentity: set.Identity(), expiresAt: value.ExpiresAt()}
	for name, mutation := range map[string]struct {
		kind       artifact.Kind
		origin     artifact.Origin
		provenance []string
	}{
		"as-v5":                   {artifact.KindVerifiedFindingSet, artifact.OriginIndependentVerifier, value.Provenance()},
		"as-v6":                   {artifact.KindDeterministicEvidence, artifact.OriginDeterministicTool, value.Provenance()},
		"missing-verified":        {artifact.KindRunExport, artifact.OriginHost, []string{set.Identity(), set.SnapshotIdentity(), set.AnalysisResultIdentity(), set.ReviewSnapshotIdentity()}},
		"missing-review-snapshot": {artifact.KindRunExport, artifact.OriginHost, []string{set.Identity(), set.SnapshotIdentity(), set.AnalysisResultIdentity(), set.VerifiedSetIdentity()}},
	} {
		t.Run(name, func(t *testing.T) {
			changed, err := artifact.New(set.Scope(), mutation.kind, "application/json", value.Classification(), mutation.origin, value.Protection(), mutation.provenance, encoded, at, value.ExpiresAt())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := artifacts.Put(context.Background(), changed, at); err != nil {
				t.Fatal(err)
			}
			mapping.artifactIdentity = changed.Identity()
			if _, err := store.loadDiagnosticArtifact(context.Background(), set.Scope(), mapping, at); !errors.Is(err, ErrCorruptRecord) {
				t.Fatalf("legacy or missing lineage accepted: %v", err)
			}
		})
	}
	other, err := diagnostics.NewFinalReviewSet(set.Scope(), set.SnapshotIdentity(), set.HeadRevision(), diagnostics.FinalOutcomeFailed, diagnostics.Set{}, diagnostics.Set{})
	if err != nil {
		t.Fatal(err)
	}
	expectTenantTransaction(mock, set.Scope().TenantID())
	mock.ExpectQuery("SELECT set_identity, artifact_identity, expires_at").WithArgs(set.Scope().TenantID(), set.Scope().RepositoryID(), set.Scope().ReviewRunID()).WillReturnRows(sqlmock.NewRows([]string{"set_identity", "artifact_identity", "expires_at"}).AddRow(other.Identity(), value.Identity(), value.ExpiresAt()))
	mock.ExpectCommit()
	if created, err := store.PutDiagnosticSet(context.Background(), set); created || !errors.Is(err, diagnostics.ErrSetConflict) {
		t.Fatalf("immutable mapping overwritten: created=%t error=%v", created, err)
	}
	assertMock(t, mock)
}

func TestDiagnosticStoreFinalV7AbsentEvidenceAndCorruptArtifact(t *testing.T) {
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-early-final")
	final, err := diagnostics.NewFinalReviewSet(scope, "", "", diagnostics.FinalOutcomeAbstained, diagnostics.Set{}, diagnostics.Set{})
	if err != nil {
		t.Fatal(err)
	}
	artifacts, _ := artifact.NewMemoryStore(artifact.ProtectionProcessPrivate, 10)
	database, _ := newMockDatabase(t)
	at := time.UnixMilli(100)
	store, _ := NewDiagnosticStore(database, artifacts, DiagnosticStoreOptions{Classification: artifact.ClassificationRestricted, Protection: artifact.ProtectionProcessPrivate, Retention: time.Hour, Clock: diagnosticFixedClock{at}})
	value, err := store.newDiagnosticArtifact(final, at)
	if err != nil || value.Kind() != artifact.KindRunExport || value.Origin() != artifact.OriginHost || !slices.Equal(value.Provenance(), []string{final.Identity()}) {
		t.Fatalf("early artifact=%#v err=%v", value, err)
	}
	mapping := diagnosticMapping{setIdentity: final.Identity(), artifactIdentity: value.Identity(), expiresAt: value.ExpiresAt()}
	if _, err := artifacts.Put(context.Background(), value, at); err != nil {
		t.Fatal(err)
	}
	if got, err := store.loadDiagnosticArtifact(context.Background(), scope, mapping, at); err != nil || got.Identity() != final.Identity() {
		t.Fatalf("early load=%#v err=%v", got, err)
	}
	encoded, _ := diagnostics.EncodeSet(final)
	for name, mutation := range map[string]struct {
		kind       artifact.Kind
		origin     artifact.Origin
		provenance []string
	}{
		"wrong-kind":    {artifact.KindDeterministicEvidence, artifact.OriginHost, value.Provenance()},
		"wrong-origin":  {artifact.KindRunExport, artifact.OriginDeterministicTool, value.Provenance()},
		"extra-lineage": {artifact.KindRunExport, artifact.OriginHost, []string{final.Identity(), strings.Repeat("a", 64)}},
	} {
		t.Run(name, func(t *testing.T) {
			changed, err := artifact.New(scope, mutation.kind, "application/json", value.Classification(), mutation.origin, value.Protection(), mutation.provenance, encoded, at, value.ExpiresAt())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := artifacts.Put(context.Background(), changed, at); err != nil {
				t.Fatal(err)
			}
			mapping.artifactIdentity = changed.Identity()
			if _, err := store.loadDiagnosticArtifact(context.Background(), scope, mapping, at); !errors.Is(err, ErrCorruptRecord) {
				t.Fatalf("corrupt artifact accepted: %v", err)
			}
		})
	}
}
