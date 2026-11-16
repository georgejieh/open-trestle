package diagnostics

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileStoreV6ThenV5SameScopeConflictsAndPreservesV6(t *testing.T) {
	v6, err := deterministicSetAtCount(t, "run-v6-v5-collision", 1)
	if err != nil || v6.Validate() != nil || v6.SchemaVersion() != 6 {
		t.Fatalf("v6=(%#v,%v)", v6, err)
	}
	finding, err := NewFinding(
		strings.Repeat("a", 64), strings.Repeat("b", 64),
		"Independently verified issue", "The independently verified issue remains.",
		SeverityWarning, "verified.go", 4, 4, []string{strings.Repeat("c", 64)},
	)
	if err != nil {
		t.Fatal(err)
	}
	v5, err := NewSetWithDeterministicChecks(
		v6.Scope(), v6.SnapshotIdentity(), v6.HeadRevision(),
		strings.Repeat("e", 64), strings.Repeat("f", 64),
		1, 0, 0, 1, 1, 0, nil, v6.DeterministicChecks(), []Finding{finding},
	)
	if err != nil || v5.Validate() != nil || v5.SchemaVersion() != 5 || len(v5.Findings()) != 1 {
		t.Fatalf("v5=(%#v,%v)", v5, err)
	}
	if v6.Scope().Identity() != v5.Scope().Identity() || v6.Identity() == v5.Identity() {
		t.Fatalf("sets must share scope and have distinct identities: v6=%s v5=%s", v6.Identity(), v5.Identity())
	}

	store, err := NewFileStore(filepath.Join(t.TempDir(), "diagnostics"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	created, err := store.PutDiagnosticSet(ctx, v6)
	if err != nil || !created {
		t.Fatalf("put v6=(%t,%v)", created, err)
	}
	created, err = store.PutDiagnosticSet(ctx, v5)
	if created || !errors.Is(err, ErrSetConflict) {
		t.Fatalf("put v5 after v6=(%t,%v), want ErrSetConflict", created, err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewFileStore(store.root)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, err := reopened.GetDiagnosticSet(ctx, v6.Scope())
	if err != nil || got.Identity() != v6.Identity() || got.SchemaVersion() != 6 || len(got.DeterministicObservations()) != 1 || len(got.Findings()) != 0 {
		t.Fatalf("persisted set=(%#v,%v), want original v6", got, err)
	}
}
