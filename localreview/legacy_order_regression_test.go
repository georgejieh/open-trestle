package localreview

import (
	"errors"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"os"
	"path/filepath"
	"testing"
)

func TestPackedIntegrationPreservesLegacyConstructorErrorPriority(t *testing.T) {
	f := newRmModelFixture(t, rmModelFixtureOptions{})
	o := rmOptions(t, f, rmNewClock())
	defer o.ObjectsRoot.Close()
	if err := os.MkdirAll(filepath.Join(f.objects, "pack"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.objects, "pack", "not-a-pack"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	o.Repository = evidence.RepositoryIdentity{}
	s, err := NewSession(o)
	if s != nil || !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("default invalid repository plus nonempty pack: session=%v error=%v, want invalid session", s, err)
	}
	if _, err := o.ObjectsRoot.Stat("."); err != nil {
		t.Fatalf("failed constructor closed caller root: %v", err)
	}
}
