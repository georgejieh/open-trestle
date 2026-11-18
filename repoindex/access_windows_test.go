//go:build windows

package repoindex

import (
	"testing"

	"github.com/georgejieh/open-trestle/internal/ownersonly/ownersonlytest"
)

// privateTempDir returns a new owner-only directory for an index folder.
func privateTempDir(t *testing.T) string { return ownersonlytest.TempDir(t) }

// exposeToOthers lets the Users group read path.
func exposeToOthers(t *testing.T, path string) {
	t.Helper()
	ownersonlytest.Grant(t, path, ownersonlytest.Users+":(R)")
}
