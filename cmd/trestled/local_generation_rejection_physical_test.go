//go:build unix

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func testGenerationRejectionPhysical(t *testing.T, fact controlplane.HistoricalContextPacketFact, inventory runtimeconfig.RouteInventory, policy runtimeconfig.RuntimePolicy, handler string, args []string, repository evidence.RepositoryIdentity) {
	t.Helper()
	ctx := context.Background()
	statePath := daemonTestFlagValue(t, args, "--state-dir")
	gitRoot, rootDigest, err := openDaemonLocalGitRoot(daemonTestFlagValue(t, args, "--local-git-objects-root"), repository)
	if err != nil {
		t.Fatal(err)
	}
	defer gitRoot.Close()
	objectStore, err := scm.NewLocalGitObjectStore(gitRoot, repository)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := scm.NewLocalGitSourceAdapter(objectStore)
	if err != nil {
		t.Fatal(err)
	}
	binding := historicalRecordedSourceBinding{RootIdentity: rootDigest, RepositoryIdentity: repository.Identity(), AdapterIdentity: adapter.Identity().Identity()}
	stateRoot, err := os.OpenRoot(statePath)
	if err != nil {
		t.Fatal(err)
	}
	defer stateRoot.Close()
	artifactRoot, err := stateRoot.OpenRoot("artifacts")
	if err != nil {
		t.Fatal(err)
	}
	defer artifactRoot.Close()
	check := func(handler string, now time.Time) error {
		return observeGenerationRejectionPhysical(ctx, stateRoot, artifactRoot, fact, policy, inventory, handler, daemonTestGenerationSanitizer().ExpectedBinaryDigests(), binding, now)
	}
	if err := check(handler, time.Now().UTC()); err != nil {
		t.Fatalf("physical rejection proof: %v", err)
	}
	if err := check(strings.Repeat("f", 64), time.Now().UTC()); err == nil {
		t.Fatal("wrong enrolled handler admitted")
	}
	if err := check(handler, time.UnixMilli(fact.PreparedEvent().PacketDescriptor().ExpiresAtMilliseconds)); err == nil {
		t.Fatal("expired physical receipt admitted")
	}
	extra := filepath.Join(statePath, "artifacts", fact.Plan().Scope().Identity()+"-"+strings.Repeat("f", 64)+".artifact.json")
	if err := os.WriteFile(extra, []byte("orphan"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := check(handler, time.Now().UTC()); err == nil {
		t.Fatal("extra scope artifact admitted")
	}
	if err := os.Remove(extra); err != nil {
		t.Fatal(err)
	}
	if err := check(handler, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}

	artifactPath := filepath.Join(statePath, "artifacts", fact.Plan().Scope().Identity()+"-"+fact.PreparedEvent().OutputIdentity()+".artifact.json")
	auditPath := filepath.Join(statePath, "audit", fact.Plan().Scope().Identity()+".audit.jsonl")
	for _, path := range []string{artifactPath, auditPath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("malformed\n"), 0600); err != nil {
			t.Fatal(err)
		}
		refused := check(handler, time.Now().UTC())
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if refused == nil {
			t.Fatal("malformed physical record admitted")
		}
		if err := check(handler, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
	}
}
