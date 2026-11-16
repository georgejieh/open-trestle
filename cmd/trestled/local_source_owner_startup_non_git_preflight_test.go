package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBuildDaemonNoGitRejectsPublicStateBeforeStorageConstructors(t *testing.T) {
	for _, ownerPresent := range []bool{false, true} {
		name := "no owner"
		if ownerPresent {
			name = "existing owner"
		}
		t.Run(name, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(state, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(state, 0o755); err != nil {
				t.Fatal(err)
			}
			ownerPath := filepath.Join(state, localSourceOwnerLeaf)
			originalOwner := []byte("untrusted existing owner bytes\n")
			if ownerPresent {
				if err := os.WriteFile(ownerPath, originalOwner, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			args := []string{"--listen", "127.0.0.1:0", "--state-dir", state, "--tenant", "tenant-a", "--repository", "repo-a"}
			getenv := daemonEnvironment(map[string]string{"OPEN_TRESTLE_API_TOKEN": "01234567890123456789012345678901"})
			daemon, buildErr := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
			if daemon != nil {
				if err := daemon.Close(); err != nil {
					t.Errorf("unexpected daemon close: %v", err)
				}
			}

			info, err := os.Lstat(state)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode() != os.ModeDir|0o755 {
				t.Errorf("existing public state mode changed before refusal: got %v, want drwxr-xr-x", info.Mode())
			}
			entries, err := os.ReadDir(state)
			if err != nil {
				t.Fatal(err)
			}
			expectedEntries := 0
			if ownerPresent {
				expectedEntries = 1
			}
			if len(entries) != expectedEntries || ownerPresent && (len(entries) != 1 || entries[0].Name() != localSourceOwnerLeaf) {
				t.Errorf("storage constructor created artifacts, lock, audit, diagnostics, or another entry: %v", entries)
			}
			if ownerPresent {
				data, err := os.ReadFile(ownerPath)
				if err != nil || !bytes.Equal(data, originalOwner) {
					t.Errorf("existing owner bytes changed: got %q, err=%v", data, err)
				}
				ownerInfo, err := os.Lstat(ownerPath)
				if err != nil || ownerInfo.Mode() != 0o600 {
					t.Errorf("existing owner mode changed: info=%v, err=%v", ownerInfo, err)
				}
			}
			if daemon != nil || buildErr == nil {
				t.Errorf("public no-Git state accepted: daemon=%v, err=%v", daemon != nil, buildErr)
			}
		})
	}
}
