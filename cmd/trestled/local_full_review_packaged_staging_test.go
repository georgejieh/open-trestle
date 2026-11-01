//go:build unix

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPackagedStagingSelection(t *testing.T) {
	root := t.TempDir()
	members := map[string][]byte{
		"LICENSE":                          []byte("selected license"),
		"NOTICE":                           []byte("selected notice"),
		"ca-certificates.crt":              []byte("selected certificates"),
		"release/secret-scanner.spdx.json": []byte("selected spdx"),
		"release/vulnerability-scan.json":  []byte("selected vulnerability evidence"),
		"libexec/open-trestle/open-trestle-secret-scanner":        []byte("selected launcher"),
		"libexec/open-trestle/open-trestle-secret-scanner-worker": []byte("selected worker"),
		"licenses/nested/sentinel.txt":                            []byte("selected nested license"),
	}
	digest := func(body []byte) string {
		value := sha256.Sum256(body)
		return hex.EncodeToString(value[:])
	}
	launcher := digest(members["libexec/open-trestle/open-trestle-secret-scanner"])
	worker := digest(members["libexec/open-trestle/open-trestle-secret-scanner-worker"])
	manifest, err := json.Marshal(map[string]any{
		"schema_version": 1, "scanner": "betterleaks",
		"launcher":    map[string]string{"sha256": launcher},
		"worker":      map[string]string{"sha256": worker},
		"root_client": map[string]string{"launcher_sha256": launcher, "worker_sha256": worker},
	})
	if err != nil {
		t.Fatal(err)
	}
	members["release/secret-scanner-release.json"] = manifest
	for name, body := range members {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	alias := filepath.Join(t.TempDir(), "selected")
	if err := os.Symlink(root, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPEN_TRESTLE_PACKAGED_STAGING", alias)
	staging, err := readPackagedStaging()
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if staging.root != resolved || !filepath.IsAbs(staging.root) || staging.releaseSHA256 != digest(manifest) || staging.launcherSHA256 != launcher || staging.workerSHA256 != worker {
		t.Fatalf("selected staging not bound: %+v", staging)
	}
	wantFlags := "-s -w -buildid= -X github.com/georgejieh/open-trestle/internal/secretscan.expectedSecretScannerLauncherSHA256=" + launcher + " -X github.com/georgejieh/open-trestle/internal/secretscan.expectedSecretScannerWorkerSHA256=" + worker
	if staging.scannerFlags != wantFlags {
		t.Fatalf("selected pair not bound into flags: %s", staging.scannerFlags)
	}
	destination := t.TempDir()
	staging.copyRuntimeMembers(t, destination)
	for name, want := range members {
		got, err := os.ReadFile(filepath.Join(destination, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("selected member %s not copied: %v", name, err)
		}
	}
	t.Run("wrong pair digest", func(t *testing.T) {
		workerPath := filepath.Join(root, "libexec/open-trestle/open-trestle-secret-scanner-worker")
		if err := os.WriteFile(workerPath, []byte("changed worker"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.WriteFile(workerPath, members["libexec/open-trestle/open-trestle-secret-scanner-worker"], 0600); err != nil {
				t.Error(err)
			}
		})
		if _, err := readPackagedStaging(); err == nil || !strings.Contains(err.Error(), "open-trestle-secret-scanner-worker differs from release digest") {
			t.Fatalf("selected wrong digest not refused: %v", err)
		}
	})
	t.Run("wrong manifest", func(t *testing.T) {
		manifestPath := filepath.Join(root, "release/secret-scanner-release.json")
		if err := os.WriteFile(manifestPath, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := os.WriteFile(manifestPath, manifest, 0600); err != nil {
				t.Error(err)
			}
		})
		if _, err := readPackagedStaging(); err == nil || !strings.Contains(err.Error(), "invalid staged scanner release manifest") {
			t.Fatalf("selected wrong manifest not refused: %v", err)
		}
	})
	for _, selection := range []string{"", filepath.Join(root, "absent"), filepath.Join(root, "LICENSE")} {
		t.Run("invalid selection "+selection, func(t *testing.T) {
			t.Setenv("OPEN_TRESTLE_PACKAGED_STAGING", selection)
			if _, err := readPackagedStaging(); err == nil {
				t.Fatal("invalid explicit staging selection fell back")
			}
		})
	}
}
