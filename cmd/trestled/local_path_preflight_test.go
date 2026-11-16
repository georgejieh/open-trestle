package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The target is inspected only through its known real path, never through a configured link.
func TestLocalGitPathPreflightRejectsBeforeArtifactConstruction(t *testing.T) {
	for _, full := range []bool{false, true} {
		for _, kind := range []string{"linked state ancestor", "linked artifact leaf", "public state", "public artifacts", "file state", "file artifacts"} {
			t.Run(kind+map[bool]string{false: " deterministic", true: " full"}[full], func(t *testing.T) {
				args, getenv, _, _, _, _, _ := localFullDaemonFixture(t)
				if !full {
					args = args[:len(args)-5]
				}
				root := t.TempDir()
				real := filepath.Join(root, "real")
				if err := os.Mkdir(real, 0o700); err != nil {
					t.Fatal(err)
				}
				sentinel := filepath.Join(real, "sentinel")
				if err := os.WriteFile(sentinel, []byte("unchanged"), 0o600); err != nil {
					t.Fatal(err)
				}
				state := real
				switch kind {
				case "linked state ancestor":
					linked := filepath.Join(root, "linked")
					if err := os.Symlink(real, linked); err != nil {
						t.Fatal(err)
					}
					state = filepath.Join(linked, "runtime")
				case "linked artifact leaf":
					state = filepath.Join(root, "runtime")
					if err := os.Mkdir(state, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(real, filepath.Join(state, "artifacts")); err != nil {
						t.Fatal(err)
					}
				case "public state":
					state = real
					if err := os.Chmod(state, 0o755); err != nil {
						t.Fatal(err)
					}
				case "public artifacts":
					state = filepath.Join(root, "runtime")
					if err := os.Mkdir(state, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.Mkdir(filepath.Join(state, "artifacts"), 0o755); err != nil {
						t.Fatal(err)
					}
				case "file state":
					state = filepath.Join(root, "runtime")
					if err := os.WriteFile(state, []byte("not a directory"), 0o600); err != nil {
						t.Fatal(err)
					}
				case "file artifacts":
					state = filepath.Join(root, "runtime")
					if err := os.Mkdir(state, 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(state, "artifacts"), []byte("artifact file unchanged"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				args[3] = state // --state-dir value
				if kind == "linked artifact leaf" {
					closer, checkErr := localPathPreflight(state)
					if closer != nil {
						closer()
					}
					if !errors.Is(checkErr, ErrInvalidDaemonConfiguration) {
						t.Fatalf("linked artifact passed direct preflight: %v", checkErr)
					}
				}
				d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
				if d != nil {
					d.Close()
				}
				if d != nil || !errors.Is(err, ErrInvalidDaemonConfiguration) {
					t.Fatalf("daemon=%v err=%v", d, err)
				}
				data, err := os.ReadFile(sentinel)
				if err != nil || string(data) != "unchanged" {
					t.Fatalf("sentinel=%q err=%v", data, err)
				}
				info, err := os.Lstat(real)
				if err != nil {
					t.Fatal(err)
				}
				expected := os.FileMode(0o700)
				if kind == "public state" {
					expected = 0o755
				}
				if info.Mode().Perm() != expected {
					t.Fatalf("real root mode=%#o", info.Mode().Perm())
				}
				entries, err := os.ReadDir(real)
				if err != nil || len(entries) != 1 || entries[0].Name() != "sentinel" {
					t.Fatalf("real target modified: %v, %v", entries, err)
				}
				if kind == "linked state ancestor" {
					if _, err := os.Lstat(filepath.Join(real, "runtime")); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("artifact constructor created runtime in real target: %v", err)
					}
				}
				if kind == "public artifacts" {
					info, err := os.Lstat(filepath.Join(state, "artifacts"))
					if err != nil || info.Mode().Perm() != 0o755 {
						t.Fatalf("artifact mode changed: %v %v", info, err)
					}
					entries, err := os.ReadDir(filepath.Join(state, "artifacts"))
					if err != nil || len(entries) != 0 {
						t.Fatalf("artifact constructor ran: %v %v", entries, err)
					}
				}
				if kind == "linked artifact leaf" {
					link, err := os.Lstat(filepath.Join(state, "artifacts"))
					if err != nil || link.Mode()&os.ModeSymlink == 0 {
						t.Fatalf("artifact link modified: %v %v", link, err)
					}
				}
				if kind == "file artifacts" {
					filePath := filepath.Join(state, "artifacts")
					info, statErr := os.Lstat(filePath)
					data, readErr := os.ReadFile(filePath)
					if statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || readErr != nil || string(data) != "artifact file unchanged" {
						t.Fatalf("artifact file changed: info=%v stat=%v data=%q read=%v", info, statErr, data, readErr)
					}
					entries, listErr := os.ReadDir(state)
					if listErr != nil || len(entries) != 1 || entries[0].Name() != "artifacts" {
						t.Fatalf("state mutated: %v %v", entries, listErr)
					}
				}
			})
		}
	}
}

func TestLocalGitPathPreflightAcceptsFreshAndPrivateRoots(t *testing.T) {
	for _, kind := range []string{"absent state", "absent artifacts", "private artifacts", "normalized alias"} {
		t.Run(kind, func(t *testing.T) {
			args, getenv, _, _, _, _, _ := localFullDaemonFixture(t)
			args = args[:len(args)-5]
			state := args[3]
			if kind != "absent state" {
				if err := os.Mkdir(state, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "normalized alias" {
				args[3] = filepath.Join(state, "..", "runtime") + string(filepath.Separator) + "."
			}
			if kind == "private artifacts" {
				artifacts := filepath.Join(state, "artifacts")
				if err := os.Mkdir(artifacts, 0o700); err != nil {
					t.Fatal(err)
				}
				original := []byte("private artifact unchanged")
				if err := os.WriteFile(filepath.Join(artifacts, "original"), original, 0o600); err != nil {
					t.Fatal(err)
				}
				closer, err := localPathPreflight(state)
				if err != nil || closer == nil {
					t.Fatalf("private child rejected by read-only path preflight: closer=%v err=%v", closer != nil, err)
				}
				closer()
				d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
				if d != nil {
					d.Close()
				}
				if d != nil || !errors.Is(err, ErrInvalidDaemonConfiguration) {
					t.Fatalf("existing artifacts were enrolled as first use: daemon=%v err=%v", d, err)
				}
				stateEntries, err := os.ReadDir(state)
				if err != nil || len(stateEntries) != 1 || stateEntries[0].Name() != "artifacts" {
					t.Fatalf("state mutated before owner enrollment: entries=%v err=%v", stateEntries, err)
				}
				artifactEntries, err := os.ReadDir(artifacts)
				if err != nil || len(artifactEntries) != 1 || artifactEntries[0].Name() != "original" {
					t.Fatalf("artifact child mutated before owner enrollment: entries=%v err=%v", artifactEntries, err)
				}
				for _, path := range []string{state, artifacts} {
					info, err := os.Lstat(path)
					if err != nil || info.Mode() != os.ModeDir|0o700 {
						t.Fatalf("private directory changed: path=%q info=%v err=%v", path, info, err)
					}
				}
				info, err := os.Lstat(filepath.Join(artifacts, "original"))
				if err != nil || info.Mode() != 0o600 {
					t.Fatalf("original artifact mode changed: info=%v err=%v", info, err)
				}
				data, err := os.ReadFile(filepath.Join(artifacts, "original"))
				if err != nil || !bytes.Equal(data, original) {
					t.Fatalf("original artifact bytes changed: data=%q err=%v", data, err)
				}
				if owner, err := os.Lstat(filepath.Join(state, localSourceOwnerLeaf)); owner != nil || !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("refused first use minted owner: info=%v err=%v", owner, err)
				}
				return
			}
			d, err := buildDaemon(context.Background(), args, getenv, &bytes.Buffer{})
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
		})
	}
}
