package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/internal/update"
)

// Every key here is generated for the test, written to its temporary folder
// and thrown away with it.

func writeKey(t *testing.T, dir string, key any, mode os.FileMode) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "release-key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func writeRelease(t *testing.T, dir, version string) (string, []byte) {
	t.Helper()
	archive := testsupport.UpdateArchive(version, update.Target)
	path := filepath.Join(dir, update.ArchiveName)
	if err := os.WriteFile(path, archive, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sha256", testsupport.UpdateSidecar(archive, update.ArchiveName), 0o444); err != nil {
		t.Fatal(err)
	}
	return path, archive
}

func runTool(args ...string) (int, string, string) {
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestSignWritesAVerifyingSignature(t *testing.T) {
	dir := t.TempDir()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := writeKey(t, dir, private, 0o600)
	archivePath, archive := writeRelease(t, dir, "0.2.0")
	code, out, errOut := runTool("sign", "--key", keyPath, "--archive", archivePath, "--tag", "v0.2.0")
	if code != 0 || errOut != "" {
		t.Fatalf("exit=%d\n%s%s", code, out, errOut)
	}
	pemBytes, _ := os.ReadFile(keyPath)
	if strings.Contains(out, string(pemBytes)) || strings.Contains(out, "PRIVATE") {
		t.Fatal("the tool printed the private key")
	}
	raw, err := os.ReadFile(archivePath + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	if info, _ := os.Stat(archivePath + ".sig"); info.Mode().Perm() != 0o444 {
		t.Fatalf("signature mode %v", info.Mode())
	}
	ring, err := update.ParseKeyRing([]byte(mustPublicKey(t, keyPath)))
	if err != nil {
		t.Fatal(err)
	}
	statement, key, err := ring.Verify(raw)
	sum := sha256.Sum256(archive)
	if err != nil || statement.ArchiveSHA256 != hex.EncodeToString(sum[:]) || statement.ArchiveSize != int64(len(archive)) || statement.Version != "0.2.0" || statement.Tag != "v0.2.0" || statement.Target != update.Target {
		t.Fatalf("statement=%+v err=%v", statement, err)
	}
	if !strings.Contains(out, "with key "+key.ID) || !bytes.Equal(public, key.Key) {
		t.Fatalf("output names the wrong key:\n%s", out)
	}
	// The verify subcommand agrees, and catches a changed archive.
	keysPath := filepath.Join(dir, "release_keys.txt")
	if err := os.WriteFile(keysPath, []byte(mustPublicKey(t, keyPath)), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := runTool("verify", "--keys", keysPath, "--archive", archivePath); code != 0 || !strings.Contains(out, "verified open-trestle-linux-amd64.pyz 0.2.0 (v0.2.0)") {
		t.Fatalf("verify: exit=%d\n%s%s", code, out, errOut)
	}
	other := t.TempDir()
	otherArchive, _ := writeRelease(t, other, "0.2.1")
	if err := os.WriteFile(otherArchive+".sig", raw, 0o444); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runTool("verify", "--keys", keysPath, "--archive", otherArchive); code != 1 || !strings.Contains(errOut, "does not describe this archive") {
		t.Fatalf("verify accepted another archive: exit=%d %s", code, errOut)
	}
	// An existing signature is never replaced.
	if code, _, errOut := runTool("sign", "--key", keyPath, "--archive", archivePath, "--tag", "v0.2.0"); code != 1 || !strings.Contains(errOut, "already exists") {
		t.Fatalf("overwrote the signature: exit=%d %s", code, errOut)
	}
}

func mustPublicKey(t *testing.T, keyPath string) string {
	t.Helper()
	code, out, errOut := runTool("public-key", "--key", keyPath)
	if code != 0 || !strings.HasPrefix(out, "# key ") || !strings.Contains(out, "\ned25519 ") {
		t.Fatalf("public-key: exit=%d\n%s%s", code, out, errOut)
	}
	return out
}

func TestSignRefusals(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		prepare func(t *testing.T, dir string) []string
		want    string
	}{
		"key readable by others": {func(t *testing.T, dir string) []string {
			archive, _ := writeRelease(t, dir, "0.2.0")
			return []string{"--key", writeKey(t, dir, private, 0o644), "--archive", archive, "--tag", "v0.2.0"}
		}, "readable by its owner only"},
		"symlinked key": {func(t *testing.T, dir string) []string {
			archive, _ := writeRelease(t, dir, "0.2.0")
			link := filepath.Join(dir, "link.pem")
			if err := os.Symlink(writeKey(t, dir, private, 0o600), link); err != nil {
				t.Fatal(err)
			}
			return []string{"--key", link, "--archive", archive, "--tag", "v0.2.0"}
		}, "symbolic link is refused"},
		"not Ed25519": {func(t *testing.T, dir string) []string {
			archive, _ := writeRelease(t, dir, "0.2.0")
			return []string{"--key", writeKey(t, dir, ecKey, 0o600), "--archive", archive, "--tag", "v0.2.0"}
		}, "is not an Ed25519 key"},
		"tag for another version": {func(t *testing.T, dir string) []string {
			archive, _ := writeRelease(t, dir, "0.2.0")
			return []string{"--key", writeKey(t, dir, private, 0o600), "--archive", archive, "--tag", "v0.2.1"}
		}, "does not name the archive's version 0.2.0"},
		"renamed archive": {func(t *testing.T, dir string) []string {
			archive, _ := writeRelease(t, dir, "0.2.0")
			renamed := filepath.Join(dir, "candidate.pyz")
			if err := os.Rename(archive, renamed); err != nil {
				t.Fatal(err)
			}
			return []string{"--key", writeKey(t, dir, private, 0o600), "--archive", renamed, "--tag", "v0.2.0"}
		}, "must be named open-trestle-linux-amd64.pyz"},
		"sidecar mismatch": {func(t *testing.T, dir string) []string {
			archive, _ := writeRelease(t, dir, "0.2.0")
			if err := os.Chmod(archive+".sha256", 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(archive+".sha256", []byte(strings.Repeat("0", 64)+"  "+update.ArchiveName+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			return []string{"--key", writeKey(t, dir, private, 0o600), "--archive", archive, "--tag", "v0.2.0"}
		}, "does not match the archive"},
		"not an archive": {func(t *testing.T, dir string) []string {
			archive := filepath.Join(dir, update.ArchiveName)
			if err := os.WriteFile(archive, []byte("#!/usr/bin/env python3\nnot a zip"), 0o555); err != nil {
				t.Fatal(err)
			}
			return []string{"--key", writeKey(t, dir, private, 0o600), "--archive", archive, "--tag", "v0.2.0"}
		}, "not a packaged Open Trestle archive"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			args := test.prepare(t, dir)
			code, out, errOut := runTool(append([]string{"sign"}, args...)...)
			if code != 1 || out != "" || !strings.Contains(errOut, test.want) {
				t.Fatalf("exit=%d\nstdout=%s\nstderr=%s", code, out, errOut)
			}
			if _, err := os.Lstat(filepath.Join(dir, update.ArchiveName+".sig")); err == nil {
				t.Fatal("a refused signing wrote a signature")
			}
		})
	}
}

func TestUsage(t *testing.T) {
	for _, args := range [][]string{nil, {"sign"}, {"sign", "--key", "k"}, {"verify", "--keys", "k"}, {"public-key"}, {"other"}, {"sign", "--key", "k", "--archive", "a", "--tag", "v1.0.0", "extra"}} {
		if code, _, errOut := runTool(args...); code != 2 || !strings.HasPrefix(errOut, "usage: signrelease sign") {
			t.Fatalf("%v: exit=%d %s", args, code, errOut)
		}
	}
}
