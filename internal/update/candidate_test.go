package update

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/internal/testsupport"
)

func newWorkspace(t *testing.T) *Workspace {
	t.Helper()
	t.Setenv("TMPDIR", t.TempDir())
	workspace, err := NewWorkspace()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = workspace.Remove() })
	return workspace
}

func setAfterCopy(t *testing.T, hook func(string)) {
	t.Helper()
	previous := afterCopy
	afterCopy = hook
	t.Cleanup(func() { afterCopy = previous })
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func digest(content []byte) string {
	sum := sha256.Sum256(content)
	return hex.EncodeToString(sum[:])
}

func TestNewWorkspaceIsPrivate(t *testing.T) {
	workspace := newWorkspace(t)
	if mode(t, workspace.Dir()) != 0o700 || !strings.HasPrefix(filepath.Base(workspace.Dir()), "open-trestle-update-") {
		t.Fatalf("workspace %s mode %v", workspace.Dir(), mode(t, workspace.Dir()))
	}
	if err := workspace.Remove(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(workspace.Dir()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the workspace was not removed")
	}
}

func TestPrepareLocalVerifiesTheCopy(t *testing.T) {
	dir := localFolder(t, "0.1.6-dev")
	build, _, err := FindLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(build.Archive)
	workspace := newWorkspace(t)
	prepared, err := PrepareLocal(build, nil, workspace)
	if err != nil {
		t.Fatal(err)
	}
	copied := prepared.Copy
	if copied.Archive != filepath.Join(workspace.Dir(), ArchiveName) || copied.Version.String() != "0.1.6-dev" || copied.SHA256 != digest(original) || copied.Size != int64(len(original)) || prepared.Signed || prepared.SignatureUnchecked {
		t.Fatalf("prepared %+v", prepared)
	}
	if mode(t, copied.Archive) != 0o555 || mode(t, copied.Archive+".sha256") != 0o444 {
		t.Fatalf("copy modes %v %v", mode(t, copied.Archive), mode(t, copied.Archive+".sha256"))
	}
}

// The copy is what is verified: a change to the source after copying does not
// reach it, and a change to the copy before verification is refused.
func TestPrepareLocalVerifiesAfterCopying(t *testing.T) {
	dir := localFolder(t, "0.1.6-dev")
	build, _, err := FindLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := os.ReadFile(build.Archive)
	setAfterCopy(t, func(string) {
		os.Remove(build.Archive)
		writeFile(t, build.Archive, testsupport.UpdateArchive("9.9.9", Target), 0o555)
	})
	prepared, err := PrepareLocal(build, nil, newWorkspace(t))
	if err != nil || prepared.Copy.SHA256 != digest(original) || prepared.Copy.Version.String() != "0.1.6-dev" {
		t.Fatalf("a source change reached the copy: %+v %v", prepared, err)
	}
	build, _, err = FindLocal(localFolder(t, "0.1.6-dev"))
	if err != nil {
		t.Fatal(err)
	}
	setAfterCopy(t, func(workspace string) {
		copied := filepath.Join(workspace, ArchiveName)
		os.Chmod(copied, 0o755)
		file, err := os.OpenFile(copied, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		file.Write([]byte("tampered"))
		file.Close()
		os.Chmod(copied, 0o555)
	})
	if _, err := PrepareLocal(build, nil, newWorkspace(t)); !errors.Is(err, ErrCandidateRefused) || !strings.Contains(err.Error(), "sidecar does not match") {
		t.Fatalf("a changed copy was accepted: %v", err)
	}
}

func TestPrepareLocalRefusesAMismatchedSidecar(t *testing.T) {
	dir := localFolder(t, "0.1.6-dev")
	sidecar := filepath.Join(dir, SidecarName)
	os.Chmod(sidecar, 0o644)
	writeFile(t, sidecar, []byte(strings.Repeat("0", 64)+"  "+ArchiveName+"\n"), 0o444)
	build, _, err := FindLocal(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareLocal(build, nil, newWorkspace(t)); !errors.Is(err, ErrCandidateRefused) {
		t.Fatalf("err=%v", err)
	}
}

// signedStatement signs the statement for archive at tag with private.
func signedStatement(t *testing.T, private ed25519.PrivateKey, archive []byte, version string) []byte {
	t.Helper()
	raw, err := Sign(private, Statement{
		Archive: ArchiveName, ArchiveSHA256: digest(archive), ArchiveSize: int64(len(archive)), Contract: StatementContract,
		SchemaVersion: 1, Tag: "v" + version, Target: Target, Version: version,
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestPrepareLocalChecksASignatureBesideIt(t *testing.T) {
	private, public := testKey(t)
	otherPrivate, _ := testKey(t)
	for name, test := range map[string]struct {
		ring      KeyRing
		signer    ed25519.PrivateKey
		version   string
		want      error
		signed    bool
		unchecked bool
	}{
		"verifies":            {KeyRing{public}, private, "0.2.0", nil, true, false},
		"other signer":        {KeyRing{public}, otherPrivate, "0.2.0", ErrCandidateRefused, false, false},
		"other version":       {KeyRing{public}, private, "0.2.1", ErrCandidateRefused, false, false},
		"no key: not checked": {nil, private, "0.2.0", nil, false, true},
	} {
		t.Run(name, func(t *testing.T) {
			dir := localFolder(t, "0.2.0")
			archive, _ := os.ReadFile(filepath.Join(dir, ArchiveName))
			signed := archive
			if test.version != "0.2.0" {
				signed = testsupport.UpdateArchive(test.version, Target)
			}
			writeFile(t, filepath.Join(dir, SignatureName), signedStatement(t, test.signer, signed, test.version), 0o444)
			build, _, err := FindLocal(dir)
			if err != nil || build.Signature == "" {
				t.Fatalf("build=%+v err=%v", build, err)
			}
			prepared, err := PrepareLocal(build, test.ring, newWorkspace(t))
			if !errors.Is(err, test.want) || err == nil && (prepared.Signed != test.signed || prepared.SignatureUnchecked != test.unchecked) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

// fakeRelease serves a signed release of archive at version.
func fakeRelease(t *testing.T, private ed25519.PrivateKey, version string, archive []byte) (*testsupport.FakeGitHub, Release) {
	t.Helper()
	tag := "v" + version
	prefix := "https://github.com/georgejieh/open-trestle/releases/download/" + tag + "/"
	signature := signedStatement(t, private, archive, version)
	sidecar := testsupport.UpdateSidecar(archive, ArchiveName)
	fake := testsupport.NewFakeGitHub()
	fake.Set(prefix+SignatureName, testsupport.FakeResponse{Body: signature})
	fake.Set(prefix+SidecarName, testsupport.FakeResponse{Body: sidecar})
	fake.Set(prefix+ArchiveName, testsupport.FakeResponse{Location: "https://release-assets.githubusercontent.com/" + tag})
	fake.Set("https://release-assets.githubusercontent.com/"+tag, testsupport.FakeResponse{Body: archive})
	return fake, Release{
		Tag: tag, Version: mustVersion(t, version),
		Archive:   Asset{URL: prefix + ArchiveName, Size: int64(len(archive))},
		Sidecar:   Asset{URL: prefix + SidecarName, Size: int64(len(sidecar))},
		Signature: Asset{URL: prefix + SignatureName, Size: int64(len(signature))},
	}
}

func requested(fake *testsupport.FakeGitHub, suffix string) bool {
	for _, request := range fake.Requests() {
		if strings.HasSuffix(request.URL, suffix) {
			return true
		}
	}
	return false
}

func TestPrepareReleaseVerifiesSignatureThenCopy(t *testing.T) {
	private, public := testKey(t)
	archive := testsupport.UpdateArchive("0.2.0", Target)
	fake, release := fakeRelease(t, private, "0.2.0", archive)
	workspace := newWorkspace(t)
	prepared, err := PrepareRelease(context.Background(), Client{Transport: fake}, KeyRing{public}, release, workspace, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !prepared.Signed || prepared.Key.ID != public.ID || prepared.Copy.SHA256 != digest(archive) || prepared.Copy.Archive != filepath.Join(workspace.Dir(), ArchiveName) || prepared.Statement.Tag != "v0.2.0" {
		t.Fatalf("prepared %+v", prepared)
	}
	if mode(t, prepared.Copy.Archive) != 0o555 {
		t.Fatalf("archive mode %v", mode(t, prepared.Copy.Archive))
	}
}

func TestPrepareReleaseRefusals(t *testing.T) {
	private, public := testKey(t)
	otherPrivate, _ := testKey(t)
	archive := testsupport.UpdateArchive("0.2.0", Target)
	for name, test := range map[string]struct {
		change          func(fake *testsupport.FakeGitHub, release *Release)
		ring            KeyRing
		hook            func(string)
		want            string
		archiveReadable bool
	}{
		"no pinned key": {nil, nil, nil, "this build cannot verify releases; install the packaged release", false},
		"wrong key": {func(fake *testsupport.FakeGitHub, release *Release) {
			fake.Set(release.Signature.URL, testsupport.FakeResponse{Body: signedStatement(t, otherPrivate, archive, "0.2.0")})
		}, KeyRing{public}, nil, "does not trust", false},
		"bad signature": {func(fake *testsupport.FakeGitHub, release *Release) {
			raw := signedStatement(t, private, archive, "0.2.0")
			raw = []byte(strings.Replace(string(raw), digest(archive), strings.Repeat("0", 64), 1))
			fake.Set(release.Signature.URL, testsupport.FakeResponse{Body: raw})
		}, KeyRing{public}, nil, "does not verify", false},
		"signature for another tag": {func(fake *testsupport.FakeGitHub, release *Release) {
			fake.Set(release.Signature.URL, testsupport.FakeResponse{Body: signedStatement(t, private, archive, "0.1.9")})
		}, KeyRing{public}, nil, "the signature is for v0.1.9, not v0.2.0", false},
		"tampered archive": {func(fake *testsupport.FakeGitHub, release *Release) {
			tampered := append([]byte(nil), archive...)
			tampered[len(tampered)-30] ^= 1
			fake.Set("https://release-assets.githubusercontent.com/v0.2.0", testsupport.FakeResponse{Body: tampered})
		}, KeyRing{public}, nil, "refused", true},
		"archive and sidecar both replaced": {func(fake *testsupport.FakeGitHub, release *Release) {
			// Same size and a matching sidecar: only the signed digest tells.
			replaced := append([]byte(nil), archive...)
			at := strings.Index(string(replaced), "test archive")
			replaced[at] = 'T'
			fake.Set("https://release-assets.githubusercontent.com/v0.2.0", testsupport.FakeResponse{Body: replaced})
			fake.Set(release.Sidecar.URL, testsupport.FakeResponse{Body: testsupport.UpdateSidecar(replaced, ArchiveName)})
		}, KeyRing{public}, nil, "SHA-256 or size is not the signed one", true},
		"archive larger than signed": {func(fake *testsupport.FakeGitHub, release *Release) {
			fake.Set("https://release-assets.githubusercontent.com/v0.2.0", testsupport.FakeResponse{Body: append(append([]byte(nil), archive...), 'x')})
		}, KeyRing{public}, nil, "larger than", true},
		"archive shorter than signed": {func(fake *testsupport.FakeGitHub, release *Release) {
			fake.Set("https://release-assets.githubusercontent.com/v0.2.0", testsupport.FakeResponse{Body: archive[:len(archive)-1]})
		}, KeyRing{public}, nil, "not the signed", true},
		"sidecar mismatch": {func(fake *testsupport.FakeGitHub, release *Release) {
			fake.Set(release.Sidecar.URL, testsupport.FakeResponse{Body: []byte(strings.Repeat("0", 64) + "  " + ArchiveName + "\n")})
		}, KeyRing{public}, nil, "sidecar does not match", true},
		"copy changed before verification": {nil, KeyRing{public}, func(workspace string) {
			copied := filepath.Join(workspace, ArchiveName)
			os.Chmod(copied, 0o755)
			os.WriteFile(copied, testsupport.UpdateArchive("0.2.0", Target)[:100], 0o755)
			os.Chmod(copied, 0o555)
		}, "refused", true},
	} {
		t.Run(name, func(t *testing.T) {
			fake, release := fakeRelease(t, private, "0.2.0", archive)
			if test.change != nil {
				test.change(fake, &release)
			}
			if test.hook != nil {
				setAfterCopy(t, test.hook)
			}
			prepared, err := PrepareRelease(context.Background(), Client{Transport: fake}, test.ring, release, newWorkspace(t), time.Minute)
			if err == nil || !strings.Contains(err.Error(), test.want) || prepared.Signed {
				t.Fatalf("prepared=%+v err=%v, want %q", prepared, err, test.want)
			}
			if !test.archiveReadable && requested(fake, ArchiveName) {
				t.Fatal("the archive was downloaded although its signature did not verify")
			}
		})
	}
}
