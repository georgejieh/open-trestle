//go:build windows

package fileauthority

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/ownersonly"
)

const (
	everyone           = "*S-1-1-0"
	users              = "*S-1-5-32-545"
	authenticatedUsers = "*S-1-5-11"
)

// trustedTempDir returns a new private directory below the test's temporary
// directory, whose ancestors must be writable only by this account and the
// system's administrators.
func trustedTempDir(t *testing.T) string {
	t.Helper()
	base := t.TempDir()
	if err := CheckDirectory(base); err != nil {
		t.Fatalf("%s or a folder above it grants other principals write access; set TMP to a folder below the user profile: %v", base, err)
	}
	directory := filepath.Join(base, "private")
	if err := ownersonly.Mkdir(directory); err != nil {
		t.Fatal(err)
	}
	return directory
}

func grant(t *testing.T, path string, ace string) {
	t.Helper()
	if output, err := exec.Command("icacls", path, "/grant", ace).CombinedOutput(); err != nil {
		t.Fatalf("icacls %s: %v\n%s", ace, err, output)
	}
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func lstat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestTrustedOwnerHasNoAnswerOnWindows(t *testing.T) {
	directory := trustedTempDir(t)
	if TrustedOwner(lstat(t, directory)) {
		t.Fatal("TrustedOwner accepted a FileInfo, which carries no owner on Windows")
	}
}

func TestPinRefusesAncestorOthersCanWrite(t *testing.T) {
	for _, test := range []struct {
		ace  string
		want bool
	}{
		{users + ":(RX)", true},
		{authenticatedUsers + ":(AD,WD)", true},
		{authenticatedUsers + ":(DC)", false},
		{everyone + ":(M)", false},
		{everyone + ":(WDAC)", false},
		{everyone + ":(OI)(CI)(IO)(F)", true},
	} {
		t.Run(test.ace, func(t *testing.T) {
			parent := filepath.Join(trustedTempDir(t), "parent")
			leaf := filepath.Join(parent, "leaf")
			if err := MkdirAllPrivate(leaf); err != nil {
				t.Fatal(err)
			}
			pin, err := PinDirectory(leaf)
			if err != nil {
				t.Fatal(err)
			}
			grant(t, parent, test.ace)
			_, pinErr := PinDirectory(leaf)
			recheckErr := pin.Recheck()
			if (pinErr == nil) != test.want || (recheckErr == nil) != test.want {
				t.Fatalf("PinDirectory = %v, Recheck = %v, want accepted %v", pinErr, recheckErr, test.want)
			}
		})
	}
}

func TestPinFinalDirectoryMayBeReadNotWritten(t *testing.T) {
	leaf := filepath.Join(trustedTempDir(t), "leaf")
	if err := MkdirAllPrivate(leaf); err != nil {
		t.Fatal(err)
	}
	grant(t, leaf, users+":(RX)")
	if err := CheckDirectory(leaf); err != nil {
		t.Fatalf("readable final directory refused: %v", err)
	}
	if PrivateDirectory(leaf, lstat(t, leaf)) {
		t.Fatal("PrivateDirectory accepted a directory others can read")
	}
	grant(t, leaf, authenticatedUsers+":(AD)")
	if err := CheckDirectory(leaf); !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("final directory others can add to accepted: %v", err)
	}
}

func TestPinRefusesJunctionInChain(t *testing.T) {
	base := trustedTempDir(t)
	target := filepath.Join(base, "target")
	if err := MkdirAllPrivate(filepath.Join(target, "leaf")); err != nil {
		t.Fatal(err)
	}
	junction := filepath.Join(base, "junction")
	if output, err := exec.Command("cmd", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink: %v\n%s", err, output)
	}
	if _, err := PinDirectory(filepath.Join(junction, "leaf")); !errors.Is(err, ErrUntrustedPath) {
		t.Fatalf("junction in the chain accepted: %v", err)
	}
	if _, err := PinDirectory(filepath.Join(target, "leaf")); err != nil {
		t.Fatal(err)
	}
}

func TestMkdirAllPrivateCreatesOwnerOnlyDirectories(t *testing.T) {
	base := trustedTempDir(t)
	grant(t, base, users+":(OI)(CI)(RX)")
	leaf := filepath.Join(base, "a", "b")
	if err := MkdirAllPrivate(leaf); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(base, "a"), leaf} {
		if !PrivateDirectory(path, lstat(t, path)) {
			t.Fatalf("%s is not private", path)
		}
	}
	existing := filepath.Join(base, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := MkdirAllPrivate(existing); err != nil {
		t.Fatal(err)
	}
	if PrivateDirectory(existing, lstat(t, existing)) {
		t.Fatal("an existing directory that inherits read access for Users was reported private")
	}
	file := filepath.Join(base, "file")
	writeFile(t, file)
	if err := MkdirAllPrivate(file); err == nil {
		t.Fatal("MkdirAllPrivate accepted a file")
	}
}

func TestPrivateAndUnwritableFiles(t *testing.T) {
	base := trustedTempDir(t)
	private := filepath.Join(base, "private")
	writeFile(t, private)
	if !PrivateFile(private, lstat(t, private)) || !UnwritableFile(private, lstat(t, private)) {
		t.Fatal("a file that inherits owner-only access was refused")
	}
	readable := filepath.Join(base, "readable")
	writeFile(t, readable)
	grant(t, readable, users+":(R)")
	if PrivateFile(readable, lstat(t, readable)) || !UnwritableFile(readable, lstat(t, readable)) {
		t.Fatal("a file others can read was reported private or writable")
	}
	writable := filepath.Join(base, "writable")
	writeFile(t, writable)
	grant(t, writable, everyone+":(W)")
	if PrivateFile(writable, lstat(t, writable)) || UnwritableFile(writable, lstat(t, writable)) {
		t.Fatal("a file others can write was accepted")
	}
	if PrivateFile(private, lstat(t, readable)) {
		t.Fatal("PrivateFile accepted a path that is not the file info describes")
	}
	if PrivateFile(base, lstat(t, base)) || PrivateDirectory(private, lstat(t, private)) {
		t.Fatal("a directory passed as a file or a file as a directory")
	}
	file, err := os.Open(readable)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || PrivateOpenFile(file, opened) {
		t.Fatal("PrivateOpenFile accepted a file others can read")
	}
}

func TestOpenReadOnlyRefusesFileOthersCanWrite(t *testing.T) {
	base := trustedTempDir(t)
	path := filepath.Join(base, "policy.json")
	writeFile(t, path)
	grant(t, path, users+":(R)")
	file, err := OpenReadOnly(path)
	if err != nil {
		t.Fatalf("readable file refused: %v", err)
	}
	_ = file.Close()
	grant(t, path, everyone+":(W)")
	if file, err := OpenReadOnly(path); !errors.Is(err, ErrUntrustedPath) {
		if file != nil {
			_ = file.Close()
		}
		t.Fatalf("file others can write accepted: %v", err)
	}
}

func TestWriteNewProtectedFileIsOwnerOnlyFromCreation(t *testing.T) {
	base := trustedTempDir(t)
	grant(t, base, users+":(OI)(CI)(RX)")
	path := filepath.Join(base, "secret")
	content := []byte("protected content")
	if err := WriteNewProtectedFile(context.Background(), path, content, len(content)); err != nil {
		t.Fatal(err)
	}
	if !PrivateFile(path, lstat(t, path)) {
		t.Fatal("protected file inherited access for Users")
	}
	output, err := exec.Command("icacls", path).CombinedOutput()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(output), "(I)") || strings.Contains(string(output), "BUILTIN\\Users") {
		t.Fatalf("protected file has inherited or Users entries:\n%s", output)
	}
	read, err := os.ReadFile(path)
	if err != nil || string(read) != string(content) {
		t.Fatalf("content = %q, %v", read, err)
	}
	if err := WriteNewProtectedFile(context.Background(), path, content, len(content)); !errors.Is(err, ErrProtectedWriteRefused) {
		t.Fatalf("existing file replaced: %v", err)
	}
}

func TestWriteNewProtectedFileRefusesParentOthersCanWrite(t *testing.T) {
	base := trustedTempDir(t)
	grant(t, base, everyone+":(M)")
	path := filepath.Join(base, "secret")
	if err := WriteNewProtectedFile(context.Background(), path, []byte("x"), 1); !errors.Is(err, ErrProtectedWriteRefused) {
		t.Fatalf("write below a parent others can write: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("refused write created the file")
	}
}

func TestRemoveValidatedProtectedFileRefusesFileOthersCanRead(t *testing.T) {
	base := trustedTempDir(t)
	path := filepath.Join(base, "record")
	writeFile(t, path)
	grant(t, path, users+":(R)")
	accept := func([]byte) error { return nil }
	if err := RemoveValidatedProtectedFile(context.Background(), path, 64, accept); !errors.Is(err, ErrProtectedRemoveRefused) {
		t.Fatalf("readable file removed: %v", err)
	}
	private := filepath.Join(base, "private")
	writeFile(t, private)
	if err := RemoveValidatedProtectedFile(context.Background(), private, 64, accept); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(private); !os.IsNotExist(err) {
		t.Fatal("private file was not removed")
	}
}

func TestSyncDirectory(t *testing.T) {
	base := trustedTempDir(t)
	if err := SyncDirectory(base); err != nil {
		t.Fatal(err)
	}
	if err := SyncDirectory(filepath.Join(base, "missing")); err == nil {
		t.Fatal("missing directory synced")
	}
}

func TestCreatePrivateFile(t *testing.T) {
	base := trustedTempDir(t)
	grant(t, base, users+":(OI)(CI)(RX)")
	path := filepath.Join(base, "new")
	file, err := CreatePrivateFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil || !PrivateOpenFile(file, info) {
		t.Fatalf("created file is not private: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := CreatePrivateFile(path); err == nil {
		t.Fatal("CreatePrivateFile replaced an existing file")
	}
}
