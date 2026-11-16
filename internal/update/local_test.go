package update

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/testsupport"
)

func writeFile(t *testing.T, path string, content []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, content, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func writeReceipt(t *testing.T, fields map[string]any, mode os.FileMode) string {
	t.Helper()
	raw, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "receipt.json")
	writeFile(t, path, raw, mode)
	return path
}

func goodReceipt() map[string]any {
	return map[string]any{
		"action": "upgrade", "archive_sha256": strings.Repeat("2", 64), "schema_version": 3, "target": Target,
		"version": "0.1.5-dev", "files": []any{}, "previous": nil,
	}
}

func TestReadReceipt(t *testing.T) {
	self := uint32(os.Getuid())
	installed, err := ReadReceipt(writeReceipt(t, goodReceipt(), 0o444), self)
	if err != nil || installed.Version.String() != "0.1.5-dev" || installed.ArchiveSHA256 != strings.Repeat("2", 64) {
		t.Fatalf("installed=%+v err=%v", installed, err)
	}
	if _, err := ReadReceipt(filepath.Join(t.TempDir(), "receipt.json"), self); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("missing receipt: %v", err)
	}
	changed := func(key string, value any) map[string]any {
		fields := goodReceipt()
		if value == nil {
			delete(fields, key)
		} else {
			fields[key] = value
		}
		return fields
	}
	link := filepath.Join(t.TempDir(), "receipt.json")
	if err := os.Symlink(writeReceipt(t, goodReceipt(), 0o444), link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"writable":       writeReceipt(t, goodReceipt(), 0o644),
		"symbolic link":  link,
		"other target":   writeReceipt(t, changed("target", "linux-arm64"), 0o444),
		"no version":     writeReceipt(t, changed("version", nil), 0o444),
		"bad version":    writeReceipt(t, changed("version", "0.1"), 0o444),
		"version number": writeReceipt(t, changed("version", 1), 0o444),
		"bad digest":     writeReceipt(t, changed("archive_sha256", "x"), 0o444),
		"no schema":      writeReceipt(t, changed("schema_version", nil), 0o444),
	} {
		if _, err := ReadReceipt(path, self); !errors.Is(err, ErrReceiptUnusable) {
			t.Fatalf("%s: err=%v", name, err)
		}
	}
	// Outside tests the owner must be root.
	if os.Getuid() != 0 {
		if _, err := ReadReceipt(writeReceipt(t, goodReceipt(), 0o444), 0); !errors.Is(err, ErrReceiptUnusable) || !strings.Contains(err.Error(), "not owned by root") {
			t.Fatalf("a receipt owned by this account was trusted as root's: %v", err)
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "receipt.json")
	writeFile(t, path, append([]byte(`{"schema_version":3}`), []byte(" {}")...), 0o444)
	if _, err := ReadReceipt(path, self); !errors.Is(err, ErrReceiptUnusable) {
		t.Fatalf("two documents: %v", err)
	}
}

func TestLocalDirectory(t *testing.T) {
	env := func(values map[string]string) func(string) string {
		return func(key string) string { return values[key] }
	}
	for _, test := range []struct {
		values map[string]string
		want   string
	}{
		{map[string]string{"XDG_DATA_HOME": "/data/", "HOME": "/home/me"}, "/data/open-trestle/updates"},
		{map[string]string{"XDG_DATA_HOME": "relative", "HOME": "/home/me"}, "/home/me/.local/share/open-trestle/updates"},
		{map[string]string{"HOME": "/home/me"}, "/home/me/.local/share/open-trestle/updates"},
	} {
		if got, err := LocalDirectory(env(test.values)); err != nil || got != test.want {
			t.Fatalf("%v: %q %v", test.values, got, err)
		}
	}
	if _, err := LocalDirectory(env(map[string]string{"HOME": "relative"})); err == nil {
		t.Fatal("a relative HOME was used")
	}
}

// localFolder makes a private update folder holding a build of version.
func localFolder(t *testing.T, version string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "updates")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	archive := testsupport.UpdateArchive(version, Target)
	writeFile(t, filepath.Join(dir, ArchiveName), archive, 0o555)
	writeFile(t, filepath.Join(dir, SidecarName), testsupport.UpdateSidecar(archive, ArchiveName), 0o444)
	return dir
}

func TestFindLocal(t *testing.T) {
	dir := localFolder(t, "0.1.6-dev")
	build, found, err := FindLocal(dir)
	if err != nil || !found || build.Version.String() != "0.1.6-dev" || build.Archive != filepath.Join(dir, ArchiveName) || build.Sidecar != filepath.Join(dir, SidecarName) || build.Signature != "" {
		t.Fatalf("build=%+v found=%v err=%v", build, found, err)
	}
	if _, found, err := FindLocal(filepath.Join(t.TempDir(), "missing")); found || err != nil {
		t.Fatalf("a missing folder: found=%v err=%v", found, err)
	}
	empty := filepath.Join(t.TempDir(), "updates")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, found, err := FindLocal(empty); found || err != nil {
		t.Fatalf("an empty folder: found=%v err=%v", found, err)
	}
	for name, test := range map[string]struct {
		prepare func(dir string)
		want    string
	}{
		"folder not private": {func(dir string) { os.Chmod(dir, 0o755) }, "must be private (mode 0700, not 0755)"},
		"archive is a link": {func(dir string) {
			other := localFolder(t, "0.1.7-dev")
			os.Remove(filepath.Join(dir, ArchiveName))
			os.Symlink(filepath.Join(other, ArchiveName), filepath.Join(dir, ArchiveName))
		}, "is a symbolic link"},
		"sidecar is a link": {func(dir string) {
			os.Remove(filepath.Join(dir, SidecarName))
			os.Symlink("/etc/hostname", filepath.Join(dir, SidecarName))
		}, "is a symbolic link"},
		"no sidecar":       {func(dir string) { os.Remove(filepath.Join(dir, SidecarName)) }, "has no open-trestle-linux-amd64.pyz.sha256 beside it"},
		"archive writable": {func(dir string) { os.Chmod(filepath.Join(dir, ArchiveName), 0o775) }, "not writable by others"},
		"archive not a file": {func(dir string) {
			os.Remove(filepath.Join(dir, ArchiveName))
			os.Mkdir(filepath.Join(dir, ArchiveName), 0o700)
		}, "is not a regular file"},
		"other target": {func(dir string) {
			os.Remove(filepath.Join(dir, ArchiveName))
			writeFile(t, filepath.Join(dir, ArchiveName), testsupport.UpdateArchive("0.1.6-dev", "linux-arm64"), 0o555)
		}, "not a packaged Open Trestle archive"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := localFolder(t, "0.1.6-dev")
			test.prepare(dir)
			if _, found, err := FindLocal(dir); found || !errors.Is(err, ErrLocalUnusable) && !errors.Is(err, ErrArchiveInvalid) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("found=%v err=%v, want %q", found, err, test.want)
			}
		})
	}
	link := filepath.Join(t.TempDir(), "updates")
	if err := os.Symlink(localFolder(t, "0.1.6-dev"), link); err != nil {
		t.Fatal(err)
	}
	if _, found, err := FindLocal(link); found || err == nil || !strings.Contains(err.Error(), "is a symbolic link") {
		t.Fatalf("a linked folder: found=%v err=%v", found, err)
	}
}

func TestFindFile(t *testing.T) {
	dir := t.TempDir()
	archive := testsupport.UpdateArchive("0.2.0", Target)
	path := filepath.Join(dir, "open-trestle-linux-amd64-new.pyz")
	writeFile(t, path, archive, 0o555)
	writeFile(t, path+".sha256", testsupport.UpdateSidecar(archive, filepath.Base(path)), 0o444)
	build, err := FindFile(path)
	if err != nil || build.Version.String() != "0.2.0" || build.Signature != "" {
		t.Fatalf("build=%+v err=%v", build, err)
	}
	writeFile(t, path+".sig", []byte("{}\n"), 0o444)
	if build, err := FindFile(path); err != nil || build.Signature != path+".sig" {
		t.Fatalf("the signature beside it was not found: %+v %v", build, err)
	}
	for _, bad := range []string{filepath.Join(dir, "missing.pyz"), filepath.Join(dir, "name with space.pyz"), filepath.Join(dir, "archive.zip")} {
		if _, err := FindFile(bad); !errors.Is(err, ErrLocalUnusable) {
			t.Fatalf("%s: %v", bad, err)
		}
	}
}
