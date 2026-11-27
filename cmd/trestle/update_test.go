package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/testsupport"
	"github.com/georgejieh/open-trestle/internal/update"
)

// Every update test runs against fakes: a temporary receipt, a FakeGitHub,
// throwaway keys, a root-owned stand-in for sudo and the installed trestle
// (owned by this account, which the tests treat as root), and one recorded
// stand-in for every program trestle update runs. Nothing reaches the
// network, runs a program or changes this machine's install.

type updateFakes struct {
	t       *testing.T
	receipt string
	github  *testsupport.FakeGitHub
	private ed25519.PrivateKey
	tmp     string
	sudo    string // the fake sudo's path
	trestle string // the fake installed trestle's path
	// commands is every program run, in order, with its environment.
	commands [][]string
	envs     [][]string
	verified []string // archives passed to verify-archive
	// installed is every upgrade command, and installedSHA256 the SHA-256
	// of the archive it named, read when it ran.
	installed       [][]string
	installedSHA256 string
	upgradeTo       string // the version the fake upgrade writes; "" fails
	verifyOutput    string // "" prints the verified line
	onVerify        func(archive string)
	terminal        bool
	daemon          bool
	// lastRelease is the release object release last published.
	lastRelease map[string]any
}

func useUpdateFakes(t *testing.T, installed string) *updateFakes {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &updateFakes{t: t, github: testsupport.NewFakeGitHub(), private: private, tmp: t.TempDir(), terminal: true}
	bin := t.TempDir()
	f.sudo, f.trestle = filepath.Join(bin, "sudo"), filepath.Join(bin, "trestle")
	for _, path := range []string{f.sudo, f.trestle} {
		if err := os.WriteFile(path, []byte("#!/bin/false\n"+filepath.Base(path)+"\n"), 0o555); err != nil {
			t.Fatal(err)
		}
	}
	f.receipt = filepath.Join(t.TempDir(), "receipt.json")
	f.writeReceipt(installed)
	t.Setenv("TMPDIR", f.tmp)
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	ring, err := update.ParseKeyRing([]byte("ed25519 " + base64.StdEncoding.EncodeToString(private.Public().(ed25519.PublicKey))))
	if err != nil {
		t.Fatal(err)
	}
	receiptPath, rootOwner, keys, transport, platform := updateReceiptPath, updateRootOwner, updateKeys, updateTransport, updatePlatform
	sudoPaths, trestlePath, euid, terminal, run, daemonRunning := updateSudoPaths, updateTrestlePath, updateEUID, updateTerminal, updateRun, updateDaemonRunning
	t.Cleanup(func() {
		updateReceiptPath, updateRootOwner, updateKeys, updateTransport, updatePlatform = receiptPath, rootOwner, keys, transport, platform
		updateSudoPaths, updateTrestlePath, updateEUID, updateTerminal, updateRun, updateDaemonRunning = sudoPaths, trestlePath, euid, terminal, run, daemonRunning
	})
	updateReceiptPath, updateRootOwner = f.receipt, uint32(os.Getuid())
	updateKeys = func() (update.KeyRing, error) { return ring, nil }
	updateTransport = f.github
	updatePlatform = "linux/amd64"
	updateSudoPaths = []string{filepath.Join(bin, "missing-sudo"), f.sudo}
	updateTrestlePath = f.trestle
	updateEUID = func() int { return 1000 }
	updateTerminal = func(io.Reader) bool { return f.terminal }
	updateRun = f.run
	updateDaemonRunning = func() bool { return f.daemon }
	return f
}

// run stands in for every program: verify-archive, the upgrade and
// build-info answer as the real ones do.
func (f *updateFakes) run(_ context.Context, command updateCommand) (int, error) {
	argv := command.argv
	f.commands = append(f.commands, argv)
	f.envs = append(f.envs, command.env)
	switch {
	case len(argv) == 2 && argv[1] == "verify-archive":
		f.verified = append(f.verified, argv[0])
		if f.onVerify != nil {
			f.onVerify(argv[0])
		}
		if f.verifyOutput != "" {
			io.WriteString(command.stdout, f.verifyOutput)
			return 1, nil
		}
		io.WriteString(command.stdout, "Open Trestle candidate archive verified.\n")
		return 0, nil
	case len(argv) >= 2 && argv[len(argv)-1] == "upgrade":
		f.installed = append(f.installed, argv)
		if content, err := os.ReadFile(argv[len(argv)-2]); err == nil {
			sum := sha256.Sum256(content)
			f.installedSHA256 = hex.EncodeToString(sum[:])
		}
		if f.upgradeTo == "" {
			return 1, nil
		}
		f.writeReceipt(f.upgradeTo)
		return 0, nil
	case len(argv) == 2 && argv[0] == f.trestle && argv[1] == "build-info":
		io.WriteString(command.stdout, `{"contract":"open-trestle/build-info","program":"trestle","schema_version":1,"source_bound":true,"source_revision":"`+strings.Repeat("c", 40)+`","source_tree":"`+strings.Repeat("d", 40)+`"}`+"\n")
		return 0, nil
	}
	return -1, errors.New("unexpected program")
}

// ran reports whether any program ran whose last argument is last.
func (f *updateFakes) ran(last string) bool {
	for _, argv := range f.commands {
		if argv[len(argv)-1] == last {
			return true
		}
	}
	return false
}

func (f *updateFakes) noKeys() { updateKeys = func() (update.KeyRing, error) { return nil, nil } }

func (f *updateFakes) writeReceipt(version string) {
	trestle, err := os.ReadFile(f.trestle)
	if err != nil {
		f.t.Fatal(err)
	}
	sum := sha256.Sum256(trestle)
	raw, err := json.Marshal(map[string]any{
		"schema_version": 3, "target": "linux-amd64", "version": version, "archive_sha256": strings.Repeat("1", 64), "action": "install",
		"files": []any{map[string]any{"elf": true, "mode": 365, "path": "usr/local/bin/trestle", "sha256": hex.EncodeToString(sum[:]), "size": len(trestle)}},
	})
	if err != nil {
		f.t.Fatal(err)
	}
	_ = os.Chmod(f.receipt, 0o644)
	if err := os.WriteFile(f.receipt, raw, 0o444); err != nil {
		f.t.Fatal(err)
	}
	if err := os.Chmod(f.receipt, 0o444); err != nil {
		f.t.Fatal(err)
	}
}

// release publishes a signed release of version on the fake GitHub and
// returns the archive's bytes.
func (f *updateFakes) release(version string, prerelease bool) []byte {
	f.t.Helper()
	archive := testsupport.UpdateArchive(version, update.Target)
	sum := sha256.Sum256(archive)
	signature, err := update.Sign(f.private, update.Statement{
		Archive: update.ArchiveName, ArchiveSHA256: hex.EncodeToString(sum[:]), ArchiveSize: int64(len(archive)),
		Contract: update.StatementContract, SchemaVersion: 1, Tag: "v" + version, Target: update.Target, Version: version,
	})
	if err != nil {
		f.t.Fatal(err)
	}
	tag := "v" + version
	prefix := "https://github.com/georgejieh/open-trestle/releases/download/" + tag + "/"
	sidecar := testsupport.UpdateSidecar(archive, update.ArchiveName)
	f.github.Set(prefix+update.SignatureName, testsupport.FakeResponse{Body: signature})
	f.github.Set(prefix+update.SidecarName, testsupport.FakeResponse{Body: sidecar})
	f.github.Set(prefix+update.ArchiveName, testsupport.FakeResponse{Body: archive})
	f.lastRelease = testsupport.GitHubReleaseJSON(tag, false, prerelease, []testsupport.GitHubReleaseAsset{
		{Name: update.ArchiveName, Size: int64(len(archive)), URL: prefix + update.ArchiveName},
		{Name: update.SidecarName, Size: int64(len(sidecar)), URL: prefix + update.SidecarName},
		{Name: update.SignatureName, Size: int64(len(signature)), URL: prefix + update.SignatureName},
	})
	f.github.Set(update.ReleasesURL, testsupport.FakeResponse{Body: testsupport.GitHubReleaseList(f.lastRelease)})
	return archive
}

// localBuild leaves a build of version in the local update folder.
func (f *updateFakes) localBuild(version string) string {
	f.t.Helper()
	dir := filepath.Join(os.Getenv("XDG_DATA_HOME"), "open-trestle", "updates")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		f.t.Fatal(err)
	}
	archive := testsupport.UpdateArchive(version, update.Target)
	for name, content := range map[string][]byte{update.ArchiveName: archive, update.SidecarName: testsupport.UpdateSidecar(archive, update.ArchiveName)} {
		path := filepath.Join(dir, name)
		_ = os.Chmod(path, 0o644)
		if err := os.WriteFile(path, content, 0o444); err != nil {
			f.t.Fatal(err)
		}
	}
	return dir
}

func (f *updateFakes) archiveDownloaded() bool {
	for _, request := range f.github.Requests() {
		if strings.HasSuffix(request.URL, "/"+update.ArchiveName) {
			return true
		}
	}
	return false
}

// workspaces lists the private folders left under TMPDIR.
func (f *updateFakes) workspaces() []string {
	matches, _ := filepath.Glob(filepath.Join(f.tmp, "open-trestle-update-*"))
	return matches
}

func runUpdateScript(t *testing.T, input string, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runUpdate(context.Background(), args, strings.NewReader(input), &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

func TestUpdateInstallsASignedRelease(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	archive := f.release("0.2.0", false)
	f.upgradeTo = "0.2.0"
	code, out, errOut := runUpdateScript(t, "y\n")
	if code != 0 || errOut != "" {
		t.Fatalf("exit=%d\n%s\n%s", code, out, errOut)
	}
	// verify-archive, then the upgrade, then build-info, and nothing else.
	if len(f.commands) != 3 || len(f.verified) != 1 || len(f.installed) != 1 || !f.ran("build-info") {
		t.Fatalf("commands %q", f.commands)
	}
	command := f.installed[0]
	archivePath := command[2]
	if len(command) != 4 || command[0] != f.sudo || command[1] != "--" || command[3] != "upgrade" || filepath.Base(archivePath) != update.ArchiveName || !strings.HasPrefix(filepath.Base(filepath.Dir(archivePath)), "open-trestle-update-") || filepath.Dir(filepath.Dir(archivePath)) != f.tmp {
		t.Fatalf("command %q", command)
	}
	for _, env := range f.envs {
		for _, entry := range env {
			if strings.HasPrefix(entry, "PATH=") && entry != updateFixedPath {
				t.Fatalf("a program got the PATH %q", entry)
			}
		}
	}
	// verify-archive ran on the same copy, and the upgrade ran the signed bytes.
	sum := sha256.Sum256(archive)
	if f.verified[0] != archivePath || f.installedSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("verified %v, installed %s", f.verified, f.installedSHA256)
	}
	if !strings.Contains(out, "\n    "+f.sudo+" -- "+archivePath+" upgrade\n") {
		t.Fatalf("the command is not printed exactly:\n%s", out)
	}
	for _, want := range []string{
		"Installed: 0.1.0, the packaged Linux amd64 install.",
		"✓ Update available: 0.2.0, the signed release v0.2.0 on GitHub Releases.",
		" and checking it.",
		"Verified the copy: signed with release key ",
		"This command runs:",
		"Install 0.2.0 now? (y/N):",
		"✓ Open Trestle is now 0.2.0 (source revision cccccccccccc).",
	} {
		if !initHas(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "trestled") {
		t.Fatalf("a restart was suggested with no daemon running:\n%s", out)
	}
	if left := f.workspaces(); len(left) != 0 {
		t.Fatalf("temporary folders left: %v", left)
	}
}

func TestUpdateShowsProgressOnATerminal(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	f.release("0.2.0", false)
	f.upgradeTo = "0.2.0"
	progress, terminal, _ := testProgress(true, false, 80)
	var stdout, stderr bytes.Buffer
	code := runUpdate(withReviewProgress(context.Background(), progress), []string{"--yes"}, strings.NewReader(""), &stdout, &stderr)
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("exit=%d\n%s\n%s", code, stdout.String(), stderr.String())
	}
	for _, want := range []string{"✓ Downloading ", " and checking it · 0s\n", "✓ Running the archive's own verify-archive · 0s\n"} {
		if !strings.Contains(terminal.String(), want) {
			t.Fatalf("progress lacks %q:\n%q", want, terminal.String())
		}
	}
	if strings.Contains(stdout.String(), "Downloading") {
		t.Fatalf("the plain line repeats the spinner:\n%s", stdout.String())
	}
}

func TestUpdateCheckExitCodes(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	if code, out, _ := runUpdateScript(t, "", "--check"); code != 1 || out != "" {
		t.Fatalf("offline: exit=%d %q", code, out)
	}
	f.release("0.1.0", false)
	if code, out, _ := runUpdateScript(t, "", "--check"); code != 0 || out != "Open Trestle 0.1.0 is up to date.\n" {
		t.Fatalf("up to date: exit=%d %q", code, out)
	}
	f.release("0.2.0", false)
	code, out, errOut := runUpdateScript(t, "", "--check")
	if code != 10 || out != "Update available: 0.2.0 (you have 0.1.0), the signed release v0.2.0 on GitHub Releases. Install it with: trestle update\n" || errOut != "" {
		t.Fatalf("available: exit=%d %q %q", code, out, errOut)
	}
	// A prerelease is not offered to a release install.
	f.release("0.3.0-rc.1", true)
	if code, out, _ := runUpdateScript(t, "", "--check"); code != 0 || !strings.Contains(out, "up to date") {
		t.Fatalf("prerelease offered: exit=%d %q", code, out)
	}
	if f.archiveDownloaded() || len(f.commands) != 0 {
		t.Fatalf("--check downloaded an archive or ran %q", f.commands)
	}
	if code, _, errOut := runUpdateScript(t, "", "--check", "extra"); code != 2 || !strings.Contains(errOut, "usage: trestle update") {
		t.Fatalf("usage: exit=%d %q", code, errOut)
	}
	if code, _, errOut := runUpdateScript(t, "", "--check", "--check"); code != 2 || !strings.Contains(errOut, "--check was given twice") {
		t.Fatalf("twice: exit=%d %q", code, errOut)
	}
	if code, _, errOut := runUpdateScript(t, "", "--channel", "nightly"); code != 2 || !strings.Contains(errOut, "--channel must be auto, release or local") {
		t.Fatalf("channel: exit=%d %q", code, errOut)
	}
	if code, _, errOut := runUpdateScript(t, "", "--from", "x.pyz", "--channel", "local"); code != 2 || !strings.Contains(errOut, "cannot be combined with --channel") {
		t.Fatalf("from and channel: exit=%d %q", code, errOut)
	}
	if code, out, _ := runUpdateScript(t, "", "--help"); code != 0 || !strings.HasPrefix(out, "usage: trestle update") {
		t.Fatalf("help: exit=%d %q", code, out)
	}
}

func TestUpdateCheckVerifiesTheSignature(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	f.release("0.2.0", false)
	f.github.Set("https://github.com/georgejieh/open-trestle/releases/download/v0.2.0/"+update.SignatureName, testsupport.FakeResponse{Body: []byte("{}\n")})
	code, out, errOut := runUpdateScript(t, "", "--check")
	if code != 1 || out != "" || !strings.Contains(errOut, "trestle update: v0.2.0: the update was refused: the release signature file is malformed") {
		t.Fatalf("exit=%d %q %q", code, out, errOut)
	}
}

func TestUpdateWithoutAPinnedKeyRefusesTheReleaseChannel(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	f.noKeys()
	f.release("0.2.0", false)
	for _, args := range [][]string{nil, {"--check"}, {"--channel", "release"}} {
		code, out, errOut := runUpdateScript(t, "y\n", args...)
		if code != 1 || !strings.Contains(errOut, "trestle update: this build cannot verify releases; install the packaged release. Nothing was changed.") {
			t.Fatalf("%v: exit=%d\n%s\n%s", args, code, out, errOut)
		}
	}
	if len(f.github.Requests()) != 0 || len(f.commands) != 0 {
		t.Fatalf("requests %v commands %q", f.github.Requests(), f.commands)
	}
}

// Refusals run no program from the candidate unless execs says so: Go
// checks the signature, the SHA-256 and size, the sidecar and the folders
// before the archive's own verify-archive or upgrade can run.
func TestUpdateRefusalsInstallNothing(t *testing.T) {
	releaseAsset := "https://github.com/georgejieh/open-trestle/releases/download/v0.2.0/"
	for name, test := range map[string]struct {
		prepare func(f *updateFakes)
		input   string
		code    int
		want    string
		execs   []string // the last argument of each program allowed to run
	}{
		"signed with an unknown key": {func(f *updateFakes) {
			_, other, _ := ed25519.GenerateKey(rand.Reader)
			f.private = other
			f.release("0.2.0", false)
		}, "y\n", 1, "The update was refused: the release is signed with a key this build does not trust", nil},
		"unsigned": {func(f *updateFakes) {
			f.release("0.2.0", false)
			f.github.Set(releaseAsset+update.SignatureName, testsupport.FakeResponse{Body: []byte("{}\n")})
		}, "y\n", 1, "The update was refused: the release signature file is malformed", nil},
		"tampered archive": {func(f *updateFakes) {
			archive := f.release("0.2.0", false)
			archive[len(archive)/2] ^= 1
			f.github.Set(releaseAsset+update.ArchiveName, testsupport.FakeResponse{Body: archive})
		}, "y\n", 1, "The update was refused: the SHA-256 sidecar does not match the archive. Nothing was installed.", nil},
		"archive and sidecar replaced": {func(f *updateFakes) {
			archive := f.release("0.2.0", false)
			replaced := append([]byte(nil), archive...)
			replaced[strings.Index(string(replaced), "test archive")] = 'T'
			f.github.Set(releaseAsset+update.ArchiveName, testsupport.FakeResponse{Body: replaced})
			f.github.Set(releaseAsset+update.SidecarName, testsupport.FakeResponse{Body: testsupport.UpdateSidecar(replaced, update.ArchiveName)})
		}, "y\n", 1, "The update was refused: the archive's SHA-256 or size is not the signed one. Nothing was installed.", nil},
		"verify-archive fails": {func(f *updateFakes) {
			f.release("0.2.0", false)
			f.verifyOutput = "error: distribution archive member metadata is invalid\n"
		}, "y\n", 1, "the archive's own verify-archive failed (error: distribution archive member metadata is invalid). Nothing was installed.", []string{"verify-archive"}},
		"copy changed before the upgrade": {func(f *updateFakes) {
			f.release("0.2.0", false)
			f.onVerify = func(archive string) {
				os.Chmod(archive, 0o755)
				os.WriteFile(archive, testsupport.UpdateArchive("0.2.1", update.Target), 0o755)
				os.Chmod(archive, 0o555)
			}
		}, "y\n", 1, "The update was refused: the verified copy changed before it ran. Nothing was installed.", []string{"verify-archive"}},
		"declined": {func(f *updateFakes) { f.release("0.2.0", false) }, "n\n", 0, "Nothing was installed.", []string{"verify-archive"}},
		"no terminal and no --yes": {func(f *updateFakes) {
			f.release("0.2.0", false)
			f.terminal = false
		}, "y\n", 2, "installing needs your confirmation: run trestle update in a terminal, or pass --yes. Nothing was installed.", nil},
		"no sudo": {func(f *updateFakes) {
			f.release("0.2.0", false)
			updateSudoPaths = updateSudoPaths[:1]
		}, "y\n", 1, "installing needs sudo, and no root-owned sudo was found at", nil},
		"sudo writable by others": {func(f *updateFakes) {
			f.release("0.2.0", false)
			os.Chmod(f.sudo, 0o775)
		}, "y\n", 1, "no root-owned sudo was found", nil},
		"sudo only on PATH": {func(f *updateFakes) {
			f.release("0.2.0", false)
			f.t.Setenv("PATH", filepath.Dir(f.sudo)+string(os.PathListSeparator)+os.Getenv("PATH"))
			updateSudoPaths = updateSudoPaths[:1]
		}, "y\n", 1, "no root-owned sudo was found", nil},
		"not installed": {func(f *updateFakes) {
			updateReceiptPath = filepath.Join(f.tmp, "missing", "receipt.json")
		}, "", 1, "receipt.json). trestle update updates the packaged Linux amd64 install; to install it, see docs/operations.md.", nil},
		"receipt not root's": {func(f *updateFakes) {
			updateRootOwner = uint32(os.Getuid() + 1)
		}, "", 1, "is not owned by root. Nothing was changed.", nil},
		"release archive": {func(f *updateFakes) {
			previous := updateArchiveVersion
			updateArchiveVersion = func() string { return "0.1.0-alpha.1" }
			f.t.Cleanup(func() { updateArchiveVersion = previous })
		}, "", 1, "this is Open Trestle 0.1.0-alpha.1 from a release archive, and trestle update updates only the packaged Linux amd64 install. To update, run the installer again:\n  curl -fsSL https://georgejieh.dev/open-trestle/install.sh | bash", nil},
		"release archive on Windows": {func(f *updateFakes) {
			previous := updateArchiveVersion
			updateArchiveVersion = func() string { return "0.1.0" }
			f.t.Cleanup(func() { updateArchiveVersion = previous })
			updatePlatform = "windows/amd64"
		}, "", 1, "  irm https://georgejieh.dev/open-trestle/install.ps1 | iex", nil},
		"other platform": {func(f *updateFakes) { updatePlatform = "darwin/arm64" }, "", 1, "updates are for the packaged Linux amd64 install, and this is darwin/arm64.", nil},
		"offline":        {func(f *updateFakes) {}, "", 1, "GitHub Releases could not be read: GitHub could not be reached. Nothing was changed.", nil},
	} {
		t.Run(name, func(t *testing.T) {
			f := useUpdateFakes(t, "0.1.0")
			f.upgradeTo = "0.2.0"
			test.prepare(f)
			code, out, errOut := runUpdateScript(t, test.input)
			if code != test.code || !initHas(out+errOut, test.want) {
				t.Fatalf("exit=%d\n%s\n%s", code, out, errOut)
			}
			if len(f.commands) != len(test.execs) {
				t.Fatalf("ran %q, allowed %q", f.commands, test.execs)
			}
			for i, argv := range f.commands {
				if argv[len(argv)-1] != test.execs[i] {
					t.Fatalf("ran %q, allowed %q", f.commands, test.execs)
				}
			}
			if test.execs == nil && name != "tampered archive" && name != "archive and sidecar replaced" && f.archiveDownloaded() {
				t.Fatal("downloaded an archive that could not be installed")
			}
			if left := f.workspaces(); len(left) != 0 {
				t.Fatalf("temporary folders left: %v", left)
			}
		})
	}
}

// Nothing a release says reaches the upgrade command: it is the fixed sudo,
// --, the verified copy in the private folder, and upgrade.
func TestUpdateCommandIsFixed(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	f.release("0.2.0", false)
	f.upgradeTo = "0.2.0"
	hostile := f.lastRelease
	hostile["name"], hostile["body"] = "$(touch /tmp/pwned); --yes", "`rm -rf ~` ; sudo -s"
	hostile["assets"] = append(hostile["assets"].([]any), map[string]any{"name": "--preserve-env=PATH", "size": 1, "browser_download_url": "https://github.com/georgejieh/open-trestle/releases/download/v0.2.0/--preserve-env=PATH", "state": "uploaded"})
	f.github.Set(update.ReleasesURL, testsupport.FakeResponse{Body: testsupport.GitHubReleaseList(hostile)})
	t.Setenv("SUDO_ASKPASS", "/tmp/askpass")
	if code, out, errOut := runUpdateScript(t, "y\n"); code != 0 || len(f.installed) != 1 {
		t.Fatalf("exit=%d\n%s\n%s", code, out, errOut)
	}
	command := f.installed[0]
	if len(command) != 4 || command[0] != f.sudo || command[1] != "--" || command[2] != filepath.Join(filepath.Dir(command[2]), update.ArchiveName) || command[3] != "upgrade" {
		t.Fatalf("command %q", command)
	}
	if info, err := os.Lstat(filepath.Dir(command[2])); err == nil {
		t.Fatalf("the private folder outlived the update: %v", info.Mode())
	}
	for _, entry := range f.envs[1] {
		if !strings.HasPrefix(entry, "PATH=") && !strings.HasPrefix(entry, "LANG=") && !strings.HasPrefix(entry, "TERM=") {
			t.Fatalf("the upgrade got %q from the environment", entry)
		}
	}
}

func TestUpdateRunsBuildInfoOnlyForTheReceiptsTrestle(t *testing.T) {
	for name, test := range map[string]struct {
		prepare func(f *updateFakes)
		want    string
		ran     bool
	}{
		"the receipt's binary": {func(*updateFakes) {}, "Open Trestle is now 0.2.0 (source revision cccccccccccc).", true},
		"another binary": {func(f *updateFakes) {
			other := filepath.Join(filepath.Dir(f.trestle), "other")
			os.WriteFile(other, []byte("not the receipt's trestle"), 0o555)
			updateTrestlePath = other
		}, "Open Trestle is now 0.2.0 (its build info was not read: ", false},
		"writable by others": {func(f *updateFakes) { os.Chmod(f.trestle, 0o775) }, "its build info was not read: ", false},
	} {
		t.Run(name, func(t *testing.T) {
			f := useUpdateFakes(t, "0.1.0")
			f.release("0.2.0", false)
			f.upgradeTo = "0.2.0"
			test.prepare(f)
			code, out, _ := runUpdateScript(t, "y\n")
			if code != 0 || !initHas(out, test.want) || f.ran("build-info") != test.ran {
				t.Fatalf("exit=%d ran %q\n%s", code, f.commands, out)
			}
		})
	}
}

func TestUpdateYesInstallsWithoutAsking(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	f.release("0.2.0", false)
	f.upgradeTo = "0.2.0"
	f.terminal = false
	code, out, errOut := runUpdateScript(t, "", "--yes")
	if code != 0 || len(f.installed) != 1 || strings.Contains(out, "(y/N)") {
		t.Fatalf("exit=%d installed=%v\n%s\n%s", code, f.installed, out, errOut)
	}
}

func TestUpdateAsRootRunsTheLifecycleDirectly(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	f.release("0.2.0", false)
	f.upgradeTo = "0.2.0"
	updateSudoPaths = updateSudoPaths[:1]
	updateEUID = func() int { return 0 }
	code, out, _ := runUpdateScript(t, "y\n")
	if code != 0 || len(f.installed) != 1 || len(f.installed[0]) != 2 || f.installed[0][1] != "upgrade" || !strings.Contains(out, "\n    "+f.installed[0][0]+" upgrade\n") || strings.Contains(out, "sudo") {
		t.Fatalf("exit=%d installed=%v\n%s", code, f.installed, out)
	}
}

func TestUpdateReportsAFailedUpgrade(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	f.release("0.2.0", false)
	code, out, _ := runUpdateScript(t, "y\n")
	if code != 1 || !initHas(out, "✗ The upgrade did not finish: it exited with status 1.") || !initHas(out, "The receipt names 0.1.0 as installed.") {
		t.Fatalf("exit=%d\n%s", code, out)
	}
}

func TestUpdateSaysToRestartARunningDaemon(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	f.release("0.2.0", false)
	f.upgradeTo = "0.2.0"
	f.daemon = true
	code, out, _ := runUpdateScript(t, "y\n")
	if code != 0 || !initHas(out, "The trestled daemon is still running the old version. Restart it to use 0.2.0.") {
		t.Fatalf("exit=%d\n%s", code, out)
	}
}

func TestUpdateFromTheLocalFolder(t *testing.T) {
	f := useUpdateFakes(t, "0.1.5-dev")
	f.noKeys()
	dir := f.localBuild("0.1.6-dev")
	f.upgradeTo = "0.1.6-dev"
	code, out, errOut := runUpdateScript(t, "", "--check")
	if code != 10 || !strings.Contains(out, "Update available: 0.1.6-dev (you have 0.1.5-dev), an unsigned local build in ") || !strings.Contains(errOut, "GitHub Releases not checked: this build cannot verify releases; install the packaged release.") {
		t.Fatalf("check: exit=%d %q %q", code, out, errOut)
	}
	code, out, errOut = runUpdateScript(t, "y\n")
	if code != 0 || len(f.installed) != 1 {
		t.Fatalf("exit=%d\n%s\n%s", code, out, errOut)
	}
	for _, want := range []string{
		"… Update available: 0.1.6-dev, an unsigned local build in ",
		"It is not signed by a release key, so only its SHA-256 sidecar and its own verify-archive are checked.",
		"Verified the copy: its SHA-256 matches its sidecar and its own verify-archive passed.",
		"Open Trestle is now 0.1.6-dev",
	} {
		if !initHas(out, want) {
			t.Fatalf("output lacks %q:\n%s", want, out)
		}
	}
	// The upgrade ran the private copy, never the file in the local folder.
	if strings.HasPrefix(f.installed[0][2], dir) || filepath.Dir(filepath.Dir(f.installed[0][2])) != f.tmp {
		t.Fatalf("ran %s", f.installed[0][2])
	}
	// The folder is left as it was.
	if _, err := os.Lstat(filepath.Join(dir, update.ArchiveName)); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateLocalFolderRefusals(t *testing.T) {
	f := useUpdateFakes(t, "0.1.5-dev")
	f.noKeys()
	dir := f.localBuild("0.1.5-dev")
	if code, out, errOut := runUpdateScript(t, "", "--check"); code != 0 || !strings.Contains(out, "up to date") || !strings.Contains(errOut, "is 0.1.5-dev, which is not newer.") {
		t.Fatalf("equal: exit=%d %q %q", code, out, errOut)
	}
	f.localBuild("0.1.4-dev")
	if code, _, errOut := runUpdateScript(t, "", "--check"); code != 0 || !strings.Contains(errOut, "is 0.1.4-dev, which is not newer.") {
		t.Fatalf("older: exit=%d %q", code, errOut)
	}
	f.localBuild("0.1.6-dev")
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runUpdateScript(t, "", "--check"); code != 1 || !strings.Contains(errOut, "must be private (mode 0700, not 0755)") {
		t.Fatalf("open folder: exit=%d %q", code, errOut)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, update.ArchiveName)
	if err := os.Remove(archive); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "elsewhere.pyz"), archive); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := runUpdateScript(t, "", "--check"); code != 1 || !strings.Contains(errOut, "is a symbolic link") {
		t.Fatalf("linked archive: exit=%d %q", code, errOut)
	}
	if len(f.installed) != 0 {
		t.Fatal("installed")
	}
}

func TestUpdateLocalFolderOnlyForDevelopmentInstallsByDefault(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	f.localBuild("0.2.0")
	f.release("0.1.0", false)
	if code, out, _ := runUpdateScript(t, "", "--check"); code != 0 || !strings.Contains(out, "up to date") {
		t.Fatalf("a release install used the local folder: exit=%d %q", code, out)
	}
	if code, out, _ := runUpdateScript(t, "", "--check", "--channel", "local"); code != 10 || !strings.Contains(out, "an unsigned local build") {
		t.Fatalf("--channel local: exit=%d %q", code, out)
	}
	// A signed release of the same version wins over a local build.
	f.release("0.2.0", false)
	if code, out, _ := runUpdateScript(t, "", "--check"); code != 10 || !strings.Contains(out, "the signed release v0.2.0") {
		t.Fatalf("tie: exit=%d %q", code, out)
	}
}

func TestUpdateFromAFile(t *testing.T) {
	f := useUpdateFakes(t, "0.1.0")
	f.noKeys()
	f.upgradeTo = "0.2.0"
	dir := t.TempDir()
	path := filepath.Join(dir, "open-trestle-linux-amd64-new.pyz")
	archive := testsupport.UpdateArchive("0.2.0", update.Target)
	if err := os.WriteFile(path, archive, 0o555); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sha256", testsupport.UpdateSidecar(archive, filepath.Base(path)), 0o444); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runUpdateScript(t, "y\n", "--from", path)
	if code != 0 || len(f.installed) != 1 || filepath.Base(f.installed[0][2]) != "open-trestle-linux-amd64-new.pyz" || !initHas(out, "It is not signed by a release key") {
		t.Fatalf("exit=%d installed=%v\n%s\n%s", code, f.installed, out, errOut)
	}
	f.writeReceipt("0.2.0")
	code, _, errOut = runUpdateScript(t, "y\n", "--from", path)
	if code != 1 || !strings.Contains(errOut, "is version 0.2.0, which is not newer than the installed 0.2.0") || len(f.installed) != 1 {
		t.Fatalf("not newer: exit=%d %q", code, errOut)
	}
}

func TestUpdateShellLineQuotes(t *testing.T) {
	if got := updateShellLine([]string{"sudo", "--", "/tmp/a b/it's.pyz", "upgrade"}); got != `sudo -- '/tmp/a b/it'\''s.pyz' upgrade` {
		t.Fatal(got)
	}
}
