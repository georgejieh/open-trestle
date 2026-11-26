package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/internal/buildinfo"
	"github.com/georgejieh/open-trestle/internal/update"
)

// `trestle update` finds a newer packaged build, shows it, asks, and runs
// that build's own lifecycle upgrade with sudo. It never installs without a
// yes or --yes, and never installs a candidate whose checks failed. The
// lifecycle enforces the strictly-newer, same-target rule again as root.

const (
	updateExitAvailable  = 10
	updateListTimeout    = 15 * time.Second
	updateArchiveTimeout = 10 * time.Minute
)

// Tests replace these seams; production reads the real install.
var (
	updateReceiptPath          = update.ReceiptPath
	updateRootOwner     uint32 = 0
	updateKeys                 = update.PinnedKeys
	updateTransport     http.RoundTripper
	updatePlatform      = runtime.GOOS + "/" + runtime.GOARCH
	updateSudoPaths     = []string{"/usr/bin/sudo", "/bin/sudo"}
	updateTrestlePath   = update.TrestlePath
	updateEUID          = os.Geteuid
	updateTerminal      = func(stdin io.Reader) bool { file, ok := stdin.(*os.File); return ok && isTerminal(file) }
	updateRun           = runUpdateCommand
	updateDaemonRunning = trestledRunning
	// updateArchiveVersion is set only in a build from a release archive.
	updateArchiveVersion = buildinfo.Version
)

// updateInstallerCommand re-runs the install script, which is how a release
// archive install is updated.
func updateInstallerCommand(goos string) string {
	if goos == "windows" {
		return "irm https://georgejieh.dev/open-trestle/install.ps1 | iex"
	}
	return "curl -fsSL https://georgejieh.dev/open-trestle/install.sh | bash"
}

// updateFixedPath is the PATH every program trestle update runs gets, so the
// user's PATH never chooses python3 or anything else they start.
const updateFixedPath = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// updateCommand is one program trestle update runs. argv[0] is always an
// absolute path: the verified copy, sudo, or the installed trestle.
type updateCommand struct {
	argv           []string
	env            []string
	stdin          io.Reader
	stdout, stderr io.Writer
	// timeout is zero for the upgrade, which waits on the terminal.
	timeout time.Duration
}

func writeUpdateUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle update [--check] [--yes] [--channel auto|release|local | --from FILE]   (install a newer verified build; see docs/updates.md)")
}

type updateOptions struct {
	check, yes    bool
	channel, from string
}

func parseUpdateFlags(args []string, stdout, stderr io.Writer) (updateOptions, int, bool) {
	options := updateOptions{}
	flags := flag.NewFlagSet("trestle update", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&options.check, "check", false, "check")
	flags.BoolVar(&options.yes, "yes", false, "yes")
	flags.StringVar(&options.channel, "channel", "", "channel")
	flags.StringVar(&options.from, "from", "", "from")
	seen := map[string]bool{}
	for _, argument := range args {
		if name := strings.TrimLeft(strings.SplitN(argument, "=", 2)[0], "-"); strings.HasPrefix(argument, "-") && name != "" {
			if seen[name] {
				fmt.Fprintf(stderr, "trestle update: --%s was given twice.\n", name)
				return options, 2, true
			}
			seen[name] = true
		}
	}
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeUpdateUsage(stdout)
			return options, 0, true
		}
		fmt.Fprintln(stderr, "trestle update: "+err.Error())
		writeUpdateUsage(stderr)
		return options, 2, true
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "trestle update: unexpected argument %q.\n", flags.Arg(0))
		writeUpdateUsage(stderr)
		return options, 2, true
	}
	switch {
	case options.from != "" && options.channel != "":
		fmt.Fprintln(stderr, "trestle update: --from names the build to install, so it cannot be combined with --channel.")
		return options, 2, true
	case options.channel == "":
		options.channel = "auto"
	case options.channel != "auto" && options.channel != "release" && options.channel != "local":
		fmt.Fprintln(stderr, "trestle update: --channel must be auto, release or local.")
		return options, 2, true
	}
	return options, 0, false
}

// updateCandidate is the build an update would install.
type updateCandidate struct {
	kind    string // "release", "local" or "file"
	version update.Version
	release update.Release
	build   update.LocalBuild
}

// source says where the candidate comes from.
func (c updateCandidate) source() string {
	switch c.kind {
	case "release":
		return "the signed release " + c.release.Tag + " on GitHub Releases"
	case "local":
		return "an unsigned local build in " + initDisplayPath(filepath.Dir(c.build.Archive))
	}
	return "the file " + initDisplayPath(c.build.Archive)
}

func runUpdate(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	options, code, done := parseUpdateFlags(args, stdout, stderr)
	if done {
		return code
	}
	fail := func(code int, format string, values ...any) int {
		fmt.Fprintf(stderr, "trestle update: "+format+"\n", values...)
		return code
	}
	if version := updateArchiveVersion(); version != "" {
		return fail(1, "this is Open Trestle %s from a release archive, and trestle update updates only the packaged Linux amd64 install. To update, run the installer again:\n  %s", version, updateInstallerCommand(strings.SplitN(updatePlatform, "/", 2)[0]))
	}
	if updatePlatform != "linux/amd64" {
		return fail(1, "updates are for the packaged Linux amd64 install, and this is %s. Build trestle from source here instead (docs/getting-started.md).", updatePlatform)
	}
	installed, err := update.ReadReceipt(updateReceiptPath, updateRootOwner)
	if errors.Is(err, update.ErrNotInstalled) {
		return fail(1, "Open Trestle is not installed as a package on this machine (there is no %s). trestle update updates the packaged Linux amd64 install; to install it, see docs/operations.md.", updateReceiptPath)
	}
	if err != nil {
		return fail(1, "%v. Nothing was changed. Check the install with: sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz verify-installed", err)
	}
	ring, err := updateKeys()
	if err != nil {
		return fail(1, "this build's release keys cannot be read (%v).", err)
	}
	w := latestReviewPrinter(ctx, stdout, "")
	if !options.check {
		w.say("%s", w.style.paint(initToneHeading, "Open Trestle · update"))
		w.say("  Installed: %s, the packaged Linux amd64 install.", installed.Version)
	}
	client := update.Client{Transport: updateTransport}
	candidate, found, notes, err := findUpdate(ctx, client, ring, installed.Version, options)
	for _, note := range notes {
		if options.check {
			fmt.Fprintln(stderr, "trestle update: "+note)
		} else {
			w.say("  %s %s", w.optional, note)
		}
	}
	if err != nil {
		return fail(1, "%v. Nothing was changed.", err)
	}
	if !found {
		if options.check {
			checked := newOutPrinter(ctx, stdout)
			checked.note(checked.ok, fmt.Sprintf("Open Trestle %s is up to date.", installed.Version))
		} else {
			w.say("  %s Open Trestle %s is up to date.", w.ok, installed.Version)
		}
		return 0
	}
	if options.check {
		if candidate.kind == "release" {
			if _, _, err := update.VerifyReleaseSignature(ctx, client, ring, candidate.release); err != nil {
				return fail(1, "%s: %v.", candidate.release.Tag, err)
			}
		}
		if checked := newOutPrinter(ctx, stdout); checked.terminal {
			checked.note(checked.wait, fmt.Sprintf("Update available: %s (you have %s), %s.", candidate.version, installed.Version, candidate.source()))
			checked.next("trestle update")
		} else {
			fmt.Fprintf(stdout, "Update available: %s (you have %s), %s. Install it with: trestle update\n", candidate.version, installed.Version, candidate.source())
		}
		return updateExitAvailable
	}
	return installUpdate(ctx, w, client, ring, installed, candidate, options, stdin, stdout, stderr, fail)
}

// findUpdate picks the newest candidate the options allow, strictly newer
// than installed. notes say what was not checked and why.
func findUpdate(ctx context.Context, client update.Client, ring update.KeyRing, installed update.Version, options updateOptions) (updateCandidate, bool, []string, error) {
	if options.from != "" {
		build, err := update.FindFile(options.from)
		if err != nil {
			return updateCandidate{}, false, nil, err
		}
		if build.Version.Compare(installed) <= 0 {
			if options.check {
				return updateCandidate{}, false, []string{fmt.Sprintf("%s is version %s, which is not newer.", initDisplayPath(build.Archive), build.Version)}, nil
			}
			return updateCandidate{}, false, nil, fmt.Errorf("%s is version %s, which is not newer than the installed %s", initDisplayPath(build.Archive), build.Version, installed)
		}
		return updateCandidate{kind: "file", version: build.Version, build: build}, true, nil, nil
	}
	var best updateCandidate
	found := false
	notes := []string{}
	consider := func(candidate updateCandidate) {
		if !found || candidate.version.Compare(best.version) > 0 {
			best, found = candidate, true
		}
	}
	// A development install looks at GitHub Releases only when it can verify
	// them; every other install must.
	releaseOptional := options.channel == "auto" && installed.Development()
	var releaseErr error
	if options.channel == "auto" || options.channel == "release" {
		if len(ring) == 0 {
			releaseErr = update.ErrNoPinnedKey
		} else if releases, err := client.Releases(ctx, updateListTimeout); err != nil {
			releaseErr = err
		} else if release, ok := update.Newest(releases, installed); ok {
			consider(updateCandidate{kind: "release", version: release.Version, release: release})
		}
	}
	if options.channel == "local" || options.channel == "auto" && installed.Development() {
		dir, err := update.LocalDirectory(os.Getenv)
		if err != nil {
			return updateCandidate{}, false, notes, err
		}
		build, ok, err := update.FindLocal(dir)
		switch {
		case err != nil:
			return updateCandidate{}, false, notes, err
		case !ok:
			notes = append(notes, "No local build in "+initDisplayPath(dir)+".")
		case build.Version.Compare(installed) <= 0:
			notes = append(notes, fmt.Sprintf("The local build in %s is %s, which is not newer.", initDisplayPath(dir), build.Version))
		default:
			// consider keeps the earlier candidate on a tie, so a signed
			// release of the same version wins over a local build.
			consider(updateCandidate{kind: "local", version: build.Version, build: build})
		}
	}
	if releaseErr != nil {
		if !releaseOptional {
			return updateCandidate{}, false, notes, releaseErr
		}
		notes = append([]string{"GitHub Releases not checked: " + releaseErr.Error() + "."}, notes...)
	}
	return best, found, notes, nil
}

func installUpdate(ctx context.Context, w *initWizard, client update.Client, ring update.KeyRing, installed update.Installed, candidate updateCandidate, options updateOptions, stdin io.Reader, stdout, stderr io.Writer, fail func(int, string, ...any) int) int {
	switch {
	case candidate.kind == "release":
		w.say("  %s Update available: %s, %s.", w.ok, candidate.version, candidate.source())
	case candidate.build.Signature != "" && len(ring) != 0:
		w.say("  %s Update available: %s, %s. The .sig beside it must verify with a release key.", w.ok, candidate.version, candidate.source())
	default:
		w.say("  %s Update available: %s, %s.", w.wait, candidate.version, candidate.source())
		w.say("    It is not signed by a release key, so only its SHA-256 sidecar and its own verify-archive are checked. Install it only if you built it or trust whoever put it there.")
	}
	var command []string
	if updateEUID() != 0 {
		sudo, err := updateFindSudo()
		if err != nil {
			return fail(1, "installing needs sudo, and no root-owned sudo was found at %s. Nothing was installed. Install sudo, or run trestle update as root.", strings.Join(updateSudoPaths, " or "))
		}
		command = []string{sudo, "--"}
	}
	if !options.yes && !updateTerminal(stdin) {
		return fail(2, "installing needs your confirmation: run trestle update in a terminal, or pass --yes. Nothing was installed.")
	}
	workspace, err := update.NewWorkspace()
	if err != nil {
		return fail(1, "%v. Nothing was installed.", err)
	}
	defer func() {
		if err := workspace.Remove(); err != nil {
			fmt.Fprintf(stderr, "trestle update: the temporary folder %s could not be removed; delete it yourself.\n", workspace.Dir())
		}
	}()
	var prepared update.Prepared
	if candidate.kind == "release" {
		w.say("  %s Downloading %s and checking it.", w.wait, updateSize(candidate.release.Archive.Size))
		prepared, err = update.PrepareRelease(ctx, client, ring, candidate.release, workspace, updateArchiveTimeout)
	} else {
		prepared, err = update.PrepareLocal(candidate.build, ring, workspace)
	}
	if err != nil {
		w.say("  %s %s. Nothing was installed.", w.bad, updateSentence(err))
		return 1
	}
	copied := prepared.Copy
	if copied.Version.Compare(candidate.version) != 0 || copied.Version.Compare(installed.Version) <= 0 {
		w.say("  %s Refused: the copy is version %s, not the %s that was shown. Nothing was installed.", w.bad, copied.Version, candidate.version)
		return 1
	}
	// The archive's own code runs only after the Go checks above passed.
	if err := workspace.Recheck(copied); err != nil {
		w.say("  %s %s. Nothing was installed.", w.bad, updateSentence(err))
		return 1
	}
	if err := updateVerifyArchive(ctx, copied.Archive); err != nil {
		w.say("  %s Refused: the archive's own verify-archive failed (%v). Nothing was installed.", w.bad, err)
		return 1
	}
	switch {
	case prepared.Signed:
		w.say("  %s Verified the copy: signed with release key %s, with the signed SHA-256 and size, and its own verify-archive passed.", w.ok, prepared.Key.ID)
	case prepared.SignatureUnchecked:
		w.say("  %s Verified the copy: its SHA-256 matches its sidecar and its own verify-archive passed. The .sig beside it was not checked: this build has no release key.", w.ok)
	default:
		w.say("  %s Verified the copy: its SHA-256 matches its sidecar and its own verify-archive passed.", w.ok)
	}
	command = append(command, copied.Archive, "upgrade")
	w.say("  Installing needs administrator rights. This command runs:")
	w.sayVerbatim("    " + updateShellLine(command))
	if !options.yes && !updateConfirm(ctx, w, stdin, copied.Version) {
		w.say("  Nothing was installed.")
		return 0
	}
	if err := workspace.Recheck(copied); err != nil {
		w.say("  %s %s. Nothing was installed.", w.bad, updateSentence(err))
		return 1
	}
	exitCode, runErr := updateRun(ctx, updateCommand{argv: command, env: updateInstallEnvironment(), stdin: stdin, stdout: stdout, stderr: stderr})
	after, readErr := update.ReadReceipt(updateReceiptPath, updateRootOwner)
	if runErr != nil || exitCode != 0 || readErr != nil || after.Version.Compare(copied.Version) != 0 {
		status := "it could not be started"
		if runErr == nil {
			status = fmt.Sprintf("it exited with status %d", exitCode)
		}
		w.say("  %s The upgrade did not finish: %s.", w.bad, status)
		if readErr == nil {
			w.say("    The receipt names %s as installed.", after.Version)
		} else {
			w.say("    The receipt cannot be read (%v). Check the install with: sudo /usr/local/libexec/open-trestle/open-trestle-distribution.pyz verify-installed", readErr)
		}
		return 1
	}
	w.say("  %s Open Trestle is now %s (%s).", w.ok, after.Version, updateBuildRevision(ctx, after))
	if updateDaemonRunning() {
		w.say("  The trestled daemon is still running the old version. Restart it to use %s.", after.Version)
	}
	return 0
}

// updateConfirm asks before installing. Only y or yes installs.
func updateConfirm(ctx context.Context, w *initWizard, stdin io.Reader, version update.Version) bool {
	for range initMaxTries {
		fmt.Fprint(w.out, w.style.paint(initTonePrompt, "  Install "+version.String()+" now? (y/N): "))
		answer := strings.ToLower(homeReadChoice(ctx, stdin))
		fmt.Fprintln(w.out)
		switch answer {
		case "y", "yes":
			return true
		case "", "n", "no", "q":
			return false
		}
		w.say("    Please answer y or n.")
	}
	return false
}

// updateShellLine prints argv as a shell command, quoting any argument with
// characters a shell would read specially.
func updateShellLine(argv []string) string {
	quoted := make([]string, len(argv))
	for i, argument := range argv {
		plain := argument != ""
		for _, character := range argument {
			if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("/._+-=:,@", character)) {
				plain = false
				break
			}
		}
		if plain {
			quoted[i] = argument
		} else {
			quoted[i] = "'" + strings.ReplaceAll(argument, "'", `'\''`) + "'"
		}
	}
	return strings.Join(quoted, " ")
}

// updateSentence is an error as the start of a sentence.
func updateSentence(err error) string {
	text := err.Error()
	if text == "" {
		return "Failed"
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

func updateSize(size int64) string {
	if size >= 1<<20 {
		return fmt.Sprintf("%.1f MiB", float64(size)/(1<<20))
	}
	return fmt.Sprintf("%d KiB", (size+1023)/1024)
}

// updateFindSudo is the first root-owned sudo at a fixed path; the user's
// PATH is not searched.
func updateFindSudo() (string, error) {
	for _, path := range updateSudoPaths {
		if update.CheckRootFile(path, updateRootOwner, update.InstalledFile{}) == nil {
			return path, nil
		}
	}
	return "", errors.New("no root-owned sudo")
}

// updateInstallEnvironment is the fixed PATH and C locale, plus TERM so sudo
// can prompt on this terminal.
func updateInstallEnvironment() []string {
	environment := []string{updateFixedPath, "LANG=C"}
	if term := os.Getenv("TERM"); term != "" {
		environment = append(environment, "TERM="+term)
	}
	return environment
}

// updateVerifyArchive runs the verified copy's own verify-archive as this
// account.
func updateVerifyArchive(ctx context.Context, archive string) error {
	var output updateBoundedBuffer
	code, err := updateRun(ctx, updateCommand{argv: []string{archive, "verify-archive"}, env: []string{updateFixedPath, "LANG=C"}, stdout: &output, stderr: &output, timeout: 2 * time.Minute})
	if err != nil || code != 0 || output.String() != "Open Trestle candidate archive verified.\n" {
		message := strings.TrimSpace(output.String())
		switch {
		case message != "":
		case err != nil:
			message = err.Error()
		default:
			message = fmt.Sprintf("exit status %d", code)
		}
		return errors.New(message)
	}
	return nil
}

// updateBuildRevision describes the installed trestle's source revision. It
// runs build-info only when the binary is root-owned, not writable by
// others, and is exactly the file the receipt names.
func updateBuildRevision(ctx context.Context, installed update.Installed) string {
	if installed.Trestle == (update.InstalledFile{}) {
		return "the receipt names no trestle binary, so its build info was not read"
	}
	if err := update.CheckRootFile(updateTrestlePath, updateRootOwner, installed.Trestle); err != nil {
		return "its build info was not read: " + err.Error()
	}
	var output updateBoundedBuffer
	code, err := updateRun(ctx, updateCommand{argv: []string{updateTrestlePath, "build-info"}, env: []string{updateFixedPath, "LANG=C"}, stdout: &output, stderr: io.Discard, timeout: 10 * time.Second})
	var info struct {
		SourceBound    bool   `json:"source_bound"`
		SourceRevision string `json:"source_revision"`
	}
	if err != nil || code != 0 || json.Unmarshal(output.Bytes(), &info) != nil {
		return "its build info could not be read"
	}
	if !info.SourceBound || !lastReviewCommit.MatchString(info.SourceRevision) {
		return "its build records no source revision"
	}
	return "source revision " + initShort(info.SourceRevision)
}

// runUpdateCommand runs one program with a fixed environment from /. The
// upgrade has no deadline and is not tied to the context: Ctrl-C reaches
// sudo and the lifecycle through the terminal, and the lifecycle recovers
// its own transaction.
func runUpdateCommand(ctx context.Context, command updateCommand) (int, error) {
	if len(command.argv) == 0 || !filepath.IsAbs(command.argv[0]) {
		return -1, errors.New("not an absolute program path")
	}
	var process *exec.Cmd
	if command.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, command.timeout)
		defer cancel()
		process = exec.CommandContext(ctx, command.argv[0], command.argv[1:]...)
	} else {
		process = exec.Command(command.argv[0], command.argv[1:]...)
	}
	process.Dir, process.Env = "/", command.env
	process.Stdin, process.Stdout, process.Stderr = command.stdin, command.stdout, command.stderr
	err := process.Run()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return exit.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// trestledRunning reports a process named trestled on this machine.
func trestledRunning() bool {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return false
	}
	for index, entry := range entries {
		if index > 1<<17 {
			break
		}
		if name := entry.Name(); name != "" && strings.Trim(name, "0123456789") == "" {
			if comm, err := os.ReadFile(filepath.Join("/proc", name, "comm")); err == nil && strings.TrimSpace(string(comm)) == "trestled" {
				return true
			}
		}
	}
	return false
}

// updateBoundedBuffer keeps the first 64 KiB written to it.
type updateBoundedBuffer struct{ bytes.Buffer }

func (b *updateBoundedBuffer) Write(p []byte) (int, error) {
	if room := 64<<10 - b.Len(); room > 0 {
		b.Buffer.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}
