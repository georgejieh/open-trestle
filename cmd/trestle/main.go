package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/georgejieh/open-trestle/internal/buildinfo"
	"github.com/georgejieh/open-trestle/internal/checksandbox"
	"github.com/georgejieh/open-trestle/internal/config"
	"github.com/georgejieh/open-trestle/internal/review"
)

func main() {
	// A check sandbox on Linux re-executes this program as its first process.
	checksandbox.RunChildIfRequested()
	if len(os.Args) == 1 {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runHome(ctx, os.Stdin, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if len(os.Args) >= 2 && os.Args[1] == "keys" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runKeys(ctx, os.Args[2:], os.Stdin, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if len(os.Args) >= 2 && os.Args[1] == "update" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runUpdate(ctx, os.Args[2:], os.Stdin, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if len(os.Args) >= 2 && os.Args[1] == "review" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runWithContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if len(os.Args) >= 2 && os.Args[1] == "index" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runIndex(ctx, os.Args[2:], os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if len(os.Args) >= 2 && os.Args[1] == "profile" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runProfile(ctx, os.Args[2:], os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if len(os.Args) >= 2 && os.Args[1] == "mcp" {
		os.Exit(runMCP(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) >= 2 && os.Args[1] == "lsp" {
		os.Exit(runLSP(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) >= 2 && os.Args[1] == "init" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runInit(ctx, os.Args[2:], os.Stdin, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if len(os.Args) >= 3 && os.Args[1] == "local-git" && (os.Args[2] == "model-review" || os.Args[2] == "retained-memory-input") {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runWithContext(ctx, os.Args[1:], os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithContext(context.Background(), args, stdout, stderr)
}

func runWithContext(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		writeUsage(stdout)
		return 0
	}
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		writeVersion(stdout)
		return 0
	}
	if len(args) == 2 && (args[1] == "--help" || args[1] == "-h") {
		if command, ok := trestleCommandNamed(args[0]); ok {
			command.usage(stdout)
			return 0
		}
	}
	if len(args) > 0 && args[0] == "build-info" {
		if len(args) != 1 {
			fmt.Fprintln(stderr, "usage: trestle build-info")
			return 2
		}
		if err := buildinfo.Write(stdout, "trestle"); err != nil {
			fmt.Fprintf(stderr, "build-info: %v\n", err)
			return 1
		}
		return 0
	}
	if len(args) >= 1 && args[0] == "setup" {
		return runSetup(args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "config" {
		return runConfig(args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "evaluate" {
		return runEvaluate(args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "admin" {
		return runAdmin(args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "runs" {
		return runRemote(args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "profiles" {
		return runProfiles(args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "usage" {
		return runUsage(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "keys" {
		return runKeys(ctx, args[1:], os.Stdin, stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "update" {
		return runUpdate(ctx, args[1:], os.Stdin, stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "index" {
		return runIndex(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "checks" {
		return runChecks(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "profile" {
		return runProfile(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "doctor" {
		return runDoctor(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 1 && args[0] == "status" {
		return runStatus(ctx, args[1:], stdout, stderr)
	}
	// `trestle review <path>` reviews a fixture file, as before; any other
	// form reviews the latest change with the repository's setup.
	if len(args) >= 1 && args[0] == "review" && !(len(args) == 2 && !strings.HasPrefix(args[1], "-")) {
		return runLatestReview(ctx, args[1:], stdout, stderr)
	}
	if len(args) >= 2 && args[0] == "local-git" {
		switch args[1] {
		case "model-review":
			return runLocalGitModelReview(ctx, args[2:], stdout, stderr)
		case "submit-review":
			return runLocalGitSubmitReview(args[2:], stdout, stderr)
		case "retained-memory-input":
			return runLocalGitRetainedMemoryInput(ctx, args[2:], stdout, stderr)
		case "inspect":
			return runLocalGitInspect(args[2:], stdout, stderr)
		case "change":
			return runLocalGitChange(args[2:], stdout, stderr)
		case "review":
			return runLocalGitReview(args[2:], stdout, stderr)
		}
	}
	if len(args) == 3 && args[0] == "ci" {
		switch args[1] {
		case "--format=json":
			return runCI(args[2], stdout, stderr)
		case "--format=sarif":
			return runSARIF(args[2], stdout, stderr)
		}
	}
	// A first word that is no command gets a short refusal; a known command
	// with the wrong arguments, and no arguments at all, get the overview.
	if len(args) > 0 && args[0] != "help" {
		if _, known := trestleCommandNamed(args[0]); !known {
			writeUnknownCommand(stderr, args[0])
			return 2
		}
	}
	if len(args) != 2 {
		writeUsage(stderr)
		return 2
	}
	switch args[0] {
	case "validate-fixture":
		return runValidateFixture(args[1], stdout, stderr)
	case "review":
		return runReview(args[1], stdout, stderr)
	default:
		writeUsage(stderr)
		return 2
	}
}

func runValidateFixture(fixturePath string, stdout, stderr io.Writer) int {
	fixture, err := review.LoadLocalFixture(fixturePath, config.DefaultLocal())
	if err != nil {
		fmt.Fprintf(stderr, "validate fixture: %v\n", err)
		return 1
	}
	if _, err := fmt.Fprintf(stdout, "valid fixture %s\n", fixture.Identity()); err != nil {
		fmt.Fprintf(stderr, "write result: %v\n", err)
		return 1
	}
	return 0
}

func runReview(fixturePath string, stdout, stderr io.Writer) int {
	result, err := review.ReviewLocalFixture(fixturePath, config.DefaultLocal())
	if err != nil {
		outcome := review.ErrorOutcome(err)
		fmt.Fprintf(stderr, "status: %s\nreason: %v\n", outcome, err)
		if outcome == review.OutcomeBlocked {
			return 4
		}
		return 1
	}

	var output string
	exitCode := 0
	if result.Outcome() == review.OutcomeInconclusive {
		output = fmt.Sprintf("status: %s\nfixture: %s\nreason: %s\n", result.Outcome(), result.FixtureIdentity(), result.Reason())
		exitCode = 3
	} else {
		findings := result.Findings()
		items := result.EvidenceItems()
		if len(findings) != len(items) {
			fmt.Fprintln(stderr, "render result: finding and evidence counts differ")
			return 1
		}
		var builder strings.Builder
		fmt.Fprintf(&builder, "status: %s\nfixture: %s\n", result.Outcome(), result.FixtureIdentity())
		for i, finding := range findings {
			sourceRange := finding.SourceRange()
			item := items[i]
			fmt.Fprintf(
				&builder,
				"finding: %s %s %s\nsource: %s:%d-%d\nevidence: %s %s\n",
				finding.ID(),
				finding.Severity(),
				finding.Title(),
				sourceRange.Path(),
				sourceRange.StartLine(),
				sourceRange.EndLine(),
				item.ID(),
				item.Digest(),
			)
		}
		output = builder.String()
	}
	if _, err := io.WriteString(stdout, output); err != nil {
		fmt.Fprintf(stderr, "write result: %v\n", err)
		return 1
	}
	return exitCode
}

// trestleCommand is a top-level command: what it does, in a few words, and
// its full usage.
type trestleCommand struct {
	name, what string
	usage      func(io.Writer)
}

// trestleCommandGroups are the commands grouped by who uses them, as
// `trestle --help` and docs/commands.md list them.
var trestleCommandGroups = []struct {
	name     string
	commands []trestleCommand
}{
	{"Everyday", []trestleCommand{
		{"review", "Review the latest change or a fixture", writeLatestReviewUsage},
		{"status", "Setup, key, spending and last review", writeStatusUsage},
		{"update", "Install a newer verified build", writeUpdateUsage},
		{"usage", "Spending against each API key's limit", writeUsageUsage},
		{"profiles", "The specialist review profiles", writeProfilesUsage},
	}},
	{"Setup and keys", []trestleCommand{
		{"init", "Guided setup and the first review", writeInitUsage},
		{"keys", "See, save and remove API keys", writeKeysUsage},
		{"checks", "Run the repository's tests in a sandbox", writeChecksUsage},
		{"doctor", "Check the install and setup, with fixes", writeDoctorUsage},
	}},
	{"Integrations", []trestleCommand{
		{"local-git", "The direct review for CI, and Git tools", writeLocalGitUsage},
		{"runs", "Submit, follow and cancel daemon runs", writeRunsUsage},
		{"mcp", "Serve reviews to an MCP client", writeMCPUsage},
		{"lsp", "Serve findings to an editor", writeLSPUsage},
	}},
	{"Operators", []trestleCommand{
		{"setup", "Protected configuration and backups", writeSetupUsage},
		{"config", "Validate and bind route configuration", writeConfigUsage},
		{"admin", "The daemon's runtime status", writeAdminUsage},
		{"index", "The repository index", writeIndexUsage},
		{"profile", "Languages, tests and CI checks", writeProfileUsage},
		{"version", "The version, in one line", func(w io.Writer) { fmt.Fprintln(w, "usage: trestle version   (or trestle --version)") }},
		{"build-info", "The build's source identity, as JSON", func(w io.Writer) { fmt.Fprintln(w, "usage: trestle build-info") }},
	}},
	{"Evaluation", []trestleCommand{
		{"evaluate", "Evaluate captured reviews", writeEvaluateUsage},
		{"validate-fixture", "Check a review fixture file", func(w io.Writer) { fmt.Fprintln(w, "usage: trestle validate-fixture <path>") }},
		{"ci", "Review a fixture file as JSON or SARIF", func(w io.Writer) {
			fmt.Fprintln(w, "usage: trestle ci --format=json <path>")
			fmt.Fprintln(w, "       trestle ci --format=sarif <path>")
		}},
	}},
}

func writeLocalGitUsage(w io.Writer) {
	writeLocalGitModelReviewUsage(w)
	writeLocalGitSubmitReviewUsage(w)
	writeLocalGitInspectUsage(w)
	writeLocalGitChangeUsage(w)
	writeLocalGitReviewUsage(w)
	writeLocalGitRetainedMemoryInputUsage(w)
}

// trestleCommandNamed finds a top-level command.
func trestleCommandNamed(name string) (trestleCommand, bool) {
	for _, group := range trestleCommandGroups {
		for _, command := range group.commands {
			if command.name == name {
				return command, true
			}
		}
	}
	return trestleCommand{}, false
}

// writeUsage is the overview of `trestle --help` on standard output and of a
// bare `trestle` without a terminal on standard error. The first line stays a
// usage line: the packaged install's smoke probe requires standard error to
// start with "usage: trestle ".
func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle <command> [flags]")
	fmt.Fprintln(w, "Open Trestle reviews a code change with models you choose.")
	fmt.Fprintln(w, "Guides: docs/README.md · "+homeDocs)
	fmt.Fprintln(w, "\nStart here:")
	fmt.Fprintln(w, "  trestle init      Set up this repository, then review")
	fmt.Fprintln(w, "  trestle review    Review the latest committed change")
	fmt.Fprintln(w, "  trestle           Status and next actions (in a terminal)")
	for _, group := range trestleCommandGroups {
		fmt.Fprintf(w, "\n%s:\n", group.name)
		for _, command := range group.commands {
			fmt.Fprintf(w, "  %-18s%s\n", command.name, command.what)
		}
	}
	fmt.Fprintln(w, "\nRun trestle <command> --help for flags.")
}

// writeUnknownCommand refuses a first word that is no command, with the
// nearest command name when one is close.
func writeUnknownCommand(w io.Writer, name string) {
	fmt.Fprintf(w, "trestle: %q is not a trestle command.\n", name)
	if suggestion := nearestCommand(name); suggestion != "" {
		fmt.Fprintf(w, "Did you mean: %s?\n", suggestion)
	}
	fmt.Fprintln(w, "Run trestle --help to see all commands.")
}

// nearestCommand is the closest command name within one edit for every three
// characters of name (at least one), or "" when none is.
func nearestCommand(name string) string {
	best, bestDistance := "", max(1, len(name)/3)+1
	for _, group := range trestleCommandGroups {
		for _, command := range group.commands {
			if distance := editDistance(strings.ToLower(name), command.name); distance < bestDistance {
				best, bestDistance = command.name, distance
			}
		}
	}
	return best
}

// editDistance is the Levenshtein distance between a and b, in bytes.
func editDistance(a, b string) int {
	previous := make([]int, len(b)+1)
	for j := range previous {
		previous[j] = j
	}
	for i := 1; i <= len(a); i++ {
		current := make([]int, len(b)+1)
		current[0] = i
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			current[j] = min(previous[j]+1, current[j-1]+1, previous[j-1]+cost)
		}
		previous = current
	}
	return previous[len(b)]
}

// writeVersion prints the version in one line: the packaged install's version
// when this is its trestle, and the source revision when the build records it.
func writeVersion(w io.Writer) {
	revision := "no source revision recorded"
	if value := buildinfo.Revision(); value != "" {
		revision = "source revision " + initShort(value)
	}
	if installed, ok := updatePackageInstalled(); ok && runningInstalledTrestle() {
		fmt.Fprintf(w, "Open Trestle %s (%s), the packaged Linux amd64 install\n", installed.Version, revision)
		return
	}
	fmt.Fprintf(w, "Open Trestle development build (%s)\n", revision)
}

// runningInstalledTrestle reports whether this program is the packaged
// install's trestle.
func runningInstalledTrestle() bool {
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	resolved, err := filepath.EvalSymlinks(executable)
	return err == nil && sameCheckout(resolved, updateTrestlePath)
}
