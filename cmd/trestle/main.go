package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
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
	if len(os.Args) >= 2 && os.Args[1] == "acp" {
		os.Exit(runACP(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) >= 2 && os.Args[1] == "init" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runInit(ctx, os.Args[2:], os.Stdin, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if len(os.Args) >= 2 && os.Args[1] == "tui" {
		os.Exit(runTUI(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
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

// writeUsage prints every command's usage, grouped by who uses it. It is the
// text of `trestle --help` on standard output and of a refused command line on
// standard error. The first line stays a usage line: the packaged install's
// smoke probe requires standard error to start with "usage: trestle ".
func writeUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle <command> [flags]")
	fmt.Fprintln(w, "Open Trestle reviews a code change with models you choose. New here: run trestle init inside a Git repository.")
	fmt.Fprintln(w, "Guides: docs/README.md · "+homeDocs)

	writeUsageGroup(w, "Everyday")
	fmt.Fprintln(w, "usage: trestle   (in a terminal: this repository's status and next actions)")
	writeLatestReviewUsage(w)
	writeUpdateUsage(w)
	writeUsageUsage(w)
	writeProfilesUsage(w)

	writeUsageGroup(w, "Setup and keys")
	fmt.Fprintln(w, "usage: trestle init [--no-input] [answer flags]   (start here: guided setup and first review; see docs/getting-started.md)")
	writeKeysUsage(w)
	writeChecksUsage(w)

	writeUsageGroup(w, "Integrations")
	writeLocalGitModelReviewUsage(w)
	writeRunsUsage(w)
	writeTUIUsage(w)
	writeMCPUsage(w)
	writeLSPUsage(w)
	writeACPUsage(w)
	writeLocalGitSubmitReviewUsage(w)

	writeUsageGroup(w, "Operators")
	writeSetupUsage(w)
	writeConfigUsage(w)
	writeAdminUsage(w)
	writeLocalGitInspectUsage(w)
	writeLocalGitChangeUsage(w)
	writeLocalGitReviewUsage(w)
	writeLocalGitRetainedMemoryInputUsage(w)
	writeIndexUsage(w)
	fmt.Fprintln(w, "usage: trestle build-info")

	writeUsageGroup(w, "Evaluation")
	writeEvaluateUsage(w)
	fmt.Fprintln(w, "usage: trestle validate-fixture <path>")
	fmt.Fprintln(w, "       trestle ci --format=json <path>")
	fmt.Fprintln(w, "       trestle ci --format=sarif <path>")
}

func writeUsageGroup(w io.Writer, name string) {
	fmt.Fprintf(w, "\n%s:\n", name)
}
