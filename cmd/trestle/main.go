package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/georgejieh/open-trestle/internal/config"
	"github.com/georgejieh/open-trestle/internal/review"
)

func main() {
	if len(os.Args) >= 2 && os.Args[1] == "mcp" {
		os.Exit(runMCP(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) >= 2 && os.Args[1] == "lsp" {
		os.Exit(runLSP(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) >= 2 && os.Args[1] == "acp" {
		os.Exit(runACP(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) >= 3 && os.Args[1] == "setup" && os.Args[2] == "web" {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		code := runSetupWeb(ctx, os.Args[3:], os.Getenv, os.Stdout, os.Stderr)
		stop()
		os.Exit(code)
	}
	if len(os.Args) >= 3 && os.Args[1] == "setup" && os.Args[2] == "tui" {
		os.Exit(runSetupTUI(os.Args[3:], os.Stdin, os.Stdout, os.Stderr))
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
	if len(args) >= 2 && args[0] == "local-git" {
		switch args[1] {
		case "model-review":
			return runLocalGitModelReview(ctx, args[2:], stdout, stderr)
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

func writeUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle validate-fixture <path>")
	fmt.Fprintln(stderr, "       trestle review <path>")
	fmt.Fprintln(stderr, "       trestle ci --format=json <path>")
	fmt.Fprintln(stderr, "       trestle ci --format=sarif <path>")
	writeSetupUsage(stderr)
	writeConfigUsage(stderr)
	writeEvaluateUsage(stderr)
	writeAdminUsage(stderr)
	writeRunsUsage(stderr)
	writeMCPUsage(stderr)
	writeLSPUsage(stderr)
	writeACPUsage(stderr)
	writeTUIUsage(stderr)
	writeLocalGitInspectUsage(stderr)
	writeLocalGitChangeUsage(stderr)
	writeLocalGitReviewUsage(stderr)
	writeLocalGitModelReviewUsage(stderr)
	writeLocalGitRetainedMemoryInputUsage(stderr)
}
