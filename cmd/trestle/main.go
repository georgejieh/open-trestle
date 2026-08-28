package main

import (
	"fmt"
	"io"
	"os"

	"github.com/georgejieh/open-trestle/internal/config"
	"github.com/georgejieh/open-trestle/internal/review"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 3 && args[0] == "ci" && args[1] == "--format=json" {
		return runCI(args[2], stdout, stderr)
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
	fixtureFile, err := os.Open(fixturePath)
	if err != nil {
		fmt.Fprintf(stderr, "open fixture: %v\n", err)
		return 1
	}
	defer fixtureFile.Close()

	fixture, err := review.LoadFixture(fixtureFile, config.DefaultLocal())
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
		finding := result.Finding()
		sourceRange := finding.SourceRange()
		item := result.Evidence()
		output = fmt.Sprintf(
			"status: %s\nfixture: %s\nfinding: %s %s %s\nsource: %s:%d-%d\nevidence: %s %s\n",
			result.Outcome(),
			result.FixtureIdentity(),
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
}
