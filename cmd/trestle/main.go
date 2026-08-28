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
	fmt.Fprintf(stdout, "valid fixture %s\n", fixture.Identity())
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

	fmt.Fprintf(stdout, "status: %s\nfixture: %s\n", result.Outcome(), result.FixtureIdentity())
	if result.Outcome() == review.OutcomeInconclusive {
		fmt.Fprintf(stdout, "reason: %s\n", result.Reason())
		return 3
	}
	finding := result.Finding()
	sourceRange := finding.SourceRange()
	item := result.Evidence()
	fmt.Fprintf(stdout, "finding: %s %s %s\n", finding.ID(), finding.Severity(), finding.Title())
	fmt.Fprintf(stdout, "source: %s:%d-%d\n", sourceRange.Path(), sourceRange.StartLine(), sourceRange.EndLine())
	fmt.Fprintf(stdout, "evidence: %s %s\n", item.ID(), item.Digest())
	return 0
}

func writeUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle validate-fixture <path>")
	fmt.Fprintln(stderr, "       trestle review <path>")
}
