package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/internal/config"
	"github.com/georgejieh/open-trestle/internal/review"
)

const ciReceiptSchemaVersion = 2

type ciReceipt struct {
	SchemaVersion int            `json:"schema_version"`
	Status        review.Outcome `json:"status"`
	FixtureID     string         `json:"fixture_id,omitempty"`
	RequestID     string         `json:"request_id,omitempty"`
	SnapshotID    string         `json:"snapshot_id,omitempty"`
	Revision      string         `json:"revision,omitempty"`
	Reason        string         `json:"reason,omitempty"`
	Findings      []ciFinding    `json:"findings"`
}

type ciFinding struct {
	ID       string          `json:"id"`
	Title    string          `json:"title"`
	Severity review.Severity `json:"severity"`
	Source   ciSource        `json:"source"`
	Evidence ciEvidence      `json:"evidence"`
}

type ciSource struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type ciEvidence struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

func runCI(fixturePath string, stdout, stderr io.Writer) int {
	result, err := review.ReviewLocalFixture(fixturePath, config.DefaultLocal())
	receipt := ciReceipt{SchemaVersion: ciReceiptSchemaVersion, Findings: make([]ciFinding, 0)}
	if err != nil {
		receipt.Status = review.ErrorOutcome(err)
		receipt.Reason = err.Error()
		if receipt.Status == review.OutcomeBlocked {
			return writeCIReceipt(receipt, stdout, stderr, 4)
		}
		return writeCIReceipt(receipt, stdout, stderr, 1)
	}

	receipt.Status = result.Outcome()
	receipt.FixtureID = result.FixtureIdentity()
	receipt.RequestID = result.RequestID()
	receipt.SnapshotID = result.SnapshotIdentity()
	receipt.Revision = result.Revision()
	if result.Outcome() == review.OutcomeInconclusive {
		receipt.Reason = result.Reason()
		return writeCIReceipt(receipt, stdout, stderr, 3)
	}
	if result.Outcome() != review.OutcomeVerified {
		receipt.Reason = fmt.Sprintf("unsupported review outcome: %q", result.Outcome())
		return writeCIReceipt(receipt, stdout, stderr, 1)
	}

	findings := result.Findings()
	items := result.EvidenceItems()
	if len(findings) != len(items) {
		receipt.Status = review.OutcomeFailed
		receipt.Reason = "finding and evidence counts differ"
		return writeCIReceipt(receipt, stdout, stderr, 1)
	}
	receipt.Findings = make([]ciFinding, len(findings))
	for i, finding := range findings {
		sourceRange := finding.SourceRange()
		item := items[i]
		receipt.Findings[i] = ciFinding{
			ID:       finding.ID(),
			Title:    finding.Title(),
			Severity: finding.Severity(),
			Source: ciSource{
				Path:      sourceRange.Path(),
				StartLine: sourceRange.StartLine(),
				EndLine:   sourceRange.EndLine(),
			},
			Evidence: ciEvidence{ID: item.ID(), Digest: item.Digest()},
		}
	}
	return writeCIReceipt(receipt, stdout, stderr, 0)
}

func writeCIReceipt(receipt ciReceipt, stdout, stderr io.Writer, exitCode int) int {
	encoded, err := json.Marshal(receipt)
	if err != nil {
		fmt.Fprintf(stderr, "encode result: %v\n", err)
		return 1
	}
	encoded = append(encoded, '\n')
	if _, err := stdout.Write(encoded); err != nil {
		fmt.Fprintf(stderr, "write result: %v\n", err)
		return 1
	}
	return exitCode
}
