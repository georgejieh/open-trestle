package main

import (
	"fmt"
	"io"
	"net/url"

	"github.com/georgejieh/open-trestle/internal/review"
)

const (
	sarifSchemaURI             = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
	staticDebugOutputSARIFRule = "static-debug-output"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool       sarifTool          `json:"tool"`
	Results    []sarifResult      `json:"results"`
	Properties sarifRunProperties `json:"properties"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name  string      `json:"name"`
	Rules []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string             `json:"id"`
	ShortDescription     sarifMessage       `json:"shortDescription"`
	DefaultConfiguration sarifConfiguration `json:"defaultConfiguration"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID       string                `json:"ruleId"`
	Level        string                `json:"level"`
	Message      sarifMessage          `json:"message"`
	Locations    []sarifLocation       `json:"locations"`
	Fingerprints map[string]string     `json:"fingerprints"`
	Properties   sarifResultProperties `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

type sarifRunProperties struct {
	Status     review.Outcome `json:"trestleStatus"`
	Reason     string         `json:"trestleReason,omitempty"`
	FixtureID  string         `json:"trestleFixtureId,omitempty"`
	RequestID  string         `json:"trestleRequestId,omitempty"`
	SnapshotID string         `json:"trestleSnapshotId,omitempty"`
	Revision   string         `json:"trestleRevision,omitempty"`
}

type sarifResultProperties struct {
	EvidenceID     string `json:"trestleEvidenceId"`
	EvidenceDigest string `json:"trestleEvidenceDigest"`
}

func runSARIF(fixturePath string, stdout, stderr io.Writer) int {
	evaluation := evaluateLocalCI(fixturePath)
	log, err := buildSARIFLog(evaluation)
	if err != nil {
		fmt.Fprintf(stderr, "build SARIF result: %v\n", err)
		return 1
	}
	return writeJSONResult(log, stdout, stderr, evaluation.exitCode)
}

func buildSARIFLog(evaluation ciEvaluation) (sarifLog, error) {
	result := evaluation.result
	properties := sarifRunProperties{
		Status:     evaluation.outcome,
		Reason:     evaluation.reason,
		FixtureID:  result.FixtureIdentity(),
		RequestID:  result.RequestID(),
		SnapshotID: result.SnapshotIdentity(),
		Revision:   result.Revision(),
	}
	results := make([]sarifResult, 0)
	if evaluation.outcome == review.OutcomeVerified {
		findings := result.Findings()
		items := result.EvidenceItems()
		if len(findings) != len(items) {
			return sarifLog{}, fmt.Errorf("finding and evidence counts differ")
		}
		results = make([]sarifResult, len(findings))
		for i, finding := range findings {
			level, err := sarifLevel(finding.Severity())
			if err != nil {
				return sarifLog{}, err
			}
			sourceRange := finding.SourceRange()
			item := items[i]
			results[i] = sarifResult{
				RuleID:  staticDebugOutputSARIFRule,
				Level:   level,
				Message: sarifMessage{Text: finding.Title()},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(sourceRange.Path())},
						Region: sarifRegion{
							StartLine: sourceRange.StartLine(),
							EndLine:   sourceRange.EndLine(),
						},
					},
				}},
				Fingerprints: map[string]string{"openTrestleFindingId/v1": finding.ID()},
				Properties: sarifResultProperties{
					EvidenceID:     item.ID(),
					EvidenceDigest: item.Digest(),
				},
			}
		}
	}
	return sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "Open Trestle",
				Rules: []sarifRule{{
					ID:                   staticDebugOutputSARIFRule,
					ShortDescription:     sarifMessage{Text: "Debug output left in source"},
					DefaultConfiguration: sarifConfiguration{Level: "warning"},
				}},
			}},
			Results:    results,
			Properties: properties,
		}},
	}, nil
}

func buildLocalGitReviewSARIF(result localGitReviewResult) (sarifLog, error) {
	if result.Contract != "open-trestle/local-git-review-result" || result.SchemaVersion != 1 {
		return sarifLog{}, fmt.Errorf("local Git review result contract is invalid")
	}
	if err := validateLocalGitReviewWireEvidence(result.Findings, result.Evidence); err != nil {
		return sarifLog{}, err
	}
	results := make([]sarifResult, len(result.Findings))
	for index, finding := range result.Findings {
		item := result.Evidence[index]
		if len(finding.EvidenceIDs) != 1 || finding.EvidenceIDs[0] != item.ID || finding.Path != item.Path || finding.StartLine != item.StartLine || finding.EndLine != item.EndLine {
			return sarifLog{}, fmt.Errorf("finding and evidence binding differs")
		}
		level, err := sarifLevel(review.Severity(finding.Severity))
		if err != nil {
			return sarifLog{}, err
		}
		results[index] = sarifResult{
			RuleID:  staticDebugOutputSARIFRule,
			Level:   level,
			Message: sarifMessage{Text: finding.Title},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: sarifArtifactURI(finding.Path)},
					Region:           sarifRegion{StartLine: finding.StartLine, EndLine: finding.EndLine},
				},
			}},
			Fingerprints: map[string]string{"openTrestleFindingId/v1": finding.ID},
			Properties:   sarifResultProperties{EvidenceID: item.ID, EvidenceDigest: item.Digest},
		}
	}
	outcome := review.OutcomeInconclusive
	reason := string(result.Status)
	if result.Status == localGitReviewStatusFindings {
		outcome = review.OutcomeVerified
		reason = ""
	}
	return sarifLog{
		Schema:  sarifSchemaURI,
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name: "Open Trestle",
				Rules: []sarifRule{{
					ID:                   staticDebugOutputSARIFRule,
					ShortDescription:     sarifMessage{Text: "Debug output left in source"},
					DefaultConfiguration: sarifConfiguration{Level: "warning"},
				}},
			}},
			Results:    results,
			Properties: sarifRunProperties{Status: outcome, Reason: reason},
		}},
	}, nil
}

func validateLocalGitReviewWireEvidence(findings []localGitReviewFindingResult, items []localGitReviewEvidenceResult) error {
	if len(findings) != len(items) {
		return fmt.Errorf("finding and evidence counts differ")
	}
	findingIDs := make(map[string]struct{}, len(findings))
	evidenceIDs := make(map[string]struct{}, len(items))
	for index, finding := range findings {
		item := items[index]
		if _, exists := findingIDs[finding.ID]; exists {
			return fmt.Errorf("duplicate finding identity")
		}
		if _, exists := evidenceIDs[item.ID]; exists {
			return fmt.Errorf("duplicate evidence identity")
		}
		if len(finding.EvidenceIDs) != 1 || finding.EvidenceIDs[0] != item.ID || finding.Path != item.Path || finding.StartLine != item.StartLine || finding.EndLine != item.EndLine {
			return fmt.Errorf("finding and evidence binding differs")
		}
		findingIDs[finding.ID] = struct{}{}
		evidenceIDs[item.ID] = struct{}{}
	}
	return nil
}

func sarifLevel(severity review.Severity) (string, error) {
	switch severity {
	case review.SeverityLow:
		return "note", nil
	case review.SeverityMedium:
		return "warning", nil
	case review.SeverityHigh, review.SeverityCritical:
		return "error", nil
	default:
		return "", fmt.Errorf("unsupported finding severity: %q", severity)
	}
}

func sarifArtifactURI(sourcePath string) string {
	return (&url.URL{Path: sourcePath}).String()
}
