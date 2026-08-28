package review

import (
	"fmt"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// Severity identifies the impact of a review finding.
type Severity string

const (
	// SeverityLow identifies a low-impact finding.
	SeverityLow Severity = "low"
	// SeverityMedium identifies a moderate-impact finding.
	SeverityMedium Severity = "medium"
	// SeverityHigh identifies a high-impact finding.
	SeverityHigh Severity = "high"
	// SeverityCritical identifies a critical-impact finding.
	SeverityCritical Severity = "critical"
)

// Finding binds a review claim to source and evidence identities.
type Finding struct {
	id          string
	title       string
	severity    Severity
	sourceRange evidence.SourceRange
	evidenceIDs []string
}

// NewFinding creates an evidence-linked finding.
func NewFinding(id, title string, severity Severity, sourceRange evidence.SourceRange, evidenceIDs []string) (Finding, error) {
	if id == "" {
		return Finding{}, fmt.Errorf("finding identity is required")
	}
	if title == "" {
		return Finding{}, fmt.Errorf("finding title is required")
	}
	if !isKnownSeverity(severity) {
		return Finding{}, fmt.Errorf("unknown finding severity: %q", severity)
	}
	if sourceRange.Path() == "" {
		return Finding{}, fmt.Errorf("finding source range is required")
	}
	if len(evidenceIDs) == 0 {
		return Finding{}, fmt.Errorf("at least one evidence identity is required")
	}
	seenEvidence := make(map[string]struct{}, len(evidenceIDs))
	for _, evidenceID := range evidenceIDs {
		if evidenceID == "" {
			return Finding{}, fmt.Errorf("evidence identity is required")
		}
		if _, exists := seenEvidence[evidenceID]; exists {
			return Finding{}, fmt.Errorf("duplicate evidence identity: %q", evidenceID)
		}
		seenEvidence[evidenceID] = struct{}{}
	}
	return Finding{
		id:          id,
		title:       title,
		severity:    severity,
		sourceRange: sourceRange,
		evidenceIDs: append([]string(nil), evidenceIDs...),
	}, nil
}

func isKnownSeverity(severity Severity) bool {
	switch severity {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// ID returns the finding identity.
func (f Finding) ID() string {
	return f.id
}

// Title returns the finding title.
func (f Finding) Title() string {
	return f.title
}

// Severity returns the finding impact.
func (f Finding) Severity() Severity {
	return f.severity
}

// SourceRange returns the affected source range.
func (f Finding) SourceRange() evidence.SourceRange {
	return f.sourceRange
}

// EvidenceIDs returns a copy of the supporting evidence identities.
func (f Finding) EvidenceIDs() []string {
	return append([]string(nil), f.evidenceIDs...)
}
