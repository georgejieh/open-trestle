package diagnostics

import (
	"fmt"
	"sort"
	"strings"
)

// DeterministicObservation is one exact static-rule observation. It is not an independently verified finding.
type DeterministicObservation struct {
	identity, sourceIdentity, fingerprint, analysisResultIdentity, checkIdentity string
	title, message, path                                                         string
	severity                                                                     Severity
	startLine, endLine                                                           uint32
	evidenceIDs                                                                  []string
}

func NewDeterministicObservation(sourceIdentity, fingerprint, analysisResultIdentity, checkIdentity, title, message string, severity Severity, sourcePath string, startLine, endLine uint32, evidenceIDs []string) (DeterministicObservation, error) {
	evidence := append([]string(nil), evidenceIDs...)
	sort.Strings(evidence)
	validIdentity := validDigest(sourceIdentity) && validDigest(fingerprint) && validDigest(analysisResultIdentity) && validDigest(checkIdentity)
	validContent := validText(title, 256) && validText(message, maxDiagnosticTextBytes)
	validLocation := severity.String() != "" && validPath(sourcePath) && startLine > 0 && endLine >= startLine && endLine <= maxDiagnosticLine
	if !validIdentity || !validContent || !validLocation || len(evidence) == 0 || len(evidence) > 16 {
		return DeterministicObservation{}, ErrInvalidFinding
	}
	for index, identity := range evidence {
		if !validEvidenceID(identity) || index > 0 && identity == evidence[index-1] {
			return DeterministicObservation{}, ErrInvalidFinding
		}
	}
	observation := DeterministicObservation{sourceIdentity: sourceIdentity, fingerprint: fingerprint, analysisResultIdentity: analysisResultIdentity, checkIdentity: checkIdentity, title: strings.Clone(title), message: strings.Clone(message), severity: severity, path: strings.Clone(sourcePath), startLine: startLine, endLine: endLine, evidenceIDs: evidence}
	observation.identity = deriveDeterministicObservationIdentity(observation)
	return observation, nil
}

func (o DeterministicObservation) Identity() string               { return o.identity }
func (o DeterministicObservation) SourceIdentity() string         { return o.sourceIdentity }
func (o DeterministicObservation) Fingerprint() string            { return o.fingerprint }
func (o DeterministicObservation) AnalysisResultIdentity() string { return o.analysisResultIdentity }
func (o DeterministicObservation) CheckIdentity() string          { return o.checkIdentity }
func (o DeterministicObservation) Title() string                  { return o.title }
func (o DeterministicObservation) Message() string                { return o.message }
func (o DeterministicObservation) Severity() Severity             { return o.severity }
func (o DeterministicObservation) Path() string                   { return o.path }
func (o DeterministicObservation) StartLine() uint32              { return o.startLine }
func (o DeterministicObservation) EndLine() uint32                { return o.endLine }
func (o DeterministicObservation) EvidenceIDs() []string {
	return append([]string(nil), o.evidenceIDs...)
}
func (o DeterministicObservation) Validate() error {
	rebuilt, err := NewDeterministicObservation(o.sourceIdentity, o.fingerprint, o.analysisResultIdentity, o.checkIdentity, o.title, o.message, o.severity, o.path, o.startLine, o.endLine, o.evidenceIDs)
	if err != nil || rebuilt.identity != o.identity {
		return ErrInvalidFindingIdentity
	}
	return nil
}
func (o DeterministicObservation) String() string { return "deterministic review observation" }
func (o DeterministicObservation) GoString() string {
	return "diagnostics.DeterministicObservation{<redacted>}"
}
func (o DeterministicObservation) Format(state fmt.State, verb rune) {
	writeFormat(state, verb, "deterministic review observation", "diagnostics.DeterministicObservation{<redacted>}")
}
func deriveDeterministicObservationIdentity(o DeterministicObservation) string {
	return hashValue(struct {
		SourceIdentity         string   `json:"source_identity"`
		Fingerprint            string   `json:"fingerprint"`
		AnalysisResultIdentity string   `json:"analysis_result_identity"`
		CheckIdentity          string   `json:"check_identity"`
		Title                  string   `json:"title"`
		Message                string   `json:"message"`
		Severity               string   `json:"severity"`
		Path                   string   `json:"path"`
		StartLine              uint32   `json:"start_line"`
		EndLine                uint32   `json:"end_line"`
		Evidence               []string `json:"evidence"`
	}{o.sourceIdentity, o.fingerprint, o.analysisResultIdentity, o.checkIdentity, o.title, o.message, o.severity.String(), o.path, o.startLine, o.endLine, o.EvidenceIDs()})
}
