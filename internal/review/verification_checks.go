package review

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// MaxAuthoredCheckBytes bounds the content of one model-written check.
const MaxAuthoredCheckBytes = 12 << 10

// AuthoredCheck is a test file a verifier wrote for one of its verified
// findings. It is untrusted model text: nothing here has run it.
type AuthoredCheck struct {
	// FindingIdentity is the verified finding's identity and Path its file.
	FindingIdentity, Path string
	Framework, Content    string
}

// VerificationAuthoredChecks reads the optional check objects of a verifier
// answer that ParseContextVerificationBatch admitted. It keeps, in verdict
// order, at most MaxAuthoredChecks checks of verified findings whose
// framework the request's test_authoring offered, and counts every other
// check as dropped. A check never refuses its verdict or the answer.
func VerificationAuthoredChecks(response provider.Response, context VerificationRequestContext, candidates CandidateBatch, findings VerifiedFindingSet) ([]AuthoredCheck, int) {
	payload, err := answerDocument(response, ErrInvalidVerificationResponseEnvelope)
	if err != nil {
		return nil, 0
	}
	var frameworks []string
	if wire, err := decodeVerificationContextWire(context.Payload()); err == nil && wire.CheckRuns != nil && wire.CheckRuns.TestAuthoring != nil {
		frameworks = wire.CheckRuns.TestAuthoring.Frameworks
	}
	verified := map[string]VerifiedFinding{}
	for _, finding := range findings.Findings() {
		verified[finding.CandidateIdentity()] = finding
	}
	labels := map[string]AuthoredCheck{}
	for index, candidate := range candidates.Findings() {
		if finding, ok := verified[candidate.Identity()]; ok {
			labels[verificationCandidateLabel(index)] = AuthoredCheck{FindingIdentity: finding.Identity(), Path: finding.SourceRange().Path()}
		}
	}
	return authoredChecks(payload, frameworks, labels)
}

// authoredChecks reads the checks of a verifier document; verified maps the
// label of each verified candidate to its finding.
func authoredChecks(payload []byte, frameworks []string, verified map[string]AuthoredCheck) ([]AuthoredCheck, int) {
	var document struct {
		Verdicts []struct {
			CandidateID string          `json:"candidate_id"`
			Check       json.RawMessage `json:"check"`
		} `json:"verdicts"`
	}
	if json.Unmarshal(payload, &document) != nil {
		return nil, 0
	}
	var checks []AuthoredCheck
	dropped := 0
	for _, verdict := range document.Verdicts {
		if len(verdict.Check) == 0 {
			continue
		}
		var check struct {
			Framework string `json:"framework"`
			Content   string `json:"content"`
		}
		decoder := json.NewDecoder(bytes.NewReader(verdict.Check))
		decoder.DisallowUnknownFields()
		finding, found := verified[verdict.CandidateID]
		if !found || len(checks) == MaxAuthoredChecks || decoder.Decode(&check) != nil || !slices.Contains(frameworks, check.Framework) ||
			len(check.Content) > MaxAuthoredCheckBytes || !utf8.ValidString(check.Content) || strings.ContainsRune(check.Content, 0) || strings.TrimSpace(check.Content) == "" {
			dropped++
			continue
		}
		finding.Framework, finding.Content = check.Framework, check.Content
		checks = append(checks, finding)
	}
	return checks, dropped
}
