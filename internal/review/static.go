package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const staticDebugRuleID = "static-debug-output"

func reviewDebugOutput(content []byte, sourceRange evidence.SourceRange) (Finding, evidence.EvidenceItem, bool, error) {
	if !containsDebugOutput(content) {
		return Finding{}, evidence.EvidenceItem{}, false, nil
	}
	evidenceDigest := digestHex(content)
	evidenceID, err := canonicalIdentity("evidence-", struct {
		Rule      string `json:"rule"`
		Path      string `json:"path"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
		Digest    string `json:"digest"`
	}{
		Rule:      staticDebugRuleID,
		Path:      sourceRange.Path(),
		StartLine: sourceRange.StartLine(),
		EndLine:   sourceRange.EndLine(),
		Digest:    evidenceDigest,
	})
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, false, fmt.Errorf("identify evidence: %w", err)
	}
	item, err := evidence.NewEvidenceItem(evidenceID, evidence.EvidenceKindSource, evidenceDigest, sourceRange)
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, false, fmt.Errorf("create evidence: %w", err)
	}
	findingID, err := canonicalIdentity("finding-", struct {
		Rule       string `json:"rule"`
		EvidenceID string `json:"evidence_id"`
	}{Rule: staticDebugRuleID, EvidenceID: evidenceID})
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, false, fmt.Errorf("identify finding: %w", err)
	}
	finding, err := NewFinding(findingID, "Debug output left in source", SeverityMedium, sourceRange, []string{evidenceID})
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, false, fmt.Errorf("create finding: %w", err)
	}
	return finding, item, true, nil
}

func containsDebugOutput(content []byte) bool {
	for _, line := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(line) == `fmt.Println("debug")` {
			return true
		}
	}
	return false
}

func canonicalIdentity(prefix string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return prefix + hex.EncodeToString(digest[:]), nil
}
