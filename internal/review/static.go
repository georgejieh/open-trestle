package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"strconv"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const staticDebugRuleID = "static-debug-output"

func reviewDebugOutput(source, selected []byte, sourceRange evidence.SourceRange) (Finding, evidence.EvidenceItem, bool, error) {
	if !containsDebugOutput(source, sourceRange) {
		return Finding{}, evidence.EvidenceItem{}, false, nil
	}
	evidenceDigest := digestHex(selected)
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

func containsDebugOutput(source []byte, sourceRange evidence.SourceRange) bool {
	if path.Ext(sourceRange.Path()) != ".go" {
		return false
	}
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, sourceRange.Path(), source, parser.SkipObjectResolution)
	if err != nil {
		return false
	}
	matched := false
	ast.Inspect(file, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		startLine := fileSet.Position(call.Pos()).Line
		endLine := fileSet.Position(call.End()).Line
		if startLine < sourceRange.StartLine() || endLine > sourceRange.EndLine() {
			return true
		}
		matched = isDebugPrintlnCall(call)
		return !matched
	})
	return matched
}

func isDebugPrintlnCall(call *ast.CallExpr) bool {
	selector, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector || selector.Sel.Name != "Println" || len(call.Args) != 1 {
		return false
	}
	packageName, isIdentifier := selector.X.(*ast.Ident)
	if !isIdentifier || packageName.Name != "fmt" {
		return false
	}
	argument, isLiteral := call.Args[0].(*ast.BasicLit)
	if !isLiteral || argument.Kind != token.STRING {
		return false
	}
	value, err := strconv.Unquote(argument.Value)
	return err == nil && value == "debug"
}

func canonicalIdentity(prefix string, value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(encoded)
	return prefix + hex.EncodeToString(digest[:]), nil
}
