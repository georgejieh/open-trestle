package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"path"
	"sort"
	"strconv"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

const staticDebugRuleID = "static-debug-output"

func reviewDebugOutputs(source []byte, selection evidence.SourceRange) ([]Finding, []evidence.EvidenceItem, error) {
	ranges, err := debugOutputRanges(source, selection)
	if err != nil {
		return nil, nil, fmt.Errorf("analyze debug output: %w", err)
	}
	findings := make([]Finding, 0, len(ranges))
	items := make([]evidence.EvidenceItem, 0, len(ranges))
	for _, sourceRange := range ranges {
		finding, item, err := newDebugOutputFinding(source, sourceRange)
		if err != nil {
			return nil, nil, err
		}
		findings = append(findings, finding)
		items = append(items, item)
	}
	return findings, items, nil
}

func newDebugOutputFinding(source []byte, sourceRange evidence.SourceRange) (Finding, evidence.EvidenceItem, error) {
	selected, err := selectSourceRange(source, sourceRange)
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, fmt.Errorf("select debug output: %w", err)
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
		return Finding{}, evidence.EvidenceItem{}, fmt.Errorf("identify evidence: %w", err)
	}
	item, err := evidence.NewEvidenceItem(evidenceID, evidence.EvidenceKindSource, evidenceDigest, sourceRange)
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, fmt.Errorf("create evidence: %w", err)
	}
	findingID, err := canonicalIdentity("finding-", struct {
		Rule       string `json:"rule"`
		EvidenceID string `json:"evidence_id"`
	}{Rule: staticDebugRuleID, EvidenceID: evidenceID})
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, fmt.Errorf("identify finding: %w", err)
	}
	finding, err := NewFinding(findingID, "Debug output left in source", SeverityMedium, sourceRange, []string{evidenceID})
	if err != nil {
		return Finding{}, evidence.EvidenceItem{}, fmt.Errorf("create finding: %w", err)
	}
	return finding, item, nil
}

func containsDebugOutput(source []byte, sourceRange evidence.SourceRange) (bool, error) {
	ranges, err := debugOutputRanges(source, sourceRange)
	return len(ranges) > 0, err
}

func debugOutputRanges(source []byte, selection evidence.SourceRange) ([]evidence.SourceRange, error) {
	if path.Ext(selection.Path()) != ".go" {
		return nil, nil
	}
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, selection.Path(), source, parser.SkipObjectResolution)
	if err != nil {
		return nil, fmt.Errorf("parse Go source: %w", err)
	}
	typeInfo := &types.Info{Uses: make(map[*ast.Ident]types.Object)}
	configuration := types.Config{
		Importer: importer.Default(),
		Error:    func(error) {},
	}
	_, _ = configuration.Check("fixture", fileSet, []*ast.File{file}, typeInfo)

	seen := make(map[[2]int]struct{})
	ranges := make([]evidence.SourceRange, 0)
	var rangeErr error
	ast.Inspect(file, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall || !isDebugPrintlnCall(call, typeInfo) {
			return true
		}
		startLine := fileSet.PositionFor(call.Pos(), false).Line
		endLine := fileSet.PositionFor(call.End(), false).Line
		if endLine < selection.StartLine() || startLine > selection.EndLine() {
			return true
		}
		key := [2]int{startLine, endLine}
		if _, exists := seen[key]; exists {
			return true
		}
		seen[key] = struct{}{}
		sourceRange, err := evidence.NewSourceRange(selection.Path(), startLine, endLine)
		if err != nil {
			rangeErr = err
			return false
		}
		ranges = append(ranges, sourceRange)
		return true
	})
	if rangeErr != nil {
		return nil, rangeErr
	}
	sort.Slice(ranges, func(i, j int) bool {
		if ranges[i].StartLine() != ranges[j].StartLine() {
			return ranges[i].StartLine() < ranges[j].StartLine()
		}
		return ranges[i].EndLine() < ranges[j].EndLine()
	})
	return ranges, nil
}

func isDebugPrintlnCall(call *ast.CallExpr, typeInfo *types.Info) bool {
	selector, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector || len(call.Args) != 1 {
		return false
	}
	packageIdentifier, isIdentifier := selector.X.(*ast.Ident)
	if !isIdentifier {
		return false
	}
	packageName, isPackageName := typeInfo.Uses[packageIdentifier].(*types.PkgName)
	if !isPackageName || packageName.Imported() == nil || packageName.Imported().Path() != "fmt" {
		return false
	}
	function, isFunction := typeInfo.Uses[selector.Sel].(*types.Func)
	if !isFunction || function.Pkg() == nil || function.Pkg().Path() != "fmt" || function.Name() != "Println" {
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
