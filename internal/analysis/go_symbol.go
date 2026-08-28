package analysis

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

// Bounds syntax parsing for one caller-supplied head file.
const maxGoSourceBytes = 1 << 20

// ResolveGoEnclosingSymbol resolves one changed head range to a named Go declaration.
func ResolveGoEnclosingSymbol(change evidence.Change, headContent []byte, selection evidence.SourceRange) (symbol Symbol, found bool, err error) {
	validatedSelection, err := evidence.NewSourceRange(selection.Path(), selection.StartLine(), selection.EndLine())
	if err != nil {
		return Symbol{}, false, fmt.Errorf("validate Go selection: %w", err)
	}
	if path.Ext(validatedSelection.Path()) != ".go" {
		return Symbol{}, false, fmt.Errorf("Go resolver requires a .go path")
	}
	fileChange, ok := change.FileChangeForPath(validatedSelection.Path())
	if !ok {
		return Symbol{}, false, fmt.Errorf("change does not contain selected path")
	}
	lineMap, ok := change.LineMapForPath(validatedSelection.Path())
	if !ok || lineMap.FileChangeIdentity() != fileChange.Identity() {
		return Symbol{}, false, fmt.Errorf("change does not contain matching line evidence")
	}
	if len(headContent) > maxGoSourceBytes {
		return Symbol{}, false, fmt.Errorf("Go source exceeds %d bytes", maxGoSourceBytes)
	}
	if bytes.IndexByte(headContent, 0) >= 0 {
		return Symbol{}, false, fmt.Errorf("Go source contains NUL")
	}
	if !utf8.Valid(headContent) {
		return Symbol{}, false, fmt.Errorf("Go source must be valid UTF-8")
	}
	if goContentDigest(headContent) != fileChange.HeadDigest() {
		return Symbol{}, false, fmt.Errorf("Go source does not match head content identity")
	}
	lineCount := goPhysicalLineCount(headContent)
	if lineCount != lineMap.HeadLineCount() {
		return Symbol{}, false, fmt.Errorf("Go source line count does not match line map")
	}
	if validatedSelection.EndLine() > lineCount {
		return Symbol{}, false, fmt.Errorf("Go selection exceeds head content")
	}
	if !fileChangeContainsRange(fileChange, validatedSelection) {
		return Symbol{}, false, fmt.Errorf("Go selection is not contained in one changed range")
	}

	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, validatedSelection.Path(), headContent, parser.ParseComments|parser.SkipObjectResolution|parser.AllErrors)
	if err != nil {
		return Symbol{}, false, fmt.Errorf("parse Go source %q: %w", validatedSelection.Path(), err)
	}
	declaration, declarationRange, found, err := enclosingGoDeclaration(fileSet, file, validatedSelection)
	if err != nil {
		return Symbol{}, false, err
	}
	if !found {
		return Symbol{}, false, nil
	}
	kind := SymbolKindFunction
	qualifiedName := file.Name.Name + "." + declaration.Name.Name
	if declaration.Recv != nil {
		receiver, ok := goReceiverBaseName(declaration)
		if !ok {
			return Symbol{}, false, fmt.Errorf("unsupported Go method receiver")
		}
		kind = SymbolKindMethod
		qualifiedName = file.Name.Name + "." + receiver + "." + declaration.Name.Name
	}
	resolved, err := NewSymbol(lineMap, LanguageGo, kind, qualifiedName, declarationRange)
	if err != nil {
		return Symbol{}, false, fmt.Errorf("create Go symbol: %w", err)
	}
	return resolved, true, nil
}

func fileChangeContainsRange(fileChange evidence.FileChange, selection evidence.SourceRange) bool {
	for _, changedRange := range fileChange.ChangedRanges() {
		if selection.StartLine() >= changedRange.StartLine() && selection.EndLine() <= changedRange.EndLine() {
			return true
		}
	}
	return false
}

func enclosingGoDeclaration(fileSet *token.FileSet, file *ast.File, selection evidence.SourceRange) (*ast.FuncDecl, evidence.SourceRange, bool, error) {
	var selected *ast.FuncDecl
	var selectedRange evidence.SourceRange
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		startPosition := function.Pos()
		if function.Doc != nil {
			startPosition = function.Doc.Pos()
		}
		endPosition := function.End()
		if endPosition > function.Pos() {
			endPosition--
		}
		start := fileSet.PositionFor(startPosition, false).Line
		end := fileSet.PositionFor(endPosition, false).Line
		if start > selection.StartLine() || end < selection.EndLine() {
			continue
		}
		physicalRange, err := evidence.NewSourceRange(selection.Path(), start, end)
		if err != nil {
			return nil, evidence.SourceRange{}, false, fmt.Errorf("create Go declaration range: %w", err)
		}
		if selected == nil || physicalRange.EndLine()-physicalRange.StartLine() < selectedRange.EndLine()-selectedRange.StartLine() {
			selected = function
			selectedRange = physicalRange
		}
	}
	return selected, selectedRange, selected != nil, nil
}

func goReceiverBaseName(declaration *ast.FuncDecl) (string, bool) {
	if declaration.Recv == nil || len(declaration.Recv.List) != 1 {
		return "", false
	}
	return goReceiverTypeName(declaration.Recv.List[0].Type)
}

func goReceiverTypeName(expression ast.Expr) (string, bool) {
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name, value.Name != ""
	case *ast.StarExpr:
		return goReceiverTypeName(value.X)
	case *ast.IndexExpr:
		return goReceiverTypeName(value.X)
	case *ast.IndexListExpr:
		return goReceiverTypeName(value.X)
	case *ast.ParenExpr:
		return goReceiverTypeName(value.X)
	default:
		return "", false
	}
}

func goContentDigest(content []byte) string {
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:])
}

func goPhysicalLineCount(content []byte) int {
	if len(content) == 0 {
		return 0
	}
	count := bytes.Count(content, []byte{'\n'})
	if content[len(content)-1] != '\n' {
		count++
	}
	return count
}
