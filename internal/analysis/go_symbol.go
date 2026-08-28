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
	"sort"
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
	validated, err := validateGoSource(change, validatedSelection.Path(), headContent)
	if err != nil {
		return Symbol{}, false, err
	}
	if validatedSelection.EndLine() > validated.lineMap.HeadLineCount() {
		return Symbol{}, false, fmt.Errorf("Go selection exceeds head content")
	}
	if !fileChangeContainsRange(validated.fileChange, validatedSelection) {
		return Symbol{}, false, fmt.Errorf("Go selection is not contained in one changed range")
	}
	parsed, err := parseGoSource(validated, headContent)
	if err != nil {
		return Symbol{}, false, err
	}
	return parsed.resolve(validatedSelection)
}

// ResolveGoChangedSymbols resolves positive head Hunks to named Go declarations.
func ResolveGoChangedSymbols(change evidence.Change, sourcePath string, headContent []byte) ([]Symbol, error) {
	validated, err := validateGoSource(change, sourcePath, headContent)
	if err != nil {
		return nil, err
	}
	hunks := validated.lineMap.Hunks()
	selections := make([]evidence.SourceRange, 0, len(hunks))
	for _, hunk := range hunks {
		if hunk.HeadLineCount() == 0 {
			continue
		}
		selection, err := evidence.NewSourceRange(sourcePath, hunk.HeadStartLine(), hunk.HeadStartLine()+hunk.HeadLineCount()-1)
		if err != nil {
			return nil, fmt.Errorf("create Go Hunk range: %w", err)
		}
		selections = append(selections, selection)
	}
	if len(selections) == 0 {
		return []Symbol{}, nil
	}
	parsed, err := parseGoSource(validated, headContent)
	if err != nil {
		return nil, err
	}
	byIdentity := make(map[string]Symbol, len(selections))
	for _, selection := range selections {
		symbol, found, err := parsed.resolve(selection)
		if err != nil {
			return nil, err
		}
		if found {
			byIdentity[symbol.Identity()] = symbol
		}
	}
	symbols := make([]Symbol, 0, len(byIdentity))
	for _, symbol := range byIdentity {
		symbols = append(symbols, symbol)
	}
	sort.Slice(symbols, func(i, j int) bool {
		left := symbols[i]
		right := symbols[j]
		if left.SourceRange().StartLine() != right.SourceRange().StartLine() {
			return left.SourceRange().StartLine() < right.SourceRange().StartLine()
		}
		if left.SourceRange().EndLine() != right.SourceRange().EndLine() {
			return left.SourceRange().EndLine() < right.SourceRange().EndLine()
		}
		if left.Kind() != right.Kind() {
			return left.Kind() < right.Kind()
		}
		if left.QualifiedName() != right.QualifiedName() {
			return left.QualifiedName() < right.QualifiedName()
		}
		return left.Identity() < right.Identity()
	})
	return symbols, nil
}

type validatedGoSource struct {
	fileChange evidence.FileChange
	lineMap    evidence.LineMap
	path       string
}

type parsedGoSource struct {
	validated    validatedGoSource
	file         *ast.File
	declarations []goDeclaration
}

type goDeclaration struct {
	function    *ast.FuncDecl
	sourceRange evidence.SourceRange
}

func validateGoSource(change evidence.Change, sourcePath string, headContent []byte) (validatedGoSource, error) {
	if path.Ext(sourcePath) != ".go" {
		return validatedGoSource{}, fmt.Errorf("Go resolver requires a .go path")
	}
	fileChange, ok := change.FileChangeForPath(sourcePath)
	if !ok {
		return validatedGoSource{}, fmt.Errorf("change does not contain selected path")
	}
	lineMap, ok := change.LineMapForPath(sourcePath)
	if !ok || lineMap.FileChangeIdentity() != fileChange.Identity() {
		return validatedGoSource{}, fmt.Errorf("change does not contain matching line evidence")
	}
	if len(headContent) > maxGoSourceBytes {
		return validatedGoSource{}, fmt.Errorf("Go source exceeds %d bytes", maxGoSourceBytes)
	}
	if bytes.IndexByte(headContent, 0) >= 0 {
		return validatedGoSource{}, fmt.Errorf("Go source contains NUL")
	}
	if !utf8.Valid(headContent) {
		return validatedGoSource{}, fmt.Errorf("Go source must be valid UTF-8")
	}
	if goContentDigest(headContent) != fileChange.HeadDigest() {
		return validatedGoSource{}, fmt.Errorf("Go source does not match head content identity")
	}
	if goPhysicalLineCount(headContent) != lineMap.HeadLineCount() {
		return validatedGoSource{}, fmt.Errorf("Go source line count does not match line map")
	}
	return validatedGoSource{fileChange: fileChange, lineMap: lineMap, path: sourcePath}, nil
}

func parseGoSource(validated validatedGoSource, headContent []byte) (parsedGoSource, error) {
	fileSet := token.NewFileSet()
	file, err := parser.ParseFile(fileSet, validated.path, headContent, parser.ParseComments|parser.SkipObjectResolution|parser.AllErrors)
	if err != nil {
		return parsedGoSource{}, fmt.Errorf("parse Go source %q: %w", validated.path, err)
	}
	declarations, err := collectGoDeclarations(fileSet, file, validated.path)
	if err != nil {
		return parsedGoSource{}, err
	}
	return parsedGoSource{validated: validated, file: file, declarations: declarations}, nil
}

func (parsed parsedGoSource) resolve(selection evidence.SourceRange) (Symbol, bool, error) {
	index := sort.Search(len(parsed.declarations), func(i int) bool {
		return parsed.declarations[i].sourceRange.EndLine() >= selection.StartLine()
	})
	if index == len(parsed.declarations) {
		return Symbol{}, false, nil
	}
	selected := parsed.declarations[index]
	if selected.sourceRange.StartLine() > selection.StartLine() || selected.sourceRange.EndLine() < selection.EndLine() {
		return Symbol{}, false, nil
	}
	declaration := selected.function
	kind := SymbolKindFunction
	qualifiedName := parsed.file.Name.Name + "." + declaration.Name.Name
	if declaration.Recv != nil {
		receiver, ok := goReceiverBaseName(declaration)
		if !ok {
			return Symbol{}, false, fmt.Errorf("unsupported Go method receiver")
		}
		kind = SymbolKindMethod
		qualifiedName = parsed.file.Name.Name + "." + receiver + "." + declaration.Name.Name
	}
	resolved, err := NewSymbol(parsed.validated.lineMap, LanguageGo, kind, qualifiedName, selected.sourceRange)
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

func collectGoDeclarations(fileSet *token.FileSet, file *ast.File, sourcePath string) ([]goDeclaration, error) {
	declarations := make([]goDeclaration, 0, len(file.Decls))
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
		physicalRange, err := evidence.NewSourceRange(sourcePath, start, end)
		if err != nil {
			return nil, fmt.Errorf("create Go declaration range: %w", err)
		}
		declarations = append(declarations, goDeclaration{function: function, sourceRange: physicalRange})
	}
	return declarations, nil
}

func goReceiverBaseName(declaration *ast.FuncDecl) (string, bool) {
	if declaration.Recv == nil || len(declaration.Recv.List) != 1 {
		return "", false
	}
	receiver := declaration.Recv.List[0]
	if len(receiver.Names) > 1 {
		return "", false
	}
	return goReceiverTypeName(receiver.Type)
}

func goReceiverTypeName(expression ast.Expr) (string, bool) {
	expression = unwrapReceiverParens(expression)
	if pointer, ok := expression.(*ast.StarExpr); ok {
		expression = unwrapReceiverParens(pointer.X)
	}
	return goReceiverIndexedBase(expression)
}

func goReceiverIndexedBase(expression ast.Expr) (string, bool) {
	expression = unwrapReceiverParens(expression)
	switch value := expression.(type) {
	case *ast.Ident:
		return value.Name, value.Name != ""
	case *ast.IndexExpr:
		if !isReceiverTypeParameter(value.Index) {
			return "", false
		}
		return receiverIdentifierName(unwrapReceiverParens(value.X))
	case *ast.IndexListExpr:
		if len(value.Indices) == 0 {
			return "", false
		}
		for _, parameter := range value.Indices {
			if !isReceiverTypeParameter(parameter) {
				return "", false
			}
		}
		return receiverIdentifierName(unwrapReceiverParens(value.X))
	default:
		return "", false
	}
}

func unwrapReceiverParens(expression ast.Expr) ast.Expr {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			return expression
		}
		expression = parenthesized.X
	}
}

func isReceiverTypeParameter(expression ast.Expr) bool {
	identifier, ok := expression.(*ast.Ident)
	return ok && identifier.Name != ""
}

func receiverIdentifierName(expression ast.Expr) (string, bool) {
	identifier, ok := expression.(*ast.Ident)
	if !ok || identifier.Name == "" {
		return "", false
	}
	return identifier.Name, true
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
