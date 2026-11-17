package semanticimpact

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"strconv"
	"time"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// GoSyntaxAnalyzerIdentity names the go/parser implementation of the
// language-neutral syntax analysis model.
const GoSyntaxAnalyzerIdentity = "open-trestle/syntax/go-parser/v1"

// GoSyntaxAnalyzer analyses Go files with go/parser and reports them in the
// language-neutral syntaxanalysis model. It is safe for concurrent use.
type GoSyntaxAnalyzer struct{ limits syntaxanalysis.Limits }

// NewGoSyntaxAnalyzer returns a Go analyzer with the given limits.
func NewGoSyntaxAnalyzer(limits syntaxanalysis.Limits) (GoSyntaxAnalyzer, error) {
	if !limits.Valid() {
		return GoSyntaxAnalyzer{}, syntaxanalysis.ErrInvalidInput
	}
	return GoSyntaxAnalyzer{limits: limits}, nil
}

// Supports reports whether the language is Go.
func (a GoSyntaxAnalyzer) Supports(language syntaxanalysis.Language) bool {
	return language == syntaxanalysis.LanguageGo
}

// Analyze parses one Go file. go/parser recovers from syntax errors, so a
// file with errors still yields the declarations it could read, plus a
// parse_error gap for each error position and each bad node.
func (a GoSyntaxAnalyzer) Analyze(ctx context.Context, source syntaxanalysis.Source) (syntaxanalysis.FileAnalysis, error) {
	if source.Path() == "" || source.Language() != syntaxanalysis.LanguageGo {
		return syntaxanalysis.FileAnalysis{}, syntaxanalysis.ErrInvalidInput
	}
	limits := a.limits
	if !limits.Valid() {
		limits = syntaxanalysis.DefaultLimits()
	}
	if err := ctx.Err(); err != nil {
		return syntaxanalysis.FileAnalysis{}, err
	}
	if source.Size() > limits.MaxFileBytes {
		return syntaxanalysis.WholeFileGap(source, GoSyntaxAnalyzerIdentity, syntaxanalysis.GapLimitExceeded, syntaxanalysis.LimitFileSize), nil
	}
	started := time.Now()
	content := source.Content()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, source.Path(), content, parser.AllErrors|parser.SkipObjectResolution)
	raw := syntaxanalysis.RawFile{}
	var list scanner.ErrorList
	if errors.As(err, &list) {
		for _, e := range list {
			raw.Gaps = append(raw.Gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapParseError, Span: lineErrorSpan(content, e.Pos.Offset)})
		}
	} else if err != nil {
		return syntaxanalysis.WholeFileGap(source, GoSyntaxAnalyzerIdentity, syntaxanalysis.GapParseError, ""), nil
	}
	if file == nil {
		return syntaxanalysis.WholeFileGap(source, GoSyntaxAnalyzerIdentity, syntaxanalysis.GapParseError, ""), nil
	}
	tf := fset.File(file.Pos())
	if tf == nil {
		return syntaxanalysis.WholeFileGap(source, GoSyntaxAnalyzerIdentity, syntaxanalysis.GapAnalysisFailed, ""), nil
	}
	w := goWalker{file: tf, raw: &raw}
	w.collect(file)
	if err := ctx.Err(); err != nil {
		return syntaxanalysis.FileAnalysis{}, err
	}
	if time.Since(started) > limits.FileDeadline {
		return syntaxanalysis.WholeFileGap(source, GoSyntaxAnalyzerIdentity, syntaxanalysis.GapDeadlineExceeded, ""), nil
	}
	return syntaxanalysis.Assemble(source, GoSyntaxAnalyzerIdentity, raw, limits), nil
}

// lineErrorSpan covers an error position up to the end of its line, so that
// a region is reported even for a zero-width error.
func lineErrorSpan(content []byte, offset int) syntaxanalysis.Span {
	if offset < 0 {
		offset = 0
	}
	if offset >= len(content) {
		if len(content) == 0 {
			return syntaxanalysis.Span{}
		}
		return syntaxanalysis.Span{Start: len(content) - 1, End: len(content)}
	}
	end := offset + 1
	for end < len(content) && content[end-1] != '\n' && content[end] != '\n' {
		end++
	}
	return syntaxanalysis.Span{Start: offset, End: end}
}

type goWalker struct {
	file *token.File
	raw  *syntaxanalysis.RawFile
}

func (w goWalker) span(from, to token.Pos) syntaxanalysis.Span {
	if !from.IsValid() || !to.IsValid() {
		return syntaxanalysis.Span{}
	}
	start, end := w.file.Offset(from), w.file.Offset(to)
	if end < start {
		return syntaxanalysis.Span{}
	}
	return syntaxanalysis.Span{Start: start, End: end}
}

func (w goWalker) node(n ast.Node) syntaxanalysis.Span { return w.span(n.Pos(), n.End()) }

func (w goWalker) definition(kind syntaxanalysis.DefinitionKind, name *ast.Ident, node ast.Node, container syntaxanalysis.Span) {
	if name == nil || name.Name == "_" {
		return
	}
	w.raw.Definitions = append(w.raw.Definitions, syntaxanalysis.RawDefinition{
		Kind: kind, Name: w.node(name), Node: w.node(node), Container: container, Exported: ast.IsExported(name.Name),
	})
}

func (w goWalker) reference(kind syntaxanalysis.ReferenceKind, expr ast.Expr) {
	switch e := expr.(type) {
	case *ast.Ident:
		if e.Name != "_" {
			w.raw.References = append(w.raw.References, syntaxanalysis.RawReference{Kind: kind, Name: w.node(e)})
		}
	case *ast.SelectorExpr:
		w.raw.References = append(w.raw.References, syntaxanalysis.RawReference{Kind: kind, Name: w.node(e.Sel), Qualifier: w.node(e.X)})
	case *ast.IndexExpr:
		w.reference(kind, e.X)
	case *ast.IndexListExpr:
		w.reference(kind, e.X)
	case *ast.ParenExpr:
		w.reference(kind, e.X)
	}
}

// typeReferences records the named types used in a type expression.
func (w goWalker) typeReferences(expr ast.Expr) {
	if expr == nil {
		return
	}
	ast.Inspect(expr, func(n ast.Node) bool {
		switch t := n.(type) {
		case *ast.Ident:
			w.reference(syntaxanalysis.ReferenceType, t)
			return false
		case *ast.SelectorExpr:
			w.reference(syntaxanalysis.ReferenceType, t)
			return false
		case *ast.FuncType, *ast.StructType, *ast.InterfaceType, *ast.FuncLit, *ast.CompositeLit, *ast.CallExpr, *ast.BasicLit:
			// Nested function, struct and interface types are visited on
			// their own by the file walk.
			return false
		}
		return true
	})
}

func (w goWalker) fieldTypes(fields *ast.FieldList) {
	if fields == nil {
		return
	}
	for _, f := range fields.List {
		w.typeReferences(f.Type)
	}
}

func (w goWalker) collect(file *ast.File) {
	for _, spec := range file.Imports {
		if spec.Path == nil {
			continue
		}
		path := w.node(spec.Path)
		if unquoted, err := strconv.Unquote(spec.Path.Value); err == nil && len(spec.Path.Value) == len(unquoted)+2 {
			path = syntaxanalysis.Span{Start: path.Start + 1, End: path.End - 1}
		}
		imp := syntaxanalysis.RawImport{Source: path, Node: w.node(spec)}
		if spec.Name != nil {
			imp.Alias = w.node(spec.Name)
		}
		w.raw.Imports = append(w.raw.Imports, imp)
	}
	// Definitions are the top-level declarations and the members of
	// top-level struct and interface types, as in the impact profile.
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			kind := syntaxanalysis.KindFunction
			container := syntaxanalysis.Span{}
			if d.Recv != nil && len(d.Recv.List) > 0 {
				kind = syntaxanalysis.KindMethod
				container = w.receiverName(d.Recv.List[0].Type)
			}
			w.definition(kind, d.Name, d, container)
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					kind := syntaxanalysis.KindType
					switch t := s.Type.(type) {
					case *ast.StructType:
						kind = syntaxanalysis.KindStruct
						w.structFields(t)
					case *ast.InterfaceType:
						kind = syntaxanalysis.KindInterface
						w.interfaceMethods(t)
					}
					node := ast.Node(s)
					if len(d.Specs) == 1 {
						node = d
					}
					w.definition(kind, s.Name, node, syntaxanalysis.Span{})
				case *ast.ValueSpec:
					kind := syntaxanalysis.KindVariable
					if d.Tok == token.CONST {
						kind = syntaxanalysis.KindConstant
					}
					for _, name := range s.Names {
						w.definition(kind, name, s, syntaxanalysis.Span{})
					}
				}
			}
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch d := n.(type) {
		case *ast.BadDecl, *ast.BadStmt, *ast.BadExpr:
			w.raw.Gaps = append(w.raw.Gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapParseError, Span: w.node(d)})
			return false
		case *ast.FuncDecl:
			if d.Recv != nil {
				w.fieldTypes(d.Recv)
			}
		case *ast.FuncType:
			w.fieldTypes(d.TypeParams)
			w.fieldTypes(d.Params)
			w.fieldTypes(d.Results)
		case *ast.TypeSpec:
			w.fieldTypes(d.TypeParams)
			switch d.Type.(type) {
			case *ast.StructType, *ast.InterfaceType:
			default:
				w.typeReferences(d.Type)
			}
		case *ast.ValueSpec:
			w.typeReferences(d.Type)
		case *ast.StructType:
			if d.Fields != nil {
				for _, f := range d.Fields.List {
					if len(f.Names) == 0 {
						w.reference(syntaxanalysis.ReferenceInherit, embeddedType(f.Type))
					} else {
						w.typeReferences(f.Type)
					}
				}
			}
		case *ast.InterfaceType:
			if d.Methods != nil {
				for _, f := range d.Methods.List {
					if len(f.Names) == 0 {
						w.reference(syntaxanalysis.ReferenceInherit, embeddedType(f.Type))
					}
				}
			}
		case *ast.CallExpr:
			w.reference(syntaxanalysis.ReferenceCall, d.Fun)
		case *ast.CompositeLit:
			switch d.Type.(type) {
			case nil:
			case *ast.Ident, *ast.SelectorExpr, *ast.IndexExpr, *ast.IndexListExpr:
				w.reference(syntaxanalysis.ReferenceConstruct, d.Type)
			default:
				w.typeReferences(d.Type)
			}
		case *ast.TypeAssertExpr:
			w.typeReferences(d.Type)
		}
		return true
	})
}

func (w goWalker) receiverName(expr ast.Expr) syntaxanalysis.Span {
	for {
		switch t := expr.(type) {
		case *ast.StarExpr:
			expr = t.X
		case *ast.ParenExpr:
			expr = t.X
		case *ast.IndexExpr:
			expr = t.X
		case *ast.IndexListExpr:
			expr = t.X
		case *ast.Ident:
			return w.node(t)
		default:
			return syntaxanalysis.Span{}
		}
	}
}

func (w goWalker) structFields(t *ast.StructType) {
	if t.Fields == nil {
		return
	}
	for _, f := range t.Fields.List {
		for _, name := range f.Names {
			w.definition(syntaxanalysis.KindField, name, f, syntaxanalysis.Span{})
		}
	}
}

func (w goWalker) interfaceMethods(t *ast.InterfaceType) {
	if t.Methods == nil {
		return
	}
	for _, f := range t.Methods.List {
		for _, name := range f.Names {
			w.definition(syntaxanalysis.KindMethod, name, f, syntaxanalysis.Span{})
		}
	}
}

func embeddedType(expr ast.Expr) ast.Expr {
	for {
		switch t := expr.(type) {
		case *ast.StarExpr:
			expr = t.X
		case *ast.UnaryExpr:
			expr = t.X
		default:
			return expr
		}
	}
}
