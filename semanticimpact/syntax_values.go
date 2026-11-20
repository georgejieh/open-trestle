package semanticimpact

import (
	"go/ast"
	"strconv"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// predeclaredValues are the universe constants and nil, which name no
// definition of a repository.
var predeclaredValues = map[string]bool{"nil": true, "true": true, "false": true, "iota": true}

// claim marks identifiers as handled, so that the value walk skips them.
func (w goWalker) claim(names ...*ast.Ident) {
	for _, n := range names {
		if n != nil {
			w.claimed[n] = true
		}
	}
}

// local reports whether go/parser bound the identifier to a declaration
// that is not at package level: a parameter, result, receiver, type
// parameter, local variable, constant or type, or a label.
func (w goWalker) local(id *ast.Ident) bool {
	return id.Obj != nil && (w.scope == nil || w.scope.Lookup(id.Name) != id.Obj)
}

// identValue records an identifier that no other rule claimed as a value
// use: a read or write of a package-level variable or constant, or a
// function or type named outside a call.
func (w goWalker) identValue(id *ast.Ident) {
	if w.claimed[id] || id.Name == "_" || w.local(id) {
		return
	}
	if id.Obj == nil && (predeclaredValues[id.Name] || w.imports[id.Name]) {
		return
	}
	w.add(syntaxanalysis.ReferenceValue, id, nil)
}

// selectorValue records a selector outside a call or type position, such
// as a field read, a method value or a package-level variable of an
// imported package. It is qualified by the named type the file gives the
// expression before it, written T or pkg.T, else by the expression. A
// selector on a value of a struct type that no definition names, such as
// the anonymous element type of a test table, is not recorded.
func (w goWalker) selectorValue(s *ast.SelectorExpr) {
	if w.claimed[s.Sel] {
		return
	}
	w.claim(s.Sel)
	qualifier, ok := w.typeQualifier(w.typeOf(s.X, 0))
	if !ok {
		return
	}
	if qualifier == nil {
		qualifier = s.X
	}
	w.add(syntaxanalysis.ReferenceValue, s.Sel, qualifier)
}

// call records a call, the type arguments of a generic call, the type
// argument of make and new, and the types of a conversion to a type
// literal, such as []T(x).
func (w goWalker) call(c *ast.CallExpr) {
	switch fun := ast.Unparen(c.Fun).(type) {
	case *ast.Ident:
		w.reference(syntaxanalysis.ReferenceCall, c.Fun)
		if fun.Obj == nil && (fun.Name == "make" || fun.Name == "new") && len(c.Args) > 0 {
			w.typeReferences(c.Args[0])
		}
	case *ast.SelectorExpr:
		w.reference(syntaxanalysis.ReferenceCall, c.Fun)
	case *ast.IndexExpr, *ast.IndexListExpr:
		w.reference(syntaxanalysis.ReferenceCall, c.Fun)
		w.typeArguments(fun, false)
	default:
		if typeSyntax(fun) {
			w.typeReferences(fun)
		}
	}
}

// typeArguments records the type arguments of an instantiation. A single
// index in a call may be an index into a slice of functions, so it counts
// as a type only when its syntax or its declaration in the file says so,
// unless the caller knows the expression is a type.
func (w goWalker) typeArguments(expr ast.Expr, isType bool) {
	switch e := expr.(type) {
	case *ast.IndexListExpr:
		for _, index := range e.Indices {
			w.typeReferences(index)
		}
	case *ast.IndexExpr:
		id, isIdent := e.Index.(*ast.Ident)
		if isType || typeSyntax(e.Index) || isIdent && id.Obj != nil && id.Obj.Kind == ast.Typ {
			w.typeReferences(e.Index)
		}
	}
}

// typeSyntax reports whether an expression can only be a type, or a
// pointer type such as *T.
func typeSyntax(expr ast.Expr) bool {
	switch expr.(type) {
	case *ast.ArrayType, *ast.MapType, *ast.ChanType, *ast.FuncType, *ast.StructType, *ast.InterfaceType, *ast.StarExpr:
		return true
	}
	return false
}

// typeSwitch records the types of the case clauses and claims the symbol a
// type switch binds.
func (w goWalker) typeSwitch(s *ast.TypeSwitchStmt) {
	if assign, ok := s.Assign.(*ast.AssignStmt); ok {
		for _, lhs := range assign.Lhs {
			if id, ok := lhs.(*ast.Ident); ok {
				w.claim(id)
			}
		}
	}
	if s.Body == nil {
		return
	}
	for _, stmt := range s.Body.List {
		clause, ok := stmt.(*ast.CaseClause)
		if !ok {
			continue
		}
		for _, e := range clause.List {
			if id, ok := e.(*ast.Ident); ok && id.Obj == nil && id.Name == "nil" {
				w.claim(id)
				continue
			}
			w.typeReferences(e)
		}
	}
}

// compositeKeys records the field names of a struct literal as value uses
// qualified by the literal's type, written T or pkg.T, and passes the
// element type to literals whose type is elided. The keys of a slice,
// array or map literal are values and are left to the value walk; the keys
// of a literal of an anonymous, local or unknown struct type name no
// definition.
func (w goWalker) compositeKeys(lit *ast.CompositeLit) {
	typ := lit.Type
	if typ == nil {
		typ = w.implied[lit]
	}
	switch t := unwrapType(typ).(type) {
	case *ast.ArrayType:
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				e = kv.Value
			}
			w.imply(e, t.Elt)
		}
	case *ast.MapType:
		for _, e := range lit.Elts {
			if kv, ok := e.(*ast.KeyValueExpr); ok {
				w.imply(kv.Key, t.Key)
				w.imply(kv.Value, t.Value)
			}
		}
	default:
		name, _ := w.typeQualifier(t)
		for _, e := range lit.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok {
				continue
			}
			w.claim(key)
			if name != nil && key.Name != "_" {
				w.add(syntaxanalysis.ReferenceValue, key, name)
			}
		}
	}
}

func (w goWalker) imply(e, typ ast.Expr) {
	if lit, ok := e.(*ast.CompositeLit); ok && lit.Type == nil {
		w.implied[lit] = typ
	}
}

// importNames returns the names a file's imports bind: the alias, or the
// last element of the path that is not a major version suffix, without a
// dotted suffix such as .v3 and a go- prefix or -go suffix. A package whose
// declared name differs from its path is missed here; the repository index
// knows the declared names of its own packages.
func importNames(file *ast.File) map[string]bool {
	names := map[string]bool{}
	for _, spec := range file.Imports {
		if spec.Name != nil {
			names[spec.Name.Name] = true
			continue
		}
		if spec.Path == nil {
			continue
		}
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		elements := strings.Split(path, "/")
		name := elements[len(elements)-1]
		if len(elements) > 1 && len(name) > 1 && name[0] == 'v' && strings.Trim(name[1:], "0123456789") == "" {
			name = elements[len(elements)-2]
		}
		name, _, _ = strings.Cut(name, ".")
		name = strings.TrimSuffix(strings.TrimPrefix(name, "go-"), "-go")
		names[name] = true
	}
	return names
}
