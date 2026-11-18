package semanticimpact

import (
	"go/ast"
	"go/token"
	"slices"
)

// maxTypeSteps bounds the declarations followed to find the type of an
// expression.
const maxTypeSteps = 4

// typeOf returns the type the file gives an expression, as written in a
// declaration, or nil. It follows the declaration of an identifier: a
// receiver, parameter or result, a variable declared with a type or given
// a composite literal, its address, new(T), a conversion to a type of the
// file, a call of a function of the file, or an element of a range over
// such a value.
func (w goWalker) typeOf(expr ast.Expr, steps int) ast.Expr {
	if steps > maxTypeSteps {
		return nil
	}
	switch e := ast.Unparen(expr).(type) {
	case *ast.Ident:
		if e.Obj == nil {
			return nil
		}
		switch d := e.Obj.Decl.(type) {
		case *ast.Field:
			return d.Type
		case *ast.ValueSpec:
			if d.Type != nil {
				return d.Type
			}
			i := slices.IndexFunc(d.Names, func(n *ast.Ident) bool { return n.Obj == e.Obj })
			return w.assignedType(i, len(d.Names), d.Values, steps)
		case *ast.AssignStmt:
			i := slices.IndexFunc(d.Lhs, func(x ast.Expr) bool { id, ok := x.(*ast.Ident); return ok && id.Obj == e.Obj })
			return w.assignedType(i, len(d.Lhs), d.Rhs, steps)
		}
	case *ast.CompositeLit:
		if e.Type != nil {
			return e.Type
		}
		return w.implied[e]
	case *ast.UnaryExpr:
		if e.Op == token.AND {
			return w.typeOf(e.X, steps+1)
		}
	case *ast.CallExpr:
		return resultType(e, 0)
	}
	return nil
}

// assignedType returns the type of the i-th of n names given the values.
func (w goWalker) assignedType(i, n int, values []ast.Expr, steps int) ast.Expr {
	switch {
	case i < 0:
		return nil
	case len(values) == n:
		return w.typeOf(values[i], steps+1)
	case len(values) != 1:
		return nil
	}
	switch v := values[0].(type) {
	case *ast.UnaryExpr:
		// go/parser gives the key and value of a range clause an assignment
		// from a range expression.
		if v.Op == token.RANGE {
			return elementType(w.typeOf(v.X, steps+1), i)
		}
	case *ast.CallExpr:
		return resultType(v, i)
	}
	return nil
}

// elementType returns the type of the key (i = 0) or value (i = 1) of a
// range over a value of a slice, array or map type, or of a type of the
// file defined as one.
func elementType(t ast.Expr, i int) ast.Expr {
	t = unwrapType(t)
	if id, ok := t.(*ast.Ident); ok && id.Obj != nil {
		if spec, ok := id.Obj.Decl.(*ast.TypeSpec); ok {
			t = spec.Type
		}
	}
	switch c := t.(type) {
	case *ast.ArrayType:
		if i == 1 {
			return c.Elt
		}
	case *ast.MapType:
		if i == 0 {
			return c.Key
		}
		return c.Value
	}
	return nil
}

// resultType returns the type of the i-th result of a call of new, of a
// conversion to a type of the file, or of a function declared in the file.
func resultType(call *ast.CallExpr, i int) ast.Expr {
	fun, ok := ast.Unparen(call.Fun).(*ast.Ident)
	if !ok {
		return nil
	}
	if fun.Obj == nil {
		if fun.Name == "new" && len(call.Args) == 1 && i == 0 {
			return call.Args[0]
		}
		return nil
	}
	switch d := fun.Obj.Decl.(type) {
	case *ast.TypeSpec:
		if i == 0 {
			return fun
		}
	case *ast.FuncDecl:
		if d.Type.Results == nil {
			return nil
		}
		for _, f := range d.Type.Results.List {
			n := max(len(f.Names), 1)
			if i < n {
				return f.Type
			}
			i -= n
		}
	}
	return nil
}

// typeQualifier returns the name of a named type, as T or pkg.T, to
// qualify a use of one of its members. It returns ok=false for a struct
// type whose members are no definitions, an anonymous or function-local
// struct type without embedded fields, and nil for any other type.
func (w goWalker) typeQualifier(t ast.Expr) (ast.Expr, bool) {
	switch u := unwrapType(t).(type) {
	case *ast.StructType:
		return nil, embeds(u)
	case *ast.Ident:
		if !w.local(u) {
			return u, true
		}
		if spec, ok := u.Obj.Decl.(*ast.TypeSpec); ok {
			if st, ok := spec.Type.(*ast.StructType); ok {
				return nil, embeds(st)
			}
		}
	case *ast.SelectorExpr:
		if _, ok := u.X.(*ast.Ident); ok {
			return u, true
		}
	case *ast.IndexExpr:
		return w.typeQualifier(u.X)
	case *ast.IndexListExpr:
		return w.typeQualifier(u.X)
	}
	return nil, true
}

// embeds reports whether a struct type has an embedded field, whose
// members its own selectors reach.
func embeds(st *ast.StructType) bool {
	if st.Fields == nil {
		return false
	}
	for _, f := range st.Fields.List {
		if len(f.Names) == 0 {
			return true
		}
	}
	return false
}

// unwrapType removes the parentheses and pointers around a type.
func unwrapType(expr ast.Expr) ast.Expr {
	for {
		switch t := expr.(type) {
		case *ast.ParenExpr:
			expr = t.X
		case *ast.StarExpr:
			expr = t.X
		default:
			return expr
		}
	}
}
