package semanticimpact

import "go/ast"

// goDeclaration is one top-level declaration of a Go file: a function or
// method, a type, or one name of a var or const spec. Blank names are left
// out.
type goDeclaration struct {
	name *ast.Ident
	// decl is the *ast.FuncDecl or *ast.GenDecl, and spec the *ast.TypeSpec
	// or *ast.ValueSpec of a GenDecl.
	decl ast.Decl
	spec ast.Spec
}

// goDeclarations visits the top-level declarations of a file in source
// order. The impact profile and the syntax analysis both take their
// declarations from it, so the two cannot disagree.
func goDeclarations(file *ast.File, visit func(goDeclaration)) {
	for _, decl := range file.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name.Name != "_" {
				visit(goDeclaration{name: d.Name, decl: d})
			}
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.Name != "_" {
						visit(goDeclaration{name: s.Name, decl: d, spec: s})
					}
				case *ast.ValueSpec:
					for _, name := range s.Names {
						if name.Name != "_" {
							visit(goDeclaration{name: name, decl: d, spec: s})
						}
					}
				}
			}
		}
	}
}
