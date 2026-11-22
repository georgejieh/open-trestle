package semanticimpact

import (
	"bytes"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"path"
	"slices"
	"strconv"
	"strings"
)

// goGraphSchema records declaration differences only.
const goGraphSchema = "open-trestle/semantic-impact/go-ast-graph/v2"

var goAdapterIdentity = hashJSON(struct{ Implementation, Version, Graph string }{"go/parser", "1", goGraphSchema})

type rawDeclaration struct {
	key, name, kind                string
	exported                       bool
	startLine, endLine, nameOffset int
	digest, apiDigest              string
}
type parsedGoFile struct {
	path         string
	file         *ast.File
	fset         *token.FileSet
	declarations map[string]rawDeclaration
}

func AnalyzeGo(input Input) (Profile, error) {
	if !validInput(input) {
		return Profile{}, ErrInvalidInput
	}
	baseByPath := filesByPath(input.baseFiles)
	headByPath := filesByPath(input.headFiles)
	baseParsed := map[string]parsedGoFile{}
	headParsed := map[string]parsedGoFile{}
	gaps := append([]Gap(nil), input.coverageGaps...)
	for _, f := range input.headFiles {
		if path.Ext(f.filePath) != ".go" {
			continue
		}
		parsed, ok := parseGoFile(f)
		if !ok {
			gaps = appendGap(gaps, newGap(f.filePath, GapParseFailure, "go parser rejected head source"))
			continue
		}
		headParsed[f.filePath] = parsed
	}
	declarations := []Declaration{}
	for _, changed := range input.changes {
		p := changed.filePath
		if path.Ext(p) != ".go" {
			gaps = appendGap(gaps, newGap(p, GapUnsupportedLanguage, "no approved language adapter"))
			continue
		}
		if hasAnyGap(gaps, p) {
			continue
		}
		baseFile, hasBase := baseByPath[p]
		headFile, hasHead := headByPath[p]
		if !hasBase && !hasHead {
			if !hasAnyGap(gaps, p) {
				gaps = appendGap(gaps, newGap(p, GapSourceUnavailable, "changed source is unavailable"))
			}
			continue
		}
		var bp, hp parsedGoFile
		var bok, hok bool
		if hasBase {
			bp, bok = parseGoFile(baseFile)
			if !bok {
				gaps = appendGap(gaps, newGap(p, GapParseFailure, "go parser rejected base source"))
			} else {
				baseParsed[p] = bp
			}
		}
		if hasHead {
			hp, hok = headParsed[p]
			if !hok {
				if _, exists := headParsed[p]; exists {
					hp, hok = headParsed[p], true
				} else if parsed, ok := parseGoFile(headFile); ok {
					hp, hok = parsed, true
					headParsed[p] = parsed
				} else if !containsGap(gaps, p, GapParseFailure) {
					gaps = appendGap(gaps, newGap(p, GapParseFailure, "go parser rejected head source"))
				}
			}
		}
		if (hasBase && !bok) || (hasHead && !hok) {
			continue
		}
		keys := map[string]bool{}
		if bok {
			for k := range bp.declarations {
				keys[k] = true
			}
		}
		if hok {
			for k := range hp.declarations {
				keys[k] = true
			}
		}
		ordered := make([]string, 0, len(keys))
		for k := range keys {
			ordered = append(ordered, k)
		}
		slices.Sort(ordered)
		for _, k := range ordered {
			bd, bexists := bp.declarations[k]
			hd, hexists := hp.declarations[k]
			var ch Change
			var rd rawDeclaration
			switch {
			case !bexists && hexists:
				ch, rd = ChangeAdded, hd
			case bexists && !hexists:
				ch, rd = ChangeRemoved, bd
			case bd.digest != hd.digest:
				ch, rd = ChangeModified, hd
			default:
				continue
			}
			if len(rd.name) > 1024 || len(rd.key) > 4096 {
				return Profile{}, ErrImpactLimit
			}
			publicAPIChange := rd.exported && (ch != ChangeModified || bd.apiDigest != hd.apiDigest)
			declarations = append(declarations, newDeclaration(p, rd, ch, publicAPIChange))
			if len(declarations) > maximumDeclarations {
				return Profile{}, ErrImpactLimit
			}
		}
	}
	slices.SortFunc(declarations, func(a, b Declaration) int {
		if c := strings.Compare(a.filePath, b.filePath); c != 0 {
			return c
		}
		return strings.Compare(a.key, b.key)
	})
	if len(gaps) > maximumGaps {
		return Profile{}, ErrImpactLimit
	}
	slices.SortFunc(gaps, func(a, b Gap) int {
		if c := strings.Compare(a.filePath, b.filePath); c != 0 {
			return c
		}
		return strings.Compare(string(a.reason), string(b.reason))
	})
	profile := Profile{adapterIdentity: goAdapterIdentity, graphSchema: goGraphSchema, inputIdentity: input.identity, baseSnapshotIdentity: input.baseSnapshotIdentity, headSnapshotIdentity: input.headSnapshotIdentity, changeModelIdentity: input.changeModelIdentity, declarations: declarations, gaps: gaps}
	profile.identity = deriveProfileIdentity(profile)
	if _, err := EncodeProfile(profile); err != nil {
		return Profile{}, err
	}
	return profile, nil
}
func parseGoFile(f File) (parsedGoFile, bool) {
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, f.filePath, f.content, parser.SkipObjectResolution)
	if err != nil {
		return parsedGoFile{}, false
	}
	out := parsedGoFile{path: f.filePath, file: node, fset: fset, declarations: map[string]rawDeclaration{}}
	initCount := 0
	duplicate := false
	goDeclarations(node, func(g goDeclaration) {
		name := g.name.Name
		var key, kind string
		var declNode ast.Node
		switch s := g.spec.(type) {
		case nil:
			d := g.decl.(*ast.FuncDecl)
			key, kind, declNode = "func:"+name, "function", d
			if d.Recv == nil && name == "init" {
				initCount++
				if initCount > 1 {
					key += "#" + strconv.Itoa(initCount)
				}
			}
			if d.Recv != nil && len(d.Recv.List) > 0 {
				key, kind = "method:"+formatExpr(fset, d.Recv.List[0].Type)+"."+name, "method"
			}
		case *ast.TypeSpec:
			key, kind, declNode = "type:"+name, "type", s
		case *ast.ValueSpec:
			kind = strings.ToLower(g.decl.(*ast.GenDecl).Tok.String())
			key, declNode = kind+":"+name, s
		}
		if _, exists := out.declarations[key]; exists {
			duplicate = true
			return
		}
		out.declarations[key] = rawDecl(fset, declNode, key, name, kind, ast.IsExported(name), g.name.Pos())
	})
	if duplicate {
		return parsedGoFile{}, false
	}
	return out, true
}

// GoBlankVariablesChanged reports whether the package-level var specs whose
// names are all blank (var _ = register(), var _ I = (*T)(nil)) differ
// between a base and a head Go source, or whether either fails to parse. Such
// a spec leaves no declaration in a profile, yet its initializer runs at
// package initialization. A nil source, for an added or removed file, has
// none.
func GoBlankVariablesChanged(base, head []byte) bool {
	b, bok := goBlankVariables(base)
	h, hok := goBlankVariables(head)
	return !bok || !hok || !slices.Equal(b, h)
}
func goBlankVariables(content []byte) ([]string, bool) {
	if content == nil {
		return nil, true
	}
	fset := token.NewFileSet()
	node, err := parser.ParseFile(fset, "", content, parser.SkipObjectResolution)
	if err != nil {
		return nil, false
	}
	var specs []string
	for _, decl := range node.Decls {
		d, ok := decl.(*ast.GenDecl)
		if !ok || d.Tok != token.VAR {
			continue
		}
		for _, spec := range d.Specs {
			s := spec.(*ast.ValueSpec)
			if slices.ContainsFunc(s.Names, func(name *ast.Ident) bool { return name.Name != "_" }) {
				continue
			}
			var b bytes.Buffer
			if format.Node(&b, fset, s) != nil {
				return nil, false
			}
			specs = append(specs, b.String())
		}
	}
	return specs, true
}
func rawDecl(fset *token.FileSet, node ast.Node, key, name, kind string, exported bool, namePos token.Pos) rawDeclaration {
	var b bytes.Buffer
	_ = format.Node(&b, fset, node)
	syntaxSource := b.String()
	apiSource := syntaxSource
	if fn, ok := node.(*ast.FuncDecl); ok {
		signature := *fn
		signature.Body = nil
		b.Reset()
		_ = format.Node(&b, fset, &signature)
		apiSource = b.String()
	}
	return rawDeclaration{key: key, name: name, kind: kind, exported: exported, startLine: fset.PositionFor(node.Pos(), false).Line, endLine: fset.PositionFor(node.End(), false).Line, nameOffset: fset.PositionFor(namePos, false).Offset, digest: hashJSON(struct{ Key, Source string }{key, syntaxSource}), apiDigest: hashJSON(struct{ Key, Source string }{key, apiSource})}
}
func formatExpr(fset *token.FileSet, expr ast.Expr) string {
	var b bytes.Buffer
	if format.Node(&b, fset, expr) != nil {
		return "unknown"
	}
	return b.String()
}
func newDeclaration(p string, r rawDeclaration, ch Change, publicAPIChange bool) Declaration {
	wire := struct {
		Path, Key, Name, Kind, Change, Digest, APIDigest string
		Exported, PublicAPIChange                        bool
		Start, End                                       int
	}{p, r.key, r.name, r.kind, string(ch), r.digest, r.apiDigest, r.exported, publicAPIChange, r.startLine, r.endLine}
	return Declaration{identity: hashJSON(wire), key: r.key, name: r.name, kind: r.kind, filePath: p, syntaxDigest: r.digest, apiDigest: r.apiDigest, change: ch, exported: r.exported, publicAPIChange: publicAPIChange, startLine: r.startLine, endLine: r.endLine}
}
func newGap(p string, reason GapReason, detail string) Gap {
	return Gap{identity: hashJSON(struct {
		Path   string
		Reason GapReason
		Detail string
	}{p, reason, detail}), filePath: p, reason: reason, detail: detail}
}
func appendGap(gaps []Gap, g Gap) []Gap { return append(gaps, g) }
func hasAnyGap(gaps []Gap, p string) bool {
	for _, g := range gaps {
		if g.filePath == p {
			return true
		}
	}
	return false
}
func containsGap(gaps []Gap, p string, r GapReason) bool {
	for _, g := range gaps {
		if g.filePath == p && g.reason == r {
			return true
		}
	}
	return false
}
func filesByPath(files []File) map[string]File {
	out := make(map[string]File, len(files))
	for _, f := range files {
		out[f.filePath] = f
	}
	return out
}
func validInput(i Input) bool {
	rebuilt, err := NewInputWithCoverageGaps(i.baseSnapshotIdentity, i.headSnapshotIdentity, i.changeModelIdentity, i.changes, i.baseFiles, i.headFiles, i.coverageGaps)
	return err == nil && rebuilt.identity == i.identity
}
