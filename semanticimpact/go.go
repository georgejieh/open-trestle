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

const goGraphSchema = "open-trestle/semantic-impact/go-ast-graph/v1"

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
	refs := buildReferences(declarations, headParsed)
	if len(refs) > maximumReferences {
		return Profile{}, ErrImpactLimit
	}
	if len(gaps) > maximumGaps {
		return Profile{}, ErrImpactLimit
	}
	slices.SortFunc(gaps, func(a, b Gap) int {
		if c := strings.Compare(a.filePath, b.filePath); c != 0 {
			return c
		}
		return strings.Compare(string(a.reason), string(b.reason))
	})
	profile := Profile{adapterIdentity: goAdapterIdentity, graphSchema: goGraphSchema, inputIdentity: input.identity, baseSnapshotIdentity: input.baseSnapshotIdentity, headSnapshotIdentity: input.headSnapshotIdentity, changeModelIdentity: input.changeModelIdentity, declarations: declarations, references: refs, gaps: gaps}
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
	for _, decl := range node.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			if d.Name.Name == "_" {
				continue
			}
			key := "func:" + d.Name.Name
			if d.Recv == nil && d.Name.Name == "init" {
				initCount++
				if initCount > 1 {
					key += "#" + strconv.Itoa(initCount)
				}
			}
			kind := "function"
			if d.Recv != nil && len(d.Recv.List) > 0 {
				receiver := formatExpr(fset, d.Recv.List[0].Type)
				key = "method:" + receiver + "." + d.Name.Name
				kind = "method"
			}
			if _, exists := out.declarations[key]; exists {
				return parsedGoFile{}, false
			}
			out.declarations[key] = rawDecl(fset, d, key, d.Name.Name, kind, ast.IsExported(d.Name.Name), d.Name.Pos())
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					if s.Name.Name == "_" {
						continue
					}
					key := "type:" + s.Name.Name
					if _, exists := out.declarations[key]; exists {
						return parsedGoFile{}, false
					}
					out.declarations[key] = rawDecl(fset, s, key, s.Name.Name, "type", ast.IsExported(s.Name.Name), s.Name.Pos())
				case *ast.ValueSpec:
					kind := strings.ToLower(d.Tok.String())
					for _, name := range s.Names {
						if name.Name == "_" {
							continue
						}
						key := kind + ":" + name.Name
						if _, exists := out.declarations[key]; exists {
							return parsedGoFile{}, false
						}
						out.declarations[key] = rawDecl(fset, s, key, name.Name, kind, ast.IsExported(name.Name), name.Pos())
					}
				}
			}
		}
	}
	return out, true
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
func buildReferences(declarations []Declaration, files map[string]parsedGoFile) []Reference {
	refs := []Reference{}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	for _, d := range declarations {
		for _, p := range paths {
			if len(refs) > maximumReferences {
				return refs
			}
			file := files[p]
			ast.Inspect(file.file, func(node ast.Node) bool {
				id, ok := node.(*ast.Ident)
				if !ok || id.Name != d.name {
					return true
				}
				pos := file.fset.PositionFor(id.Pos(), false)
				for _, declared := range file.declarations {
					if declared.nameOffset == pos.Offset {
						return true
					}
				}
				wire := struct {
					Declaration, Path string
					Line, Column      int
					Test              bool
					Grade             Grade
				}{d.identity, p, pos.Line, pos.Column, strings.HasSuffix(p, "_test.go"), GradeSyntacticCandidate}
				refs = append(refs, Reference{identity: hashJSON(wire), declarationIdentity: d.identity, declarationKey: d.key, filePath: p, line: pos.Line, column: pos.Column, affectedTest: wire.Test, grade: GradeSyntacticCandidate})
				return len(refs) <= maximumReferences
			})
		}
	}
	slices.SortFunc(refs, func(a, b Reference) int {
		if c := strings.Compare(a.declarationIdentity, b.declarationIdentity); c != 0 {
			return c
		}
		if c := strings.Compare(a.filePath, b.filePath); c != 0 {
			return c
		}
		if a.line != b.line {
			return a.line - b.line
		}
		return a.column - b.column
	})
	return refs
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
