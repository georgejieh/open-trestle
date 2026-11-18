package syntaxwasm

import (
	"embed"
	"errors"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

//go:embed queries/*.scm
var queryFiles embed.FS

// errQueryPack marks a query pack that does not follow the capture
// vocabulary. It is a defect in the pack, caught by the golden tests.
var errQueryPack = errors.New("syntax query pack is invalid")

// pack is the analysis a language gets on top of its grammar: query files
// in queries/, concatenated, and an optional finishing step for rules that
// depend on the assembled definition tree.
type pack struct {
	query  string
	finish finisher
}

type finisher func(content []byte, raw syntaxanalysis.RawFile, analysis *syntaxanalysis.FileAnalysis)

type packSpec struct {
	files  []string
	finish finisher
}

// packSpecs lists the languages that have a query pack. A language with a
// grammar in a family module but no entry here reports a no_query_pack gap.
var packSpecs = map[syntaxanalysis.Language]packSpec{
	syntaxanalysis.LanguageJava:       {files: []string{"java"}, finish: finishJava},
	syntaxanalysis.LanguageJavaScript: {files: []string{"ecmascript", "javascript", "jsx"}, finish: finishECMAScript},
	syntaxanalysis.LanguageTypeScript: {files: []string{"ecmascript", "typescript"}, finish: finishECMAScript},
	syntaxanalysis.LanguageTSX:        {files: []string{"ecmascript", "typescript", "jsx"}, finish: finishECMAScript},
	syntaxanalysis.LanguagePython:     {files: []string{"python"}, finish: finishPython},
	syntaxanalysis.LanguageC:          {files: []string{"c"}, finish: finishC},
	syntaxanalysis.LanguageCPP:        {files: []string{"cpp"}, finish: finishCPP},
	syntaxanalysis.LanguageCSharp:     {files: []string{"csharp"}, finish: finishCSharp},
	syntaxanalysis.LanguageSwift:      {files: []string{"swift"}, finish: finishSwift},
	syntaxanalysis.LanguageRust:       {files: []string{"rust"}, finish: finishRust},
	syntaxanalysis.LanguagePHP:        {files: []string{"php"}, finish: finishPHP},
	syntaxanalysis.LanguageRuby:       {files: []string{"ruby"}, finish: finishRuby},
	syntaxanalysis.LanguageHTML:       {files: []string{"html"}, finish: finishHTML},
}

func loadPacks() (map[syntaxanalysis.Language]pack, error) {
	packs := map[syntaxanalysis.Language]pack{}
	for language, spec := range packSpecs {
		var query strings.Builder
		for _, file := range spec.files {
			text, err := queryFiles.ReadFile("queries/" + file + ".scm")
			if err != nil {
				return nil, err
			}
			query.Write(text)
			query.WriteByte('\n')
		}
		packs[language] = pack{query: query.String(), finish: spec.finish}
	}
	return packs, nil
}

// role is what a capture means to the host. Capture names follow a small
// vocabulary; see docs/syntax-analysis.md.
type role struct {
	kind       roleKind
	definition syntaxanalysis.DefinitionKind
	reference  syntaxanalysis.ReferenceKind
	// text is the required text of a roleMatch capture.
	text string
}

type roleKind int

const (
	roleIgnored roleKind = iota
	roleDefinition
	roleReference
	roleImport
	roleExport
	roleName
	roleExported
	roleQualifier
	roleImportSource
	roleImportName
	roleImportAlias
	roleMatch
	roleContainer
	roleOpaque
	roleLocal
	roleSymbol
)

// captureRoles maps every capture name of a query to its role and refuses
// a name outside the vocabulary. Names starting with an underscore are
// helpers for anchoring patterns and carry no meaning. A capture named
// match.<word> keeps its match only when the captured text is <word>; it
// stands in for a text predicate, which the shim does not evaluate.
func captureRoles(names []string) ([]role, error) {
	roles := make([]role, len(names))
	for i, name := range names {
		switch {
		case strings.HasPrefix(name, "_"):
			roles[i] = role{kind: roleIgnored}
		case strings.HasPrefix(name, "match."):
			word := strings.TrimPrefix(name, "match.")
			if word == "" {
				return nil, errQueryPack
			}
			roles[i] = role{kind: roleMatch, text: word}
		case strings.HasPrefix(name, "definition."):
			kind := syntaxanalysis.DefinitionKind(strings.TrimPrefix(name, "definition."))
			if !kind.Valid() {
				return nil, errQueryPack
			}
			roles[i] = role{kind: roleDefinition, definition: kind}
		case strings.HasPrefix(name, "reference."):
			kind := syntaxanalysis.ReferenceKind(strings.TrimPrefix(name, "reference."))
			if !kind.Valid() {
				return nil, errQueryPack
			}
			roles[i] = role{kind: roleReference, reference: kind}
		default:
			kind, ok := map[string]roleKind{
				"import": roleImport, "export": roleExport, "name": roleName,
				"exported": roleExported, "qualifier": roleQualifier,
				"import.source": roleImportSource, "import.name": roleImportName,
				"import.alias": roleImportAlias, "container": roleContainer, "opaque": roleOpaque,
				"local": roleLocal, "symbol": roleSymbol,
			}[name]
			if !ok {
				return nil, errQueryPack
			}
			roles[i] = role{kind: kind}
		}
	}
	return roles, nil
}

// rawFile turns decoded matches into raw records. Each match must carry
// exactly one record capture: a definition, a reference, an import or an
// export, unless it only marks opaque or local spans.
func rawFile(content []byte, result analysisResult, roles []role) (syntaxanalysis.RawFile, error) {
	raw := syntaxanalysis.RawFile{}
	var opaqueSpans, localSpans []syntaxanalysis.Span
matches:
	for _, m := range result.matches {
		var record *capture
		var recordRole role
		var name, qualifier, source, imported, alias, container syntaxanalysis.Span
		var names, opaque, local []syntaxanalysis.Span
		exported := false
		for i := range m.captures {
			c := &m.captures[i]
			span := syntaxanalysis.Span{Start: c.start, End: c.end}
			r := roles[c.index]
			switch r.kind {
			case roleDefinition, roleReference, roleImport, roleExport:
				if record != nil {
					return syntaxanalysis.RawFile{}, errQueryPack
				}
				record, recordRole = c, r
			case roleName, roleSymbol:
				if r.kind == roleSymbol && span.End-span.Start > 1 && content[span.Start] == ':' {
					span.Start++
				}
				if name.Empty() {
					name = span
				}
				names = append(names, span)
			case roleExported:
				exported = true
			case roleQualifier:
				qualifier = span
			case roleImportSource:
				source = span
			case roleImportName:
				imported = span
			case roleImportAlias:
				alias = span
			case roleContainer:
				container = span
			case roleOpaque:
				opaque = append(opaque, span)
			case roleLocal:
				local = append(local, span)
			case roleMatch:
				if string(content[c.start:c.end]) != r.text {
					continue matches
				}
			}
		}
		opaqueSpans = append(opaqueSpans, opaque...)
		localSpans = append(localSpans, local...)
		if record == nil {
			if len(opaque)+len(local) > 0 {
				continue
			}
			return syntaxanalysis.RawFile{}, errQueryPack
		}
		node := syntaxanalysis.Span{Start: record.start, End: record.end}
		switch recordRole.kind {
		case roleDefinition:
			raw.Definitions = append(raw.Definitions, syntaxanalysis.RawDefinition{Kind: recordRole.definition, Name: name, Node: node, Container: container, Exported: exported})
		case roleReference:
			raw.References = append(raw.References, syntaxanalysis.RawReference{Kind: recordRole.reference, Name: name, Qualifier: qualifier})
		case roleImport:
			raw.Imports = append(raw.Imports, syntaxanalysis.RawImport{Source: source, Name: imported, Alias: alias, Node: node})
		case roleExport:
			raw.Exports = append(raw.Exports, names...)
		}
	}
	raw.References = dropOpaque(raw.References, mergeSpans(opaqueSpans))
	raw.Definitions = dropLocals(content, raw.Definitions, mergeSpans(localSpans))
	for _, r := range result.regions {
		raw.Gaps = append(raw.Gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapParseError, Span: syntaxanalysis.Span{Start: r.start, End: r.end}})
	}
	return raw, nil
}

// mergeSpans sorts spans by start and joins the overlapping ones.
func mergeSpans(spans []syntaxanalysis.Span) []syntaxanalysis.Span {
	if len(spans) == 0 {
		return nil
	}
	slices.SortFunc(spans, func(a, b syntaxanalysis.Span) int { return a.Start - b.Start })
	merged := spans[:1]
	for _, s := range spans[1:] {
		if last := &merged[len(merged)-1]; s.Start <= last.End {
			last.End = max(last.End, s.End)
		} else {
			merged = append(merged, s)
		}
	}
	return merged
}

// insideSpans reports whether the byte at offset lies in one of the merged
// spans.
func insideSpans(merged []syntaxanalysis.Span, offset int) bool {
	at, _ := slices.BinarySearchFunc(merged, offset, func(s syntaxanalysis.Span, start int) int { return s.Start - start })
	if at < len(merged) && merged[at].Start == offset {
		return true
	}
	return at > 0 && offset < merged[at-1].End
}

// dropOpaque removes the type references whose name lies inside one of the
// opaque spans: code that the grammar reads as declarations although the
// names in it are values or macro arguments.
func dropOpaque(references []syntaxanalysis.RawReference, merged []syntaxanalysis.Span) []syntaxanalysis.RawReference {
	if len(merged) == 0 {
		return references
	}
	kept := references[:0]
	for _, r := range references {
		if r.Kind != syntaxanalysis.ReferenceType || !insideSpans(merged, r.Name.Start) {
			kept = append(kept, r)
		}
	}
	return kept
}

// dropLocals removes the variables, and the function declarations that end
// in a semicolon, whose name lies inside one of the local spans: locals of a
// function body and the functions a friend declaration names. Function
// definitions there, such as the methods of a local class, are kept.
func dropLocals(content []byte, definitions []syntaxanalysis.RawDefinition, merged []syntaxanalysis.Span) []syntaxanalysis.RawDefinition {
	if len(merged) == 0 {
		return definitions
	}
	kept := definitions[:0]
	for _, d := range definitions {
		local := false
		switch d.Kind {
		case syntaxanalysis.KindVariable:
			local = true
		case syntaxanalysis.KindFunction:
			local = d.Node.End > d.Node.Start && d.Node.End <= len(content) && content[d.Node.End-1] == ';'
		}
		if !local || !insideSpans(merged, d.Name.Start) {
			kept = append(kept, d)
		}
	}
	return kept
}
