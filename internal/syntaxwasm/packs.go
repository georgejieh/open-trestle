package syntaxwasm

import (
	"embed"
	"errors"
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
				"import.alias": roleImportAlias,
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
// export.
func rawFile(content []byte, result analysisResult, roles []role) (syntaxanalysis.RawFile, error) {
	raw := syntaxanalysis.RawFile{}
matches:
	for _, m := range result.matches {
		var record *capture
		var recordRole role
		var name, qualifier, source, imported, alias syntaxanalysis.Span
		var names []syntaxanalysis.Span
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
			case roleName:
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
			case roleMatch:
				if string(content[c.start:c.end]) != r.text {
					continue matches
				}
			}
		}
		if record == nil {
			return syntaxanalysis.RawFile{}, errQueryPack
		}
		node := syntaxanalysis.Span{Start: record.start, End: record.end}
		switch recordRole.kind {
		case roleDefinition:
			raw.Definitions = append(raw.Definitions, syntaxanalysis.RawDefinition{Kind: recordRole.definition, Name: name, Node: node, Exported: exported})
		case roleReference:
			raw.References = append(raw.References, syntaxanalysis.RawReference{Kind: recordRole.reference, Name: name, Qualifier: qualifier})
		case roleImport:
			raw.Imports = append(raw.Imports, syntaxanalysis.RawImport{Source: source, Name: imported, Alias: alias, Node: node})
		case roleExport:
			raw.Exports = append(raw.Exports, names...)
		}
	}
	for _, r := range result.regions {
		raw.Gaps = append(raw.Gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapParseError, Span: syntaxanalysis.Span{Start: r.start, End: r.end}})
	}
	return raw, nil
}
