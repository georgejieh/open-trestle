package syntaxanalysis

import (
	"slices"
	"sort"
	"unicode/utf8"
)

// Span is a half-open byte range of the source. An empty span marks an
// absent optional part, such as a missing alias.
type Span struct{ Start, End int }

// Empty reports whether the span covers no bytes.
func (s Span) Empty() bool { return s.End <= s.Start }

// RawDefinition is a definition as an analyzer found it, before validation.
type RawDefinition struct {
	Kind      DefinitionKind
	Name      Span
	Node      Span
	Container Span
	Exported  bool
}

// RawReference is a reference as an analyzer found it.
type RawReference struct {
	Kind      ReferenceKind
	Name      Span
	Qualifier Span
}

// RawImport is an import as an analyzer found it.
type RawImport struct {
	Source, Name, Alias, Node Span
}

// RawGap is a gap as an analyzer found it. A gap with an empty span covers
// the whole file.
type RawGap struct {
	Reason GapReason
	Limit  Limit
	Span   Span
}

// RawFile collects an analyzer's raw records for one source.
type RawFile struct {
	Definitions []RawDefinition
	References  []RawReference
	Imports     []RawImport
	Gaps        []RawGap
	// Exports are names listed in an export clause; a top-level definition
	// with one of these names is exported.
	Exports []Span
}

// definitionRank orders kinds when two records claim the same name: the
// more specific kind wins.
func definitionRank(k DefinitionKind) int {
	switch k {
	case KindVariable:
		return 0
	case KindConstant:
		return 1
	case KindField:
		return 2
	default:
		return 3
	}
}

// Assemble validates raw records against the source and builds the
// FileAnalysis. It is shared by every analyzer so that the same trust rules
// apply to all of them:
//
//   - a span outside the source makes the whole result untrustworthy, so
//     the records are dropped and the file gets an analysis_failed gap;
//   - a name that is not valid UTF-8 is dropped with an invalid_text gap;
//   - a name longer than MaxNameBytes is dropped with a name_length gap;
//   - records beyond MaxRecords are dropped in source order with a records
//     gap that starts at the first dropped record;
//   - parse-error regions beyond MaxErrorRegions are replaced by one
//     error_regions gap.
//
// Definitions that share a name span are one definition: the widest node,
// the most specific kind and either export flag win. A function whose
// parent is a class-like definition becomes a method.
func Assemble(source Source, analyzer string, raw RawFile, limits Limits) FileAnalysis {
	if !limits.Valid() {
		limits = DefaultLimits()
	}
	content := source.content
	size := len(content)
	failed := func() FileAnalysis {
		return WholeFileGap(source, analyzer, GapAnalysisFailed, "")
	}
	inBounds := func(s Span) bool { return s.Start >= 0 && s.End >= s.Start && s.End <= size }
	for _, d := range raw.Definitions {
		if !d.Kind.Valid() || !inBounds(d.Name) || !inBounds(d.Node) || !inBounds(d.Container) {
			return failed()
		}
	}
	for _, r := range raw.References {
		if !r.Kind.Valid() || !inBounds(r.Name) || !inBounds(r.Qualifier) {
			return failed()
		}
	}
	for _, i := range raw.Imports {
		if !inBounds(i.Source) || !inBounds(i.Name) || !inBounds(i.Alias) || !inBounds(i.Node) {
			return failed()
		}
	}
	for _, g := range raw.Gaps {
		if !inBounds(g.Span) {
			return failed()
		}
	}
	for _, e := range raw.Exports {
		if !inBounds(e) {
			return failed()
		}
	}

	lines := newLineIndex(content)
	gaps := []RawGap{}
	// text returns the span's text, or ok=false after recording a gap.
	text := func(s Span) (string, bool) {
		value := content[s.Start:s.End]
		if s.End-s.Start > limits.MaxNameBytes {
			gaps = append(gaps, RawGap{Reason: GapLimitExceeded, Limit: LimitNameLength, Span: s})
			return "", false
		}
		if !utf8.Valid(value) {
			gaps = append(gaps, RawGap{Reason: GapInvalidText, Span: s})
			return "", false
		}
		return string(value), true
	}
	optional := func(s Span) (Text, bool) {
		if s.Empty() {
			return Text{}, true
		}
		value, ok := text(s)
		return Text{value: value}, ok
	}

	// Merge definitions that share a name span.
	type pending struct {
		raw  RawDefinition
		name string
	}
	byName := map[Span]int{}
	merged := []pending{}
	for _, d := range raw.Definitions {
		if d.Name.Empty() || d.Node.Empty() {
			continue
		}
		if at, ok := byName[d.Name]; ok {
			m := &merged[at].raw
			if d.Node.End-d.Node.Start > m.Node.End-m.Node.Start {
				m.Node = d.Node
			}
			if definitionRank(d.Kind) > definitionRank(m.Kind) {
				m.Kind = d.Kind
			}
			if m.Container.Empty() {
				m.Container = d.Container
			}
			m.Exported = m.Exported || d.Exported
			continue
		}
		byName[d.Name] = len(merged)
		merged = append(merged, pending{raw: d})
	}
	kept := merged[:0]
	for _, p := range merged {
		name, ok := text(p.raw.Name)
		if !ok {
			continue
		}
		p.name = name
		kept = append(kept, p)
	}
	merged = kept
	slices.SortStableFunc(merged, func(a, b pending) int {
		if a.raw.Node.Start != b.raw.Node.Start {
			return a.raw.Node.Start - b.raw.Node.Start
		}
		if a.raw.Node.End != b.raw.Node.End {
			return b.raw.Node.End - a.raw.Node.End
		}
		return a.raw.Name.Start - b.raw.Name.Start
	})

	budget := limits.MaxRecords
	var firstDropped = -1
	drop := func(at int) {
		if firstDropped < 0 || at < firstDropped {
			firstDropped = at
		}
	}

	definitions := make([]Definition, 0, len(merged))
	stack := []int{}
	for _, p := range merged {
		if len(definitions) >= budget {
			drop(p.raw.Node.Start)
			break
		}
		container, ok := optional(p.raw.Container)
		if !ok {
			continue
		}
		for len(stack) > 0 {
			top := definitions[stack[len(stack)-1]]
			if p.raw.Node.Start >= top.Range.StartByte && p.raw.Node.End <= top.Range.EndByte {
				break
			}
			stack = stack[:len(stack)-1]
		}
		parent := -1
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		kind := p.raw.Kind
		if kind == KindFunction && parent >= 0 && definitions[parent].Kind.Container() {
			kind = KindMethod
		}
		definitions = append(definitions, Definition{
			Kind: kind, Name: Text{value: p.name}, Container: container,
			Range: lines.rangeOf(p.raw.Node), NameRange: lines.rangeOf(p.raw.Name),
			Parent: parent, Exported: p.raw.Exported,
		})
		stack = append(stack, len(definitions)-1)
	}
	budget -= len(definitions)

	if len(raw.Exports) > 0 {
		exported := map[string]bool{}
		for _, e := range raw.Exports {
			if value, ok := text(e); ok {
				exported[value] = true
			}
		}
		for i := range definitions {
			if definitions[i].Parent < 0 && exported[definitions[i].Name.value] {
				definitions[i].Exported = true
			}
		}
	}

	imports := []Import{}
	rawImports := slices.Clone(raw.Imports)
	slices.SortStableFunc(rawImports, func(a, b RawImport) int {
		if a.Node.Start != b.Node.Start {
			return a.Node.Start - b.Node.Start
		}
		return a.Source.Start - b.Source.Start
	})
	seenImports := map[RawImport]bool{}
	for _, i := range rawImports {
		if i.Source.Empty() || seenImports[i] {
			continue
		}
		seenImports[i] = true
		if len(imports) >= budget {
			drop(i.Node.Start)
			break
		}
		sourceText, ok := text(i.Source)
		if !ok {
			continue
		}
		name, ok := optional(i.Name)
		if !ok {
			continue
		}
		alias, ok := optional(i.Alias)
		if !ok {
			continue
		}
		node := i.Node
		if node.Empty() {
			node = i.Source
		}
		imports = append(imports, Import{
			Source: Text{value: sourceText}, Name: name, Alias: alias,
			Range: lines.rangeOf(node), Enclosing: enclosing(definitions, node.Start),
		})
	}
	budget -= len(imports)

	references := []Reference{}
	rawReferences := slices.Clone(raw.References)
	slices.SortStableFunc(rawReferences, func(a, b RawReference) int {
		if a.Name.Start != b.Name.Start {
			return a.Name.Start - b.Name.Start
		}
		return a.Name.End - b.Name.End
	})
	seenReferences := map[RawReference]bool{}
	for _, r := range rawReferences {
		if r.Name.Empty() || seenReferences[r] {
			continue
		}
		seenReferences[r] = true
		if len(references) >= budget {
			drop(r.Name.Start)
			break
		}
		name, ok := text(r.Name)
		if !ok {
			continue
		}
		qualifier, ok := optional(r.Qualifier)
		if !ok {
			continue
		}
		references = append(references, Reference{
			Kind: r.Kind, Name: Text{value: name}, Qualifier: qualifier,
			Range: lines.rangeOf(r.Name), Enclosing: enclosing(definitions, r.Name.Start),
		})
	}
	if firstDropped >= 0 {
		gaps = append(gaps, RawGap{Reason: GapLimitExceeded, Limit: LimitRecords, Span: Span{Start: firstDropped, End: size}})
	}

	// Parse-error regions: merge overlaps and bound the count.
	errorRegions := []Span{}
	for _, g := range raw.Gaps {
		if g.Reason == GapParseError && !g.Span.Empty() {
			errorRegions = append(errorRegions, g.Span)
		} else if g.Reason == GapParseError {
			errorRegions = append(errorRegions, pointSpan(g.Span.Start, size))
		} else {
			gaps = append(gaps, g)
		}
	}
	slices.SortFunc(errorRegions, func(a, b Span) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		return a.End - b.End
	})
	mergedRegions := []Span{}
	for _, r := range errorRegions {
		if n := len(mergedRegions); n > 0 && r.Start <= mergedRegions[n-1].End {
			mergedRegions[n-1].End = max(mergedRegions[n-1].End, r.End)
			continue
		}
		mergedRegions = append(mergedRegions, r)
	}
	if len(mergedRegions) > limits.MaxErrorRegions {
		rest := mergedRegions[limits.MaxErrorRegions]
		mergedRegions = mergedRegions[:limits.MaxErrorRegions]
		gaps = append(gaps, RawGap{Reason: GapLimitExceeded, Limit: LimitErrorRegions, Span: Span{Start: rest.Start, End: size}})
	}
	for _, r := range mergedRegions {
		gaps = append(gaps, RawGap{Reason: GapParseError, Span: r})
	}

	out := make([]Gap, 0, len(gaps))
	seenGaps := map[RawGap]bool{}
	for _, g := range gaps {
		if seenGaps[g] {
			continue
		}
		seenGaps[g] = true
		gap := Gap{Reason: g.Reason, Limit: g.Limit}
		if !g.Span.Empty() {
			gap.HasRange = true
			gap.Range = lines.rangeOf(g.Span)
		}
		out = append(out, gap)
	}
	slices.SortStableFunc(out, func(a, b Gap) int {
		if a.HasRange != b.HasRange {
			if !a.HasRange {
				return -1
			}
			return 1
		}
		if a.Range.StartByte != b.Range.StartByte {
			return a.Range.StartByte - b.Range.StartByte
		}
		if a.Reason != b.Reason {
			if a.Reason < b.Reason {
				return -1
			}
			return 1
		}
		return a.Range.EndByte - b.Range.EndByte
	})

	return FileAnalysis{
		Path: source.path, Language: source.language, ContentSHA256: source.digest, Analyzer: analyzer,
		Definitions: definitions, References: references, Imports: imports, Gaps: out,
	}
}

// pointSpan widens a zero-width error position, such as a missing token, to
// one byte so that it can be reported as a region.
func pointSpan(at, size int) Span {
	if at >= size {
		if size == 0 {
			return Span{}
		}
		return Span{Start: size - 1, End: size}
	}
	return Span{Start: at, End: at + 1}
}

// enclosing finds the innermost definition containing the offset. The
// definitions are sorted by start and properly nested, so the candidates
// are the last definition starting at or before the offset and its parents.
func enclosing(definitions []Definition, offset int) int {
	i := sort.Search(len(definitions), func(i int) bool { return definitions[i].Range.StartByte > offset }) - 1
	for depth := 0; i >= 0 && depth <= len(definitions); depth++ {
		if definitions[i].Range.Contains(offset) {
			return i
		}
		i = definitions[i].Parent
	}
	return -1
}

type lineIndex struct{ starts []int }

func newLineIndex(content []byte) lineIndex {
	starts := []int{0}
	for i, b := range content {
		if b == '\n' {
			starts = append(starts, i+1)
		}
	}
	return lineIndex{starts: starts}
}

func (l lineIndex) position(offset int) Position {
	line := sort.Search(len(l.starts), func(i int) bool { return l.starts[i] > offset }) - 1
	return Position{Line: line + 1, Column: offset - l.starts[line] + 1}
}

func (l lineIndex) rangeOf(s Span) Range {
	return Range{StartByte: s.Start, EndByte: s.End, Start: l.position(s.Start), End: l.position(s.End)}
}
