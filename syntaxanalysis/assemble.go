package syntaxanalysis

import (
	"slices"
	"sort"
	"unicode/utf8"
)

// definitionRank orders kinds when two records claim the same name: the
// more specific kind wins.
func definitionRank(k DefinitionKind) int {
	switch k {
	case KindVariable:
		return 0
	case KindField:
		return 1
	case KindConstant:
		return 2
	default:
		return 3
	}
}

// Assemble validates raw records against the source and builds the
// FileAnalysis. It is shared by every analyzer so that the same trust rules
// apply to all of them:
//
//   - a span outside the source, or a name of a definition or an import
//     outside its node, makes the whole result untrustworthy, so the
//     records are dropped and the file gets an analysis_failed gap;
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
	if !validRaw(raw, len(source.content)) {
		return WholeFileGap(source, analyzer, GapAnalysisFailed, "")
	}
	b := &builder{content: source.content, lines: NewLineIndex(source.content), limits: limits, budget: limits.MaxRecords, firstDropped: -1}
	merged, byName := b.mergeDefinitions(raw.Definitions)
	definitions := b.definitionTree(merged)
	markExportList(b, definitions, raw.Exports)
	imports := b.imports(raw.Imports, definitions)
	references := b.references(raw.References, byName, definitions)
	return FileAnalysis{
		Path: source.path, Language: source.language, ContentSHA256: source.digest, Analyzer: analyzer,
		Definitions: definitions, References: references, Imports: imports, Gaps: b.allGaps(raw.Gaps),
	}
}

// ExportThroughOwners applies the rule of Definition.Exported to flags that
// hold each definition's own visibility: a definition whose parent is not
// exported is not exported. An analyzer applies it after Assemble and after
// any rule of its own that sets the flags.
func ExportThroughOwners(a *FileAnalysis) {
	for i := range a.Definitions {
		if p := a.Definitions[i].Parent; p >= 0 && p < i && !a.Definitions[p].Exported {
			a.Definitions[i].Exported = false
		}
	}
}

// validRaw checks every span against the source and the name, alias and
// container of a definition or import against its node.
func validRaw(raw RawFile, size int) bool {
	inBounds := func(s Span) bool { return s.Start >= 0 && s.End >= s.Start && s.End <= size }
	part := func(node, s Span) bool { return inBounds(s) && (s.Empty() || node.Contains(s)) }
	for _, d := range raw.Definitions {
		if !d.Kind.Valid() || !inBounds(d.Node) || !part(d.Node, d.Name) || !part(d.Node, d.Container) {
			return false
		}
	}
	for _, r := range raw.References {
		if !r.Kind.Valid() || !inBounds(r.Name) || !inBounds(r.Qualifier) {
			return false
		}
	}
	for _, i := range raw.Imports {
		if !inBounds(i.Node) || !part(i.Node, i.Name) || !part(i.Node, i.Alias) || !inBounds(i.Source) {
			return false
		}
	}
	for _, g := range raw.Gaps {
		if !inBounds(g.Span) {
			return false
		}
	}
	for _, e := range raw.Exports {
		if !inBounds(e) {
			return false
		}
	}
	return true
}

// builder holds what the assembly steps share: the source, its line index,
// the record budget and the gaps found so far.
type builder struct {
	content      []byte
	lines        LineIndex
	limits       Limits
	gaps         []RawGap
	budget       int
	firstDropped int
}

// text returns the span's text, or ok=false after recording a gap.
func (b *builder) text(s Span) (string, bool) {
	value := b.content[s.Start:s.End]
	if s.End-s.Start > b.limits.MaxNameBytes {
		b.gaps = append(b.gaps, RawGap{Reason: GapLimitExceeded, Limit: LimitNameLength, Span: s})
		return "", false
	}
	if !utf8.Valid(value) {
		b.gaps = append(b.gaps, RawGap{Reason: GapInvalidText, Span: s})
		return "", false
	}
	return string(value), true
}

func (b *builder) optional(s Span) (Text, bool) {
	if s.Empty() {
		return Text{}, true
	}
	value, ok := b.text(s)
	return newText(value), ok
}

func (b *builder) drop(at int) {
	if b.firstDropped < 0 || at < b.firstDropped {
		b.firstDropped = at
	}
}

type pendingDefinition struct {
	raw  RawDefinition
	name string
}

// mergeDefinitions joins the definitions that share a name span and sorts
// them by node, outer nodes first.
func (b *builder) mergeDefinitions(raw []RawDefinition) ([]pendingDefinition, map[Span]int) {
	byName := map[Span]int{}
	merged := []pendingDefinition{}
	for _, d := range raw {
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
		merged = append(merged, pendingDefinition{raw: d})
	}
	kept := merged[:0]
	for _, p := range merged {
		if name, ok := b.text(p.raw.Name); ok {
			p.name = name
			kept = append(kept, p)
		}
	}
	slices.SortStableFunc(kept, func(x, y pendingDefinition) int {
		if x.raw.Node.Start != y.raw.Node.Start {
			return x.raw.Node.Start - y.raw.Node.Start
		}
		if x.raw.Node.End != y.raw.Node.End {
			return y.raw.Node.End - x.raw.Node.End
		}
		return x.raw.Name.Start - y.raw.Name.Start
	})
	return kept, byName
}

// definitionTree gives each definition the innermost definition whose node
// contains its own as its parent, within the record budget.
func (b *builder) definitionTree(merged []pendingDefinition) []Definition {
	definitions := make([]Definition, 0, len(merged))
	stack := []int{}
	for _, p := range merged {
		if len(definitions) >= b.budget {
			b.drop(p.raw.Node.Start)
			break
		}
		container, ok := b.optional(p.raw.Container)
		if !ok {
			continue
		}
		for len(stack) > 0 {
			top := definitions[stack[len(stack)-1]]
			same := p.raw.Node.Start == top.Range.StartByte && p.raw.Node.End == top.Range.EndByte
			if !same && p.raw.Node.Start >= top.Range.StartByte && p.raw.Node.End <= top.Range.EndByte {
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
			Kind: kind, Name: newText(p.name), Container: container,
			Range: b.lines.Range(p.raw.Node), NameRange: b.lines.Range(p.raw.Name),
			Parent: parent, Exported: p.raw.Exported,
		})
		stack = append(stack, len(definitions)-1)
	}
	b.budget -= len(definitions)
	return definitions
}

// markExportList exports the top-level definitions an export clause names.
func markExportList(b *builder, definitions []Definition, exports []Span) {
	if len(exports) == 0 {
		return
	}
	exported := map[string]bool{}
	for _, e := range exports {
		if value, ok := b.text(e); ok {
			exported[value] = true
		}
	}
	for i := range definitions {
		if definitions[i].Parent < 0 && exported[definitions[i].Name.Untrusted()] {
			definitions[i].Exported = true
		}
	}
}

// imports drops repeated imports and an import that another one of the
// same statement and source describes more completely.
func (b *builder) imports(raw []RawImport, definitions []Definition) []Import {
	sorted := slices.Clone(raw)
	slices.SortStableFunc(sorted, func(x, y RawImport) int {
		if x.Node.Start != y.Node.Start {
			return x.Node.Start - y.Node.Start
		}
		return x.Source.Start - y.Source.Start
	})
	groups := map[[2]Span][]RawImport{}
	for _, i := range sorted {
		key := [2]Span{i.Node, i.Source}
		groups[key] = append(groups[key], i)
	}
	imports := []Import{}
	seen := map[RawImport]bool{}
	for _, i := range sorted {
		if i.Source.Empty() || seen[i] || subsumed(groups[[2]Span{i.Node, i.Source}], i) {
			continue
		}
		seen[i] = true
		if len(imports) >= b.budget {
			b.drop(i.Node.Start)
			break
		}
		sourceText, ok := b.text(i.Source)
		if !ok {
			continue
		}
		name, ok := b.optional(i.Name)
		if !ok {
			continue
		}
		alias, ok := b.optional(i.Alias)
		if !ok {
			continue
		}
		node := i.Node
		if node.Empty() {
			node = i.Source
		}
		imports = append(imports, Import{
			Source: newText(sourceText), Name: name, Alias: alias,
			Range: b.lines.Range(node), Enclosing: enclosing(definitions, node.Start),
		})
	}
	b.budget -= len(imports)
	return imports
}

// subsumed reports whether another import of the same node and source, one
// of group, says everything i says and more, as when a pattern for a bare
// import and a pattern for its named members both match one statement.
func subsumed(group []RawImport, i RawImport) bool {
	fields := func(r RawImport) int {
		n := 0
		if !r.Name.Empty() {
			n++
		}
		if !r.Alias.Empty() {
			n++
		}
		return n
	}
	for _, other := range group {
		if fields(other) <= fields(i) {
			continue
		}
		if (i.Name.Empty() || i.Name == other.Name) && (i.Alias.Empty() || i.Alias == other.Alias) {
			return true
		}
	}
	return false
}

// references drops repeated references, a name already recorded with a
// qualifier when it comes again without one, and the names of definitions.
func (b *builder) references(raw []RawReference, definitionNames map[Span]int, definitions []Definition) []Reference {
	sorted := slices.Clone(raw)
	slices.SortStableFunc(sorted, func(x, y RawReference) int {
		if x.Name.Start != y.Name.Start {
			return x.Name.Start - y.Name.Start
		}
		return x.Name.End - y.Name.End
	})
	type key struct {
		kind ReferenceKind
		name Span
	}
	qualified := map[key]bool{}
	for _, r := range sorted {
		if !r.Qualifier.Empty() {
			qualified[key{r.Kind, r.Name}] = true
		}
	}
	seen := map[key]bool{}
	references := []Reference{}
	for _, r := range sorted {
		k := key{r.Kind, r.Name}
		if r.Name.Empty() || seen[k] || (r.Qualifier.Empty() && qualified[k]) {
			continue
		}
		if _, isDefinition := definitionNames[r.Name]; isDefinition {
			continue
		}
		seen[k] = true
		if len(references) >= b.budget {
			b.drop(r.Name.Start)
			break
		}
		name, ok := b.text(r.Name)
		if !ok {
			continue
		}
		// An over-long or undecodable qualifier is left out with its gap;
		// the call site itself is still recorded.
		qualifier, _ := b.optional(r.Qualifier)
		references = append(references, Reference{
			Kind: r.Kind, Name: newText(name), Qualifier: qualifier,
			Range: b.lines.Range(r.Name), Enclosing: enclosing(definitions, r.Name.Start),
		})
	}
	return references
}

// allGaps merges the parse-error regions, bounds their count, adds the
// gaps found while assembling and sorts the result.
func (b *builder) allGaps(raw []RawGap) []Gap {
	size := len(b.content)
	gaps := b.gaps
	if b.firstDropped >= 0 {
		gaps = append(gaps, RawGap{Reason: GapLimitExceeded, Limit: LimitRecords, Span: Span{Start: b.firstDropped, End: size}})
	}
	regions := []Span{}
	for _, g := range raw {
		switch {
		case g.Reason != GapParseError:
			gaps = append(gaps, g)
		case g.Span.Empty():
			regions = append(regions, pointSpan(g.Span.Start, size))
		default:
			regions = append(regions, g.Span)
		}
	}
	slices.SortFunc(regions, func(x, y Span) int {
		if x.Start != y.Start {
			return x.Start - y.Start
		}
		return x.End - y.End
	})
	merged := []Span{}
	for _, r := range regions {
		if n := len(merged); n > 0 && r.Start <= merged[n-1].End {
			merged[n-1].End = max(merged[n-1].End, r.End)
			continue
		}
		merged = append(merged, r)
	}
	if len(merged) > b.limits.MaxErrorRegions {
		rest := merged[b.limits.MaxErrorRegions]
		merged = merged[:b.limits.MaxErrorRegions]
		gaps = append(gaps, RawGap{Reason: GapLimitExceeded, Limit: LimitErrorRegions, Span: Span{Start: rest.Start, End: size}})
	}
	for _, r := range merged {
		gaps = append(gaps, RawGap{Reason: GapParseError, Span: r})
	}
	out := make([]Gap, 0, len(gaps))
	seen := map[RawGap]bool{}
	for _, g := range gaps {
		if seen[g] {
			continue
		}
		seen[g] = true
		gap := Gap{Reason: g.Reason, Limit: g.Limit}
		if !g.Span.Empty() {
			gap.HasRange = true
			gap.Range = b.lines.Range(g.Span)
		}
		out = append(out, gap)
	}
	slices.SortStableFunc(out, func(x, y Gap) int {
		if x.HasRange != y.HasRange {
			if !x.HasRange {
				return -1
			}
			return 1
		}
		if x.Range.StartByte != y.Range.StartByte {
			return x.Range.StartByte - y.Range.StartByte
		}
		if x.Reason != y.Reason {
			if x.Reason < y.Reason {
				return -1
			}
			return 1
		}
		return x.Range.EndByte - y.Range.EndByte
	})
	return out
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
// definitions are sorted by start and nested, so the candidates are the
// last definition starting at or before the offset and the definitions
// around it. Those are its parents, except around an owned definition (see
// owned), where the definition it is written in comes first.
func enclosing(definitions []Definition, offset int) int {
	i := sort.Search(len(definitions), func(i int) bool { return definitions[i].Range.StartByte > offset }) - 1
	for depth := 0; i >= 0 && depth <= len(definitions); depth++ {
		if definitions[i].Range.Contains(offset) {
			return i
		}
		next := definitions[i].Parent
		if owned(definitions, i) {
			// Skip the owned definitions written next to it; the one
			// before them may be the definition they are written in.
			k := i - 1
			for k > next && owned(definitions, k) && definitions[k].Parent == next {
				k--
			}
			if k > next && definitions[k].Range.Contains(definitions[i].Range.StartByte) {
				next = k
			}
		}
		i = next
	}
	return -1
}

// owned reports whether a definition belongs to its parent, which it names
// as its container, although it may be written inside another definition,
// such as a property declared in a constructor's parameter list.
func owned(definitions []Definition, i int) bool {
	p := definitions[i].Parent
	return p >= 0 && p < i && !definitions[i].Container.Empty() && definitions[i].Container.Untrusted() == definitions[p].Name.Untrusted()
}
