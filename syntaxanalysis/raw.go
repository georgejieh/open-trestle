package syntaxanalysis

// Span is a half-open byte range of the source. An empty span marks an
// absent optional part, such as a missing alias.
type Span struct{ Start, End int }

// Empty reports whether the span covers no bytes.
func (s Span) Empty() bool { return s.End <= s.Start }

// Contains reports whether other lies within s.
func (s Span) Contains(other Span) bool { return s.Start <= other.Start && other.End <= s.End }

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
