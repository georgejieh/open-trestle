// Package syntaxanalysis defines the language-neutral record model that every
// per-file syntax analyzer produces: definitions, references and call sites,
// imports, and coverage gaps for one source file.
//
// Every name, qualifier and import path in the model is repository text. It
// is untrusted data, carried as a Text value that prints as a placeholder.
// Consumers read it with Text.Untrusted and must present it as quoted data,
// never as part of an instruction.
package syntaxanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// ErrInvalidInput reports a source or record that violates the model's
// structural rules. It is a caller error, not an analysis failure.
var ErrInvalidInput = errors.New("invalid syntax analysis input")

// Language names a source language. Values are stable identifiers, not
// display names.
type Language string

const (
	LanguageGo         Language = "go"
	LanguageJava       Language = "java"
	LanguageJavaScript Language = "javascript"
	LanguageTypeScript Language = "typescript"
	LanguageTSX        Language = "tsx"
	LanguagePython     Language = "python"
	LanguageC          Language = "c"
	LanguageCPP        Language = "cpp"
	LanguageCSharp     Language = "csharp"
	LanguageSwift      Language = "swift"
	LanguageRust       Language = "rust"
	LanguagePHP        Language = "php"
	LanguageRuby       Language = "ruby"
	LanguageHTML       Language = "html"
)

var extensionLanguages = map[string]Language{
	".go":    LanguageGo,
	".java":  LanguageJava,
	".js":    LanguageJavaScript,
	".mjs":   LanguageJavaScript,
	".cjs":   LanguageJavaScript,
	".jsx":   LanguageJavaScript,
	".ts":    LanguageTypeScript,
	".mts":   LanguageTypeScript,
	".cts":   LanguageTypeScript,
	".tsx":   LanguageTSX,
	".py":    LanguagePython,
	".pyi":   LanguagePython,
	".c":     LanguageC,
	".h":     LanguageC,
	".cc":    LanguageCPP,
	".cpp":   LanguageCPP,
	".cxx":   LanguageCPP,
	".hh":    LanguageCPP,
	".hpp":   LanguageCPP,
	".hxx":   LanguageCPP,
	".cs":    LanguageCSharp,
	".swift": LanguageSwift,
	".rs":    LanguageRust,
	".php":   LanguagePHP,
	".rb":    LanguageRuby,
	".html":  LanguageHTML,
	".htm":   LanguageHTML,
}

// LanguageForPath maps a file name extension to a language. TypeScript
// declaration files (.d.ts) map to TypeScript through their final extension.
func LanguageForPath(filePath string) (Language, bool) {
	language, ok := extensionLanguages[strings.ToLower(path.Ext(filePath))]
	return language, ok
}

// Valid reports whether the language is one of the declared constants.
func (l Language) Valid() bool {
	for _, known := range extensionLanguages {
		if known == l {
			return true
		}
	}
	return false
}

// Text is untrusted text copied from the repository, such as an identifier
// or an import path. It formats as a placeholder so that it cannot reach a
// log line or a prompt by accident; Untrusted returns the value itself. The
// value sits behind a pointer so that even the fmt verbs that bypass Format,
// %p and %T, print an address or the type name rather than the text.
type Text struct{ value *string }

func newText(value string) Text {
	if value == "" {
		return Text{}
	}
	return Text{value: &value}
}

// Untrusted returns the repository text. The caller must treat it as data.
func (t Text) Untrusted() string {
	if t.value == nil {
		return ""
	}
	return *t.value
}

// Empty reports whether the text is absent.
func (t Text) Empty() bool { return t.value == nil || *t.value == "" }

func (t Text) String() string   { return "repository text" }
func (t Text) GoString() string { return "syntaxanalysis.Text{<untrusted>}" }

// Format keeps every fmt verb from printing the repository text.
func (t Text) Format(s fmt.State, verb rune) {
	value := "repository text"
	if verb == 'v' && s.Flag('#') {
		value = "syntaxanalysis.Text{<untrusted>}"
	}
	_, _ = s.Write([]byte(value))
}

// MarshalJSON encodes the text as a JSON string, which is a data encoding.
func (t Text) MarshalJSON() ([]byte, error) { return json.Marshal(t.Untrusted()) }

// UnmarshalJSON decodes a JSON string and requires valid UTF-8.
func (t *Text) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	if !utf8.ValidString(value) {
		return ErrInvalidInput
	}
	*t = newText(value)
	return nil
}

// Position is a 1-based line and a 1-based byte column within that line.
type Position struct {
	Line   int `json:"line"`
	Column int `json:"column"`
}

// Range is a half-open byte range of the source with its line and column
// positions. End is the position of the first byte after the range.
type Range struct {
	StartByte int      `json:"start_byte"`
	EndByte   int      `json:"end_byte"`
	Start     Position `json:"start"`
	End       Position `json:"end"`
}

// Contains reports whether the byte offset lies inside the range.
func (r Range) Contains(offset int) bool { return offset >= r.StartByte && offset < r.EndByte }

// DefinitionKind classifies a definition.
type DefinitionKind string

const (
	KindFunction    DefinitionKind = "function"
	KindMethod      DefinitionKind = "method"
	KindConstructor DefinitionKind = "constructor"
	KindClass       DefinitionKind = "class"
	KindStruct      DefinitionKind = "struct"
	KindInterface   DefinitionKind = "interface"
	KindEnum        DefinitionKind = "enum"
	KindType        DefinitionKind = "type"
	KindModule      DefinitionKind = "module"
	KindConstant    DefinitionKind = "constant"
	KindVariable    DefinitionKind = "variable"
	KindField       DefinitionKind = "field"
	KindMacro       DefinitionKind = "macro"
)

var definitionKinds = map[DefinitionKind]bool{
	KindFunction: true, KindMethod: true, KindConstructor: true, KindClass: true,
	KindStruct: true, KindInterface: true, KindEnum: true, KindType: true,
	KindModule: true, KindConstant: true, KindVariable: true, KindField: true,
	KindMacro: true,
}

// Valid reports whether the kind is one of the declared constants.
func (k DefinitionKind) Valid() bool { return definitionKinds[k] }

// Container reports whether definitions of this kind hold members, so that a
// function directly inside one is a method.
func (k DefinitionKind) Container() bool {
	switch k {
	case KindClass, KindStruct, KindInterface, KindEnum:
		return true
	}
	return false
}

// ReferenceKind classifies a reference.
type ReferenceKind string

const (
	// ReferenceCall is a call site; Name is the called name.
	ReferenceCall ReferenceKind = "call"
	// ReferenceConstruct is an object construction such as `new T()`.
	ReferenceConstruct ReferenceKind = "construct"
	// ReferenceType is a use of a name in a type position.
	ReferenceType ReferenceKind = "type"
	// ReferenceInherit is a base class, implemented interface or embedded type.
	ReferenceInherit ReferenceKind = "inherit"
	// ReferenceDecorator is a decorator or annotation application.
	ReferenceDecorator ReferenceKind = "decorator"
)

var referenceKinds = map[ReferenceKind]bool{
	ReferenceCall: true, ReferenceConstruct: true, ReferenceType: true,
	ReferenceInherit: true, ReferenceDecorator: true,
}

// Valid reports whether the kind is one of the declared constants.
func (k ReferenceKind) Valid() bool { return referenceKinds[k] }

// Definition is a named definition. Parent is the index in
// FileAnalysis.Definitions of the innermost definition that lexically
// contains this one, or -1 at the top level.
type Definition struct {
	Kind DefinitionKind `json:"kind"`
	Name Text           `json:"name"`
	// Container names the declared owner when it is not the lexical parent,
	// such as the receiver type of a Go method.
	Container Text  `json:"container,omitzero"`
	Range     Range `json:"range"`
	NameRange Range `json:"name_range"`
	Parent    int   `json:"parent"`
	// Exported reports whether the language's syntax makes the definition
	// visible outside its file or module: a capitalised Go name, a Java or
	// C#-style public modifier, a JavaScript export, or a Python name without
	// a leading underscore at module or class level.
	Exported bool `json:"exported"`
}

// Reference is a use of a name. Enclosing is the index of the innermost
// definition containing the reference, or -1 at the top level. References are
// syntactic candidates: the name is not resolved to a definition.
type Reference struct {
	Kind ReferenceKind `json:"kind"`
	Name Text          `json:"name"`
	// Qualifier is the expression before the name, such as the receiver of
	// a method call, when the syntax has one.
	Qualifier Text  `json:"qualifier,omitzero"`
	Range     Range `json:"range"`
	Enclosing int   `json:"enclosing"`
}

// Import is one imported module or binding. Source is the module, package
// or path as written. Name is the imported member for member imports, and
// Alias is the local name when the import renames it.
type Import struct {
	Source    Text  `json:"source"`
	Name      Text  `json:"name,omitzero"`
	Alias     Text  `json:"alias,omitzero"`
	Range     Range `json:"range"`
	Enclosing int   `json:"enclosing"`
}

// GapReason says why part or all of a file is not covered.
type GapReason string

const (
	// GapUnsupportedLanguage: no analyzer exists for the language.
	GapUnsupportedLanguage GapReason = "unsupported_language"
	// GapNoQueryPack: a grammar is available but no query pack is written.
	GapNoQueryPack GapReason = "no_query_pack"
	// GapAnalysisUnavailable: the analyzer cannot run on this platform or
	// could not load its module.
	GapAnalysisUnavailable GapReason = "analysis_unavailable"
	// GapAnalysisFailed: the analyzer failed for this file, for example
	// because the parser trapped or returned a malformed result.
	GapAnalysisFailed GapReason = "analysis_failed"
	// GapParseError: the region did not parse; records inside it are
	// missing or unreliable.
	GapParseError GapReason = "parse_error"
	// GapInvalidText: a name in the region is not valid UTF-8 and was left
	// out.
	GapInvalidText GapReason = "invalid_text"
	// GapLimitExceeded: a resource limit was reached; Limit says which.
	GapLimitExceeded GapReason = "limit_exceeded"
	// GapDeadlineExceeded: the per-file deadline stopped the analysis.
	GapDeadlineExceeded GapReason = "deadline_exceeded"
)

// Limit names the resource limit behind a GapLimitExceeded gap.
type Limit string

const (
	LimitFileSize     Limit = "file_size"
	LimitRecords      Limit = "records"
	LimitNameLength   Limit = "name_length"
	LimitErrorRegions Limit = "error_regions"
	LimitMatches      Limit = "matches"
	LimitMemory       Limit = "memory"
)

// Gap is a coverage gap. A gap without a range covers the whole file, or,
// for limits, everything the analyzer did not reach.
type Gap struct {
	Reason   GapReason `json:"reason"`
	Limit    Limit     `json:"limit,omitempty"`
	HasRange bool      `json:"has_range"`
	Range    Range     `json:"range,omitzero"`
}

// FileAnalysis is the analysis of one file. Records are ordered by source
// position. A FileAnalysis with no gaps is complete for the analyzer's
// query pack; records are syntactic and unresolved either way.
type FileAnalysis struct {
	Path          string       `json:"path"`
	Language      Language     `json:"language"`
	ContentSHA256 string       `json:"content_sha256"`
	Analyzer      string       `json:"analyzer"`
	Definitions   []Definition `json:"definitions"`
	References    []Reference  `json:"references"`
	Imports       []Import     `json:"imports"`
	Gaps          []Gap        `json:"gaps"`
}

// Complete reports whether the analysis has no coverage gap.
func (a FileAnalysis) Complete() bool { return len(a.Gaps) == 0 }

// EnclosingDefinition returns the index of the innermost definition whose
// range contains the byte offset, or -1.
func (a FileAnalysis) EnclosingDefinition(offset int) int {
	return enclosing(a.Definitions, offset)
}

// QualifiedName joins the names of a definition and its lexical parents
// with dots, outermost first. The result is repository text.
func (a FileAnalysis) QualifiedName(index int) Text {
	if index < 0 || index >= len(a.Definitions) {
		return Text{}
	}
	parts := []string{}
	for i, depth := index, 0; i >= 0 && i < len(a.Definitions) && depth <= len(a.Definitions); i, depth = a.Definitions[i].Parent, depth+1 {
		parts = append(parts, a.Definitions[i].Name.Untrusted())
	}
	for l, r := 0, len(parts)-1; l < r; l, r = l+1, r-1 {
		parts[l], parts[r] = parts[r], parts[l]
	}
	return newText(strings.Join(parts, "."))
}

// Source is one file to analyze.
type Source struct {
	path     string
	language Language
	content  []byte
	digest   string
}

// NewSource validates the path and language and copies the content.
func NewSource(filePath string, language Language, content []byte) (Source, error) {
	if !validPath(filePath) || !language.Valid() {
		return Source{}, ErrInvalidInput
	}
	sum := sha256.Sum256(content)
	return Source{path: filePath, language: language, content: append([]byte(nil), content...), digest: hex.EncodeToString(sum[:])}, nil
}

func (s Source) Path() string       { return s.path }
func (s Source) Language() Language { return s.language }
func (s Source) Size() int          { return len(s.content) }
func (s Source) SHA256() string     { return s.digest }

// Content returns a copy of the source bytes.
func (s Source) Content() []byte { return append([]byte(nil), s.content...) }

func (s Source) String() string   { return "syntax analysis source" }
func (s Source) GoString() string { return "syntaxanalysis.Source{<redacted>}" }
func (s Source) Format(f fmt.State, verb rune) {
	value := "syntax analysis source"
	if verb == 'v' && f.Flag('#') {
		value = "syntaxanalysis.Source{<redacted>}"
	}
	_, _ = f.Write([]byte(value))
}

func validPath(v string) bool {
	return v != "" && len(v) <= 4096 && utf8.ValidString(v) && !strings.ContainsFunc(v, unicode.IsControl) && !strings.HasPrefix(v, "/") && path.Clean(v) == v && v != "." && !strings.HasPrefix(v, "../")
}

// Limits bound the work an analyzer does for one file. Reaching a limit
// produces a GapLimitExceeded or GapDeadlineExceeded gap, never a silent
// truncation.
type Limits struct {
	// MaxFileBytes is the largest file analysed. A larger file gets a
	// whole-file gap.
	MaxFileBytes int
	// MaxRecords bounds definitions, references and imports together.
	MaxRecords int
	// MaxNameBytes bounds each name, qualifier and import path.
	MaxNameBytes int
	// MaxErrorRegions bounds the parse-error gaps reported.
	MaxErrorRegions int
	// FileDeadline bounds the time spent on one file.
	FileDeadline time.Duration
}

// DefaultLimits returns the limits analyzers use unless configured.
func DefaultLimits() Limits {
	return Limits{MaxFileBytes: 2 << 20, MaxRecords: 65536, MaxNameBytes: 1024, MaxErrorRegions: 256, FileDeadline: 5 * time.Second}
}

// Valid reports whether every limit is positive and within the model's
// hard ceilings.
func (l Limits) Valid() bool {
	return l.MaxFileBytes > 0 && l.MaxFileBytes <= 16<<20 &&
		l.MaxRecords > 0 && l.MaxRecords <= 1<<20 &&
		l.MaxNameBytes > 0 && l.MaxNameBytes <= 1<<16 &&
		l.MaxErrorRegions > 0 && l.MaxErrorRegions <= 1<<16 &&
		l.FileDeadline > 0
}

// Analyzer analyses single files. Analyze returns a FileAnalysis whenever the
// source is valid: an analysis failure, a limit or a deadline becomes a gap.
// The error result is reserved for invalid input and for cancellation of
// the caller's context. Implementations are safe for concurrent use.
type Analyzer interface {
	Supports(Language) bool
	Analyze(ctx context.Context, source Source) (FileAnalysis, error)
}

// Dispatcher routes each file to the first analyzer that supports its
// language and reports an unsupported-language gap otherwise.
type Dispatcher struct{ analyzers []Analyzer }

// NewDispatcher returns a dispatcher over the analyzers, in priority order.
func NewDispatcher(analyzers ...Analyzer) Dispatcher {
	return Dispatcher{analyzers: append([]Analyzer(nil), analyzers...)}
}

// Supports reports whether any analyzer accepts the language.
func (d Dispatcher) Supports(language Language) bool {
	for _, a := range d.analyzers {
		if a.Supports(language) {
			return true
		}
	}
	return false
}

// Analyze implements Analyzer.
func (d Dispatcher) Analyze(ctx context.Context, source Source) (FileAnalysis, error) {
	if source.path == "" {
		return FileAnalysis{}, ErrInvalidInput
	}
	for _, a := range d.analyzers {
		if a.Supports(source.language) {
			return a.Analyze(ctx, source)
		}
	}
	return WholeFileGap(source, "open-trestle/syntax/none", GapUnsupportedLanguage, ""), nil
}

// WholeFileGap returns an analysis with no records and one whole-file gap.
func WholeFileGap(source Source, analyzer string, reason GapReason, limit Limit) FileAnalysis {
	return FileAnalysis{
		Path: source.path, Language: source.language, ContentSHA256: source.digest, Analyzer: analyzer,
		Definitions: []Definition{}, References: []Reference{}, Imports: []Import{},
		Gaps: []Gap{{Reason: reason, Limit: limit}},
	}
}
