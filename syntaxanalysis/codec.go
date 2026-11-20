package syntaxanalysis

import (
	"encoding/hex"
	"slices"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/varcodec"
)

// binaryVersion is the version of the binary record encoding.
const binaryVersion = 1

// The codes of the binary encoding are positions in these lists; a value is
// only ever appended.
var (
	definitionKindCodes = []DefinitionKind{KindFunction, KindMethod, KindConstructor, KindClass, KindStruct, KindInterface, KindEnum, KindType, KindModule, KindConstant, KindVariable, KindField, KindMacro}
	referenceKindCodes  = []ReferenceKind{ReferenceCall, ReferenceConstruct, ReferenceType, ReferenceInherit, ReferenceDecorator, ReferenceValue}
	gapReasonCodes      = []GapReason{GapUnsupportedLanguage, GapNoQueryPack, GapAnalysisUnavailable, GapAnalysisFailed, GapParseError, GapInvalidText, GapLimitExceeded, GapDeadlineExceeded}
	limitCodes          = []Limit{"", LimitFileSize, LimitRecords, LimitNameLength, LimitErrorRegions, LimitMatches, LimitMemory}
)

// EncodeBinary encodes an analysis without its path in a compact binary
// form: each distinct name is written once, and records refer to it. The
// analysis must be valid, as an analyzer returns it.
func EncodeBinary(a FileAnalysis) ([]byte, error) {
	digest, err := hex.DecodeString(a.ContentSHA256)
	if err != nil || len(digest) != 32 || !a.Language.Valid() {
		return nil, ErrInvalidInput
	}
	strings := map[string]uint64{}
	table := []string{}
	ref := func(t Text) uint64 {
		v := t.Untrusted()
		if v == "" {
			return 0
		}
		if i, ok := strings[v]; ok {
			return i
		}
		table = append(table, v)
		strings[v] = uint64(len(table))
		return uint64(len(table))
	}
	body := []byte{}
	body = varcodec.AppendUvarint(body, uint64(len(a.Definitions)))
	for _, d := range a.Definitions {
		code := slices.Index(definitionKindCodes, d.Kind)
		if code < 0 || d.Parent < -1 {
			return nil, ErrInvalidInput
		}
		body = append(body, byte(code))
		body = varcodec.AppendUvarint(body, ref(d.Name))
		body = varcodec.AppendUvarint(body, ref(d.Container))
		body = appendRange(body, d.Range)
		body = appendRange(body, d.NameRange)
		body = varcodec.AppendUvarint(body, uint64(d.Parent+1))
		body = varcodec.AppendBool(body, d.Exported)
	}
	body = varcodec.AppendUvarint(body, uint64(len(a.References)))
	for _, r := range a.References {
		code := slices.Index(referenceKindCodes, r.Kind)
		if code < 0 || r.Enclosing < -1 {
			return nil, ErrInvalidInput
		}
		body = append(body, byte(code))
		body = varcodec.AppendUvarint(body, ref(r.Name))
		body = varcodec.AppendUvarint(body, ref(r.Qualifier))
		body = appendRange(body, r.Range)
		body = varcodec.AppendUvarint(body, uint64(r.Enclosing+1))
	}
	body = varcodec.AppendUvarint(body, uint64(len(a.Imports)))
	for _, i := range a.Imports {
		if i.Enclosing < -1 {
			return nil, ErrInvalidInput
		}
		body = varcodec.AppendUvarint(body, ref(i.Source))
		body = varcodec.AppendUvarint(body, ref(i.Name))
		body = varcodec.AppendUvarint(body, ref(i.Alias))
		body = appendRange(body, i.Range)
		body = varcodec.AppendUvarint(body, uint64(i.Enclosing+1))
	}
	body = varcodec.AppendUvarint(body, uint64(len(a.Gaps)))
	for _, g := range a.Gaps {
		reason, limit := slices.Index(gapReasonCodes, g.Reason), slices.Index(limitCodes, g.Limit)
		if reason < 0 || limit < 0 {
			return nil, ErrInvalidInput
		}
		body = append(body, byte(reason), byte(limit))
		body = varcodec.AppendBool(body, g.HasRange)
		if g.HasRange {
			body = appendRange(body, g.Range)
		}
	}
	out := varcodec.AppendUvarint(nil, binaryVersion)
	out = varcodec.AppendString(out, string(a.Language))
	out = varcodec.AppendString(out, a.Analyzer)
	out = append(out, digest...)
	out = varcodec.AppendUvarint(out, uint64(len(table)))
	for _, s := range table {
		out = varcodec.AppendString(out, s)
	}
	return append(out, body...), nil
}

func appendRange(dst []byte, r Range) []byte {
	dst = varcodec.AppendUvarint(dst, uint64(r.StartByte))
	dst = varcodec.AppendUvarint(dst, uint64(r.EndByte-r.StartByte))
	dst = varcodec.AppendUvarint(dst, uint64(r.Start.Line))
	dst = varcodec.AppendUvarint(dst, uint64(r.Start.Column))
	dst = varcodec.AppendUvarint(dst, uint64(r.End.Line-r.Start.Line))
	return varcodec.AppendUvarint(dst, uint64(r.End.Column))
}

// maxEncodedOffset bounds every decoded offset, line and column, well above
// the largest file an analyzer accepts.
const maxEncodedOffset = 1 << 30

func readRange(r *varcodec.Reader) Range {
	var out Range
	out.StartByte = r.Int(maxEncodedOffset)
	out.EndByte = out.StartByte + r.Int(maxEncodedOffset)
	out.Start = Position{Line: r.Int(maxEncodedOffset), Column: r.Int(maxEncodedOffset)}
	out.End = Position{Line: out.Start.Line + r.Int(maxEncodedOffset), Column: r.Int(maxEncodedOffset)}
	return out
}

// maxAnalyzerNameBytes bounds the analyzer identity of a decoded analysis.
const maxAnalyzerNameBytes = 256

// DecodeBinary decodes an EncodeBinary result and gives it the path. It
// checks every code, index and name, so a malformed or hostile encoding is
// an error and never a partial analysis. It also refuses more records,
// gaps, names or name bytes than an analyzer with these limits produces,
// before it allocates them. Records that share a name share one Text value.
func DecodeBinary(data []byte, filePath string, limits Limits) (FileAnalysis, error) {
	r := varcodec.NewReader(data)
	if r.Uvarint() != binaryVersion || !validPath(filePath) || !limits.Valid() {
		return FileAnalysis{}, ErrInvalidInput
	}
	records := limits.MaxRecords
	// count reads an element count and charges it to a budget.
	count := func(minBytes int, budget *int) int {
		n := r.Count(minBytes)
		if n > *budget {
			r.Fail()
			return 0
		}
		*budget -= n
		return n
	}
	a := FileAnalysis{Path: filePath, Language: Language(r.String())}
	if analyzer := r.Bytes(); len(analyzer) <= maxAnalyzerNameBytes {
		a.Analyzer = string(analyzer)
	}
	digest := r.Fixed(32)
	a.ContentSHA256 = hex.EncodeToString(digest)
	names := 3 * limits.MaxRecords
	texts := make([]Text, count(2, &names)+1)
	for i := 1; i < len(texts); i++ {
		v := r.Bytes()
		if len(v) == 0 || len(v) > limits.MaxNameBytes || !utf8.Valid(v) {
			return FileAnalysis{}, ErrInvalidInput
		}
		texts[i] = newText(string(v))
	}
	text := func(required bool) Text {
		i := r.Int(len(texts) - 1)
		if required && i == 0 {
			r.Fail()
		}
		return texts[i]
	}
	code := func(n int) int {
		c := int(r.Byte())
		if c >= n {
			r.Fail()
			return 0
		}
		return c
	}
	a.Definitions = make([]Definition, count(16, &records))
	for i := range a.Definitions {
		d := &a.Definitions[i]
		d.Kind = definitionKindCodes[code(len(definitionKindCodes))]
		d.Name, d.Container = text(true), text(false)
		d.Range, d.NameRange = readRange(r), readRange(r)
		d.Parent = r.Int(i) - 1
		d.Exported = r.Bool()
	}
	a.References = make([]Reference, count(10, &records))
	for i := range a.References {
		ref := &a.References[i]
		ref.Kind = referenceKindCodes[code(len(referenceKindCodes))]
		ref.Name, ref.Qualifier = text(true), text(false)
		ref.Range = readRange(r)
		ref.Enclosing = r.Int(len(a.Definitions)) - 1
	}
	a.Imports = make([]Import, count(10, &records))
	for i := range a.Imports {
		imp := &a.Imports[i]
		imp.Source, imp.Name, imp.Alias = text(true), text(false), text(false)
		imp.Range = readRange(r)
		imp.Enclosing = r.Int(len(a.Definitions)) - 1
	}
	// Every dropped name and every error region can make a gap.
	gaps := 2*limits.MaxRecords + limits.MaxErrorRegions + 16
	a.Gaps = make([]Gap, count(3, &gaps))
	for i := range a.Gaps {
		g := &a.Gaps[i]
		g.Reason = gapReasonCodes[code(len(gapReasonCodes))]
		g.Limit = limitCodes[code(len(limitCodes))]
		if g.HasRange = r.Bool(); g.HasRange {
			g.Range = readRange(r)
		}
	}
	if r.Done() != nil || !a.Language.Valid() || a.Analyzer == "" || !utf8.ValidString(a.Analyzer) {
		return FileAnalysis{}, ErrInvalidInput
	}
	return a, nil
}
