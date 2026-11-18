package syntaxwasm

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// Analyze implements syntaxanalysis.Analyzer. Every analysis failure is a
// coverage gap; the error result is only for an unsupported language and
// for cancellation of ctx.
func (a *Analyzer) Analyze(ctx context.Context, source syntaxanalysis.Source) (syntaxanalysis.FileAnalysis, error) {
	entry, ok := a.languages[source.Language()]
	if !ok || source.Path() == "" {
		return syntaxanalysis.FileAnalysis{}, syntaxanalysis.ErrInvalidInput
	}
	if err := ctx.Err(); err != nil {
		return syntaxanalysis.FileAnalysis{}, err
	}
	gap := func(reason syntaxanalysis.GapReason, limit syntaxanalysis.Limit) (syntaxanalysis.FileAnalysis, error) {
		return syntaxanalysis.WholeFileGap(source, Identity, reason, limit), nil
	}
	switch {
	case entry.pack == nil:
		return gap(syntaxanalysis.GapNoQueryPack, "")
	case a.unavailable || a.isClosed():
		return gap(syntaxanalysis.GapAnalysisUnavailable, "")
	case source.Size() > a.limits.MaxFileBytes:
		return gap(syntaxanalysis.GapLimitExceeded, syntaxanalysis.LimitFileSize)
	}
	content := source.Content()
	p, fail := a.parse(ctx, entry, source.Language(), content, a.limits, syntaxanalysis.Span{})
	if fail != nil {
		if err := ctx.Err(); err != nil {
			return syntaxanalysis.FileAnalysis{}, err
		}
		return gap(fail.reason, fail.limit)
	}
	deadline := p.started.Add(a.limits.FileDeadline)
	if source.Language() == syntaxanalysis.LanguageC && strings.EqualFold(path.Ext(source.Path()), ".h") {
		source, entry, p = a.headerAsCPP(ctx, source, entry, p, deadline)
	}
	analysis, err := a.finishFile(ctx, source, entry, content, p.raw, p.embedded, deadline)
	if err != nil {
		return syntaxanalysis.FileAnalysis{}, err
	}
	return analysis, nil
}

// parse runs one guest analysis under the analyzer's call lock.
func (a *Analyzer) parse(ctx context.Context, entry languageEntry, language syntaxanalysis.Language, content []byte, limits syntaxanalysis.Limits, scope syntaxanalysis.Span) (parsed, *failure) {
	a.calls.RLock()
	defer a.calls.RUnlock()
	if a.isClosed() {
		return parsed{}, &failure{reason: syntaxanalysis.GapAnalysisUnavailable}
	}
	return entry.family.analyze(ctx, language, entry.pack, content, limits, scope)
}

// headerAsCPP decides the language of a .h file. It is C by its name, and
// is analysed and reported as C++ when a C++ parse within the deadline has
// fewer error regions, or as many and more definitions. C reads much C++
// without errors, for example a namespace as a function definition, but
// then finds no definitions in it.
func (a *Analyzer) headerAsCPP(ctx context.Context, source syntaxanalysis.Source, entry languageEntry, c parsed, deadline time.Time) (syntaxanalysis.Source, languageEntry, parsed) {
	cppEntry, ok := a.languages[syntaxanalysis.LanguageCPP]
	limits := a.limits
	limits.FileDeadline = time.Until(deadline)
	if !ok || cppEntry.pack == nil || limits.FileDeadline <= 0 {
		return source, entry, c
	}
	content := source.Content()
	cpp, fail := a.parse(ctx, cppEntry, syntaxanalysis.LanguageCPP, content, limits, syntaxanalysis.Span{})
	cppSource, err := syntaxanalysis.NewSource(source.Path(), syntaxanalysis.LanguageCPP, content)
	if fail != nil || err != nil {
		return source, entry, c
	}
	cErrors, cppErrors := parseErrors(c.raw), parseErrors(cpp.raw)
	if cppErrors < cErrors || cppErrors == cErrors && len(cpp.raw.Definitions) > len(c.raw.Definitions) {
		return cppSource, cppEntry, cpp
	}
	return source, entry, c
}

// finishFile adds the embedded code, assembles the records and applies the
// language's rules, within the file's deadline: past it, the file gets a
// deadline gap. A panic in this host code is an analysis failure of the
// file, not of the process.
func (a *Analyzer) finishFile(ctx context.Context, source syntaxanalysis.Source, entry languageEntry, content []byte, raw syntaxanalysis.RawFile, embedded []embeddedCode, deadline time.Time) (analysis syntaxanalysis.FileAnalysis, err error) {
	defer func() {
		if recover() != nil {
			analysis, err = syntaxanalysis.WholeFileGap(source, Identity, syntaxanalysis.GapAnalysisFailed, ""), nil
		}
	}()
	late := func() bool { return time.Now().After(deadline) }
	overrun := syntaxanalysis.WholeFileGap(source, Identity, syntaxanalysis.GapDeadlineExceeded, "")
	if entry.pack.filter != nil {
		entry.pack.filter(content, &raw)
	}
	for _, e := range embedded {
		if err := a.addEmbedded(ctx, content, e, &raw, deadline); err != nil {
			return syntaxanalysis.FileAnalysis{}, err
		}
	}
	if late() {
		return overrun, nil
	}
	analysis = syntaxanalysis.Assemble(source, Identity, raw, a.limits)
	if late() {
		return overrun, nil
	}
	if !hasGap(analysis, syntaxanalysis.GapAnalysisFailed) {
		if entry.pack.finish != nil {
			entry.pack.finish(content, raw, &analysis)
		}
		syntaxanalysis.ExportThroughOwners(&analysis)
	}
	if late() {
		return overrun, nil
	}
	return analysis, nil
}

// addEmbedded analyses code embedded in a file, such as an inline HTML
// script, with the pack of its language, and adds its records to the
// file's at their offsets in the file. It shares the file's deadline. A
// failure becomes a gap over the embedded code; only cancellation of ctx
// is an error.
func (a *Analyzer) addEmbedded(ctx context.Context, content []byte, e embeddedCode, raw *syntaxanalysis.RawFile, deadline time.Time) error {
	language, ok := htmlScriptLanguage(content[e.tag.Start:e.tag.End])
	entry, known := a.languages[language]
	if !ok || !known || entry.pack == nil || e.code.Empty() {
		return nil
	}
	limits := a.limits
	limits.FileDeadline = time.Until(deadline)
	if limits.FileDeadline <= 0 {
		raw.Gaps = append(raw.Gaps, syntaxanalysis.RawGap{Reason: syntaxanalysis.GapDeadlineExceeded, Span: e.code})
		return nil
	}
	code := content[e.code.Start:e.code.End]
	p, fail := a.parse(ctx, entry, language, code, limits, syntaxanalysis.Span{Start: 0, End: len(code)})
	embedded := p.raw
	if fail != nil {
		if err := ctx.Err(); err != nil {
			return err
		}
		raw.Gaps = append(raw.Gaps, syntaxanalysis.RawGap{Reason: fail.reason, Limit: fail.limit, Span: e.code})
		return nil
	}
	if entry.pack.filter != nil {
		entry.pack.filter(code, &embedded)
	}
	// What an inline script exports, by an export list or an export
	// statement, is its own binding and not the page's, so embedded.Exports
	// and the exported flags are left out.
	at := e.code.Start
	shift := func(s syntaxanalysis.Span) syntaxanalysis.Span {
		if s.Empty() {
			return s
		}
		return syntaxanalysis.Span{Start: s.Start + at, End: s.End + at}
	}
	for _, d := range embedded.Definitions {
		d.Name, d.Node, d.Container, d.Exported = shift(d.Name), shift(d.Node), shift(d.Container), false
		raw.Definitions = append(raw.Definitions, d)
	}
	for _, r := range embedded.References {
		r.Name, r.Qualifier = shift(r.Name), shift(r.Qualifier)
		raw.References = append(raw.References, r)
	}
	for _, i := range embedded.Imports {
		i.Source, i.Name, i.Alias, i.Node = shift(i.Source), shift(i.Name), shift(i.Alias), shift(i.Node)
		raw.Imports = append(raw.Imports, i)
	}
	for _, g := range embedded.Gaps {
		switch {
		case g.Reason == syntaxanalysis.GapParseError:
			// A missing token is a parse error of zero width.
			g.Span = syntaxanalysis.Span{Start: g.Span.Start + at, End: g.Span.End + at}
		case g.Span.Empty():
			g.Span = e.code
		default:
			g.Span = shift(g.Span)
		}
		raw.Gaps = append(raw.Gaps, g)
	}
	return nil
}

func hasGap(a syntaxanalysis.FileAnalysis, reason syntaxanalysis.GapReason) bool {
	for _, g := range a.Gaps {
		if g.Reason == reason {
			return true
		}
	}
	return false
}

func parseErrors(raw syntaxanalysis.RawFile) int {
	n := 0
	for _, g := range raw.Gaps {
		if g.Reason == syntaxanalysis.GapParseError {
			n++
		}
	}
	return n
}
