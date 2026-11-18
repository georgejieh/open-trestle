package syntaxworker

import (
	"context"
	"errors"
	"time"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// exchange is the outcome of one request: an analysis that passed
// checkAnswer, or why there is none.
type exchange struct {
	analysis  syntaxanalysis.FileAnalysis
	abandoned bool
	// err is a failed write or read of a frame; rejected is an answer that
	// does not describe the file that was sent.
	err      error
	rejected bool
}

// Analyze implements syntaxanalysis.Analyzer.
func (p *Pool) Analyze(ctx context.Context, source syntaxanalysis.Source) (syntaxanalysis.FileAnalysis, error) {
	if source.Path() == "" {
		return syntaxanalysis.FileAnalysis{}, syntaxanalysis.ErrInvalidInput
	}
	select {
	case p.slots <- struct{}{}:
	case <-ctx.Done():
		return syntaxanalysis.FileAnalysis{}, ctx.Err()
	}
	defer func() { <-p.slots }()
	gap := func(reason syntaxanalysis.GapReason) (syntaxanalysis.FileAnalysis, error) {
		return syntaxanalysis.WholeFileGap(source, Identity, reason, ""), nil
	}
	// The workers analyse with the default limits; a larger file would get
	// the same gap from them after being copied there.
	if source.Size() > syntaxanalysis.DefaultLimits().MaxFileBytes {
		return syntaxanalysis.WholeFileGap(source, Identity, syntaxanalysis.GapLimitExceeded, syntaxanalysis.LimitFileSize), nil
	}
	w, err := p.acquire()
	if err != nil {
		return syntaxanalysis.FileAnalysis{}, err
	}
	if w == nil {
		return gap(syntaxanalysis.GapAnalysisUnavailable)
	}
	p.mu.Lock()
	p.next++
	q := request{id: p.next, path: source.Path(), language: source.Language(), content: source.Content()}
	p.mu.Unlock()
	bound := p.config.FileBound
	if !w.seen[source.Language()] {
		bound += p.config.CompileAllowance
		w.seen[source.Language()] = true
	}
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		p.discard(w, &p.stats.Canceled)
		return syntaxanalysis.FileAnalysis{}, ctx.Err()
	case <-timer.C:
		p.discard(w, &p.stats.TimedOut)
		return gap(syntaxanalysis.GapDeadlineExceeded)
	case got := <-exchangeWith(w, q, source):
		switch {
		case got.err != nil && errors.Is(got.err, errProtocol) && !exited(w), got.rejected:
			p.discard(w, &p.stats.Malformed)
			return gap(syntaxanalysis.GapAnalysisFailed)
		case got.err != nil:
			p.discard(w, &p.stats.Crashed)
			return gap(syntaxanalysis.GapAnalysisFailed)
		case got.abandoned:
			p.discard(w, &p.stats.Abandoned)
		default:
			p.release(w)
		}
		return got.analysis, nil
	}
}

// exchangeWith sends a request and reads, decodes and checks the answer on
// its own goroutine, so that all of it is inside the caller's time bound.
func exchangeWith(w *worker, q request, source syntaxanalysis.Source) <-chan exchange {
	result := make(chan exchange, 1)
	go func() {
		if err := writeFrame(w.stdin, q.encode()); err != nil {
			result <- exchange{err: err}
			return
		}
		payload, err := readFrame(w.stdout)
		if err != nil {
			result <- exchange{err: err}
			return
		}
		answer, err := decodeResponse(payload)
		if err != nil {
			result <- exchange{err: err}
			return
		}
		analysis, ok := checkAnswer(answer, q, source)
		result <- exchange{analysis: analysis, abandoned: answer.abandoned > 0, rejected: !ok}
	}()
	return result
}

// exited reports whether the worker process has ended, which tells a crash
// from a worker that wrote a malformed frame and kept running.
func exited(w *worker) bool {
	select {
	case <-w.exited:
		return true
	case <-time.After(100 * time.Millisecond):
		return false
	}
}

// checkAnswer decodes a response within the limits the worker analyses with
// and checks that it describes the file that was sent: the same request,
// language and content digest, and records inside the content.
func checkAnswer(answer response, q request, source syntaxanalysis.Source) (syntaxanalysis.FileAnalysis, bool) {
	if answer.id != q.id || answer.status != statusAnalysed {
		return syntaxanalysis.FileAnalysis{}, false
	}
	analysis, err := syntaxanalysis.DecodeBinary(answer.analysis, source.Path(), syntaxanalysis.DefaultLimits())
	if err != nil || analysis.ContentSHA256 != source.SHA256() {
		return syntaxanalysis.FileAnalysis{}, false
	}
	if analysis.Language != source.Language() && !(source.Language() == syntaxanalysis.LanguageC && analysis.Language == syntaxanalysis.LanguageCPP) {
		return syntaxanalysis.FileAnalysis{}, false
	}
	size := source.Size()
	inside := func(r syntaxanalysis.Range) bool { return r.StartByte <= r.EndByte && r.EndByte <= size }
	for _, d := range analysis.Definitions {
		if !inside(d.Range) || !inside(d.NameRange) {
			return syntaxanalysis.FileAnalysis{}, false
		}
	}
	for _, r := range analysis.References {
		if !inside(r.Range) {
			return syntaxanalysis.FileAnalysis{}, false
		}
	}
	for _, i := range analysis.Imports {
		if !inside(i.Range) {
			return syntaxanalysis.FileAnalysis{}, false
		}
	}
	for _, g := range analysis.Gaps {
		if g.HasRange && !inside(g.Range) {
			return syntaxanalysis.FileAnalysis{}, false
		}
	}
	return analysis, true
}
