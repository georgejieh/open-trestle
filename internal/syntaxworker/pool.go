package syntaxworker

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// Config describes how a Pool starts and bounds its workers.
type Config struct {
	// Command is the worker executable and its arguments.
	Command []string
	// Environment is the whole environment of a worker; nil means none.
	Environment []string
	// Workers bounds the workers running at once. Zero means
	// DefaultWorkers.
	Workers int
	// FileBound is the hard wall-clock bound on one file, after which the
	// worker is killed. Zero means three times the default per-file
	// deadline plus five seconds, above the analyzer's own watchdog.
	FileBound time.Duration
	// CompileAllowance is added to the bound of the first file of each
	// language in a worker, which compiles that language's module and
	// queries first. Zero means one minute.
	CompileAllowance time.Duration
}

// maxStartFailures is how many workers in a row may fail to start before
// the pool stops starting them and reports analysis as unavailable.
const maxStartFailures = 3

// Pool is a syntaxanalysis.Analyzer that analyses each file in a worker
// process. Every worker failure becomes a coverage gap of that file. It is
// safe for concurrent use.
type Pool struct {
	config Config
	slots  chan struct{}

	mu            sync.Mutex
	idle          []*worker
	next          uint64
	startFailures int
	stats         Stats
	closed        bool
}

// Stats counts what happened to the pool's workers.
type Stats struct {
	Started, Killed, TimedOut, Crashed, Malformed, Abandoned int
}

// NewPool returns a pool; it starts workers when files arrive.
func NewPool(config Config) (*Pool, error) {
	if len(config.Command) == 0 || config.Workers < 0 || config.FileBound < 0 || config.CompileAllowance < 0 {
		return nil, errors.New("invalid syntax worker pool configuration")
	}
	if config.Workers == 0 {
		config.Workers = DefaultWorkers()
	}
	if config.FileBound == 0 {
		config.FileBound = 3*syntaxanalysis.DefaultLimits().FileDeadline + 5*time.Second
	}
	if config.CompileAllowance == 0 {
		config.CompileAllowance = time.Minute
	}
	if config.Environment == nil {
		config.Environment = []string{}
	}
	return &Pool{config: config, slots: make(chan struct{}, config.Workers)}, nil
}

// Workers returns the number of workers that may run at once.
func (p *Pool) Workers() int { return p.config.Workers }

// Stats returns the worker counts so far.
func (p *Pool) Stats() Stats {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.stats
}

// Supports reports whether the workers analyse the language: every declared
// language has an analyzer in the worker program.
func (p *Pool) Supports(language syntaxanalysis.Language) bool { return language.Valid() }

type worker struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	exited chan struct{}
	seen   map[syntaxanalysis.Language]bool
}

func (p *Pool) start() (*worker, error) {
	cmd := exec.Command(p.config.Command[0], p.config.Command[1:]...)
	cmd.Env = p.config.Environment
	cmd.Dir = os.TempDir()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	w := &worker{cmd: cmd, stdin: stdin, stdout: bufio.NewReaderSize(stdout, 1<<16), exited: make(chan struct{}), seen: map[syntaxanalysis.Language]bool{}}
	go func() {
		_ = cmd.Wait()
		close(w.exited)
	}()
	return w, nil
}

func (w *worker) kill() {
	_ = w.cmd.Process.Kill()
	<-w.exited
}

// acquire returns an idle worker or starts one. A nil worker with a nil
// error means the pool can no longer start workers.
func (p *Pool) acquire() (*worker, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, errors.New("syntax worker pool is closed")
	}
	if n := len(p.idle); n > 0 {
		w := p.idle[n-1]
		p.idle = p.idle[:n-1]
		p.mu.Unlock()
		return w, nil
	}
	if p.startFailures >= maxStartFailures {
		p.mu.Unlock()
		return nil, nil
	}
	p.mu.Unlock()
	w, err := p.start()
	p.mu.Lock()
	defer p.mu.Unlock()
	if err != nil {
		p.startFailures++
		return nil, nil
	}
	p.stats.Started++
	return w, nil
}

func (p *Pool) release(w *worker) {
	p.mu.Lock()
	if !p.closed {
		p.startFailures = 0
		p.idle = append(p.idle, w)
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	w.kill()
}

func (p *Pool) discard(w *worker, count *int) {
	w.kill()
	p.mu.Lock()
	p.stats.Killed++
	*count++
	p.mu.Unlock()
}

type exchange struct {
	answer response
	err    error
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
		result <- exchange{answer: answer, err: err}
	}()
	timer := time.NewTimer(bound)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		w.kill()
		return syntaxanalysis.FileAnalysis{}, ctx.Err()
	case <-timer.C:
		p.discard(w, &p.stats.TimedOut)
		return gap(syntaxanalysis.GapDeadlineExceeded)
	case got := <-result:
		if got.err != nil {
			if errors.Is(got.err, errProtocol) && !exited(w) {
				p.discard(w, &p.stats.Malformed)
			} else {
				p.discard(w, &p.stats.Crashed)
			}
			return gap(syntaxanalysis.GapAnalysisFailed)
		}
		analysis, ok := checkAnswer(got.answer, q, source)
		if !ok {
			p.discard(w, &p.stats.Malformed)
			return gap(syntaxanalysis.GapAnalysisFailed)
		}
		if got.answer.abandoned > 0 {
			p.discard(w, &p.stats.Abandoned)
		} else {
			p.release(w)
		}
		return analysis, nil
	}
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

// checkAnswer decodes a response and checks that it describes the file that
// was sent: the same request, language and content digest, and records
// inside the content.
func checkAnswer(answer response, q request, source syntaxanalysis.Source) (syntaxanalysis.FileAnalysis, bool) {
	if answer.id != q.id || answer.status != statusAnalysed {
		return syntaxanalysis.FileAnalysis{}, false
	}
	analysis, err := syntaxanalysis.DecodeBinary(answer.analysis, source.Path())
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

// Close stops every idle worker. Analyses still running finish first, and
// their workers stop when they are released.
func (p *Pool) Close() {
	p.mu.Lock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.mu.Unlock()
	for _, w := range idle {
		_ = w.stdin.Close()
		select {
		case <-w.exited:
		case <-time.After(2 * time.Second):
			w.kill()
		}
	}
}

// Identity names the pool in the gaps it reports for a failed worker.
const Identity = "open-trestle/syntax/worker/v1"
