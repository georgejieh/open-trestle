package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/localreview"
)

// Progress of a review on standard error. On a terminal one line shows the
// current stage with a spinner and the time it has taken, redrawn in place;
// each finished stage leaves a line with its duration. Elsewhere (a pipe, a
// file, TERM=dumb) each stage start is one plain line. Nothing is written to
// standard output, and the line is cleared before any other message or the
// result is written. There is no percentage: model time is unknown, so only
// counts of reviewers done are shown.

const progressTick = 100 * time.Millisecond

var (
	progressFrames      = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	progressFramesASCII = []string{"|", "/", "-", "\\"}
)

type reviewProgress struct {
	mu      sync.Mutex
	out     io.Writer
	style   initStyle
	live    bool
	width   int
	now     func() time.Time
	restore func()

	// The current stage.
	label string
	since time.Time
	// name, total and done describe reviewers of a specialist review;
	// concurrent is set while a wave of them runs at once.
	name        string
	total, done int
	concurrent  bool

	frame   int
	drawn   bool
	stopped bool
	quit    chan struct{}
	exited  chan struct{}
}

type progressKey struct{}

func withReviewProgress(ctx context.Context, p *reviewProgress) context.Context {
	return context.WithValue(ctx, progressKey{}, p)
}

func reviewProgressOf(ctx context.Context) *reviewProgress {
	if ctx == nil {
		return nil
	}
	p, _ := ctx.Value(progressKey{}).(*reviewProgress)
	return p
}

// startReviewProgress returns nil unless stderr is a file. Its methods accept
// a nil receiver.
func startReviewProgress(stderr io.Writer) *reviewProgress {
	file, ok := stderr.(*os.File)
	if !ok {
		return nil
	}
	p := &reviewProgress{out: stderr, style: newInitStyle(stderr, false), width: initWidth, now: time.Now}
	if initTerminal(stderr) && os.Getenv("TERM") != "dumb" {
		if restore, ok := initEnableTerminalOutput(stderr); ok {
			p.live, p.restore = true, restore
		}
	}
	if !p.live {
		return p
	}
	if columns := terminalColumns(file); columns > 0 {
		p.width = columns
	}
	p.style.ascii = p.style.ascii || progressASCII()
	p.quit, p.exited = make(chan struct{}), make(chan struct{})
	go p.run()
	return p
}

// progressASCII reports a locale that is set and is not UTF-8.
func progressASCII() bool {
	if runtime.GOOS == "windows" {
		return false
	}
	for _, name := range []string{"LC_ALL", "LC_CTYPE", "LANG"} {
		if value := strings.ToLower(os.Getenv(name)); value != "" {
			return !strings.Contains(value, "utf-8") && !strings.Contains(value, "utf8")
		}
	}
	return false
}

func (p *reviewProgress) run() {
	defer close(p.exited)
	ticker := time.NewTicker(progressTick)
	defer ticker.Stop()
	for {
		select {
		case <-p.quit:
			return
		case <-ticker.C:
			p.mu.Lock()
			p.drawLocked()
			p.mu.Unlock()
		}
	}
}

// stop clears the line and ends the ticker. It is safe to call more than
// once; later calls to the other methods do nothing.
func (p *reviewProgress) stop() {
	if p == nil {
		return
	}
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		return
	}
	p.stopped, p.label = true, ""
	p.clearLocked()
	p.mu.Unlock()
	if p.quit != nil {
		close(p.quit)
		<-p.exited
	}
	if p.restore != nil {
		p.restore()
	}
}

// begin starts a stage and ends the one before it. An announced stage prints
// its own line when it starts, so plain output does not repeat it.
func (p *reviewProgress) begin(label string, announced bool) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.beginLocked(label, announced)
}

// end finishes the current stage, if any.
func (p *reviewProgress) end() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endLocked()
}

func (p *reviewProgress) beginLocked(label string, announced bool) {
	if p.stopped {
		return
	}
	p.endLocked()
	p.label, p.since = label, p.now()
	if !p.live {
		if !announced {
			fmt.Fprintln(p.out, p.textLocked())
		}
		return
	}
	p.drawLocked()
}

func (p *reviewProgress) endLocked() {
	if p.label == "" {
		return
	}
	if p.live {
		p.clearLocked()
		mark, _, _, _ := p.style.marks()
		tail := p.style.paint(initToneDim, " · "+progressElapsed(p.now().Sub(p.since)))
		fmt.Fprintln(p.out, p.fit(mark+" ", p.textLocked(), tail))
	}
	p.label = ""
}

func (p *reviewProgress) textLocked() string {
	switch {
	case p.concurrent:
		return fmt.Sprintf("%s · %d of %d reviewers done", p.label, p.done, p.total)
	case p.name != "" && p.total > 0:
		return fmt.Sprintf("%s · %s (%d of %d reviewers)", p.label, p.name, p.done+1, p.total)
	case p.name != "":
		return p.label + " · " + p.name
	}
	return p.label
}

func (p *reviewProgress) drawLocked() {
	if !p.live || p.stopped || p.label == "" {
		return
	}
	frames := progressFrames
	if p.style.ascii {
		frames = progressFramesASCII
	}
	spinner := p.style.paint(initTonePrompt, frames[p.frame%len(frames)])
	p.frame++
	tail := p.style.paint(initToneDim, " · "+progressElapsed(p.now().Sub(p.since)))
	fmt.Fprint(p.out, "\r"+p.fit(spinner+" ", p.textLocked(), tail)+"\x1b[K")
	p.drawn = true
}

func (p *reviewProgress) clearLocked() {
	if p.drawn {
		fmt.Fprint(p.out, "\r\x1b[K")
		p.drawn = false
	}
}

// fit shortens text so that the line stays one column short of the terminal
// width, which keeps the cursor from wrapping.
func (p *reviewProgress) fit(lead, text, tail string) string {
	room := max(1, p.width-1-initVisible(lead)-initVisible(tail))
	if utf8.RuneCountInString(text) > room {
		ellipsis := "…"
		if p.style.ascii {
			ellipsis = "..."
		}
		text = string([]rune(text)[:max(0, room-utf8.RuneCountInString(ellipsis))]) + ellipsis
	}
	return lead + text + tail
}

// progressElapsed formats a duration as "38s", "1m 12s" or "1h 02m".
func progressElapsed(d time.Duration) string {
	seconds := int(d.Seconds())
	switch {
	case seconds >= 3600:
		return fmt.Sprintf("%dh %02dm", seconds/3600, seconds%3600/60)
	case seconds >= 60:
		return fmt.Sprintf("%dm %02ds", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%ds", seconds)
}

// startMember starts the stages of one reviewer. name is empty unless the
// review has specialists. A reviewer in a concurrent wave shares the wave's
// line instead.
func (p *reviewProgress) startMember(name string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.concurrent {
		return
	}
	p.endLocked()
	p.name = name
	p.beginLocked("Preparing the review", false)
}

// memberEvents returns the session hook that moves the stage with each model
// request, or nil without progress.
func (p *reviewProgress) memberEvents() func(localreview.ProgressEvent) {
	if p == nil {
		return nil
	}
	return func(event localreview.ProgressEvent) {
		label := "Reviewing"
		switch event.Stage {
		case localreview.ProgressFinder:
			label = "Finding problems"
		case localreview.ProgressChecker:
			label = "Checking findings"
		}
		if event.Retry {
			label += " (retrying)"
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		if !p.concurrent && label != p.label {
			p.beginLocked(label, false)
		}
	}
}

// memberDone counts a finished reviewer and ends its stage.
func (p *reviewProgress) memberDone() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.concurrent {
		p.endLocked()
	}
	p.done++
}

// setReviewers sets how many reviewers the review has.
func (p *reviewProgress) setReviewers(total int) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.total = total
}

// beginWave and endWave bracket reviewers that run at once.
func (p *reviewProgress) beginWave() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endLocked()
	p.concurrent = true
	p.beginLocked("Reviewing", false)
}

func (p *reviewProgress) endWave() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endLocked()
	p.concurrent = false
}

// finish starts the last stage, after every reviewer is done.
func (p *reviewProgress) finish() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.endLocked()
	p.name, p.total = "", 0
	p.beginLocked("Finishing", false)
}

// progressWriter clears the progress line before each write to standard
// error.
type progressWriter struct {
	p *reviewProgress
	w io.Writer
}

func (s progressWriter) Write(b []byte) (int, error) {
	s.p.mu.Lock()
	defer s.p.mu.Unlock()
	s.p.clearLocked()
	return s.w.Write(b)
}

// stopWriter stops the progress before the first write of the result, and
// passes every byte through unchanged.
type stopWriter struct {
	p *reviewProgress
	w io.Writer
}

func (s stopWriter) Write(b []byte) (int, error) {
	s.p.stop()
	return s.w.Write(b)
}
