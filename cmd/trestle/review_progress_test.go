package main

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/localreview"
)

// testProgress is a progress whose terminal is a buffer and whose clock only
// moves when the test says so.
func testProgress(live, ascii bool, width int) (*reviewProgress, *bytes.Buffer, *time.Time) {
	var buf bytes.Buffer
	clock := time.Unix(0, 0)
	return &reviewProgress{out: &buf, style: initStyle{ascii: ascii}, live: live, width: width, now: func() time.Time { return clock }}, &buf, &clock
}

func (p *reviewProgress) tick() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.drawLocked()
}

func TestReviewProgressTerminalFrames(t *testing.T) {
	p, buf, clock := testProgress(true, false, 60)
	p.begin("Repository checks", true)
	*clock = clock.Add(38 * time.Second)
	p.tick()
	p.begin("Finding problems", false)
	*clock = clock.Add(72 * time.Second)
	p.tick()
	p.stop()
	want := "\r⠋ Repository checks · 0s\x1b[K" +
		"\r⠙ Repository checks · 38s\x1b[K" +
		"\r\x1b[K✓ Repository checks · 38s\n" +
		"\r⠹ Finding problems · 0s\x1b[K" +
		"\r⠸ Finding problems · 1m 12s\x1b[K" +
		"\r\x1b[K"
	if buf.String() != want {
		t.Fatalf("frames:\n%q\nwant:\n%q", buf.String(), want)
	}
}

func TestReviewProgressASCIIFrames(t *testing.T) {
	p, buf, clock := testProgress(true, true, 60)
	p.begin("Indexing the repository", true)
	*clock = clock.Add(2 * time.Second)
	p.tick()
	p.end()
	want := "\r| Indexing the repository · 0s\x1b[K" +
		"\r/ Indexing the repository · 2s\x1b[K" +
		"\r\x1b[K[ok] Indexing the repository · 2s\n"
	if buf.String() != want {
		t.Fatalf("frames:\n%q\nwant:\n%q", buf.String(), want)
	}
}

func TestReviewProgressColorsFollowStyle(t *testing.T) {
	p, buf, _ := testProgress(true, false, 60)
	p.style.palette = initColor256
	p.begin("Finding problems", false)
	if !strings.Contains(buf.String(), "\x1b[38;5;25m⠋\x1b[0m") || !strings.Contains(buf.String(), "\x1b[2m · 0s\x1b[0m") {
		t.Fatalf("frame %q does not use the init tones", buf.String())
	}
}

func TestReviewProgressPlainLines(t *testing.T) {
	p, buf, clock := testProgress(false, false, 60)
	p.begin("Indexing the repository", true)
	p.begin("Preparing the review", false)
	*clock = clock.Add(time.Minute)
	p.tick()
	p.begin("Finding problems (retrying)", false)
	p.finish()
	p.stop()
	want := "Preparing the review\nFinding problems (retrying)\nFinishing\nReviewed in 1m 00s.\n"
	if buf.String() != want {
		t.Fatalf("plain output %q, want %q", buf.String(), want)
	}
	if strings.ContainsAny(buf.String(), "\x1b\r") {
		t.Fatal("plain output has control characters")
	}
}

func TestReviewProgressClosesAFinishedRunWithItsTime(t *testing.T) {
	p, buf, clock := testProgress(true, false, 60)
	p.begin("Indexing the repository", true)
	*clock = clock.Add(134 * time.Second)
	p.finish()
	p.stop()
	p.stop()
	if got := buf.String(); !strings.HasSuffix(got, "\x1b[KReviewed in 2m 14s.\n") || strings.Count(got, "Reviewed in") != 1 {
		t.Fatalf("closing line %q", got)
	}
}

func TestReviewProgressSaysNothingWithoutAFinishedRun(t *testing.T) {
	p, buf, _ := testProgress(true, false, 60)
	p.stop()
	q, plain, _ := testProgress(false, false, 60)
	q.begin("Finding problems", false)
	q.stop()
	if buf.Len() != 0 || strings.Contains(plain.String(), "Reviewed in") {
		t.Fatalf("closing line without a finished run: %q %q", buf.String(), plain.String())
	}
}

func TestReviewProgressFitsTheTerminal(t *testing.T) {
	p, buf, _ := testProgress(true, false, 30)
	p.begin("Checking findings", false)
	p.name, p.total = "backend_specialist_with_a_long_name", 4
	p.tick()
	line := strings.TrimSuffix(strings.TrimPrefix(strings.Split(buf.String(), "\r")[2], ""), "\x1b[K")
	if initVisible(line) > 29 || !strings.HasSuffix(line, " · 0s") || !strings.Contains(line, "…") {
		t.Fatalf("line %q (%d columns) does not fit 29", line, initVisible(line))
	}
	p, buf, _ = testProgress(true, true, 30)
	p.begin("Checking findings", false)
	p.name, p.total = "backend_specialist_with_a_long_name", 4
	p.tick()
	if line := strings.TrimSuffix(strings.Split(buf.String(), "\r")[2], "\x1b[K"); initVisible(line) > 29 || !strings.Contains(line, "...") {
		t.Fatalf("ASCII line %q does not fit", line)
	}
}

func TestReviewProgressReviewerCounts(t *testing.T) {
	p, buf, _ := testProgress(false, false, 60)
	p.setReviewers(4)
	p.startMember("general")
	p.memberDone()
	p.startMember("bug_hunter")
	p.memberEvents()(testEvent(true, false))
	p.memberEvents()(testEvent(false, true))
	p.memberDone()
	p.beginWave()
	p.memberEvents()(testEvent(true, false))
	p.memberDone()
	p.endWave()
	p.finish()
	want := "Preparing the review · general (1 of 4 reviewers)\n" +
		"Preparing the review · bug_hunter (2 of 4 reviewers)\n" +
		"Finding problems · bug_hunter (2 of 4 reviewers)\n" +
		"Checking findings (retrying) · bug_hunter (2 of 4 reviewers)\n" +
		"Reviewing · 2 of 4 reviewers done\n" +
		"Finishing\n"
	if buf.String() != want {
		t.Fatalf("counts:\n%q\nwant:\n%q", buf.String(), want)
	}
}

func TestReviewProgressWaveIsOneLine(t *testing.T) {
	p, buf, clock := testProgress(true, false, 60)
	p.setReviewers(4)
	p.memberDone()
	p.beginWave()
	p.startMember("backend")
	p.memberEvents()(testEvent(true, false))
	*clock = clock.Add(123 * time.Second)
	p.memberDone()
	p.tick()
	p.endWave()
	want := "\r⠋ Reviewing · 1 of 4 reviewers done · 0s\x1b[K" +
		"\r⠙ Reviewing · 2 of 4 reviewers done · 2m 03s\x1b[K" +
		"\r\x1b[K✓ Reviewing · 2 of 4 reviewers done · 2m 03s\n"
	if buf.String() != want {
		t.Fatalf("wave:\n%q\nwant:\n%q", buf.String(), want)
	}
}

func TestReviewProgressWritersKeepOutputIntact(t *testing.T) {
	p, buf, _ := testProgress(true, false, 60)
	p.begin("Finding problems", false)
	var stderr, stdout bytes.Buffer
	progressWriter{p, &stderr}.Write([]byte("hint\n"))
	if stderr.String() != "hint\n" || !strings.HasSuffix(buf.String(), "\r\x1b[K") {
		t.Fatalf("stderr %q, terminal %q", stderr.String(), buf.String())
	}
	result := []byte("{\"status\":\"findings\"}\n")
	n, err := stopWriter{p, &stdout}.Write(result)
	if n != len(result) || err != nil || !bytes.Equal(stdout.Bytes(), result) {
		t.Fatalf("stdout changed: %q", stdout.String())
	}
	before := buf.String()
	p.begin("Finishing", false)
	p.tick()
	p.stop()
	if buf.String() != before {
		t.Fatalf("progress wrote after the result: %q", buf.String()[len(before):])
	}
	if strings.Contains(buf.String(), "findings") {
		t.Fatal("result reached the terminal buffer")
	}
}

func TestReviewProgressNeedsAFile(t *testing.T) {
	if startReviewProgress(&bytes.Buffer{}) != nil {
		t.Fatal("progress started on a buffer")
	}
	var p *reviewProgress
	p.begin("x", false)
	p.end()
	p.finish()
	p.stop()
	if p.memberEvents() != nil || reviewProgressOf(nil) != nil || reviewProgressOf(context.Background()) != nil {
		t.Fatal("nil progress is not inert")
	}
}

func TestStartReviewProgressOnAPipeIsPlain(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	p := startReviewProgress(writer)
	if p == nil || p.live || p.quit != nil {
		t.Fatalf("pipe progress %+v", p)
	}
}

func TestProgressElapsed(t *testing.T) {
	for d, want := range map[time.Duration]string{0: "0s", 59 * time.Second: "59s", 72 * time.Second: "1m 12s", 3723 * time.Second: "1h 02m"} {
		if got := progressElapsed(d); got != want {
			t.Fatalf("%v = %q, want %q", d, got, want)
		}
	}
}

// TestReviewProgressLeavesStdoutUnchanged runs a review with progress and
// without: the result is the same bytes, and the stage lines go to the
// progress stream only.
func TestReviewProgressLeavesStdoutUnchanged(t *testing.T) {
	var outputs [2][]byte
	var codes [2]int
	var stages string
	for index := range outputs {
		f := newLocalModelFixture(t, localModelFixtureOptions{})
		ctx := context.Background()
		var progressOut *bytes.Buffer
		if index == 1 {
			p, buf, _ := testProgress(false, false, 60)
			ctx, progressOut = withReviewProgress(ctx, p), buf
		}
		var stdout, stderr bytes.Buffer
		codes[index] = runLocalGitModelReviewObserved(ctx, f.args[2:], &stdout, &stderr, nil)
		outputs[index] = localModelHexIdentity.ReplaceAll(stdout.Bytes(), []byte("<id>"))
		if progressOut != nil {
			stages = progressOut.String()
			if strings.Contains(stderr.String(), "Finding problems") {
				t.Fatal("stage lines reached the error stream of a supplied progress")
			}
		}
	}
	if codes[0] != codes[1] || !bytes.Equal(outputs[0], outputs[1]) {
		t.Fatalf("progress changed the result:\n%s\n%s", outputs[0], outputs[1])
	}
	if want := "Preparing the review\nFinding problems\nChecking findings\nFinishing\n"; stages != want {
		t.Fatalf("stages %q, want %q", stages, want)
	}
}

func testEvent(finder, retry bool) localreview.ProgressEvent {
	stage := localreview.ProgressChecker
	if finder {
		stage = localreview.ProgressFinder
	}
	return localreview.ProgressEvent{Stage: stage, Retry: retry}
}
