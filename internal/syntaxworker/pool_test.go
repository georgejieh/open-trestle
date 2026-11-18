package syntaxworker

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// The test binary is its own worker: started with the mode argument, it
// serves requests and never runs the tests.
const workerMode = "syntaxworker-test-worker"

func TestMain(m *testing.M) {
	if len(os.Args) == 3 && os.Args[1] == workerMode {
		switch os.Args[2] {
		case "fake":
			os.Exit(serveFake())
		case "real":
			os.Exit(Run(context.Background(), nil, os.Stdin, os.Stdout))
		}
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// fakeAnalyzer misbehaves according to the file name, so that one worker
// mode covers every hostile case.
type fakeAnalyzer struct{ abandoned *int }

func (fakeAnalyzer) Supports(syntaxanalysis.Language) bool { return true }

func (f fakeAnalyzer) Analyze(_ context.Context, source syntaxanalysis.Source) (syntaxanalysis.FileAnalysis, error) {
	base := source.Path()[strings.LastIndex(source.Path(), "/")+1:]
	switch base {
	case "hang.go":
		select {}
	case "crash.go":
		os.Exit(3)
	case "garbage.go":
		fmt.Fprint(os.Stdout, "\x05\x00\x00\x00junk!")
		select {}
	case "lie.go":
		other, _ := syntaxanalysis.NewSource(source.Path(), source.Language(), []byte("other content"))
		return syntaxanalysis.WholeFileGap(other, "fake", syntaxanalysis.GapParseError, ""), nil
	case "abandon.go":
		*f.abandoned = 1
	}
	return syntaxanalysis.WholeFileGap(source, "fake", syntaxanalysis.GapParseError, ""), nil
}

func serveFake() int {
	abandoned := 0
	if Serve(context.Background(), os.Stdin, os.Stdout, fakeAnalyzer{abandoned: &abandoned}, func() int { return abandoned }) != nil {
		return 1
	}
	return 0
}

func newTestPool(t *testing.T, mode string, workers int) *Pool {
	t.Helper()
	pool, err := NewPool(Config{Command: []string{os.Args[0], workerMode, mode}, Workers: workers, FileBound: 2 * time.Second, CompileAllowance: time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func analyzeFile(t *testing.T, pool *Pool, path, content string) syntaxanalysis.FileAnalysis {
	t.Helper()
	language, _ := syntaxanalysis.LanguageForPath(path)
	source, err := syntaxanalysis.NewSource(path, language, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	analysis, err := pool.Analyze(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	return analysis
}

func onlyGap(a syntaxanalysis.FileAnalysis) syntaxanalysis.GapReason {
	if len(a.Gaps) != 1 {
		return ""
	}
	return a.Gaps[0].Reason
}

func TestPoolReplacesHostileWorkers(t *testing.T) {
	pool := newTestPool(t, "fake", 1)
	for _, c := range []struct {
		file     string
		analyzer string
		reason   syntaxanalysis.GapReason
	}{
		{"ok.go", "fake", syntaxanalysis.GapParseError},
		{"hang.go", Identity, syntaxanalysis.GapDeadlineExceeded},
		{"ok.go", "fake", syntaxanalysis.GapParseError},
		{"crash.go", Identity, syntaxanalysis.GapAnalysisFailed},
		{"garbage.go", Identity, syntaxanalysis.GapAnalysisFailed},
		{"lie.go", Identity, syntaxanalysis.GapAnalysisFailed},
		{"abandon.go", "fake", syntaxanalysis.GapParseError},
		{"ok.go", "fake", syntaxanalysis.GapParseError},
	} {
		got := analyzeFile(t, pool, "src/"+c.file, "package src\n")
		if got.Analyzer != c.analyzer || onlyGap(got) != c.reason || got.Path != "src/"+c.file {
			t.Fatalf("%s: analyzer %q gaps %v", c.file, got.Analyzer, got.Gaps)
		}
	}
	stats := pool.Stats()
	if stats.TimedOut != 1 || stats.Crashed != 1 || stats.Malformed != 2 || stats.Abandoned != 1 || stats.Started != 6 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestPoolGivesAnOversizedFileItsGapWithoutAWorker(t *testing.T) {
	pool := newTestPool(t, "fake", 1)
	got := analyzeFile(t, pool, "big.go", strings.Repeat("x", syntaxanalysis.DefaultLimits().MaxFileBytes+1))
	if len(got.Gaps) != 1 || got.Gaps[0].Limit != syntaxanalysis.LimitFileSize || pool.Stats().Started != 0 {
		t.Fatalf("gaps %v, stats %+v", got.Gaps, pool.Stats())
	}
}

func TestPoolReportsUnavailableWhenWorkersCannotStart(t *testing.T) {
	pool, err := NewPool(Config{Command: []string{"/nonexistent/open-trestle-worker"}, Workers: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	for i := 0; i < maxStartFailures+2; i++ {
		if got := analyzeFile(t, pool, "a.go", "package a"); onlyGap(got) != syntaxanalysis.GapAnalysisUnavailable {
			t.Fatalf("gaps = %v", got.Gaps)
		}
	}
	if pool.Stats().Started != 0 {
		t.Fatal("a worker started")
	}
}

func TestPoolCancellationKillsTheWorker(t *testing.T) {
	pool := newTestPool(t, "fake", 1)
	source, _ := syntaxanalysis.NewSource("hang.go", syntaxanalysis.LanguageGo, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := pool.Analyze(ctx, source); err == nil {
		t.Fatal("canceled analysis succeeded")
	}
	if got := analyzeFile(t, pool, "ok.go", ""); onlyGap(got) != syntaxanalysis.GapParseError {
		t.Fatalf("after cancellation: %v", got.Gaps)
	}
}

func TestPoolRunsWorkersConcurrently(t *testing.T) {
	pool := newTestPool(t, "fake", 4)
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "ok.go"
			if i%16 == 5 {
				name = "crash.go"
			}
			path := fmt.Sprintf("d%d/%s", i, name)
			source, _ := syntaxanalysis.NewSource(path, syntaxanalysis.LanguageGo, []byte(path))
			got, err := pool.Analyze(context.Background(), source)
			if err != nil || got.Path != path || got.ContentSHA256 != source.SHA256() {
				errs <- path
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for path := range errs {
		t.Errorf("wrong answer for %s", path)
	}
	if started := pool.Stats().Started; started > 4+4 {
		t.Fatalf("started %d workers", started)
	}
}

func TestRealWorkerAnalysesGoAndWebAssemblyLanguages(t *testing.T) {
	pool := newTestPool(t, "real", 1)
	pool.config.CompileAllowance = time.Minute
	goFile := analyzeFile(t, pool, "a/main.go", "package a\n\nfunc Run() { helper() }\n")
	if goFile.Analyzer == Identity || len(goFile.Definitions) != 2 || goFile.Definitions[1].Name.Untrusted() != "Run" {
		t.Fatalf("go analysis = %s %v", goFile.Analyzer, goFile.Gaps)
	}
	py := analyzeFile(t, pool, "a/tool.py", "def run():\n    helper()\n")
	if py.Analyzer == Identity {
		t.Fatalf("python analysis failed: %v", py.Gaps)
	}
	if onlyGap(py) == syntaxanalysis.GapAnalysisUnavailable {
		t.Skip("the wazero compiler does not run on this platform")
	}
	if len(py.Definitions) != 1 || len(py.References) != 1 {
		t.Fatalf("python analysis = %d definitions, %d references", len(py.Definitions), len(py.References))
	}
}

func TestProtocolRejectsMalformedFrames(t *testing.T) {
	for _, input := range []string{"\x01\x00", "\x05\x00\x00\x00abc", "\xff\xff\xff\xffx"} {
		if _, err := readFrame(bufio.NewReader(strings.NewReader(input))); err == nil {
			t.Fatalf("frame %q read", input)
		}
	}
	if _, err := decodeResponse([]byte{1, 0, 9, 0}); err == nil {
		t.Fatal("unknown status decoded")
	}
	q := request{id: 7, path: "a.go", language: syntaxanalysis.LanguageGo, content: []byte("x")}
	got, err := decodeRequest(q.encode())
	if err != nil || got.id != 7 || got.path != "a.go" || string(got.content) != "x" {
		t.Fatalf("request = %+v, %v", got, err)
	}
}
