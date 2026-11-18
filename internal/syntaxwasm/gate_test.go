//go:build linux

package syntaxwasm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// The go/no-go gate of the syntax analysis design: a 100 KB file analysed in
// under 150 ms warm and under 150 MB resident for one language.
const (
	gateFileBytes   = 100 << 10
	gateWarmLimit   = 150 * time.Millisecond
	gateResidentMiB = 150
	gateWarmRuns    = 15
)

// gateFixture is the realistic fixture a language's gate file repeats.
// Lines starting with one of once appear only in the first copy, and a page
// with body set repeats only the lines inside its body, so that every
// repetition still parses.
type gateFixture struct {
	path string
	once []string
	body bool
}

var gateFixtures = map[syntaxanalysis.Language]gateFixture{
	syntaxanalysis.LanguageJava:       {path: "testdata/java/InventoryService.java", once: []string{"package ", "import "}},
	syntaxanalysis.LanguageJavaScript: {path: "testdata/javascript/event-bus.js"},
	syntaxanalysis.LanguageTypeScript: {path: "testdata/typescript/repository.ts"},
	syntaxanalysis.LanguageTSX:        {path: "testdata/tsx/Dashboard.tsx"},
	syntaxanalysis.LanguagePython:     {path: "testdata/python/scheduler.py"},
	syntaxanalysis.LanguageC:          {path: "testdata/c/kvstore.c"},
	syntaxanalysis.LanguageCPP:        {path: "testdata/cpp/scheduler.cpp"},
	syntaxanalysis.LanguageCSharp:     {path: "testdata/csharp/OrderProcessor.cs", once: []string{"using ", "global using ", "namespace "}},
	syntaxanalysis.LanguageRust:       {path: "testdata/rust/ledger.rs"},
	syntaxanalysis.LanguageSwift:      {path: "testdata/swift/TaskQueue.swift"},
	syntaxanalysis.LanguagePHP:        {path: "testdata/php/OrderService.php", once: []string{"<?php", "declare("}},
	syntaxanalysis.LanguageRuby:       {path: "testdata/ruby/job_queue.rb"},
	syntaxanalysis.LanguageHTML:       {path: "testdata/html/dashboard.html", body: true},
}

type gateResult struct {
	Language       string  `json:"language"`
	Bytes          int     `json:"bytes"`
	CompileMillis  float64 `json:"compile_ms"`
	FirstMillis    float64 `json:"first_analysis_ms"`
	WarmMedianMs   float64 `json:"warm_median_ms"`
	WarmMaxMs      float64 `json:"warm_max_ms"`
	WarmCPUMs      float64 `json:"warm_cpu_ms"`
	PeakResidentMB float64 `json:"peak_resident_mib"`
	Records        int     `json:"records"`
	Gaps           int     `json:"gaps"`
}

// gateSource repeats a fixture until it reaches the gate size.
func gateSource(t testing.TB, language syntaxanalysis.Language) []byte {
	t.Helper()
	fixture := gateFixtures[language]
	content, err := os.ReadFile(fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	head, tail := "", ""
	text := string(content)
	if fixture.body {
		start := strings.Index(text, "<body")
		start += strings.Index(text[start:], "\n") + 1
		end := strings.LastIndex(text, "</body>")
		head, text, tail = text[:start], text[start:end], text[end:]
	}
	var body []string
	for _, line := range strings.Split(text, "\n") {
		if !slices.ContainsFunc(fixture.once, func(prefix string) bool { return strings.HasPrefix(line, prefix) }) {
			body = append(body, line)
		}
	}
	out := head + text
	for len(out)+len(tail) < gateFileBytes {
		out += "\n" + strings.Join(body, "\n")
	}
	return []byte(out + tail)
}

// TestSyntaxGate runs each language in a fresh process, twice: first with an
// empty compilation cache, then with the cache the first run filled. Set
// OPEN_TRESTLE_SYNTAX_GATE=1 to run it.
func TestSyntaxGate(t *testing.T) {
	if os.Getenv("OPEN_TRESTLE_SYNTAX_GATE") != "1" {
		t.Skip("set OPEN_TRESTLE_SYNTAX_GATE=1 to measure the go/no-go gate")
	}
	languages := make([]string, 0, len(gateFixtures))
	for language := range gateFixtures {
		languages = append(languages, string(language))
	}
	slices.Sort(languages)
	failed := false
	for _, language := range languages {
		cache := filepath.Join(t.TempDir(), "cache")
		if err := os.Mkdir(cache, 0o700); err != nil {
			t.Fatal(err)
		}
		for _, run := range []string{"empty cache", "warm cache"} {
			command := exec.Command(os.Args[0], "-test.run=^TestSyntaxGateChild$", "-test.count=1")
			command.Env = append(os.Environ(), "OPEN_TRESTLE_SYNTAX_GATE_CHILD="+language, "OPEN_TRESTLE_SYNTAX_GATE_CACHE="+cache)
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("%s %s: %v\n%s", language, run, err, output)
			}
			var result gateResult
			for _, line := range strings.Split(string(output), "\n") {
				if rest, ok := strings.CutPrefix(line, "GATE "); ok {
					if err := json.Unmarshal([]byte(rest), &result); err != nil {
						t.Fatal(err)
					}
				}
			}
			if result.Language != language {
				t.Fatalf("%s %s: no result in\n%s", language, run, output)
			}
			t.Logf("%-10s %-11s %6d B  compile %7.1f ms  first %7.1f ms  warm median %6.1f ms  max %6.1f ms  cpu %6.1f ms  peak RSS %5.1f MiB  %d records  %d gaps",
				language, run, result.Bytes, result.CompileMillis, result.FirstMillis, result.WarmMedianMs, result.WarmMaxMs, result.WarmCPUMs, result.PeakResidentMB, result.Records, result.Gaps)
			if result.WarmMedianMs >= float64(gateWarmLimit.Milliseconds()) || result.PeakResidentMB >= gateResidentMiB || result.Gaps != 0 {
				failed = true
			}
		}
	}
	if failed {
		t.Fatal("the go/no-go gate is not met")
	}
}

// TestSyntaxGateChild is the measured process of TestSyntaxGate.
func TestSyntaxGateChild(t *testing.T) {
	language := syntaxanalysis.Language(os.Getenv("OPEN_TRESTLE_SYNTAX_GATE_CHILD"))
	if language == "" {
		t.Skip("run by TestSyntaxGate")
	}
	ctx := context.Background()
	unbounded := syntaxanalysis.DefaultLimits()
	unbounded.FileDeadline = time.Minute
	a, err := New(ctx, Config{CacheDirectory: os.Getenv("OPEN_TRESTLE_SYNTAX_GATE_CACHE"), Limits: unbounded})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(ctx)
	content := gateSource(t, language)
	path := strings.TrimPrefix(gateFixtures[language].path, "testdata/")
	f := a.languages[language].family
	started := time.Now()
	if _, _, err := f.compile(ctx, modeFast); err != nil {
		t.Fatal(err)
	}
	compile := time.Since(started)
	started = time.Now()
	first := analyze(t, a, path, content)
	firstTime := time.Since(started)
	times := make([]time.Duration, 0, gateWarmRuns)
	cpuBefore := processCPU(t)
	for range gateWarmRuns {
		started := time.Now()
		_ = analyze(t, a, path, content)
		times = append(times, time.Since(started))
	}
	cpu := (processCPU(t) - cpuBefore) / gateWarmRuns
	slices.Sort(times)
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	result := gateResult{
		Language: string(language), Bytes: len(content),
		CompileMillis: ms(compile), FirstMillis: ms(firstTime),
		WarmMedianMs: ms(times[len(times)/2]), WarmMaxMs: ms(times[len(times)-1]), WarmCPUMs: ms(cpu),
		PeakResidentMB: peakResidentMiB(t),
		Records:        len(first.Definitions) + len(first.References) + len(first.Imports),
		Gaps:           len(first.Gaps),
	}
	encoded, _ := json.Marshal(result)
	fmt.Printf("GATE %s\n", encoded)
}

// processCPU returns the user and system time the process has used, which
// other load on the machine affects less than wall-clock time.
func processCPU(t testing.TB) time.Duration {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		t.Fatal(err)
	}
	return time.Duration(usage.Utime.Nano() + usage.Stime.Nano())
}

func peakResidentMiB(t testing.TB) float64 {
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range bytes.Split(status, []byte("\n")) {
		if rest, ok := bytes.CutPrefix(line, []byte("VmHWM:")); ok {
			fields := strings.Fields(string(rest))
			kib, err := strconv.Atoi(fields[0])
			if err != nil {
				t.Fatal(err)
			}
			return float64(kib) / 1024
		}
	}
	t.Fatal("no VmHWM in /proc/self/status")
	return 0
}

// BenchmarkAnalyze measures warm analysis of the gate-sized file of each
// language with a query pack.
func BenchmarkAnalyze(b *testing.B) {
	a := testAnalyzer(b)
	for language, fixture := range gateFixtures {
		content := gateSource(b, language)
		path := strings.TrimPrefix(fixture.path, "testdata/")
		_ = analyze(b, a, path, content)
		b.Run(string(language), func(b *testing.B) {
			b.SetBytes(int64(len(content)))
			for b.Loop() {
				_ = analyze(b, a, path, content)
			}
		})
	}
}
