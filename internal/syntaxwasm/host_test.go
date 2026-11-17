package syntaxwasm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

var _ syntaxanalysis.Analyzer = (*Analyzer)(nil)

func newTestAnalyzer(t *testing.T, config Config) *Analyzer {
	t.Helper()
	if config.CacheDirectory == "" && runtime.GOOS == "linux" {
		config.CacheDirectory = sharedCacheDirectory(t)
	}
	a, err := New(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close(context.Background()) })
	if !a.Available() {
		t.Skip("the wazero compiler does not run on this platform")
	}
	return a
}

var (
	cacheOnce sync.Once
	cacheDir  string
)

// sharedCacheDirectory is one private compilation cache for the test
// binary, so analyzers created by different tests compile each module once.
func sharedCacheDirectory(t *testing.T) string {
	t.Helper()
	cacheOnce.Do(func() {
		dir, err := os.MkdirTemp("", "syntaxwasm-cache-")
		if err == nil && os.Chmod(dir, 0o700) == nil {
			cacheDir = dir
		}
	})
	if cacheDir == "" {
		t.Fatal("cannot create the test cache directory")
	}
	return cacheDir
}

func TestMain(m *testing.M) {
	code := m.Run()
	if cacheDir != "" {
		_ = os.RemoveAll(cacheDir)
	}
	os.Exit(code)
}

func onlyGap(t *testing.T, a syntaxanalysis.FileAnalysis, reason syntaxanalysis.GapReason, limit syntaxanalysis.Limit) {
	t.Helper()
	if len(a.Gaps) != 1 || a.Gaps[0].Reason != reason || a.Gaps[0].Limit != limit || a.Gaps[0].HasRange ||
		len(a.Definitions)+len(a.References)+len(a.Imports) != 0 {
		t.Fatalf("want one whole-file %s %s gap, got %+v", reason, limit, a)
	}
}

func hasGapWith(a syntaxanalysis.FileAnalysis, reason syntaxanalysis.GapReason, limit syntaxanalysis.Limit) bool {
	for _, g := range a.Gaps {
		if g.Reason == reason && g.Limit == limit {
			return true
		}
	}
	return false
}

func TestCommittedModulesMatchTheManifest(t *testing.T) {
	manifest, err := readManifest()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := moduleFiles.ReadDir("modules")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(manifest.Families)+1 {
		t.Fatalf("modules directory has %d entries for %d families", len(entries), len(manifest.Families))
	}
	languages := map[string]bool{}
	for _, f := range manifest.Families {
		if _, err := loadModule(f); err != nil {
			t.Fatalf("%s: %v", f.Name, err)
		}
		changed := f
		changed.WasmSHA256 = strings.Repeat("0", 64)
		if _, err := loadModule(changed); !errors.Is(err, errModule) {
			t.Fatalf("%s: a wrong digest was accepted", f.Name)
		}
		for _, l := range f.Languages {
			languages[l] = true
		}
	}
	for _, want := range []syntaxanalysis.Language{
		syntaxanalysis.LanguageJava, syntaxanalysis.LanguageJavaScript, syntaxanalysis.LanguageTypeScript,
		syntaxanalysis.LanguageTSX, syntaxanalysis.LanguagePython, syntaxanalysis.LanguageC, syntaxanalysis.LanguageCPP,
		syntaxanalysis.LanguageCSharp, syntaxanalysis.LanguageSwift, syntaxanalysis.LanguageRust, syntaxanalysis.LanguagePHP,
		syntaxanalysis.LanguageRuby, syntaxanalysis.LanguageHTML,
	} {
		if !languages[string(want)] {
			t.Fatalf("no family module has a grammar for %s", want)
		}
	}
}

func TestEveryFamilyInstantiatesAndDescribesItsLanguages(t *testing.T) {
	a := testAnalyzer(t)
	seen := map[*family]bool{}
	for language, entry := range a.languages {
		if seen[entry.family] {
			continue
		}
		seen[entry.family] = true
		inst, fail := entry.family.acquire(context.Background())
		if fail != nil {
			t.Fatalf("%s: %+v", language, fail)
		}
		if !slices.Equal(inst.languages, entry.family.manifest.Languages) {
			t.Fatalf("%s: languages %v", entry.family.manifest.Name, inst.languages)
		}
		entry.family.release(inst, true)
	}
}

func TestLanguagesWithoutQueryPacksReportAGap(t *testing.T) {
	a := testAnalyzer(t)
	for _, path := range []string{"a.rb", "a.html"} {
		language, _ := syntaxanalysis.LanguageForPath(path)
		if !a.Supports(language) || a.HasQueryPack(language) {
			t.Fatalf("%s: supports=%v pack=%v", path, a.Supports(language), a.HasQueryPack(language))
		}
		onlyGap(t, analyze(t, a, path, []byte("x")), syntaxanalysis.GapNoQueryPack, "")
	}
	source, _ := syntaxanalysis.NewSource("a.go", syntaxanalysis.LanguageGo, []byte("package a"))
	if _, err := a.Analyze(context.Background(), source); !errors.Is(err, syntaxanalysis.ErrInvalidInput) {
		t.Fatal("Go must be left to the go/parser analyzer")
	}
}

func TestUnavailableCompilerIsAGapNotTheInterpreter(t *testing.T) {
	saved := compilerAvailable
	compilerAvailable = func() bool { return false }
	defer func() { compilerAvailable = saved }()
	a, err := New(context.Background(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(context.Background())
	if a.Available() || a.runtime != nil {
		t.Fatal("no runtime may be created without the compiler")
	}
	onlyGap(t, analyze(t, a, "a.py", []byte("x = 1\n")), syntaxanalysis.GapAnalysisUnavailable, "")
}

func TestConfigValidation(t *testing.T) {
	for _, config := range []Config{
		{MemoryLimitPages: 70000},
		{InstancesPerFamily: -1},
		{Limits: syntaxanalysis.Limits{MaxFileBytes: 1}},
	} {
		if _, err := New(context.Background(), config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%+v accepted: %v", config, err)
		}
	}
}

func TestCacheDirectoryMustBePrivate(t *testing.T) {
	if runtime.GOOS != "linux" {
		for _, dir := range []string{t.TempDir(), ""} {
			if dir == "" {
				continue
			}
			if _, err := New(context.Background(), Config{CacheDirectory: dir}); !errors.Is(err, ErrCacheUntrusted) {
				t.Fatalf("cache directory accepted on %s", runtime.GOOS)
			}
		}
		return
	}
	base := t.TempDir()
	private := filepath.Join(base, "private")
	shared := filepath.Join(base, "shared")
	link := filepath.Join(base, "link")
	for _, dir := range []string{private, shared} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(shared, 0o770); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(private, link); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{"relative", shared, link, filepath.Join(base, "missing"), private + "/."} {
		if _, err := New(context.Background(), Config{CacheDirectory: dir}); !errors.Is(err, ErrCacheUntrusted) {
			t.Fatalf("%s accepted: %v", dir, err)
		}
	}
	a, err := New(context.Background(), Config{CacheDirectory: private})
	if err != nil {
		t.Fatal(err)
	}
	analysis := analyze(t, a, "a.py", []byte("def f():\n    pass\n"))
	_ = a.Close(context.Background())
	if len(analysis.Definitions) != 1 {
		t.Fatalf("analysis with a cache = %+v", analysis)
	}
	entries, _ := os.ReadDir(private)
	if len(entries) == 0 {
		t.Fatal("the compilation cache was not written")
	}
}

func TestFileSizeLimit(t *testing.T) {
	limits := syntaxanalysis.DefaultLimits()
	limits.MaxFileBytes = 1 << 20
	a := newTestAnalyzer(t, Config{Limits: limits})
	line := []byte("compute(alpha, beta, gamma)  # one call on each line of this file\n")
	atLimit := bytes.Repeat(line, (1<<20)/len(line))
	atLimit = append(atLimit, bytes.Repeat([]byte("#"), (1<<20)-len(atLimit))...)
	if len(atLimit) != 1<<20 {
		t.Fatal("fixture size")
	}
	analysis := analyze(t, a, "big.py", atLimit)
	if !analysis.Complete() || len(analysis.References) == 0 {
		t.Fatalf("file at the limit: gaps %+v, %d references", analysis.Gaps, len(analysis.References))
	}
	onlyGap(t, analyze(t, a, "big.py", append(atLimit, '\n')), syntaxanalysis.GapLimitExceeded, syntaxanalysis.LimitFileSize)
}

func TestRecordLimitIsAGap(t *testing.T) {
	limits := syntaxanalysis.DefaultLimits()
	limits.MaxRecords = 50
	a := newTestAnalyzer(t, Config{Limits: limits})
	analysis := analyze(t, a, "calls.py", bytes.Repeat([]byte("f()\n"), 500))
	if len(analysis.References) != 50 || !hasGapWith(analysis, syntaxanalysis.GapLimitExceeded, syntaxanalysis.LimitRecords) {
		t.Fatalf("%d references, gaps %+v", len(analysis.References), analysis.Gaps)
	}
}

func TestNameLengthLimitIsAGap(t *testing.T) {
	limits := syntaxanalysis.DefaultLimits()
	limits.MaxNameBytes = 64
	a := newTestAnalyzer(t, Config{Limits: limits})
	long := strings.Repeat("n", 65)
	analysis := analyze(t, a, "names.js", []byte("function "+long+"() {}\nfunction ok() {}\n"))
	if len(analysis.Definitions) != 1 || analysis.Definitions[0].Name.Untrusted() != "ok" || !hasGapWith(analysis, syntaxanalysis.GapLimitExceeded, syntaxanalysis.LimitNameLength) {
		t.Fatalf("definitions %+v, gaps %+v", analysis.Definitions, analysis.Gaps)
	}
}

func TestSyntaxErrorsAreRegionsAndTheRestIsAnalysed(t *testing.T) {
	a := testAnalyzer(t)
	cases := map[string]string{
		"broken.py":    "def before():\n    pass\n\ndef broken(:\n    return )\n\ndef after():\n    before()\n",
		"Broken.java":  "class A {\n  void before() {}\n  void broken( { int x = ; }\n  void after() { before(); }\n}\n",
		"broken.ts":    "function before(): void {}\nfunction broken(a: ) { let = ; }\nfunction after() { before(); }\n",
		"broken.js":    "function before() {}\nconst x = (;\nfunction after() { before(); }\n",
		"broken.c":     "int before(void) { return 1; }\nint broken(int a { return ; }\nint after(void) { return before(); }\n",
		"broken.cpp":   "void before() {}\nint broken(std::vector<int> a { return ; }\nvoid after() { before(); }\n",
		"Broken.cs":    "class A {\n  void before() {}\n  void broken( { int x = ; }\n  void after() { before(); }\n}\n",
		"broken.rs":    "fn before() {}\nfn broken( { let x = ; }\nfn after() { before(); }\n",
		"broken.swift": "func before() {}\nfunc broken( { let x = }\nfunc after() { before() }\n",
	}
	for path, content := range cases {
		analysis := analyze(t, a, path, []byte(content))
		names := map[string]bool{}
		for _, d := range analysis.Definitions {
			names[d.Name.Untrusted()] = true
		}
		if !names["before"] || !names["after"] {
			t.Fatalf("%s: definitions around the error are missing: %v", path, names)
		}
		regions := 0
		for _, g := range analysis.Gaps {
			if g.Reason != syntaxanalysis.GapParseError || !g.HasRange {
				t.Fatalf("%s: unexpected gap %+v", path, g)
			}
			regions++
		}
		if regions == 0 {
			t.Fatalf("%s: no parse error region", path)
		}
		calls := 0
		for _, r := range analysis.References {
			if r.Kind == syntaxanalysis.ReferenceCall && r.Name.Untrusted() == "before" && r.Enclosing >= 0 && analysis.Definitions[r.Enclosing].Name.Untrusted() == "after" {
				calls++
			}
		}
		if calls != 1 {
			t.Fatalf("%s: call after the error region not found", path)
		}
	}
}

func TestInvalidUTF8NeverReachesText(t *testing.T) {
	a := testAnalyzer(t)
	cases := map[string]string{
		"bad.py":    "def caf\xff\xfe():\n    pass\n\ndef good():\n    caf\xff\xfe()\n",
		"bad.js":    "function \xc3\x28x() {}\nimport y from \"mod\xff\";\nfunction good() {}\n",
		"Bad.java":  "class C\xff { void m\xe2\x82() {} void good() {} }\n",
		"bad.c":     "int caf\xff\xfe(void) { return 0; }\nint good(void) { return caf\xff\xfe(); }\n",
		"bad.cpp":   "struct S\xc3\x28 { void m\xe2\x82() {} };\nvoid good() { S\xc3\x28 s; }\n",
		"Bad.cs":    "class C\xff { void m\xe2\x82() {} void good() {} }\n",
		"bad.rs":    "fn caf\xff\xfe() {}\nfn good() { caf\xff\xfe(); }\n",
		"bad.swift": "func caf\xff\xfe() {}\nfunc good() { caf\xff\xfe() }\n",
	}
	for path, content := range cases {
		analysis := analyze(t, a, path, []byte(content))
		check := func(t2 syntaxanalysis.Text) {
			if !utf8.ValidString(t2.Untrusted()) {
				t.Fatalf("%s: invalid UTF-8 escaped into a record", path)
			}
		}
		good := false
		for _, d := range analysis.Definitions {
			check(d.Name)
			good = good || d.Name.Untrusted() == "good"
		}
		for _, r := range analysis.References {
			check(r.Name)
			check(r.Qualifier)
		}
		for _, i := range analysis.Imports {
			check(i.Source)
		}
		if !good || analysis.Complete() {
			t.Fatalf("%s: good=%v gaps=%+v", path, good, analysis.Gaps)
		}
	}
}

func TestDeeplyNestedInputDoesNotCrashOrHang(t *testing.T) {
	a := testAnalyzer(t)
	depth := 100000
	cases := map[string][]byte{
		"nested.js":    append(append([]byte("const x = "), bytes.Repeat([]byte("["), depth)...), bytes.Repeat([]byte("]"), depth)...),
		"nested.py":    append(append([]byte("x = "), bytes.Repeat([]byte("("), depth)...), bytes.Repeat([]byte(")"), depth)...),
		"Nested.java":  append(append([]byte("class A { int x = "), bytes.Repeat([]byte("("), depth)...), append(bytes.Repeat([]byte(")"), depth), []byte("1; }")...)...),
		"open.ts":      bytes.Repeat([]byte("{"), depth),
		"nested.c":     append(append([]byte("int x = "), bytes.Repeat([]byte("("), depth)...), bytes.Repeat([]byte(")"), depth)...),
		"nested.cpp":   append(append([]byte("auto x = "), bytes.Repeat([]byte("{"), depth)...), bytes.Repeat([]byte("}"), depth)...),
		"deep.cpp":     bytes.Repeat([]byte("namespace a { "), depth/10),
		"nested.rs":    append(append([]byte("const X: u8 = "), bytes.Repeat([]byte("("), depth)...), bytes.Repeat([]byte(")"), depth)...),
		"Nested.cs":    append(append([]byte("class A { int x = "), bytes.Repeat([]byte("("), depth)...), append(bytes.Repeat([]byte(")"), depth), []byte("1; }")...)...),
		"open.rs":      bytes.Repeat([]byte("{"), depth),
		"nested.swift": append(append([]byte("let x = "), bytes.Repeat([]byte("["), depth)...), bytes.Repeat([]byte("]"), depth)...),
		"open.swift":   bytes.Repeat([]byte("{"), depth),
	}
	for path, content := range cases {
		started := time.Now()
		analysis := analyze(t, a, path, content)
		if elapsed := time.Since(started); elapsed > 2*syntaxanalysis.DefaultLimits().FileDeadline {
			t.Fatalf("%s took %v", path, elapsed)
		}
		if analysis.Path != path {
			t.Fatalf("%s: analysis for %s", path, analysis.Path)
		}
	}
	// The analyzer still works after the hostile inputs.
	if got := analyze(t, a, "ok.py", []byte("def f():\n    pass\n")); len(got.Definitions) != 1 || !got.Complete() {
		t.Fatalf("analysis after hostile input = %+v", got)
	}
}

func TestVeryLongLines(t *testing.T) {
	a := testAnalyzer(t)
	var b strings.Builder
	for i := 0; b.Len() < 1<<20; i++ {
		b.WriteString("function f")
		b.WriteString(strings.Repeat("x", i%7))
		b.WriteString("() { return g(1, 2, 3, 4, 5, 6, 7, 8, 9, 10); } ")
	}
	analysis := analyze(t, a, "long.js", []byte(b.String()))
	if !analysis.Complete() || len(analysis.Definitions) < 1000 {
		t.Fatalf("%d definitions, gaps %+v", len(analysis.Definitions), analysis.Gaps)
	}
	last := analysis.References[len(analysis.References)-1]
	if last.Range.Start.Line != 1 || last.Range.Start.Column < 1<<19 {
		t.Fatalf("last reference at %+v", last.Range.Start)
	}
}

func TestDeadlineStopsARunawayParse(t *testing.T) {
	limits := syntaxanalysis.DefaultLimits()
	limits.FileDeadline = 5 * time.Millisecond
	a := newTestAnalyzer(t, Config{Limits: limits, InstancesPerFamily: 1})
	// Warm the instance and its query so the deadline covers the parse only.
	_ = analyze(t, a, "warm.ts", []byte("let a = 1;\n"))
	var b strings.Builder
	for b.Len() < 2<<20-256 {
		b.WriteString("export function handler(a: number, b: string): Promise<void> { return run(a, b.length, [a, b]); }\n")
	}
	content := []byte(b.String())
	started := time.Now()
	analysis := analyze(t, a, "large.ts", content)
	elapsed := time.Since(started)
	onlyGap(t, analysis, syntaxanalysis.GapDeadlineExceeded, "")
	if elapsed > time.Second {
		t.Fatalf("the deadline fired after %v", elapsed)
	}
	f := a.languages[syntaxanalysis.LanguageTypeScript].family
	f.mu.Lock()
	idle := len(f.idle)
	f.mu.Unlock()
	if idle != 0 {
		t.Fatal("the instance stopped by the deadline was kept")
	}
	// Without the deadline the same file takes much longer, so the gap
	// came from stopping the parse, not from a fast failure.
	unbounded := syntaxanalysis.DefaultLimits()
	unbounded.FileDeadline = 2 * time.Minute
	full := newTestAnalyzer(t, Config{Limits: unbounded})
	started = time.Now()
	complete := analyze(t, full, "large.ts", content)
	if !complete.Complete() || time.Since(started) < 10*limits.FileDeadline {
		t.Fatalf("full analysis: gaps %+v in %v", complete.Gaps, time.Since(started))
	}
	if got := analyze(t, a, "small.ts", []byte("function f() {}\n")); len(got.Definitions) != 1 {
		t.Fatalf("analysis after the deadline = %+v", got)
	}
}

func TestGuestIgnoringTheStopChecksIsContained(t *testing.T) {
	saved := stopRequested
	stopRequested = func(context.Context) bool { return false }
	restored := false
	restore := func() {
		if !restored {
			stopRequested = saved
			restored = true
		}
	}
	defer restore()
	limits := syntaxanalysis.DefaultLimits()
	limits.FileDeadline = 5 * time.Millisecond
	a := newTestAnalyzer(t, Config{Limits: limits, InstancesPerFamily: 1})
	var b strings.Builder
	for b.Len() < 2<<20-256 {
		b.WriteString("export function handler(a: number, b: string): Promise<void> { return run(a, b.length, [a, b]); }\n")
	}
	started := time.Now()
	analysis := analyze(t, a, "large.ts", []byte(b.String()))
	elapsed := time.Since(started)
	onlyGap(t, analysis, syntaxanalysis.GapDeadlineExceeded, "")
	if elapsed > 2*time.Second {
		t.Fatalf("the watchdog fired after %v", elapsed)
	}
	f := a.languages[syntaxanalysis.LanguageTypeScript].family
	f.mu.Lock()
	switched := f.terminating
	f.mu.Unlock()
	if !switched {
		t.Fatal("the family did not switch to terminating code")
	}
	// With terminating code the deadline holds even while the guest's stop
	// checks are still ignored. The small file first compiles that code.
	if got := analyze(t, a, "small.ts", []byte("function f() {}\n")); len(got.Definitions) != 1 {
		t.Fatalf("analysis with terminating code = %+v", got)
	}
	started = time.Now()
	onlyGap(t, analyze(t, a, "large.ts", []byte(b.String())), syntaxanalysis.GapDeadlineExceeded, "")
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("terminating code stopped after %v", elapsed)
	}
	restore()
	if got := analyze(t, a, "small.ts", []byte("function f() {}\n")); len(got.Definitions) != 1 {
		t.Fatalf("analysis with terminating code = %+v", got)
	}
	// Close waits for no orphan and must not unmap code an orphan runs.
	for deadline := time.Now().Add(30 * time.Second); ; {
		a.mu.Lock()
		orphans := a.orphans
		a.mu.Unlock()
		if orphans == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the orphaned call never finished")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestMemoryLimitIsAGap(t *testing.T) {
	probe := newTestAnalyzer(t, Config{})
	f := probe.languages[syntaxanalysis.LanguagePython].family
	compiled, _, err := f.compile(context.Background(), modeFast)
	if err != nil {
		t.Fatal(err)
	}
	initial := compiled.ExportedMemories()["memory"].Min()
	a := newTestAnalyzer(t, Config{MemoryLimitPages: initial + 256})
	if got := analyze(t, a, "small.py", []byte("def f():\n    pass\n")); len(got.Definitions) != 1 {
		t.Fatalf("small file under the memory cap = %+v", got)
	}
	big := bytes.Repeat([]byte("def f(a, b):\n    return g(a, [b, b], {a: b})\n"), 30000)
	onlyGap(t, analyze(t, a, "big.py", big), syntaxanalysis.GapLimitExceeded, syntaxanalysis.LimitMemory)
	if got := analyze(t, a, "small.py", []byte("def f():\n    pass\n")); len(got.Definitions) != 1 {
		t.Fatalf("analysis after the memory limit = %+v", got)
	}
}

func TestConcurrentAnalysesMatchSequentialOnes(t *testing.T) {
	a := newTestAnalyzer(t, Config{InstancesPerFamily: 2})
	inputs := map[string][]byte{
		"a.py":   []byte("import os\n\ndef a():\n    os.path.join('x')\n"),
		"b.js":   []byte("import x from 'y';\nexport function b() { x(); }\n"),
		"c.ts":   []byte("interface C { m(): void }\nclass D implements C { m() {} }\n"),
		"D.java": []byte("class D { void m() { n(); } void n() {} }\n"),
	}
	want := map[string]string{}
	for path, content := range inputs {
		want[path] = renderGolden(analyze(t, a, path, content))
	}
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for i := 0; i < 16; i++ {
		for path, content := range inputs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				language, _ := syntaxanalysis.LanguageForPath(path)
				source, _ := syntaxanalysis.NewSource(path, language, content)
				got, err := a.Analyze(context.Background(), source)
				if err != nil || renderGolden(got) != want[path] {
					errs <- path
				}
			}()
		}
	}
	wg.Wait()
	close(errs)
	for path := range errs {
		t.Fatalf("concurrent analysis of %s differs", path)
	}
}

func TestCancelledContextIsAnError(t *testing.T) {
	a := testAnalyzer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	source, _ := syntaxanalysis.NewSource("a.py", syntaxanalysis.LanguagePython, []byte("x = 1\n"))
	if _, err := a.Analyze(ctx, source); !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}

func TestClosedAnalyzerReportsUnavailable(t *testing.T) {
	a, err := New(context.Background(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Available() {
		t.Skip("the wazero compiler does not run on this platform")
	}
	_ = analyze(t, a, "a.py", []byte("x = 1\n"))
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	onlyGap(t, analyze(t, a, "a.py", []byte("x = 1\n")), syntaxanalysis.GapAnalysisUnavailable, "")
}

func TestResultPointersAreBoundsChecked(t *testing.T) {
	a := testAnalyzer(t)
	f := a.languages[syntaxanalysis.LanguagePython].family
	inst, fail := f.acquire(context.Background())
	if fail != nil {
		t.Fatal(fail)
	}
	defer f.release(inst, false)
	size := inst.memory.Size()
	for _, pointer := range []uint32{0, size - 4, size, 0xffffffff} {
		if _, err := inst.result(pointer); !errors.Is(err, errProtocol) {
			t.Fatalf("pointer %#x accepted", pointer)
		}
	}
	// A header that claims more bytes than the memory holds.
	header := make([]byte, 8)
	binary.LittleEndian.PutUint32(header, resultMagic)
	binary.LittleEndian.PutUint32(header[4:], 0xfffffff0)
	if !inst.memory.Write(size-16, header) {
		t.Fatal("write")
	}
	if _, err := inst.result(size - 16); !errors.Is(err, errProtocol) {
		t.Fatal("an oversized result length was accepted")
	}
}

func TestCloseWaitsForAnalysesInProgress(t *testing.T) {
	a, err := New(context.Background(), Config{CacheDirectory: sharedCacheDirectory(t), InstancesPerFamily: 4})
	if err != nil {
		t.Fatal(err)
	}
	if !a.Available() {
		t.Skip("the wazero compiler does not run on this platform")
	}
	content := bytes.Repeat([]byte("def f(a):\n    return g(a, [a, a])\n"), 3000)
	_ = analyze(t, a, "warm.py", content)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 5 {
				source, _ := syntaxanalysis.NewSource("f.py", syntaxanalysis.LanguagePython, content)
				got, err := a.Analyze(context.Background(), source)
				if err != nil {
					t.Error(err)
					return
				}
				if !got.Complete() && !hasGapWith(got, syntaxanalysis.GapAnalysisUnavailable, "") {
					t.Errorf("unexpected gaps %+v", got.Gaps)
					return
				}
			}
		}()
	}
	time.Sleep(20 * time.Millisecond)
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}
