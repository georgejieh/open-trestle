package syntaxwasm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/tetratelabs/wazero"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

var _ syntaxanalysis.Analyzer = (*Analyzer)(nil)

// testConfig adds the shared compilation cache where the platform accepts
// a cache directory.
func testConfig(t *testing.T, config Config) Config {
	t.Helper()
	if config.CacheDirectory == "" && cacheAccepted() {
		config.CacheDirectory = sharedCacheDirectory(t)
	}
	return config
}

func newTestAnalyzer(t *testing.T, config Config) *Analyzer {
	t.Helper()
	a, err := New(context.Background(), testConfig(t, config))
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

// cacheAccepted reports whether this platform accepts a private cache
// directory; macOS and Windows refuse every one.
func cacheAccepted() bool {
	dir, err := os.MkdirTemp("", "syntaxwasm-probe-")
	if err != nil {
		return false
	}
	defer os.RemoveAll(dir)
	_, err = privateCacheDirectory(dir)
	return err == nil
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

// TestEveryFamilyInstantiatesAndDescribesItsLanguages acquires one
// instance per family; acquiring checks the exports, the ABI version and
// that the module describes the manifest's languages.
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
		entry.family.release(inst, true)
	}
}

func TestLanguagesWithoutQueryPacksReportAGap(t *testing.T) {
	a := newTestAnalyzer(t, Config{})
	for language, entry := range a.languages {
		if entry.pack == nil {
			t.Fatalf("%s has a grammar in a family module but no query pack", language)
		}
	}
	// A grammar without a pack, as when a family gains a language before
	// its pack is written, reports only a no_query_pack gap.
	entry := a.languages[syntaxanalysis.LanguageHTML]
	entry.pack = nil
	a.languages[syntaxanalysis.LanguageHTML] = entry
	if !a.Supports(syntaxanalysis.LanguageHTML) || a.HasQueryPack(syntaxanalysis.LanguageHTML) {
		t.Fatal("the language without a pack must stay supported")
	}
	onlyGap(t, analyze(t, a, "a.html", []byte("<p id=x></p>")), syntaxanalysis.GapNoQueryPack, "")
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

func TestEngineFailureIsUnavailable(t *testing.T) {
	if !compilerAvailable() {
		t.Skip("the wazero compiler does not run on this platform")
	}
	saved := newWazeroRuntime
	newWazeroRuntime = func(context.Context, wazero.RuntimeConfig) wazero.Runtime { panic("no executable memory") }
	defer func() { newWazeroRuntime = saved }()
	a, err := New(context.Background(), Config{})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close(context.Background())
	if a.Available() {
		t.Fatal("an engine that failed to start was reported available")
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
	if !cacheAccepted() {
		if _, err := New(context.Background(), Config{CacheDirectory: t.TempDir()}); !errors.Is(err, ErrCacheUntrusted) {
			t.Fatalf("cache directory accepted: %v", err)
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

func TestMalformedResultSpansFailTheFileAndDiscardTheInstance(t *testing.T) {
	content := []byte("class Box { void f() {} }")
	roles := []role{{kind: roleDefinition, definition: syntaxanalysis.KindClass}, {kind: roleName}}
	// The name lies outside the node it names.
	result := analysisResult{matches: []match{{captures: []capture{{index: 0, start: 10, end: 20}, {index: 1, start: 1, end: 2}}}}}
	if _, _, err := rawFile(content, result, roles); !errors.Is(err, errProtocol) {
		t.Fatalf("a name outside its node was accepted: %v", err)
	}
	source, _ := syntaxanalysis.NewSource("Box.cs", syntaxanalysis.LanguageCSharp, content)
	raw := syntaxanalysis.RawFile{Definitions: []syntaxanalysis.RawDefinition{{Kind: syntaxanalysis.KindClass, Name: syntaxanalysis.Span{Start: 1, End: 2}, Node: syntaxanalysis.Span{Start: 10, End: 20}}}}
	if got := syntaxanalysis.Assemble(source, Identity, raw, syntaxanalysis.DefaultLimits()); !hasGapWith(got, syntaxanalysis.GapAnalysisFailed, "") {
		t.Fatalf("Assemble accepted a name outside its node: %+v", got)
	}
}

func TestPanicInHostCodeIsAnAnalysisFailure(t *testing.T) {
	a := newTestAnalyzer(t, Config{})
	entry := a.languages[syntaxanalysis.LanguagePython]
	p := *entry.pack
	p.finish = func([]byte, syntaxanalysis.RawFile, *syntaxanalysis.FileAnalysis) { panic("defect") }
	entry.pack = &p
	a.languages[syntaxanalysis.LanguagePython] = entry
	onlyGap(t, analyze(t, a, "a.py", []byte("def f():\n    pass\n")), syntaxanalysis.GapAnalysisFailed, "")
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
	for range 16 {
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
	a, err := New(context.Background(), testConfig(t, Config{}))
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
	a, err := New(context.Background(), testConfig(t, Config{InstancesPerFamily: 4}))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Available() {
		t.Skip("the wazero compiler does not run on this platform")
	}
	content := bytes.Repeat([]byte("def f(a):\n    return g(a, [a, a])\n"), 3000)
	_ = analyze(t, a, "warm.py", content)
	// Close runs once a guest is inside an analysis.
	running := make(chan struct{})
	var once sync.Once
	saved := stopRequested
	stopRequested = func(ctx context.Context) bool {
		once.Do(func() { close(running) })
		return saved(ctx)
	}
	defer func() { stopRequested = saved }()
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
	<-running
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestNewInstancesStartFromTheFamilyImage(t *testing.T) {
	ctx := context.Background()
	a := newTestAnalyzer(t, Config{InstancesPerFamily: 2})
	f := a.languages[syntaxanalysis.LanguageCPP].family
	cIndex := slices.Index(f.manifest.Languages, string(syntaxanalysis.LanguageC))
	cppIndex := slices.Index(f.manifest.Languages, string(syntaxanalysis.LanguageCPP))
	image := func() *memoryImage {
		f.mu.Lock()
		defer f.mu.Unlock()
		return f.image
	}
	// A file whose text must never reach the image.
	marker := []byte("int image_marker_5e1f9c(void);\n")
	if got := analyze(t, a, "marker.c", marker); len(got.Definitions) != 1 {
		t.Fatalf("analysis = %+v", got)
	}
	if _, ok := image().queries[cIndex]; !ok {
		t.Fatal("the compiled C query did not become the family image")
	}
	// The instance that analysed the C file lacks the C++ query and has
	// seen repository content, so a fresh instance compiles it.
	content, err := os.ReadFile("testdata/cpp/scheduler.cpp")
	if err != nil {
		t.Fatal(err)
	}
	want, err := os.ReadFile("testdata/cpp/scheduler.cpp.golden")
	if err != nil {
		t.Fatal(err)
	}
	if got := renderGolden(analyze(t, a, "testdata/cpp/scheduler.cpp", content)); got != string(want) {
		t.Fatal("the C++ analysis differs from its golden file")
	}
	queries := image().queries
	if _, ok := queries[cppIndex]; !ok {
		t.Fatal("the image lacks the C++ query")
	}
	if _, ok := queries[cIndex]; !ok {
		t.Fatal("the image lacks the C query")
	}
	for _, page := range image().pages {
		if bytes.Contains(page, []byte("image_marker_5e1f9c")) {
			t.Fatal("repository content reached the family image")
		}
	}
	// A second instance starts from the image with both queries compiled,
	// and analyses exactly like the first.
	first, fail := f.acquire(ctx)
	if fail != nil {
		t.Fatal(fail)
	}
	second, fail := f.acquire(ctx)
	if fail != nil {
		t.Fatal(fail)
	}
	for _, inst := range []*instance{first, second} {
		if _, ok := inst.queries[cppIndex]; !ok {
			t.Fatal("an instance lacks the compiled C++ query")
		}
	}
	f.release(first, true)
	f.release(second, true)
	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			source, _ := syntaxanalysis.NewSource("testdata/cpp/scheduler.cpp", syntaxanalysis.LanguageCPP, content)
			got, err := a.Analyze(ctx, source)
			if err != nil || renderGolden(got) != string(want) {
				errs <- "an analysis on a pooled instance differs from the golden file"
			}
		}()
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}
}
