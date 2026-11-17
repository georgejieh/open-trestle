package adapter

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"os"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/betterleaks/betterleaks/report"
	"github.com/betterleaks/betterleaks/sources"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
)

func newTestAdapter(run func(context.Context, sources.Source) iter.Seq[detect.Result], totalBytes func() uint64, deadline time.Duration) *Adapter {
	return &Adapter{
		runtime:      detectorRuntime{run: run, totalBytes: totalBytes},
		deadline:     deadline,
		buildProfile: protocol.BuildProfile,
	}
}

type qualificationIdentity struct {
	Scanner          string `json:"scanner"`
	ScannerVersion   string `json:"scanner_version"`
	ScannerCommit    string `json:"scanner_commit"`
	RulesetIdentity  string `json:"ruleset_identity"`
	RulesetRuleCount int    `json:"ruleset_rule_count"`
	BuildProfile     string `json:"build_profile"`
}

type qualificationOccurrence struct {
	Name              string `json:"name"`
	AcceptedDetection bool   `json:"accepted_detection"`
	SpanID            string `json:"span_id"`
}

type qualificationFixture struct {
	ID            string                    `json:"id"`
	ContentBase64 string                    `json:"content_base64"`
	Occurrences   []qualificationOccurrence `json:"occurrences"`
}

type qualificationFinding struct {
	RuleID string `json:"rule_id"`
	SpanID string `json:"span_id"`
}

type qualificationCoverage struct {
	ScannerIdentity qualificationIdentity  `json:"scanner_identity"`
	Fixtures        []qualificationFixture `json:"fixtures"`
	NearMiss        struct {
		ID            string                 `json:"id"`
		ContentBase64 string                 `json:"content_base64"`
		Findings      []qualificationFinding `json:"findings"`
	} `json:"near_miss"`
}

type qualificationSpan struct {
	ID               string `json:"id"`
	FixtureID        string `json:"fixture_id"`
	RuleID           string `json:"rule_id"`
	StartLine        int    `json:"start_line"`
	EndLine          int    `json:"end_line"`
	StartColumn      int    `json:"start_column"`
	EndColumn        int    `json:"end_column"`
	StartByte        int    `json:"start_byte"`
	EndByteExclusive int    `json:"end_byte_exclusive"`
}

type qualificationSpans struct {
	Spans []qualificationSpan `json:"spans"`
}

func TestPinnedRuleIDInventoryMatchesHostAllowlist(t *testing.T) {
	inventory := strings.Join(pinnedRuleIDsV1[:], "\n") + "\n"
	digest := sha256.Sum256([]byte(inventory))
	if got := hex.EncodeToString(digest[:]); got != "de5e47aa6bcf8e4379d5ecd85d460aea0d6baf50bdfe6877fbd80052ae237f45" {
		t.Fatalf("worker rule ID inventory differs from the host allowlist: %s", got)
	}
	if !sort.StringsAreSorted(pinnedRuleIDsV1[:]) || len(pinnedRuleIDsV1) != protocol.RulesetRuleCount {
		t.Fatal("worker rule ID inventory is not the exact sorted pin")
	}
}

func TestPinnedInitializationAndDisabledFeatures(t *testing.T) {
	if internalScanDeadline != 5*time.Second {
		t.Fatal("internal scan deadline is not five seconds")
	}
	adapter, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if adapter.detector.MaxDecodeDepth != 0 || !adapter.detector.MatchContext.IsZero() || adapter.detector.MinConfidence != "" || !adapter.detector.IgnoreGitleaksAllow || !adapter.detector.SkipFindingAppend {
		t.Fatal("detector policy differs from the pinned profile")
	}
	if adapter.detector.ValidationPool != nil || adapter.detector.RuleTimings != nil || adapter.detector.ReportPath != "" || adapter.detector.Reporter != nil || adapter.detector.MaxArchiveDepth != 0 {
		t.Fatal("disabled detector feature is configured")
	}
	if got := len(adapter.detector.Config.Rules); got != protocol.RulesetRuleCount {
		t.Fatalf("got %d rules, want %d", got, protocol.RulesetRuleCount)
	}
}

func TestSingleFragmentSourceYieldsWholeContentWithoutAttributes(t *testing.T) {
	content := bytes.Repeat([]byte("x"), 256*1024)
	source := newSingleFragmentSource(content)
	calls := 0
	err := source.Fragments(context.Background(), func(fragment sources.Fragment, err error) error {
		calls++
		if err != nil || fragment.Raw != string(content) || fragment.StartLine != 1 || fragment.Bytes != nil || len(fragment.Attributes) != 0 {
			t.Fatal("single fragment source changed content or added metadata")
		}
		return nil
	})
	if err != nil || calls != 1 || !source.completed.Load() {
		t.Fatalf("source did not complete exactly once: calls=%d err=%v", calls, err)
	}
}

func TestSingleFragmentSourceRequiresSuccessfulPostYieldContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := newSingleFragmentSource([]byte("value"))
	err := source.Fragments(ctx, func(fragment sources.Fragment, err error) error {
		cancel()
		return nil
	})
	if !errors.Is(err, context.Canceled) || source.completed.Load() {
		t.Fatal("source completed after post-yield cancellation")
	}

	callbackErr := errors.New("callback failed")
	source = newSingleFragmentSource([]byte("value"))
	if err := source.Fragments(context.Background(), func(sources.Fragment, error) error { return callbackErr }); !errors.Is(err, callbackErr) || source.completed.Load() {
		t.Fatal("source completed after callback error")
	}
}

func TestExactCoordinateProjectionRoundTripsByteColumns(t *testing.T) {
	content := []byte("β prefix\r\nsecond\nthird")
	cases := []findingCoordinates{
		{RuleID: "github-oauth", StartLine: 1, EndLine: 1, StartColumn: 4, EndColumn: 9},
		{RuleID: "github-oauth", StartLine: 1, EndLine: 2, StartColumn: 4, EndColumn: 6},
		{RuleID: "github-oauth", StartLine: 2, EndLine: 3, StartColumn: 1, EndColumn: 5},
	}
	for _, finding := range cases {
		match, ok := projectFinding(7, content, finding, pinnedRuleIDSet())
		if !ok {
			t.Fatalf("valid finding rejected: %#v", finding)
		}
		if !utf8.Valid(content[match.StartByte:match.EndByteExclusive]) {
			t.Fatal("projection split UTF-8")
		}
	}
}

func TestCoordinateProjectionRejectsInvalidOrNonRoundTripSpans(t *testing.T) {
	content := []byte("βeta\nnext\n")
	cases := []findingCoordinates{
		{RuleID: "unknown", StartLine: 1, EndLine: 1, StartColumn: 1, EndColumn: 1},
		{RuleID: "github-oauth", StartLine: 0, EndLine: 1, StartColumn: 1, EndColumn: 1},
		{RuleID: "github-oauth", StartLine: 1, EndLine: 1, StartColumn: 0, EndColumn: 1},
		{RuleID: "github-oauth", StartLine: 1, EndLine: 2, StartColumn: 2, EndColumn: 0},
		{RuleID: "github-oauth", StartLine: 1, EndLine: 1, StartColumn: 2, EndColumn: 3},
		{RuleID: "github-oauth", StartLine: 3, EndLine: 3, StartColumn: 1, EndColumn: 2},
	}
	for _, finding := range cases {
		if _, ok := projectFinding(0, content, finding, pinnedRuleIDSet()); ok {
			t.Fatalf("invalid finding accepted: %#v", finding)
		}
	}
}

func TestQualificationFixturesAreRealScannerOracles(t *testing.T) {
	adapter, err := New()
	if err != nil {
		t.Fatal(err)
	}
	coverage := readCoverage(t)
	spans := readSpans(t)
	spanByFixture := make(map[string][]qualificationSpan)
	for _, span := range spans.Spans {
		spanByFixture[span.FixtureID] = append(spanByFixture[span.FixtureID], span)
	}

	fixtures := append([]qualificationFixture(nil), coverage.Fixtures...)
	fixtures = append(fixtures, qualificationFixture{ID: coverage.NearMiss.ID, ContentBase64: coverage.NearMiss.ContentBase64})
	wantIdentity := qualificationIdentity{
		Scanner:          protocol.ScannerName,
		ScannerVersion:   protocol.ScannerVersion,
		ScannerCommit:    protocol.ScannerCommit,
		RulesetIdentity:  protocol.RulesetIdentity,
		RulesetRuleCount: protocol.RulesetRuleCount,
		BuildProfile:     protocol.BuildProfile,
	}
	if coverage.ScannerIdentity != wantIdentity {
		t.Fatal("qualification identity differs from the adapter pin")
	}
	detections := 0
	for run := 0; run < 3; run++ {
		for _, fixture := range fixtures {
			content, err := base64.StdEncoding.DecodeString(fixture.ContentBase64)
			if err != nil {
				t.Fatal(err)
			}
			response := adapter.Scan(context.Background(), protocol.Request{
				SchemaVersion: 1,
				RequestID:     strings.Repeat("a", 64),
				Sources:       []protocol.Source{{Ordinal: 0, Content: content}},
			})
			if response.Status != protocol.StatusComplete {
				t.Fatalf("run %d fixture %s did not complete", run, fixture.ID)
			}
			want := spanByFixture[fixture.ID]
			if len(response.Matches) != len(want) {
				t.Fatalf("run %d fixture %s produced %d matches, want %d", run, fixture.ID, len(response.Matches), len(want))
			}
			for index, match := range response.Matches {
				expected := want[index]
				if match.RuleID != expected.RuleID || match.StartByte != expected.StartByte || match.EndByteExclusive != expected.EndByteExclusive {
					t.Fatalf("run %d fixture %s match %d = %#v, want %#v", run, fixture.ID, index, match, expected)
				}
			}
			detections += len(response.Matches)
		}
	}
	if detections != 36 {
		t.Fatalf("got %d qualification findings across three runs, want 36", detections)
	}
}

func TestSequentialSourcesPreserveRepeatsAndCanonicalOrder(t *testing.T) {
	coverage := readCoverage(t)
	var repeat qualificationFixture
	for _, fixture := range coverage.Fixtures {
		if fixture.ID == "oauth-repeat-unicode-crlf" {
			repeat = fixture
		}
	}
	content, err := base64.StdEncoding.DecodeString(repeat.ContentBase64)
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := New()
	if err != nil {
		t.Fatal(err)
	}
	response := adapter.Scan(context.Background(), protocol.Request{
		SchemaVersion: 1,
		RequestID:     strings.Repeat("b", 64),
		Sources: []protocol.Source{
			{Ordinal: 0, Content: content},
			{Ordinal: 1, Content: content},
		},
	})
	if response.Status != protocol.StatusComplete || len(response.Matches) != 4 {
		t.Fatalf("unexpected repeated result: %s, %d matches", response.Status, len(response.Matches))
	}
	for index := 1; index < len(response.Matches); index++ {
		if !matchLess(response.Matches[index-1], response.Matches[index]) {
			t.Fatal("matches are not in canonical order")
		}
	}
	seen := make(map[string]struct{})
	for _, match := range response.Matches {
		if _, exists := seen[match.OccurrenceID]; exists {
			t.Fatal("repeat occurrence IDs are not content-independent locations")
		}
		seen[match.OccurrenceID] = struct{}{}
	}
}

func TestGitleaksAllowMarkerCannotSuppressFinding(t *testing.T) {
	coverage := readCoverage(t)
	content, err := base64.StdEncoding.DecodeString(coverage.Fixtures[0].ContentBase64)
	if err != nil {
		t.Fatal(err)
	}
	content = append(content, []byte(" // gitleaks:allow")...)
	adapter, err := New()
	if err != nil {
		t.Fatal(err)
	}
	response := adapter.Scan(context.Background(), protocol.Request{
		SchemaVersion: 1,
		RequestID:     strings.Repeat("c", 64),
		Sources:       []protocol.Source{{Ordinal: 0, Content: content}},
	})
	if response.Status != protocol.StatusComplete || len(response.Matches) != 1 {
		t.Fatal("repository allow marker suppressed a finding")
	}
}

func TestResponseProjectionContainsNoUpstreamFindingData(t *testing.T) {
	coverage := readCoverage(t)
	content, _ := base64.StdEncoding.DecodeString(coverage.Fixtures[0].ContentBase64)
	adapter, err := New()
	if err != nil {
		t.Fatal(err)
	}
	request := protocol.Request{SchemaVersion: 1, RequestID: strings.Repeat("d", 64), Sources: []protocol.Source{{Ordinal: 0, Content: content}}}
	response := adapter.Scan(context.Background(), request)
	frame, err := protocol.EncodeResponseFrame(response, protocol.ResponseExpectation{Request: request, RulesetIdentity: protocol.RulesetIdentity, RuleIDs: pinnedRuleIDSet()})
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{
		content,
		[]byte(base64.StdEncoding.EncodeToString(content)),
		[]byte("NOTREAL"),
		[]byte(`"Match"`), []byte(`"Secret"`), []byte(`"Fingerprint"`),
		[]byte(`"Line"`), []byte(`"CaptureGroups"`), []byte(`"ValidationMeta"`),
	} {
		if bytes.Contains(frame, forbidden) {
			t.Fatalf("serialized response contains forbidden data %q", forbidden)
		}
	}
}

func TestResultErrorDrainsAndDiscardsMatches(t *testing.T) {
	var yielded atomic.Int32
	var byteCount atomic.Uint64
	adapter := newTestAdapter(func(ctx context.Context, source sources.Source) iter.Seq[detect.Result] {
		return func(yield func(detect.Result) bool) {
			_ = source.Fragments(ctx, func(fragment sources.Fragment, err error) error {
				byteCount.Add(uint64(len(fragment.Raw)))
				yielded.Add(1)
				_ = yield(detect.Result{Finding: report.Finding{RuleID: "github-oauth", StartLine: 1, EndLine: 1, StartColumn: 1, EndColumn: 1}})
				yielded.Add(1)
				_ = yield(detect.Result{Err: errors.New("upstream secret: NOTREAL")})
				yielded.Add(1)
				_ = yield(detect.Result{Finding: report.Finding{RuleID: "github-oauth", StartLine: 1, EndLine: 1, StartColumn: 2, EndColumn: 2}})
				return nil
			})
		}
	}, byteCount.Load, time.Second)
	request := requestWithContent("abc")
	response := adapter.Scan(context.Background(), request)
	if response.Status != protocol.StatusScanFailed || len(response.Matches) != 0 || yielded.Load() != 3 {
		t.Fatal("result error did not drain and discard all matches")
	}
	frame, err := protocol.EncodeResponseFrame(response, protocol.ResponseExpectation{
		Request: request, RulesetIdentity: protocol.RulesetIdentity, RuleIDs: pinnedRuleIDSet(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(frame, []byte("NOTREAL")) || bytes.Contains(frame, []byte("upstream secret")) {
		t.Fatal("upstream error content was serialized")
	}
}

func TestByteCountAndSourceCompletionAreRequired(t *testing.T) {
	for name, run := range map[string]func(context.Context, sources.Source) iter.Seq[detect.Result]{
		"no source": func(context.Context, sources.Source) iter.Seq[detect.Result] { return emptyResults() },
		"early iterator stop": func(ctx context.Context, source sources.Source) iter.Seq[detect.Result] {
			return func(yield func(detect.Result) bool) {
				_ = source.Fragments(ctx, func(sources.Fragment, error) error { return errors.New("stop") })
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			adapter := newTestAdapter(run, func() uint64 { return 0 }, time.Second)
			response := adapter.Scan(context.Background(), requestWithContent("abc"))
			if response.Status != protocol.StatusScanFailed || len(response.Matches) != 0 {
				t.Fatal("incomplete source was published")
			}
		})
	}
}

func TestInternalDeadlineCancelsAndDrains(t *testing.T) {
	var returned atomic.Bool
	adapter := newTestAdapter(func(ctx context.Context, source sources.Source) iter.Seq[detect.Result] {
		return func(yield func(detect.Result) bool) {
			_ = source.Fragments(ctx, func(sources.Fragment, error) error {
				<-ctx.Done()
				returned.Store(true)
				return ctx.Err()
			})
		}
	}, func() uint64 { return 0 }, 5*time.Millisecond)
	response := adapter.Scan(context.Background(), requestWithContent("abc"))
	if response.Status != protocol.StatusScanFailed || len(response.Matches) != 0 || !returned.Load() {
		t.Fatal("deadline did not cancel, drain, and fail closed")
	}
}

func TestMatchCapCancelsDrainsAndReturnsResourceExhausted(t *testing.T) {
	var emitted atomic.Int32
	var runCalls atomic.Int32
	var byteCount atomic.Uint64
	adapter := newTestAdapter(func(ctx context.Context, source sources.Source) iter.Seq[detect.Result] {
		return func(yield func(detect.Result) bool) {
			runCalls.Add(1)
			_ = source.Fragments(ctx, func(fragment sources.Fragment, err error) error {
				byteCount.Add(uint64(len(fragment.Raw)))
				for index := 0; index < maximumMatches+10; index++ {
					emitted.Add(1)
					_ = yield(detect.Result{Finding: report.Finding{RuleID: "github-oauth", StartLine: 1, EndLine: 1, StartColumn: 1, EndColumn: 1}})
				}
				return nil
			})
		}
	}, byteCount.Load, time.Second)
	request := requestWithContent("a")
	request.Sources = append(request.Sources, protocol.Source{Ordinal: 1, Content: []byte("b")})
	response := adapter.Scan(context.Background(), request)
	if response.Status != protocol.StatusResourceExhausted || len(response.Matches) != 0 || emitted.Load() != maximumMatches+10 || runCalls.Load() != 1 {
		t.Fatal("match cap did not cancel, drain, discard, and stop later sources")
	}
}

func TestDecodeFilesystemRemoteAndReportingPathsAreAbsent(t *testing.T) {
	for _, path := range []string{"adapter.go", "source.go"} {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{
			"betterleaks/cmd", "DetectSource", "sources.File", "sources.Files",
			"sources.Directory", "sources.Remote", "AddGitleaksIgnore", ".SkipFunc(",
			"ReportPath =", "Reporter =", "--timeout", "datastore", "archive",
		} {
			if strings.Contains(string(encoded), forbidden) {
				t.Fatalf("%s contains forbidden path %q", path, forbidden)
			}
		}
	}

	coverage := readCoverage(t)
	content, err := base64.StdEncoding.DecodeString(coverage.Fixtures[0].ContentBase64)
	if err != nil {
		t.Fatal(err)
	}
	encodedContent := []byte(base64.StdEncoding.EncodeToString(content))
	adapter, err := New()
	if err != nil {
		t.Fatal(err)
	}
	response := adapter.Scan(context.Background(), protocol.Request{
		SchemaVersion: 1,
		RequestID:     strings.Repeat("f", 64),
		Sources:       []protocol.Source{{Ordinal: 0, Content: encodedContent}},
	})
	if response.Status != protocol.StatusComplete || len(response.Matches) != 0 {
		t.Fatal("encoded content was decoded or otherwise reported")
	}
}

func TestMaximumSequentialEmptySourcesComplete(t *testing.T) {
	adapter, err := New()
	if err != nil {
		t.Fatal(err)
	}
	sourceList := make([]protocol.Source, maximumSources)
	for index := range sourceList {
		sourceList[index] = protocol.Source{Ordinal: index, Content: []byte{}}
	}
	response := adapter.Scan(context.Background(), protocol.Request{
		SchemaVersion: 1,
		RequestID:     strings.Repeat("1", 64),
		Sources:       sourceList,
	})
	if response.Status != protocol.StatusComplete || len(response.Matches) != 0 {
		t.Fatal("maximum sequential empty-source request did not complete")
	}
}

func TestCanceledFinalContextCannotComplete(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var byteCount atomic.Uint64
	adapter := newTestAdapter(func(runCtx context.Context, source sources.Source) iter.Seq[detect.Result] {
		return func(yield func(detect.Result) bool) {
			_ = source.Fragments(runCtx, func(fragment sources.Fragment, err error) error {
				byteCount.Add(uint64(len(fragment.Raw)))
				return nil
			})
			cancel()
		}
	}, byteCount.Load, time.Second)
	response := adapter.Scan(ctx, requestWithContent("abc"))
	if response.Status != protocol.StatusScanFailed || len(response.Matches) != 0 {
		t.Fatal("canceled final context produced a complete response")
	}
}

func TestRealScannerWritesNoStdoutOrStderr(t *testing.T) {
	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldStdout, oldStderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = stdoutWriter, stderrWriter
	adapter, newErr := New()
	if newErr == nil {
		response := adapter.Scan(context.Background(), requestWithContent("ordinary text"))
		if response.Status != protocol.StatusComplete {
			newErr = errors.New("scan did not complete")
		}
	}
	os.Stdout, os.Stderr = oldStdout, oldStderr
	_ = stdoutWriter.Close()
	_ = stderrWriter.Close()
	stdoutBytes := readPipe(t, stdoutReader)
	stderrBytes := readPipe(t, stderrReader)
	if newErr != nil {
		t.Fatal(newErr)
	}
	if len(stdoutBytes) != 0 || len(stderrBytes) != 0 {
		t.Fatalf("scanner wrote stdout=%q stderr=%q", stdoutBytes, stderrBytes)
	}
}

func readPipe(t *testing.T, reader *os.File) []byte {
	t.Helper()
	defer reader.Close()
	content, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	return content
}

func BenchmarkDirectAdapter16MiB(b *testing.B) {
	adapter, err := New()
	if err != nil {
		b.Fatal(err)
	}
	content := bytes.Repeat([]byte("z"), 16*1024*1024)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := 0; iteration < b.N; iteration++ {
		source := newSingleFragmentSource(content)
		before := adapter.runtime.totalBytes()
		ctx, cancel := context.WithTimeout(context.Background(), internalScanDeadline)
		findings := 0
		failed := false
		for result := range adapter.runtime.run(ctx, source) {
			if result.Err != nil {
				failed = true
			} else {
				findings++
			}
		}
		cancel()
		after := adapter.runtime.totalBytes()
		if failed || findings != 0 || !source.completed.Load() || after-before != uint64(len(content)) {
			b.Fatal("direct adapter benchmark did not complete cleanly")
		}
	}
}

func emptyResults() iter.Seq[detect.Result] {
	return func(func(detect.Result) bool) {}
}

func requestWithContent(content string) protocol.Request {
	return protocol.Request{SchemaVersion: 1, RequestID: strings.Repeat("e", 64), Sources: []protocol.Source{{Ordinal: 0, Content: []byte(content)}}}
}

func readCoverage(t *testing.T) qualificationCoverage {
	t.Helper()
	var manifest qualificationCoverage
	readJSON(t, "../../testdata/coverage-manifest.json", &manifest)
	return manifest
}

func readSpans(t *testing.T) qualificationSpans {
	t.Helper()
	var manifest qualificationSpans
	readJSON(t, "../../testdata/expected-spans.json", &manifest)
	sort.Slice(manifest.Spans, func(i, j int) bool {
		left, right := manifest.Spans[i], manifest.Spans[j]
		if left.FixtureID != right.FixtureID {
			return left.FixtureID < right.FixtureID
		}
		if left.StartByte != right.StartByte {
			return left.StartByte < right.StartByte
		}
		if left.EndByteExclusive != right.EndByteExclusive {
			return left.EndByteExclusive < right.EndByteExclusive
		}
		return left.RuleID < right.RuleID
	})
	return manifest
}

func readJSON(t *testing.T, path string, target any) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(encoded, target); err != nil {
		t.Fatal(err)
	}
}
