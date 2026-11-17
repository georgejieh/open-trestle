//go:build linux

package secretscan

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// scanHelperIntegrationVariable enables the tests that build and run the real
// scan helper. Building the guest and the helper and filling the cache take
// about a minute and need the Go toolchain, so the default go test run skips
// them.
const scanHelperIntegrationVariable = "OPEN_TRESTLE_SCAN_HELPER_INTEGRATION"

func TestMain(m *testing.M) {
	code := m.Run()
	if scanHelper.directory != "" {
		_ = os.RemoveAll(scanHelper.directory)
	}
	os.Exit(code)
}

// scanHelper is the real helper every integration test shares: built once
// per test binary, installed read-only and prewarmed.
var (
	scanHelperOnce sync.Once
	scanHelper     struct {
		directory string
		config    SessionConfig
		err       error
	}
)

func scanHelperForTest(t *testing.T) SessionConfig {
	t.Helper()
	if os.Getenv(scanHelperIntegrationVariable) != "1" {
		t.Skip("set " + scanHelperIntegrationVariable + "=1 to build and run the real scan helper")
	}
	scanHelperOnce.Do(func() { scanHelper.err = installScanHelper(t) })
	if scanHelper.err != nil {
		t.Fatal(scanHelper.err)
	}
	return scanHelper.config
}

// installScanHelper builds the helper with the scanner module's build
// command, installs a read-only copy and prewarms a new cache directory.
func installScanHelper(t *testing.T) error {
	directory, err := os.MkdirTemp("", "open-trestle-scan-helper-session-")
	if err != nil {
		return err
	}
	scanHelper.directory = directory
	module, err := filepath.Abs(filepath.Join("..", "..", "workers", "secret-scanner"))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	started := time.Now()
	build := exec.CommandContext(ctx, "go", "run", "./internal/cmd/build-scan-helper", "-o", filepath.Join(directory, "build"))
	build.Dir = module
	build.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
	var stdout, stderr bytes.Buffer
	build.Stdout, build.Stderr = &stdout, &stderr
	if err := build.Run(); err != nil {
		return fmt.Errorf("build the scan helper: %w: %s", err, stderr.Bytes())
	}
	built := strings.TrimSpace(stdout.String())
	if !filepath.IsAbs(built) {
		return fmt.Errorf("build-scan-helper printed %q, want an absolute helper path", built)
	}
	t.Logf("helper build: %v", time.Since(started))
	content, err := os.ReadFile(built)
	if err != nil {
		return err
	}
	if err := os.Mkdir(filepath.Join(directory, "install"), 0o700); err != nil {
		return err
	}
	installed := filepath.Join(directory, "install", "open-trestle-scan-helper")
	if err := os.WriteFile(installed, content, 0o500); err != nil {
		return err
	}
	if err := os.Chmod(installed, 0o555); err != nil {
		return err
	}
	digest := sha256.Sum256(content)
	config := SessionConfig{
		HelperPath:     installed,
		HelperSHA256:   hex.EncodeToString(digest[:]),
		BuildProfile:   HostRE2BuildProfile,
		CacheDirectory: filepath.Join(directory, "cache"),
	}
	started = time.Now()
	if err := Prewarm(context.Background(), config); err != nil {
		return fmt.Errorf("prewarm: %w", err)
	}
	t.Logf("prewarm of a new cache: %v", time.Since(started))
	scanHelper.config = config
	return nil
}

type helperFixture struct {
	id      string
	content []byte
}

type helperExpectedSpan struct {
	FixtureID        string `json:"fixture_id"`
	RuleID           string `json:"rule_id"`
	SourceOrdinal    int    `json:"source_ordinal"`
	StartByte        int    `json:"start_byte"`
	EndByteExclusive int    `json:"end_byte_exclusive"`
}

// readScannerFixtures returns the scanner's qualification fixtures, the near
// miss last, and the expected spans by fixture.
func readScannerFixtures(t *testing.T) ([]helperFixture, map[string][]helperExpectedSpan) {
	t.Helper()
	var coverage struct {
		Fixtures []struct {
			ID            string `json:"id"`
			ContentBase64 string `json:"content_base64"`
		} `json:"fixtures"`
		NearMiss struct {
			ID            string `json:"id"`
			ContentBase64 string `json:"content_base64"`
		} `json:"near_miss"`
	}
	var expected struct {
		Spans []helperExpectedSpan `json:"spans"`
	}
	for name, target := range map[string]any{"coverage-manifest.json": &coverage, "expected-spans.json": &expected} {
		encoded, err := os.ReadFile(filepath.Join("..", "..", "workers", "secret-scanner", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, target); err != nil {
			t.Fatal(err)
		}
	}
	entries := append(coverage.Fixtures, coverage.NearMiss)
	fixtures := make([]helperFixture, 0, len(entries))
	for _, entry := range entries {
		content, err := base64.StdEncoding.DecodeString(entry.ContentBase64)
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, helperFixture{id: entry.ID, content: content})
	}
	spans := map[string][]helperExpectedSpan{}
	for _, span := range expected.Spans {
		spans[span.FixtureID] = append(spans[span.FixtureID], span)
	}
	if len(fixtures) != 12 || len(expected.Spans) != 12 {
		t.Fatalf("%d fixtures and %d spans, want 12 and 12", len(fixtures), len(expected.Spans))
	}
	return fixtures, spans
}

func compareSpans(left, right helperExpectedSpan) int {
	return cmp.Or(cmp.Compare(left.SourceOrdinal, right.SourceOrdinal), cmp.Compare(left.StartByte, right.StartByte),
		cmp.Compare(left.EndByteExclusive, right.EndByteExclusive), strings.Compare(left.RuleID, right.RuleID))
}

func openHelperSessionForTest(t *testing.T, config SessionConfig) *Session {
	t.Helper()
	session, err := OpenSession(context.Background(), config)
	if err != nil {
		t.Fatalf("open session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func TestScanHelperSessionFindsTheExpectedSpans(t *testing.T) {
	config := scanHelperForTest(t)
	fixtures, expected := readScannerFixtures(t)
	session := openHelperSessionForTest(t, config)
	started := time.Now()
	total := 0
	for _, fixture := range fixtures {
		result, err := session.Scan(context.Background(), [][]byte{fixture.content})
		if err != nil || !result.Complete() {
			t.Fatalf("%s: scan failed: %v, %v", fixture.id, result.Failure(), err)
		}
		if metadata := result.Metadata(); metadata.BuildProfile != HostRE2BuildProfile || metadata.HelperSHA256 != config.HelperSHA256 {
			t.Fatalf("%s: unexpected metadata %+v", fixture.id, metadata)
		}
		var got []helperExpectedSpan
		for _, match := range result.Matches() {
			got = append(got, helperExpectedSpan{RuleID: match.RuleID, SourceOrdinal: match.SourceOrdinal, StartByte: match.StartByte, EndByteExclusive: match.EndByteExclusive})
		}
		want := make([]helperExpectedSpan, 0, len(expected[fixture.id]))
		for _, span := range expected[fixture.id] {
			span.FixtureID = ""
			want = append(want, span)
		}
		slices.SortFunc(got, compareSpans)
		slices.SortFunc(want, compareSpans)
		if !slices.Equal(got, want) {
			t.Fatalf("%s: spans %+v, want %+v", fixture.id, got, want)
		}
		total += len(got)
	}
	if total != 12 {
		t.Fatalf("%d spans, want the 12 expected spans", total)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	t.Logf("%d fixture scans and close: %v", len(fixtures), time.Since(started))
}

func TestScanHelperSessionSanitizesAndTheMaskedSourcesRescanClean(t *testing.T) {
	config := scanHelperForTest(t)
	fixtures, _ := readScannerFixtures(t)
	sources := make([][]byte, len(fixtures))
	for index, fixture := range fixtures {
		sources[index] = fixture.content
	}
	session := openHelperSessionForTest(t, config)
	projection := session.Sanitize(context.Background(), sources)
	if !projection.Complete() || projection.Initial().MatchCount != 12 || projection.Residual().MatchCount != 0 || projection.MaskedByteCount() == 0 {
		t.Fatalf("sanitize did not mask every span: %v", projection.Failure())
	}
	masked := projection.Sources()
	for index := range masked {
		if len(masked[index]) != len(sources[index]) {
			t.Fatalf("source %d changed length", index)
		}
	}
	result, err := session.Scan(context.Background(), masked)
	if err != nil || !result.Complete() || len(result.Matches()) != 0 {
		t.Fatalf("masked sources did not rescan clean: %v, %d matches", err, len(result.Matches()))
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// reviewSource is size bytes of code-like text with every fixture embedded.
func reviewSource(fixtures []helperFixture, seed, size int) []byte {
	var text bytes.Buffer
	for line := 0; text.Len() < size-4096; line++ {
		if line%97 == 0 {
			fixture := fixtures[(seed+line/97)%len(fixtures)]
			text.Write(fixture.content)
			text.WriteByte('\n')
			continue
		}
		fmt.Fprintf(&text, "\tvalue%d := compute(config%d, %d) // scan %d\n", line%89, line%13, line*seed, seed)
	}
	text.WriteString(strings.Repeat(" ", size-text.Len()-1))
	text.WriteByte('\n')
	return text.Bytes()
}

func TestScanHelperReviewOfFourScansClosesCleanly(t *testing.T) {
	config := scanHelperForTest(t)
	fixtures, _ := readScannerFixtures(t)
	started := time.Now()
	err := RunReviewSession(context.Background(), config.Opener(), func(ctx context.Context, review ReviewSession) error {
		for scan := range 4 {
			source := reviewSource(fixtures, scan, 256*1024)
			result, err := review.Scan(ctx, [][]byte{source})
			if err != nil || !result.Complete() || len(result.Matches()) == 0 || result.Metadata().ScannedByteCount != len(source) {
				return fmt.Errorf("scan %d: %w (%d matches)", scan, err, len(result.Matches()))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("review failed: %v", err)
	}
	t.Logf("review of 4 scans of 256 KiB: %v", time.Since(started))
}

// repeatedFixtures is size bytes of the scanner's fixtures repeated, one per
// line, padded with spaces: finding-dense content.
func repeatedFixtures(fixtures []helperFixture, size int) []byte {
	var text bytes.Buffer
	for {
		for _, fixture := range fixtures {
			if text.Len()+len(fixture.content)+1 > size-1 {
				text.WriteString(strings.Repeat(" ", size-text.Len()-1))
				text.WriteByte('\n')
				return text.Bytes()
			}
			text.Write(fixture.content)
			text.WriteByte('\n')
		}
	}
}

// TestScanHelperSessionScansDenseContent runs finding-dense requests through
// sessions with the production limits. Requests of one and two full sources
// complete well within the watchdog, and a request at the protocol's size
// limit stops at the match limit with the failure class the native worker
// reports for it.
func TestScanHelperSessionScansDenseContent(t *testing.T) {
	config := scanHelperForTest(t)
	fixtures, _ := readScannerFixtures(t)
	dense := repeatedFixtures(fixtures, 256*1024)
	repeated := func(count int) [][]byte {
		sources := make([][]byte, count)
		for index := range sources {
			sources[index] = dense
		}
		return sources
	}
	session := openHelperSessionForTest(t, config)
	perSource := 0
	for _, count := range []int{1, 2} {
		started := time.Now()
		result, err := session.Scan(context.Background(), repeated(count))
		elapsed := time.Since(started)
		if err != nil || !result.Complete() {
			t.Fatalf("%d dense sources: %v, %v", count, result.Failure(), err)
		}
		if count == 1 {
			perSource = len(result.Matches())
		}
		if perSource < 1000 || len(result.Matches()) != count*perSource {
			t.Fatalf("%d dense sources: %d matches, %d for one source", count, len(result.Matches()), perSource)
		}
		if elapsed > sessionScanWatchdog/2 {
			t.Fatalf("%d dense sources took %v, more than half the watchdog", count, elapsed)
		}
		t.Logf("%d dense sources: %v, %d matches", count, elapsed, len(result.Matches()))
	}
	if err := session.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	session = openHelperSessionForTest(t, config)
	started := time.Now()
	result, err := session.Scan(context.Background(), repeated(8))
	if result.Complete() || result.Failure() != FailureResourceLimit || !errors.Is(err, errScanIncomplete) {
		t.Fatalf("dense request at the size limit: %v, %v", result.Failure(), err)
	}
	if elapsed := time.Since(started); elapsed > sessionScanWatchdog/2 {
		t.Fatalf("dense request at the size limit took %v, more than half the watchdog", elapsed)
	}
}

func TestScanHelperWithTheWrongDigestDoesNotStart(t *testing.T) {
	config := scanHelperForTest(t)
	wrong := sha256.Sum256([]byte("another helper"))
	config.HelperSHA256 = hex.EncodeToString(wrong[:])
	if session, err := OpenSession(context.Background(), config); session != nil || !errors.Is(err, ErrHelperUntrusted) {
		t.Fatalf("session with the wrong helper digest was not refused: %v", err)
	}
	if err := Prewarm(context.Background(), config); !errors.Is(err, ErrHelperUntrusted) {
		t.Fatalf("prewarm with the wrong helper digest was not refused: %v", err)
	}
}

func TestScanHelperGroupWritableCacheIsRefused(t *testing.T) {
	config := scanHelperForTest(t)
	config.CacheDirectory = filepath.Join(t.TempDir(), "cache")
	if err := os.Mkdir(config.CacheDirectory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(config.CacheDirectory, 0o770); err != nil {
		t.Fatal(err)
	}
	if session, err := OpenSession(context.Background(), config); session != nil || !errors.Is(err, ErrCacheUntrusted) {
		t.Fatalf("session with a group-writable cache was not refused: %v", err)
	}
	if err := Prewarm(context.Background(), config); !errors.Is(err, ErrCacheUntrusted) {
		t.Fatalf("prewarm with a group-writable cache was not refused: %v", err)
	}
}
