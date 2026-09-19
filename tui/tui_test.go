package tui

import (
	"bytes"
	"context"
	"errors"
	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	analysishandler "github.com/georgejieh/open-trestle/handlers/analysis"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

type fakeService struct {
	mu                               sync.Mutex
	receipt                          controlplane.ReviewRunReceipt
	set                              diagnostics.Set
	runErr, diagnosticErr, cancelErr error
	cancels                          int
}

func (s *fakeService) GetRun(context.Context, audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receipt, s.runErr
}
func (s *fakeService) GetDiagnosticSet(context.Context, audit.ReviewScope) (diagnostics.Set, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.set, s.diagnosticErr
}
func (s *fakeService) CancelRun(context.Context, audit.ReviewScope) (controlplane.ReviewRunReceipt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cancels++
	return s.receipt, s.cancelErr
}
func TestRunRendersAuthenticatedRunAndVerifiedDiagnostics(t *testing.T) {
	service, scope := tuiFixture(t)
	var output bytes.Buffer
	interface_, err := New(service, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 100, Plain: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := interface_.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	rendered := output.String()
	for _, want := range []string{"OPEN TRESTLE", "tenant-a / repo-a / run-ui", "active", "acquire", "available", "Verified diagnostics", "src/main.go:7", "Avoid unchecked result", "text is untrusted"} {
		if !strings.Contains(rendered, want) {
			t.Errorf("missing %q in:\n%s", want, rendered)
		}
	}
	if strings.Contains(rendered, "\x1b[") {
		t.Fatal("plain output contains terminal control")
	}
}
func TestRunKeepsTaskHeaderWithinMinimumWidth(t *testing.T) {
	service, scope := tuiFixture(t)
	var output bytes.Buffer
	interface_, err := New(service, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 60, Plain: true})
	if err != nil || interface_.Run(context.Background()) != nil {
		t.Fatal(err)
	}
	foundHeader, foundRow := false, false
	for _, line := range strings.Split(output.String(), "\n") {
		isHeader := strings.Contains(line, "ATTEMPTS")
		isRow := strings.Contains(line, "acquire_source")
		if (isHeader || isRow) && utf8.RuneCountInString(line) > 60 {
			t.Fatalf("task table width=%d: %q", utf8.RuneCountInString(line), line)
		}
		foundHeader = foundHeader || isHeader
		foundRow = foundRow || isRow
	}
	if !foundHeader || !foundRow {
		t.Fatalf("task table missing from %s", output.String())
	}
}

func TestRunRendersDiagnosticVerificationCoverage(t *testing.T) {
	service, scope := tuiFixture(t)
	finding := service.set.Findings()[0]
	set, err := diagnostics.NewSetWithCoverage(scope, service.set.SnapshotIdentity(), service.set.HeadRevision(), service.set.VerifiedSetIdentity(), 3, 1, 1, []diagnostics.Finding{finding})
	if err != nil {
		t.Fatal(err)
	}
	service.set = set
	var output bytes.Buffer
	interface_, err := New(service, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 100, Plain: true})
	if err != nil || interface_.Run(context.Background()) != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"3 candidate(s): 1 verified", "1 rejected, 1 inconclusive", "Coverage incomplete", "does not approve"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q in %s", want, output.String())
		}
	}
}

func TestRunRendersIncompleteDiagnosticSourceCoverage(t *testing.T) {
	service, scope := tuiFixture(t)
	finding := service.set.Findings()[0]
	set, err := diagnostics.NewSetWithSourceCoverage(scope, service.set.SnapshotIdentity(), service.set.HeadRevision(), service.set.VerifiedSetIdentity(), strings.Repeat("f", 64), 3, 1, 1, 173, 1, 172, []diagnostics.Finding{finding})
	if err != nil {
		t.Fatal(err)
	}
	service.set = set
	var output bytes.Buffer
	interface_, err := New(service, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 100, Plain: true})
	if err != nil || interface_.Run(context.Background()) != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"3 candidate(s): 1 verified", "173 source(s): 1 selected, 172 omitted", "Source coverage incomplete", "does not approve"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q in %s", want, output.String())
		}
	}
}

func TestRunRendersDiagnosticOmissionReasons(t *testing.T) {
	service, scope := tuiFixture(t)
	finding := service.set.Findings()[0]
	unsupported, _ := diagnostics.NewOmissionSummary(diagnostics.OmissionUnsupported, 2)
	selection, _ := diagnostics.NewOmissionSummary(diagnostics.OmissionSelectionLimit, 170)
	set, err := diagnostics.NewSetWithOmissionReasons(scope, service.set.SnapshotIdentity(), service.set.HeadRevision(), service.set.VerifiedSetIdentity(), strings.Repeat("f", 64), 3, 1, 1, 173, 1, 172, []diagnostics.OmissionSummary{unsupported, selection}, []diagnostics.Finding{finding})
	if err != nil {
		t.Fatal(err)
	}
	service.set = set
	var output bytes.Buffer
	interface_, err := New(service, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 100, Plain: true})
	if err != nil || interface_.Run(context.Background()) != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"173 source(s): 1 selected, 172 omitted", "Omission reasons:", "  170 selection limit", "  2 unsupported", "Source coverage incomplete"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %q in %s", want, output.String())
		}
	}
}

func TestRunRendersDeterministicCheckOutcomes(t *testing.T) {
	tests := []struct {
		name                                 string
		state                                diagnostics.DeterministicCheckState
		sourceState                          analysishandler.DeterministicCheckState
		applicableFiles, applicableRanges    uint32
		checkedFiles, checkedRanges, matches uint32
		want                                 string
	}{
		{"cleared gate", diagnostics.CheckPassed, analysishandler.CheckPassed, 1, 2, 1, 2, 0, "Cleared gate: static debug output passed."},
		{"failed check", diagnostics.CheckFailed, analysishandler.CheckFailed, 1, 2, 1, 2, 1, "Failed check: static debug output failed; exact matches require review."},
		{"incomplete check", diagnostics.CheckIncomplete, analysishandler.CheckIncomplete, 1, 2, 1, 1, 0, "Incomplete check: static debug output did not cover every applicable range; human review is required."},
		{"abstention", diagnostics.CheckNotApplicable, analysishandler.CheckNotApplicable, 0, 0, 0, 0, 0, "Abstention: no changed Go range was applicable; this rule was not cleared."},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service, scope := tuiFixture(t)
			finding := service.set.Findings()[0]
			changeIdentity := strings.Repeat("7", 64)
			source, err := analysishandler.NewDeterministicCheck(changeIdentity, test.sourceState, test.applicableFiles, test.applicableRanges, test.checkedFiles, test.checkedRanges, test.matches)
			if err != nil {
				t.Fatal(err)
			}
			check, err := diagnostics.NewDeterministicCheck(source.Identity(), strings.Repeat("8", 64), changeIdentity, test.state, test.applicableFiles, test.applicableRanges, test.checkedFiles, test.checkedRanges, test.matches)
			if err != nil {
				t.Fatal(err)
			}
			set, err := diagnostics.NewSetWithDeterministicChecks(scope, service.set.SnapshotIdentity(), service.set.HeadRevision(), service.set.VerifiedSetIdentity(), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, []diagnostics.DeterministicCheck{check}, []diagnostics.Finding{finding})
			if err != nil {
				t.Fatal(err)
			}
			service.set = set
			var output bytes.Buffer
			interface_, err := New(service, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 100, Plain: true})
			if err != nil || interface_.Run(context.Background()) != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), test.want) {
				t.Fatalf("missing %q in %s", test.want, output.String())
			}
			if test.state != diagnostics.CheckPassed && strings.Contains(output.String(), "Cleared gate:") {
				t.Fatalf("non-passing check shown as cleared in %s", output.String())
			}
		})
	}
}

func TestRunOmitsEmptyDiagnosticOmissionReasons(t *testing.T) {
	service, scope := tuiFixture(t)
	finding := service.set.Findings()[0]
	set, err := diagnostics.NewSetWithOmissionReasons(scope, service.set.SnapshotIdentity(), service.set.HeadRevision(), service.set.VerifiedSetIdentity(), strings.Repeat("f", 64), 1, 0, 0, 1, 1, 0, nil, []diagnostics.Finding{finding})
	if err != nil {
		t.Fatal(err)
	}
	service.set = set
	var output bytes.Buffer
	interface_, err := New(service, strings.NewReader("q\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 80, Plain: true})
	if err != nil || interface_.Run(context.Background()) != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "Omission reasons:") {
		t.Fatalf("empty omission heading in %s", output.String())
	}
}

func TestRunRequiresInteractiveCancellationConfirmation(t *testing.T) {
	service, scope := tuiFixture(t)
	var output bytes.Buffer
	interface_, _ := New(service, strings.NewReader("cancel run-ui\nc\ncancel wrong\nc\ncancel run-ui\nq\n"), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 80, Plain: true})
	if err := interface_.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	if service.cancels != 1 {
		t.Fatalf("cancels=%d", service.cancels)
	}
	if !strings.Contains(output.String(), "Cancellation requested") || !strings.Contains(output.String(), "Confirmation did not match") {
		t.Fatalf("output=%s", output.String())
	}
}
func TestRunKeepsLastSnapshotAfterRefreshFailure(t *testing.T) {
	service, scope := tuiFixture(t)
	inputReader, inputWriter := ioPipe(t)
	var output synchronizedBuffer
	interface_, _ := New(service, inputReader, &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 80, Plain: true})
	done := make(chan error, 1)
	go func() { done <- interface_.Run(context.Background()) }()
	waitFor(t, time.Second, func() bool { return strings.Contains(output.String(), "OPEN TRESTLE") })
	service.mu.Lock()
	service.runErr = errors.New("offline")
	service.mu.Unlock()
	_, _ = inputWriter.Write([]byte("r\n"))
	waitFor(t, time.Second, func() bool { return strings.Contains(output.String(), "Refresh failed") })
	_, _ = inputWriter.Write([]byte("q\n"))
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
func tuiFixture(t *testing.T) (*fakeService, audit.ReviewScope) {
	t.Helper()
	scope, _ := audit.NewReviewScope("tenant-a", "repo-a", "run-ui")
	task, _ := controlplane.NewTaskDefinition("acquire", controlplane.TaskAcquireSource, strings.Repeat("a", 64), strings.Repeat("b", 64), nil, 2, 100, 1000, true)
	plan, _ := controlplane.NewReviewRunPlan(scope, strings.Repeat("c", 64), strings.Repeat("d", 64), controlplane.ReviewRunLocal, []controlplane.TaskDefinition{task})
	opened, _ := controlplane.NewRunEvent(plan, 1, "", controlplane.RunEventOpened, controlplane.TaskDefinition{}, 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(1000))
	available, _ := controlplane.NewRunEvent(plan, 2, opened.Identity(), controlplane.RunEventTaskAvailable, task, 0, "", "", time.Time{}, "", 0, time.Time{}, time.UnixMilli(1001))
	state, _ := controlplane.ReplayReviewRun(plan, []controlplane.RunEvent{opened, available})
	receipt, _ := controlplane.NewReviewRunReceipt(state)
	finding, _ := diagnostics.NewFinding(strings.Repeat("e", 64), strings.Repeat("f", 64), "Avoid unchecked result", "This output must remain visibly untrusted.", diagnostics.SeverityWarning, "src/main.go", 7, 8, []string{"evidence:one"})
	set, _ := diagnostics.NewSet(scope, strings.Repeat("1", 64), strings.Repeat("2", 40), strings.Repeat("3", 64), []diagnostics.Finding{finding})
	return &fakeService{receipt: receipt, set: set}, scope
}

type synchronizedBuffer struct {
	mu sync.Mutex
	bytes.Buffer
}

func (b *synchronizedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.Write(p)
}
func (b *synchronizedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.Buffer.String()
}
func ioPipe(t *testing.T) (*io.PipeReader, *io.PipeWriter) {
	t.Helper()
	reader, writer := io.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	return reader, writer
}
func waitFor(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		runtime.Gosched()
	}
	t.Fatal("condition not met")
}

func TestRunRejectsOversizedCommands(t *testing.T) {
	service, scope := tuiFixture(t)
	var output bytes.Buffer
	interface_, _ := New(service, strings.NewReader(strings.Repeat("x", maxCommandBytes+1)), &output, Options{Scope: scope, RefreshInterval: time.Second, Width: 80, Plain: true})
	if err := interface_.Run(context.Background()); !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("err=%v", err)
	}
}
func TestNewRejectsTypedNilDependenciesAndAggressivePolling(t *testing.T) {
	_, scope := tuiFixture(t)
	var service *fakeService
	if _, err := New(service, strings.NewReader(""), io.Discard, Options{Scope: scope}); !errors.Is(err, ErrInvalidInterface) {
		t.Fatalf("typed nil err=%v", err)
	}
	live, _ := tuiFixture(t)
	if _, err := New(live, strings.NewReader(""), io.Discard, Options{Scope: scope, RefreshInterval: time.Millisecond}); !errors.Is(err, ErrInvalidInterface) {
		t.Fatalf("polling err=%v", err)
	}
}
