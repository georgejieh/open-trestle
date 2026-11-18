package syntaxwasm

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tetratelabs/wazero"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// countWatchdog counts the calls the watchdog gives up on until the test
// ends.
func countWatchdog(t *testing.T) *atomic.Int64 {
	t.Helper()
	fired := &atomic.Int64{}
	saved := watchdogFired
	watchdogFired = func() { fired.Add(1) }
	t.Cleanup(func() { watchdogFired = saved })
	return fired
}

func waitForNoAbandonedCalls(t *testing.T, a *Analyzer) {
	t.Helper()
	for deadline := time.Now().Add(2 * time.Minute); a.AbandonedCalls() != 0; {
		if time.Now().After(deadline) {
			t.Fatal("the abandoned call never ended")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// guestIgnoringStops makes every stop check answer that the guest may go
// on. The first check of a call waits until the watchdog has given up on
// the call, and, with a release channel, until it closes. The guest keeps
// reaching stop checks; a guest that never does cannot be stopped in fast
// code and is not modelled here. It returns the count of checks answered
// after the call was abandoned.
func guestIgnoringStops(t *testing.T, release <-chan struct{}) *atomic.Int64 {
	t.Helper()
	saved := stopRequested
	t.Cleanup(func() { stopRequested = saved })
	answered := &atomic.Int64{}
	stopRequested = func(ctx context.Context) bool {
		for !callAbandoned(ctx) {
			time.Sleep(time.Millisecond)
		}
		if release != nil {
			<-release
		}
		answered.Add(1)
		return false
	}
	return answered
}

func largeTypeScript() []byte {
	var b strings.Builder
	for b.Len() < 2<<20-256 {
		b.WriteString("export function handler(a: number, b: string): Promise<void> { return run(a, b.length, [a, b]); }\n")
	}
	return []byte(b.String())
}

func TestDeadlineStopsARunawayParse(t *testing.T) {
	fired := countWatchdog(t)
	limits := syntaxanalysis.DefaultLimits()
	limits.FileDeadline = 5 * time.Millisecond
	a := newTestAnalyzer(t, Config{Limits: limits, InstancesPerFamily: 1})
	// Warm the instance and its query so the deadline covers the parse only.
	_ = analyze(t, a, "warm.ts", []byte("let a = 1;\n"))
	content := largeTypeScript()
	onlyGap(t, analyze(t, a, "large.ts", content), syntaxanalysis.GapDeadlineExceeded, "")
	if n := fired.Load(); n != 0 {
		t.Fatalf("the watchdog fired %d times; the stop checks should have ended the call", n)
	}
	f := a.languages[syntaxanalysis.LanguageTypeScript].family
	f.mu.Lock()
	idle := len(f.idle)
	f.mu.Unlock()
	if idle != 0 {
		t.Fatal("the instance stopped by the deadline was kept")
	}
	// Without the deadline the same file takes much longer, so the gap came
	// from stopping the parse, not from a fast failure.
	unbounded := syntaxanalysis.DefaultLimits()
	unbounded.FileDeadline = 2 * time.Minute
	full := newTestAnalyzer(t, Config{Limits: unbounded})
	started := time.Now()
	complete := analyze(t, full, "large.ts", content)
	if !complete.Complete() || time.Since(started) < 10*limits.FileDeadline {
		t.Fatalf("full analysis: gaps %+v in %v", complete.Gaps, time.Since(started))
	}
	if got := analyze(t, a, "small.ts", []byte("function f() {}\n")); len(got.Definitions) != 1 {
		t.Fatalf("analysis after the deadline = %+v", got)
	}
}

func TestGuestReachingStopChecksButIgnoringThemIsEndedByTheWatchdog(t *testing.T) {
	fired := countWatchdog(t)
	limits := syntaxanalysis.DefaultLimits()
	limits.FileDeadline = 5 * time.Millisecond
	a := newTestAnalyzer(t, Config{Limits: limits, InstancesPerFamily: 1})
	// Compile the query first, so the watched call is the parse.
	_ = analyze(t, a, "warm.ts", []byte("let a = 1;\n"))
	large := largeTypeScript()
	answered := guestIgnoringStops(t, nil)
	started := time.Now()
	onlyGap(t, analyze(t, a, "large.ts", large), syntaxanalysis.GapDeadlineExceeded, "")
	if elapsed := time.Since(started); elapsed < watchdog(limits.FileDeadline) {
		t.Fatalf("the analysis returned after %v, before the watchdog", elapsed)
	}
	if n := fired.Load(); n != 1 {
		t.Fatalf("the watchdog fired %d times", n)
	}
	f := a.languages[syntaxanalysis.LanguageTypeScript].family
	f.mu.Lock()
	switched := f.terminating
	f.mu.Unlock()
	if !switched {
		t.Fatal("the family did not switch to terminating code")
	}
	// The abandoned call ends at its next stop check: one check is answered
	// after the watchdog, and the one after it traps the guest.
	waitForNoAbandonedCalls(t, a)
	if n := answered.Load(); n != 1 {
		t.Fatalf("%d stop checks were answered after the call was abandoned", n)
	}

	// With terminating code the deadline holds even while the guest's stop
	// checks are ignored: the call ends without the watchdog. The small file
	// first compiles that code.
	stopRequested = func(context.Context) bool { return false }
	if got := analyze(t, a, "small.ts", []byte("function f() {}\n")); len(got.Definitions) != 1 {
		t.Fatalf("analysis with terminating code = %+v", got)
	}
	onlyGap(t, analyze(t, a, "large.ts", large), syntaxanalysis.GapDeadlineExceeded, "")
	if n := fired.Load(); n != 1 {
		t.Fatalf("the watchdog fired %d times", n)
	}
}

func TestSwitchToTerminatingCodeDiscardsIdleFastInstances(t *testing.T) {
	a := newTestAnalyzer(t, Config{InstancesPerFamily: 2})
	f := a.languages[syntaxanalysis.LanguagePython].family
	first, _ := f.acquire(context.Background())
	second, _ := f.acquire(context.Background())
	f.release(first, true)
	f.switchToTerminating()
	f.release(second, true)
	f.mu.Lock()
	idle := len(f.idle)
	f.mu.Unlock()
	if idle != 0 {
		t.Fatalf("%d fast instances stayed idle after the switch", idle)
	}
	if got := analyze(t, a, "a.py", []byte("def f():\n    pass\n")); len(got.Definitions) != 1 {
		t.Fatalf("analysis with terminating code = %+v", got)
	}
}

func TestCloseDuringAnAbandonedCallClosesTheRuntimesWhenItEnds(t *testing.T) {
	limits := syntaxanalysis.DefaultLimits()
	limits.FileDeadline = 5 * time.Millisecond
	a, err := New(context.Background(), testConfig(t, Config{Limits: limits, InstancesPerFamily: 1}))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Available() {
		t.Skip("the wazero compiler does not run on this platform")
	}
	_ = analyze(t, a, "warm.ts", []byte("let a = 1;\n"))
	release := make(chan struct{})
	guestIgnoringStops(t, release)
	onlyGap(t, analyze(t, a, "large.ts", largeTypeScript()), syntaxanalysis.GapDeadlineExceeded, "")
	if n := a.AbandonedCalls(); n != 1 {
		t.Fatalf("%d abandoned calls reported", n)
	}
	if err := a.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	compiled := a.languages[syntaxanalysis.LanguageTypeScript].family.modules[modeFast].compiled
	// The abandoned call still runs, so its runtime must stay open.
	if module, err := a.runtime.InstantiateModule(context.Background(), compiled, wazero.NewModuleConfig().WithName("")); err != nil {
		t.Fatalf("the runtime was closed under a running call: %v", err)
	} else {
		_ = module.Close(context.Background())
	}
	close(release)
	waitForNoAbandonedCalls(t, a)
	if _, err := a.runtime.InstantiateModule(context.Background(), compiled, wazero.NewModuleConfig().WithName("")); err == nil {
		t.Fatal("the runtime stayed open after the last abandoned call ended")
	}
}
