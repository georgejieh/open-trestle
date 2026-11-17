package secretscan

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

const (
	// helperSessionArgument selects the helper's session mode: request frames
	// arrive on stdin until EOF at a frame boundary, and each gets exactly one
	// response frame on stdout, or the helper exits non-zero without writing
	// one. A session writes a request only after the previous response and
	// closes stdin only between requests; the helper treats stdin hanging up
	// during a request as the death of its parent.
	helperSessionArgument = "--stdio-v1-session"
	// sessionScanWatchdog bounds every exchange with the helper: one scan, or
	// the wait for a clean exit at Close. The helper's guest stops a scan at
	// its own deadline of 30 seconds, five times the native worker's 5 s
	// with a fifth to spare, because it runs Betterleaks up to five times
	// slower. It notices that deadline only between rules and then still
	// encodes its response, so the watchdog adds the longest rule pass of a
	// finding-dense source and some slack before it kills the helper.
	sessionScanWatchdog = 40 * time.Second
	// sessionStartAllowance is extra time for the first exchange, measured
	// from the spawn, because the helper loads and prepares its guest before
	// it reads the first request.
	sessionStartAllowance = 10 * time.Second
	// sessionScanLimit is the most scans one helper process may serve.
	sessionScanLimit = 64
	// prewarmDeadline bounds Prewarm from the spawn to the helper's exit.
	// Filling a cold cache compiles the guest and libre2, which takes tens
	// of seconds; the deadline leaves room for much slower machines.
	prewarmDeadline = 3 * time.Minute
)

// Session refusals and failures. None of them carries source content,
// helper output or a path.
var (
	ErrSessionConfig    = errors.New("secret scan session configuration is invalid")
	ErrHelperUntrusted  = errors.New("secret scan helper is not an unwritable regular file owned by root or the current user with the expected SHA-256")
	ErrCacheUntrusted   = errors.New("secret scan cache is not a directory of the current user without group or other permissions on a path only root or the current user can change")
	ErrSessionClosed    = errors.New("secret scan session is closed")
	ErrSessionPoisoned  = errors.New("secret scan session failed earlier and accepts no further scans")
	ErrSessionScanLimit = errors.New("secret scan session reached its limit of 64 scans")

	errHelperStart          = errors.New("secret scan helper could not be started")
	errHelperDeadline       = errors.New("secret scan helper missed its deadline")
	errHelperStderr         = errors.New("secret scan helper wrote to standard error")
	errHelperExited         = errors.New("secret scan helper exited before the session was closed")
	errHelperExit           = errors.New("secret scan helper exited unsuccessfully")
	errHelperNoResponse     = errors.New("secret scan helper ended its output without a response")
	errHelperFrame          = errors.New("secret scan helper sent a short, empty or oversized frame")
	errHelperResponse       = errors.New("secret scan helper response does not match its request")
	errHelperIO             = errors.New("secret scan helper pipe failed")
	errHelperTrailingOutput = errors.New("secret scan helper wrote output after its last response")
	errScanCanceled         = errors.New("secret scan was canceled")
	errScanInput            = errors.New("secret scan input is outside the protocol bounds")
	errScanRequest          = errors.New("secret scan request could not be built")
	errScanIncomplete       = errors.New("secret scan did not complete")
)

// SessionConfig names the helper executable a Session runs, the build profile
// its responses must carry and the helper's compilation cache.
type SessionConfig struct {
	// HelperPath is the absolute, clean path of the helper executable.
	HelperPath string
	// HelperSHA256 is the expected lowercase hexadecimal SHA-256 of the
	// helper file. The file is hashed before every spawn.
	HelperSHA256 string
	// BuildProfile is the only build profile accepted in responses. It must
	// be HostRE2BuildProfile, the profile the scan helper emits.
	BuildProfile string
	// CacheDirectory is the absolute, clean path of the helper's private
	// compilation cache, which the helper gets as its working directory.
	// The helper loads native code from it, so it must be a directory, not
	// a symbolic link, owned by the effective user with no group or other
	// permission bit, and every directory above it must be owned by root or
	// the current user and writable by no one else unless it is sticky.
	// Both checks run before every spawn. OpenSession never creates it;
	// Prewarm creates the final directory with mode 0700 if it is missing.
	//
	// The cache is trusted at the level of its owner, like the helper file
	// when the current user owns it. wazero checks a cache entry only
	// against a checksum, so anyone who can write the cache directory
	// controls the code the helper runs, including any process of the
	// current user. The directory checks exist so that no other user can
	// write or even reach it; they do not protect it from its owner.
	CacheDirectory string
}

// ReviewSession is the scanner lifetime of one review: the review opens it at
// its start, routes every scan through it and closes it at its end. A review
// must treat a non-nil Close as a failure of the whole review.
type ReviewSession interface {
	Scan(ctx context.Context, sources [][]byte) (ScanResult, error)
	Sanitize(ctx context.Context, sources [][]byte) Projection
	Close() error
}

// ReviewSessionOpener opens the session for one review.
type ReviewSessionOpener func(ctx context.Context) (ReviewSession, error)

// Opener returns a ReviewSessionOpener that starts a helper Session with
// this configuration.
func (config SessionConfig) Opener() ReviewSessionOpener {
	return func(ctx context.Context) (ReviewSession, error) {
		session, err := OpenSession(ctx, config)
		if err != nil {
			return nil, err
		}
		return session, nil
	}
}

// RunReviewSession opens a session, runs review with it and always closes
// it. It returns nil only if review returned nil and the session closed
// cleanly. A session that fails at Close makes the review fail even when
// every scan inside it returned complete, because the helper's exit status
// and the end of its output are only known then.
func RunReviewSession(ctx context.Context, open ReviewSessionOpener, review func(context.Context, ReviewSession) error) error {
	if ctx == nil || open == nil || review == nil {
		return ErrSessionConfig
	}
	session, err := open(ctx)
	if err != nil {
		return err
	}
	if session == nil {
		return ErrSessionConfig
	}
	closed := false
	defer func() {
		if !closed {
			_ = session.Close()
		}
	}()
	reviewErr := review(ctx, session)
	closed = true
	return errors.Join(reviewErr, session.Close())
}

// Session runs scans through one long-lived helper process that speaks the
// stdio scanner protocol in session mode.
//
// Trust: Scan returns a complete result only for a response that parsed and
// validated against its own request (request ID, ruleset identity, pinned
// rule IDs, build profile) from a helper that had shown no fault until then.
// Some faults can only be seen at Close: the exit status, output after the
// last response, and a standard error byte that raced with a response. The
// results of a session are therefore final only once Close returned nil; a
// non-nil Close means no result of the session may be relied on, and the
// review that used it has failed. RunReviewSession enforces this.
//
// Failure: the first failure of any kind poisons the session. The helper's
// process group is killed and reaped at once, no further request is sent,
// every later Scan fails immediately with ErrSessionPoisoned, and there is no
// retry or respawn. A session serves at most 64 scans; the next one is a
// failure. A Session is safe for concurrent use; calls are serialized.
type Session struct {
	mu        sync.Mutex
	settings  sessionSettings
	ruleIDs   map[string]struct{}
	process   *helperProcess
	spawned   time.Time
	scans     int
	exchanged bool
	closed    bool
	closeErr  error
}

type sessionSettings struct {
	config         SessionConfig
	scanWatchdog   time.Duration
	startAllowance time.Duration
	scanLimit      int
	random         io.Reader
	createCache    bool
	hooks          processHooks
}

// processHooks let tests order the events of one helper process. Production
// sessions leave every hook nil.
type processHooks struct {
	// beforeStart runs just before the helper is started.
	beforeStart func()
	// exitObserved runs in the exit watcher once the helper has exited,
	// before the watcher decides whether the exit came too early.
	exitObserved func()
	// exitJudged runs in the exit watcher after that decision, before the
	// watcher records an early exit.
	exitJudged func(early bool)
	// closingStarted runs in Close right after the closing transition.
	closingStarted func()
}

// OpenSession verifies the helper file against config.HelperSHA256 and the
// cache directory as SessionConfig.CacheDirectory describes, then spawns the
// helper with an empty environment, the cache directory as its working
// directory, only stdin, stdout and stderr, and its own process group. It
// does not wait for the helper to become ready; the first exchange carries
// the start allowance. ctx bounds only the open itself.
//
// The helper compiles its guest and starts libre2 before it reads the first
// request. With a cache that Prewarm filled this fits the start allowance.
// With a cold cache the compile can take longer than the first exchange's
// deadline, and the first Scan then fails closed with a missed deadline and
// poisons the session; a review must not open its session before Prewarm
// has succeeded once for the configuration.
//
// Sessions run on Linux only. On Windows and macOS the cache check refuses
// every directory, and the helper refuses every working directory, because
// owner and mode bits do not prove that a directory is private there: on
// Windows access is a property of the ACL, and on macOS an extended ACL,
// which a new directory can inherit from its parent, grants access
// independently of the mode bits. Neither is verified, so neither a session
// nor Prewarm starts on Windows or macOS until an ACL check exists.
func OpenSession(ctx context.Context, config SessionConfig) (*Session, error) {
	return openSession(ctx, sessionSettings{
		config:         config,
		scanWatchdog:   sessionScanWatchdog,
		startAllowance: sessionStartAllowance,
		scanLimit:      sessionScanLimit,
		random:         rand.Reader,
	})
}

// Prewarm fills the helper's compilation cache so that later sessions with
// the same configuration start within their start allowance. It verifies the
// helper and the cache directory as OpenSession does, except that it first
// creates a missing final cache directory with mode 0700 when every
// directory above it passes the checks; it creates nothing else. It then runs
// the helper in session mode with standard input closed at once, so the
// helper compiles its guest, starts libre2 and exits. Prewarm returns nil
// only if the helper exits 0 within prewarmDeadline of its spawn, or sooner
// if ctx ends, without writing to standard output or standard error. On any
// failure it kills the helper's process group, reaps it and returns the
// failure.
func Prewarm(ctx context.Context, config SessionConfig) error {
	return prewarm(ctx, sessionSettings{
		config:         config,
		scanWatchdog:   sessionScanWatchdog,
		startAllowance: prewarmDeadline - sessionScanWatchdog,
		scanLimit:      sessionScanLimit,
		random:         rand.Reader,
		createCache:    true,
	})
}

// prewarm opens a session and closes it at once. Close closes stdin and
// requires no output and a clean exit by the first exchange's deadline, the
// start allowance plus the watchdog after the spawn; it kills and reaps the
// process group in every case.
func prewarm(ctx context.Context, settings sessionSettings) error {
	session, err := openSession(ctx, settings)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { session.process.failWith(errScanCanceled) })
	defer stop()
	return session.Close()
}

func openSession(ctx context.Context, settings sessionSettings) (*Session, error) {
	if ctx == nil || !validSessionSettings(settings) {
		return nil, ErrSessionConfig
	}
	if ctx.Err() != nil {
		return nil, errScanCanceled
	}
	helper, err := openVerifiedHelper(settings.config.HelperPath, settings.config.HelperSHA256)
	if err != nil {
		return nil, err
	}
	defer helper.close()
	directory, err := openCacheDirectory(settings.config.CacheDirectory, settings.createCache)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, errScanCanceled
	}
	process, err := startHelperProcess(helper, directory, settings.hooks)
	if err != nil {
		return nil, err
	}
	return &Session{settings: settings, ruleIDs: pinnedRuleIDSetProduction(), process: process, spawned: time.Now()}, nil
}

func validSessionSettings(settings sessionSettings) bool {
	return validAbsolutePath(settings.config.HelperPath) && validDigest(settings.config.HelperSHA256) &&
		settings.config.BuildProfile == HostRE2BuildProfile && validAbsolutePath(settings.config.CacheDirectory) &&
		filepath.Dir(settings.config.CacheDirectory) != settings.config.CacheDirectory &&
		settings.scanWatchdog > 0 && settings.startAllowance >= 0 && settings.scanLimit > 0 && settings.random != nil
}

func validAbsolutePath(path string) bool {
	return path != "" && filepath.IsAbs(path) && filepath.Clean(path) == path
}

// Scan sends one request to the helper and waits for its response under the
// per-scan watchdog, shortened by ctx. Any failure poisons the session. The
// error is nil exactly when the result is complete.
func (session *Session) Scan(ctx context.Context, sources [][]byte) (ScanResult, error) {
	if session == nil {
		return ScanResult{failure: FailurePolicy}, ErrSessionClosed
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	return session.scanLocked(ctx, sources)
}

func (session *Session) scan(ctx context.Context, sources [][]byte) ScanResult {
	result, _ := session.Scan(ctx, sources)
	return result
}

// Sanitize masks every match and rescans the masked sources, as
// Client.Sanitize does, with both scans in this session.
func (session *Session) Sanitize(ctx context.Context, sources [][]byte) Projection {
	return newProjector(session).Sanitize(ctx, sources)
}

// Err returns the first failure of the session, or nil while it is healthy
// and after a clean Close.
func (session *Session) Err() error {
	if session == nil {
		return ErrSessionClosed
	}
	return session.process.fault()
}

// Close ends the session: it closes the helper's stdin, requires that the
// helper writes nothing more and exits 0 within the watchdog with no
// standard error output, then kills whatever is left in its process group and
// reaps it. It returns nil only if the session saw no failure at all. Later
// calls return the same result.
func (session *Session) Close() error {
	if session == nil {
		return ErrSessionClosed
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed {
		return session.closeErr
	}
	session.closed = true
	session.closeErr = session.finish()
	return session.closeErr
}

func (session *Session) scanLocked(ctx context.Context, sources [][]byte) (ScanResult, error) {
	started := time.Now()
	metadata := session.metadata(sources)
	finish := func(failure FailureClass, err error) (ScanResult, error) {
		metadata.Duration = time.Since(started)
		return ScanResult{metadata: metadata, failure: failure}, err
	}
	poison := func(failure FailureClass, cause error) (ScanResult, error) {
		first := session.process.failWith(cause)
		_ = session.process.reap()
		return finish(failure, first)
	}
	if session.closed {
		return finish(FailurePolicy, ErrSessionClosed)
	}
	if failure := session.process.fault(); failure != nil {
		_ = session.process.reap()
		return finish(FailurePolicy, fmt.Errorf("%w: %w", ErrSessionPoisoned, failure))
	}
	if ctx == nil {
		return poison(FailurePolicy, ErrSessionConfig)
	}
	if ctx.Err() != nil {
		return poison(FailureCanceled, errScanCanceled)
	}
	if !validateSourceInputs(sources) {
		return poison(FailureInvalidInput, errScanInput)
	}
	if session.scans >= session.settings.scanLimit {
		return poison(FailurePolicy, ErrSessionScanLimit)
	}
	session.scans++
	request, frame, failure := newScanRequest(session.settings.random, sources)
	if failure != FailureNone {
		return poison(failure, errScanRequest)
	}
	defer clearRequestCopy(&request)
	defer clear(frame)

	response, err := session.exchange(ctx, frame, request)
	if err != nil {
		failure := FailurePolicy
		if errors.Is(err, errScanCanceled) {
			failure = FailureCanceled
		}
		return poison(failure, err)
	}
	if response.Status != StatusComplete {
		return poison(statusFailure(response.Status), fmt.Errorf("%w: %s", errScanIncomplete, response.Status))
	}
	metadata.MatchCount = len(response.Matches)
	metadata.Duration = time.Since(started)
	return ScanResult{matches: append([]Match(nil), response.Matches...), metadata: metadata, complete: true}, nil
}

func statusFailure(status string) FailureClass {
	switch status {
	case StatusInputRejected:
		return FailureInvalidInput
	case StatusResourceExhausted:
		return FailureResourceLimit
	default:
		return FailurePolicy
	}
}

func (session *Session) metadata(sources [][]byte) ScanMetadata {
	metadata := ScanMetadata{
		Scanner:         ScannerName,
		ScannerVersion:  ScannerVersion,
		ScannerCommit:   ScannerCommit,
		RulesetIdentity: RulesetIdentity,
		BuildProfile:    session.settings.config.BuildProfile,
		HelperSHA256:    session.settings.config.HelperSHA256,
		SourceCount:     len(sources),
	}
	for _, source := range sources {
		metadata.ScannedByteCount += len(source)
	}
	return metadata
}

// deadline is when an exchange starting at now must be over. The first
// exchange may also use what is left of the start allowance.
func (session *Session) deadline(now time.Time) time.Time {
	deadline := now.Add(session.settings.scanWatchdog)
	if !session.exchanged {
		if first := session.spawned.Add(session.settings.startAllowance + session.settings.scanWatchdog); first.After(deadline) {
			deadline = first
		}
	}
	return deadline
}

// exchange writes one request frame and reads one response frame. The
// watchdog and ctx both hard-stop the helper, which unblocks the pipes.
func (session *Session) exchange(ctx context.Context, frame []byte, request Request) (Response, error) {
	process := session.process
	timer := time.AfterFunc(time.Until(session.deadline(time.Now())), func() { process.failWith(errHelperDeadline) })
	stopCancel := context.AfterFunc(ctx, func() { process.failWith(errScanCanceled) })
	response, err := session.roundTrip(frame, request)
	timerStopped := timer.Stop()
	cancelStopped := stopCancel()
	if failure := process.fault(); failure != nil {
		return Response{}, failure
	}
	if !timerStopped {
		return Response{}, process.failWith(errHelperDeadline)
	}
	if !cancelStopped {
		return Response{}, process.failWith(errScanCanceled)
	}
	if err != nil {
		return Response{}, process.failWith(err)
	}
	session.exchanged = true
	return response, nil
}

func (session *Session) roundTrip(frame []byte, request Request) (Response, error) {
	process := session.process
	process.requestsSent.Add(1)
	if written, err := process.stdin.Write(frame); err != nil || written != len(frame) {
		return Response{}, errHelperIO
	}
	var prefix [framePrefixBytes]byte
	if read, err := io.ReadFull(process.stdout, prefix[:]); err != nil {
		if read == 0 && errors.Is(err, io.EOF) {
			return Response{}, errHelperNoResponse
		}
		return Response{}, errHelperFrame
	}
	declared := binary.BigEndian.Uint32(prefix[:])
	if declared == 0 || declared > maxResponseFrameBytes {
		return Response{}, errHelperFrame
	}
	responseFrame := make([]byte, framePrefixBytes+int(declared))
	defer clear(responseFrame)
	copy(responseFrame, prefix[:])
	if _, err := io.ReadFull(process.stdout, responseFrame[framePrefixBytes:]); err != nil {
		return Response{}, errHelperFrame
	}
	if process.stderrBytes.Load() != 0 {
		return Response{}, errHelperStderr
	}
	response, err := ParseResponseFrame(responseFrame, ResponseExpectation{Request: request, RulesetIdentity: RulesetIdentity, RuleIDs: session.ruleIDs})
	if err != nil || response.BuildProfile != session.settings.config.BuildProfile {
		return Response{}, errHelperResponse
	}
	return response, nil
}

func (session *Session) finish() error {
	process := session.process
	if process.beginClosing() {
		process.failWith(errHelperExited)
	}
	if hook := session.settings.hooks.closingStarted; hook != nil {
		hook()
	}
	timer := time.AfterFunc(time.Until(session.deadline(time.Now())), func() { process.failWith(errHelperDeadline) })
	defer timer.Stop()
	if process.fault() == nil {
		_ = process.stdin.Close()
		process.drainOutput()
		<-process.exited
	}
	waitError := process.reap()
	<-process.stderrDone
	// The exit watcher may still be recording an early exit; Close reports
	// only once it is done.
	<-process.watched
	timerStopped := timer.Stop()
	defer process.closeFiles()
	if failure := process.fault(); failure != nil {
		return failure
	}
	if !timerStopped {
		return process.failWith(errHelperDeadline)
	}
	if waitError != nil {
		return process.failWith(exitFailure(waitError))
	}
	if process.stderrBytes.Load() != 0 {
		return process.failWith(errHelperStderr)
	}
	return nil
}

func exitFailure(err error) error {
	var exitError *exec.ExitError
	if errors.As(err, &exitError) && exitError.ProcessState != nil {
		return fmt.Errorf("%w: %s", errHelperExit, exitError.ProcessState.String())
	}
	return errHelperExit
}

// verifiedHelper is a helper file that matched its digest. file stays open
// until the helper has started, so the platform code can execute exactly the
// verified file.
type verifiedHelper struct {
	file        *os.File
	execPath    string
	displayPath string
}

func (helper verifiedHelper) close() {
	if helper.file != nil {
		_ = helper.file.Close()
	}
}

// helperProcess owns one helper and its pipes. The process group is killed
// only while the group leader is not yet reaped, so the group ID cannot have
// been reused by an unrelated process.
type helperProcess struct {
	command *exec.Cmd
	group   processGroup
	stdin   *os.File
	stdout  *os.File
	stderr  *os.File

	exited      chan struct{}
	reapRequest chan struct{}
	reaped      chan struct{}
	stderrDone  chan struct{}
	watched     chan struct{}
	waitError   error
	hooks       processHooks

	stderrBytes  atomic.Int64
	requestsSent atomic.Int64

	// closingMu orders the helper's exit against the closing transition:
	// an exit observed before closing is set came too early.
	closingMu sync.Mutex
	closing   bool

	faultMu sync.Mutex
	failure error

	lifeMu   sync.Mutex
	reaping  bool
	stopOnce sync.Once
	reapOnce sync.Once
}

func startHelperProcess(helper verifiedHelper, directory string, hooks processHooks) (*helperProcess, error) {
	var pipes [6]*os.File
	closeAll := func() {
		for _, pipe := range pipes {
			if pipe != nil {
				_ = pipe.Close()
			}
		}
	}
	for index := 0; index < len(pipes); index += 2 {
		read, write, err := os.Pipe()
		if err != nil {
			closeAll()
			return nil, errHelperStart
		}
		pipes[index], pipes[index+1] = read, write
	}
	stdinRead, stdinWrite := pipes[0], pipes[1]
	stdoutRead, stdoutWrite := pipes[2], pipes[3]
	stderrRead, stderrWrite := pipes[4], pipes[5]
	command := &exec.Cmd{
		Path:   helper.execPath,
		Args:   []string{helper.displayPath, helperSessionArgument},
		Env:    []string{},
		Dir:    directory,
		Stdin:  stdinRead,
		Stdout: stdoutWrite,
		Stderr: stderrWrite,
	}
	configureHelperCommand(command)
	process := &helperProcess{
		command:     command,
		stdin:       stdinWrite,
		stdout:      stdoutRead,
		stderr:      stderrRead,
		exited:      make(chan struct{}),
		reapRequest: make(chan struct{}),
		reaped:      make(chan struct{}),
		stderrDone:  make(chan struct{}),
		watched:     make(chan struct{}),
		hooks:       hooks,
	}
	started := make(chan error, 1)
	go process.run(started, hooks.beforeStart)
	err := <-started
	_ = stdinRead.Close()
	_ = stdoutWrite.Close()
	_ = stderrWrite.Close()
	if err != nil {
		_ = stdinWrite.Close()
		_ = stdoutRead.Close()
		_ = stderrRead.Close()
		return nil, errHelperStart
	}
	go process.monitorStandardError()
	go process.watchExit()
	return process, nil
}

// run starts the helper and later reaps it on one goroutine locked to its OS
// thread. On Linux the parent-death signal fires when the thread that started
// the child exits, so that thread must live as long as the child.
func (process *helperProcess) run(started chan<- error, beforeStart func()) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if beforeStart != nil {
		beforeStart()
	}
	if err := process.command.Start(); err != nil {
		started <- err
		return
	}
	if err := process.group.attach(process.command.Process); err != nil {
		_ = process.command.Process.Kill()
		_ = process.command.Wait()
		process.group.release()
		started <- err
		return
	}
	started <- nil
	process.group.waitExit()
	close(process.exited)
	<-process.reapRequest
	process.lifeMu.Lock()
	process.group.kill(process.command.Process)
	process.reaping = true
	process.lifeMu.Unlock()
	process.waitError = process.command.Wait()
	process.group.release()
	close(process.reaped)
}

// failWith records cause as the session failure unless one is already
// recorded, hard-stops the helper and returns the first recorded failure.
func (process *helperProcess) failWith(cause error) error {
	process.faultMu.Lock()
	if process.failure == nil {
		process.failure = cause
	}
	first := process.failure
	process.faultMu.Unlock()
	process.hardStop()
	return first
}

func (process *helperProcess) fault() error {
	process.faultMu.Lock()
	defer process.faultMu.Unlock()
	return process.failure
}

// hardStop kills the whole process group and closes the parent's pipe ends,
// which unblocks every pending read and write.
func (process *helperProcess) hardStop() {
	process.stopOnce.Do(func() {
		process.lifeMu.Lock()
		if !process.reaping {
			process.group.kill(process.command.Process)
		}
		process.lifeMu.Unlock()
		process.closeFiles()
	})
}

func (process *helperProcess) closeFiles() {
	_ = process.stdin.Close()
	_ = process.stdout.Close()
	_ = process.stderr.Close()
}

// reap kills what is left of the process group, waits for the helper and
// returns its wait error. It blocks until the helper has exited.
func (process *helperProcess) reap() error {
	process.reapOnce.Do(func() { close(process.reapRequest) })
	<-process.reaped
	return process.waitError
}

// watchExit records an exit of the helper before Close began as a failure
// and reaps the helper.
func (process *helperProcess) watchExit() {
	defer close(process.watched)
	<-process.exited
	if hook := process.hooks.exitObserved; hook != nil {
		hook()
	}
	process.closingMu.Lock()
	early := !process.closing
	process.closingMu.Unlock()
	if hook := process.hooks.exitJudged; hook != nil {
		hook(early)
	}
	if early {
		process.failWith(errHelperExited)
		_ = process.reap()
	}
}

// beginClosing is the closing transition. It reports whether the helper had
// already exited, which is then an early exit whether or not the exit
// watcher has seen it yet.
func (process *helperProcess) beginClosing() bool {
	process.closingMu.Lock()
	defer process.closingMu.Unlock()
	process.closing = true
	select {
	case <-process.exited:
		return true
	default:
		return false
	}
}

// monitorStandardError counts standard error bytes and discards them
// unread; the first byte is a failure.
func (process *helperProcess) monitorStandardError() {
	defer close(process.stderrDone)
	buffer := make([]byte, 512)
	for {
		read, err := process.stderr.Read(buffer)
		if read > 0 {
			clear(buffer[:read])
			process.stderrBytes.Add(int64(read))
			process.failWith(errHelperStderr)
		}
		if err != nil {
			return
		}
	}
}

// drainOutput requires that stdout ends without another byte after stdin was
// closed.
func (process *helperProcess) drainOutput() {
	var buffer [512]byte
	for {
		read, err := process.stdout.Read(buffer[:])
		if read > 0 {
			clear(buffer[:read])
			process.failWith(errHelperTrailingOutput)
			return
		}
		if errors.Is(err, io.EOF) {
			return
		}
		if err != nil {
			process.failWith(errHelperIO)
			return
		}
	}
}
