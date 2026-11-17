// Package scanhelper is the scan helper process: it speaks the scanner's
// stdio protocol to its parent and runs every scan in a fresh instance of the
// WebAssembly guest, whose regular expressions it evaluates through
// regexhost.
//
// Contract:
//
//	--stdio-v1          read one request frame, require end of input, write one response frame
//	--stdio-v1-session  read request frames until end of input at a frame boundary, write one response frame each
//
// Standard input carries request frames. Response frames go to the descriptor
// that was standard output at start; standard output and standard error are
// then the null device, and nothing is written to either on purpose. The
// working directory is the compilation cache directory: it must be owned by
// the current user and have no group or other permission bits. On Windows
// and macOS, where owner and mode bits do not prove that a directory is
// private, every working directory is refused. The helper reads no
// environment variables. Before it reads the first request it compiles the
// guest and starts libre2, both through caches in that directory, so a
// session with no request fills both caches and exits 0.
//
// The cache is trusted at the level of its owner. wazero checks a cache entry
// only against a checksum, so whoever can write the cache directory controls
// the code the helper runs; the checks on the directory make sure that only
// its owner and root can.
//
// The helper sets its own core file and descriptor limits and exits when its
// parent process goes away.
package scanhelper

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"runtime/debug"
	"time"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/regexabi"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/regexhost"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/workerio"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"
)

// Arguments of the helper.
const (
	SingleArgument  = "--stdio-v1"
	SessionArgument = "--stdio-v1-session"
)

// Exit statuses. A non-zero status means at least one request got no
// response, and the response of the failing request is never written.
const (
	ExitSuccess = 0
	// ExitUsage: the arguments are not exactly one of the two above.
	ExitUsage = 64
	// ExitBadFrame: a request frame has a bad length prefix, is cut short,
	// or is followed by more input in single mode.
	ExitBadFrame = 65
	// ExitInternal: the guest digest does not match its pin, or the helper
	// could not set up its descriptors, pattern table or runtime.
	ExitInternal = 70
	// ExitGuestBridge: the host refused a regex call of the guest, or the
	// guest exited with regexabi.GuestBridgeFailureExitCode.
	ExitGuestBridge = 71
	// ExitGuestFailure: the guest exited non-zero for another reason,
	// trapped, ran out of memory, or wrote anything but one response frame
	// within the response limit.
	ExitGuestFailure = 72
	// ExitOutput: a response frame could not be written.
	ExitOutput = 74
	// ExitCacheDirectory: the working directory is not a private cache
	// directory, or the compilation cache could not be opened in it.
	ExitCacheDirectory = 78
)

// Limits of the helper and its guest.
const (
	// MaximumResponseFrameBytes is the largest response payload relayed.
	MaximumResponseFrameBytes = 4 * 1024 * 1024
	// GuestMemoryPages is the guest's linear memory limit (160 MiB).
	GuestMemoryPages = 2560
	// GuestMemoryLimit is the guest's GOMEMLIMIT. Its collector is off
	// until the heap nears this limit. A collection then runs concurrently
	// on the guest's one thread while the scan keeps allocating, so the
	// guest's memory grows well past this limit before the collection ends;
	// GuestMemoryPages leaves room for that growth on every request the
	// protocol allows.
	GuestMemoryLimit = "64MiB"
	// MemoryLimitBytes is the soft limit of the helper's own heap, which
	// also holds the guest's linear memory.
	MemoryLimitBytes = 384 * 1024 * 1024
	// MaximumDescriptors is the helper's open descriptor limit.
	MaximumDescriptors = 16
)

// parentPollInterval is how often the helper checks that its parent lives.
const parentPollInterval = 250 * time.Millisecond

const (
	guestProgramName    = "open-trestle-scan-guest"
	guestSingleArgument = "--sandboxed-stdio-v1"
)

var errGuestDigest = errors.New("scan guest digest mismatch")

// Main runs the helper process with the guest image and its pinned SHA-256
// in hex. It sets up the process (descriptors, core dumps, memory limit,
// cache directory) and returns the exit status.
func Main(arguments []string, guest []byte, guestSHA256 string) (exitCode int) {
	debug.SetTraceback("none")
	defer func() {
		if recover() != nil {
			exitCode = ExitInternal
		}
	}()
	if len(arguments) != 2 || arguments[1] != SingleArgument && arguments[1] != SessionArgument {
		return ExitUsage
	}
	protocolOutput, err := IsolateStandardStreams()
	if err != nil {
		return ExitInternal
	}
	defer protocolOutput.Close()
	if err := LimitResources(); err != nil {
		return ExitInternal
	}
	ExitWithParent()
	debug.SetMemoryLimit(MemoryLimitBytes)
	cacheDirectory, err := PrivateCacheDirectory()
	if err != nil {
		return ExitCacheDirectory
	}
	if err := UseRE2CacheDirectory(cacheDirectory); err != nil {
		return ExitCacheDirectory
	}
	return Run(context.Background(), Options{
		Session:        arguments[1] == SessionArgument,
		Guest:          guest,
		GuestSHA256:    guestSHA256,
		CacheDirectory: cacheDirectory,
		Input:          os.Stdin,
		Output:         protocolOutput,
	})
}

// Options configure Run.
type Options struct {
	// Session selects session mode; otherwise one request is served.
	Session bool
	// Guest is the guest module; GuestSHA256 its pinned hex digest.
	Guest       []byte
	GuestSHA256 string
	// CacheDirectory holds the compilation cache. Main has checked it.
	CacheDirectory string
	Input          io.Reader
	Output         io.Writer
}

// Run verifies and compiles the guest, then serves requests from Input. It
// returns an exit status.
func Run(ctx context.Context, options Options) int {
	if err := verifyGuest(options.Guest, options.GuestSHA256); err != nil {
		return ExitInternal
	}
	table, err := regexhost.PinnedTable()
	if err != nil {
		return ExitInternal
	}
	bridge, err := regexhost.NewBridge(table, regexhost.DefaultLimits)
	if err != nil {
		return ExitInternal
	}
	cache, err := wazero.NewCompilationCacheWithDir(options.CacheDirectory)
	if err != nil {
		return ExitCacheDirectory
	}
	defer cache.Close(ctx)
	// The parent stops a scan by killing the helper, so the runtime does
	// not close modules on context cancellation, which would slow every
	// guest loop.
	runtime := wazero.NewRuntimeWithConfig(ctx, wazero.NewRuntimeConfig().
		WithCompilationCache(cache).
		WithMemoryLimitPages(GuestMemoryPages).
		WithCloseOnContextDone(false))
	defer runtime.Close(ctx)
	if _, err := wasi_snapshot_preview1.Instantiate(ctx, runtime); err != nil {
		return ExitInternal
	}
	if err := bridge.Instantiate(ctx, runtime); err != nil {
		return ExitInternal
	}
	compiled, err := runtime.CompileModule(ctx, options.Guest)
	if err != nil {
		return ExitInternal
	}
	if err := table.Prepare(); err != nil {
		return ExitInternal
	}
	helper := &helper{runtime: runtime, compiled: compiled, bridge: bridge}
	if !options.Session {
		return helper.serveOne(ctx, options.Input, options.Output)
	}
	return helper.serveSession(ctx, options.Input, options.Output)
}

func verifyGuest(guest []byte, want string) error {
	expected, err := hex.DecodeString(want)
	if err != nil || len(expected) != sha256.Size || want != hex.EncodeToString(expected) {
		return errGuestDigest
	}
	digest := sha256.Sum256(guest)
	if !bytes.Equal(digest[:], expected) {
		return errGuestDigest
	}
	return nil
}

type helper struct {
	runtime  wazero.Runtime
	compiled wazero.CompiledModule
	bridge   *regexhost.Bridge
}

func (h *helper) serveOne(ctx context.Context, input io.Reader, output io.Writer) int {
	frame, err := readRequestFrame(input)
	defer clear(frame)
	if err != nil {
		return ExitBadFrame
	}
	var trailing [1]byte
	if count, err := input.Read(trailing[:]); count != 0 || err != io.EOF {
		return ExitBadFrame
	}
	return h.relay(ctx, frame, output)
}

func (h *helper) serveSession(ctx context.Context, input io.Reader, output io.Writer) int {
	for {
		frame, err := readRequestFrame(input)
		if errors.Is(err, io.EOF) {
			return ExitSuccess
		}
		if err != nil {
			clear(frame)
			return ExitBadFrame
		}
		code := h.relay(ctx, frame, output)
		clear(frame)
		if code != ExitSuccess {
			return code
		}
	}
}

func (h *helper) relay(ctx context.Context, frame []byte, output io.Writer) int {
	response, code := h.scan(ctx, frame)
	defer clear(response)
	if code != ExitSuccess {
		return code
	}
	if err := workerio.WriteAll(output, response); err != nil {
		return ExitOutput
	}
	return ExitSuccess
}

// scan runs one fresh guest instance over one request frame and returns its
// response frame.
func (h *helper) scan(ctx context.Context, frame []byte) ([]byte, int) {
	scanContext, session := h.bridge.NewSession(ctx)
	output := &limitedBuffer{limit: 4 + MaximumResponseFrameBytes}
	config := wazero.NewModuleConfig().
		WithName("").
		WithArgs(guestProgramName, guestSingleArgument).
		WithEnv("GOGC", "off").
		WithEnv("GOMEMLIMIT", GuestMemoryLimit).
		WithStdin(bytes.NewReader(frame)).
		WithStdout(output).
		WithSysNanotime().
		WithSysWalltime().
		// wazero's default random source is a fixed sequence; the Go
		// runtime seeds its map hashing from it, and repository content
		// must not be able to predict that seed.
		WithRandSource(rand.Reader)
	module, err := h.runtime.InstantiateModule(scanContext, h.compiled, config)
	if module != nil {
		_ = module.Close(ctx)
	}
	status := guestStatus(err)
	if session.Refused() > 0 || status == regexabi.GuestBridgeFailureExitCode {
		clear(output.content)
		return nil, ExitGuestBridge
	}
	if status != 0 || output.overflow || !singleResponseFrame(output.content) {
		clear(output.content)
		return nil, ExitGuestFailure
	}
	return output.content, ExitSuccess
}

// guestStatus returns the guest's exit status, 0 for a clean return and -1
// for any failure that is not an exit.
func guestStatus(err error) int {
	if err == nil {
		return 0
	}
	var exit *sys.ExitError
	if errors.As(err, &exit) {
		return int(exit.ExitCode())
	}
	return -1
}

func singleResponseFrame(content []byte) bool {
	if len(content) < 5 {
		return false
	}
	length := binary.BigEndian.Uint32(content[:4])
	return length != 0 && length <= MaximumResponseFrameBytes && uint64(length)+4 == uint64(len(content))
}

// readRequestFrame reads one request frame. It returns io.EOF only when the
// input ends before the first byte of a frame.
func readRequestFrame(input io.Reader) ([]byte, error) {
	var prefix [4]byte
	if count, err := io.ReadFull(input, prefix[:]); err != nil {
		if count == 0 && errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, io.ErrUnexpectedEOF
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 || length > workerio.MaximumRequestFrameBytes {
		return nil, errBadFrame
	}
	frame := make([]byte, 4+int(length))
	copy(frame, prefix[:])
	if _, err := io.ReadFull(input, frame[4:]); err != nil {
		clear(frame)
		return nil, io.ErrUnexpectedEOF
	}
	return frame, nil
}

var errBadFrame = errors.New("bad request frame")

// limitedBuffer collects guest output up to limit bytes and records an
// attempt to write more, which fails the scan.
type limitedBuffer struct {
	content  []byte
	limit    int
	overflow bool
}

func (b *limitedBuffer) Write(content []byte) (int, error) {
	if b.overflow || len(content) > b.limit-len(b.content) {
		b.overflow = true
		return 0, errResponseTooLarge
	}
	b.content = append(b.content, content...)
	return len(content), nil
}

var errResponseTooLarge = errors.New("guest response exceeds the response limit")
