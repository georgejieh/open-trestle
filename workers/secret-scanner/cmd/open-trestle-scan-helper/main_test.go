//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/adapter"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/helperbuild"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/regexabi"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/scanhelper"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/wasmtest"
	"golang.org/x/sys/unix"
)

const isolationChild = "OPEN_TRESTLE_SCAN_HELPER_TEST_ISOLATION_CHILD"

func TestMain(m *testing.M) {
	if os.Getenv(isolationChild) == "1" {
		os.Exit(isolationChildMain())
	}
	code := m.Run()
	if built.directory != "" {
		_ = os.RemoveAll(built.directory)
	}
	os.Exit(code)
}

// built holds the binaries every test shares. They are built once per test
// binary: the guest build and the first wazero compile of the guest each
// take tens of seconds.
var (
	buildOnce sync.Once
	built     struct {
		directory string
		guest     string
		helper    string
		hostile   string
		wrongPin  string
		unpinned  string
		cache     string
		err       error
	}
)

func binaries(t testing.TB) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the scan helper is tested on Linux")
	}
	buildOnce.Do(func() {
		built.err = buildBinaries()
	})
	if built.err != nil {
		t.Fatal(built.err)
	}
}

func buildBinaries() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	directory, err := os.MkdirTemp("", "open-trestle-scan-helper-test-")
	if err != nil {
		return err
	}
	built.directory = directory
	module := filepath.Join("..", "..")
	result, err := helperbuild.Build(ctx, module, directory)
	if err != nil {
		return err
	}
	built.guest, built.helper = result.Guest, result.Helper
	hostileGuest := filepath.Join(directory, "hostile.wasm")
	if err := os.WriteFile(hostileGuest, hostileModule(), 0o600); err != nil {
		return err
	}
	hostile, err := helperbuild.BuildHelper(ctx, module, hostileGuest, directory, "hostile-helper")
	if err != nil {
		return err
	}
	built.hostile = hostile.Helper
	wrong := sha256.Sum256([]byte("another guest"))
	wrongPin, err := helperbuild.BuildHelperWithPin(ctx, module, built.guest, hex.EncodeToString(wrong[:]), directory, "wrong-pin-helper")
	if err != nil {
		return err
	}
	built.wrongPin = wrongPin.Helper
	unpinned, err := helperbuild.BuildHelperWithPin(ctx, module, filepath.Join(module, "cmd", "open-trestle-scan-helper", "guest.wasm"), "", directory, "unpinned-helper")
	if err != nil {
		return err
	}
	built.unpinned = unpinned.Helper
	built.cache = filepath.Join(directory, "cache")
	return os.Mkdir(built.cache, 0o700)
}

type helperRun struct {
	stdout, stderr []byte
	code           int
	elapsed        time.Duration
}

// runHelper runs a helper as the parent does: an empty environment, exactly
// the given arguments and the cache directory as working directory.
func runHelper(t *testing.T, helper, directory string, input []byte, arguments ...string) helperRun {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, helper, arguments...)
	command.Env = []string{}
	command.Dir = directory
	command.Stdin = bytes.NewReader(input)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	started := time.Now()
	err := command.Run()
	run := helperRun{stdout: stdout.Bytes(), stderr: stderr.Bytes(), elapsed: time.Since(started)}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit) && exit.Exited():
		run.code = exit.ExitCode()
	default:
		t.Fatalf("helper did not exit normally: %v", err)
	}
	if len(run.stderr) != 0 {
		t.Fatalf("helper wrote %d bytes to standard error", len(run.stderr))
	}
	return run
}

// runSession runs a helper in session mode as the parent's session does: it
// writes one request frame at a time and reads its response before writing
// the next, so standard input stays open while the helper serves a request.
// It then writes trailing, bytes that are not a whole frame, and closes
// standard input. It stops writing frames once the helper ends its output.
func runSession(t testing.TB, helper, directory string, frames [][]byte, trailing []byte) helperRun {
	t.Helper()
	command := exec.Command(helper, scanhelper.SessionArgument)
	command.Env = []string{}
	command.Dir = directory
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	command.Stderr = &stderr
	started := time.Now()
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	watchdog := time.AfterFunc(10*time.Minute, func() { _ = command.Process.Kill() })
	defer watchdog.Stop()
	var output bytes.Buffer
	for _, frame := range frames {
		if _, err := stdin.Write(frame); err != nil {
			break
		}
		var prefix [4]byte
		if _, err := io.ReadFull(stdout, prefix[:]); err != nil {
			break
		}
		response := make([]byte, 4+int(binary.BigEndian.Uint32(prefix[:])))
		copy(response, prefix[:])
		if _, err := io.ReadFull(stdout, response[4:]); err != nil {
			t.Fatalf("response cut short: %v", err)
		}
		output.Write(response)
	}
	_, _ = stdin.Write(trailing)
	_ = stdin.Close()
	rest, err := io.ReadAll(stdout)
	if err != nil {
		t.Fatal(err)
	}
	output.Write(rest)
	err = command.Wait()
	run := helperRun{stdout: output.Bytes(), stderr: stderr.Bytes(), elapsed: time.Since(started)}
	var exit *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exit) && exit.Exited():
		run.code = exit.ExitCode()
	default:
		t.Fatalf("helper did not exit normally: %v", err)
	}
	if len(run.stderr) != 0 {
		t.Fatalf("helper wrote %d bytes to standard error", len(run.stderr))
	}
	return run
}

func requireFailure(t *testing.T, run helperRun, code int) {
	t.Helper()
	if run.code != code || len(run.stdout) != 0 {
		t.Fatalf("exit %d with %d output bytes, want exit %d and no output", run.code, len(run.stdout), code)
	}
}

func TestEmptySessionPreparesTheCompilationCache(t *testing.T) {
	binaries(t)
	run := runHelper(t, built.helper, built.cache, nil, scanhelper.SessionArgument)
	requireFailure(t, run, 0)
	size := directorySize(t, built.cache)
	if size == 0 {
		t.Fatal("empty session left the compilation cache empty")
	}
	t.Logf("first compile of the guest: %v, cache size %d bytes", run.elapsed, size)
	// go-re2 keeps its compiled libre2 in the same directory, found without
	// any environment variable.
	if info, err := os.Stat(filepath.Join(built.cache, "com.github.wasilibs")); err != nil || !info.IsDir() || info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("libre2 cache directory after an empty session: %v", err)
	}
	again := runHelper(t, built.helper, built.cache, nil, scanhelper.SessionArgument)
	requireFailure(t, again, 0)
	t.Logf("helper start with a prepared cache: %v", again.elapsed)
}

func TestFixturesMatchTheNativeScannerAndExpectedSpans(t *testing.T) {
	binaries(t)
	fixtures, spans := readQualification(t)
	native := nativeAdapter(t)
	var frames [][]byte
	requests := make([]protocol.Request, len(fixtures))
	for index, fixture := range fixtures {
		requests[index] = request(fixture.id, fixture.content)
		frames = append(frames, encodeRequest(t, requests[index]))
	}
	run := runSession(t, built.helper, built.cache, frames, nil)
	if run.code != 0 {
		t.Fatalf("session exited %d", run.code)
	}
	responses := splitFrames(t, run.stdout)
	if len(responses) != len(requests) {
		t.Fatalf("%d responses for %d requests", len(responses), len(requests))
	}
	detections := 0
	for index, fixture := range fixtures {
		helperResponse := parseResponse(t, requests[index], responses[index])
		nativeResponse := nativeScan(t, native, requests[index])
		requireSameScan(t, fixture.id, helperResponse, nativeResponse)
		want := spans[fixture.id]
		if len(helperResponse.Matches) != len(want) {
			t.Fatalf("%s: %d matches, want %d", fixture.id, len(helperResponse.Matches), len(want))
		}
		for position, match := range helperResponse.Matches {
			if match.RuleID != want[position].RuleID || match.StartByte != want[position].StartByte || match.EndByteExclusive != want[position].EndByteExclusive {
				t.Fatalf("%s: match %d = %+v, want %+v", fixture.id, position, match, want[position])
			}
		}
		detections += len(helperResponse.Matches)
	}
	if detections != 12 {
		t.Fatalf("%d detections, want the 12 expected spans", detections)
	}
}

func TestSyntheticMebibyteMatchesTheNativeScanner(t *testing.T) {
	binaries(t)
	fixtures, _ := readQualification(t)
	scan := request("synthetic-mebibyte", nil)
	scan.Sources = syntheticSources(fixtures, 4, 256*1024)
	run := runHelper(t, built.helper, built.cache, encodeRequest(t, scan), scanhelper.SingleArgument)
	if run.code != 0 {
		t.Fatalf("helper exited %d", run.code)
	}
	helperResponse := parseResponse(t, scan, run.stdout)
	nativeResponse := nativeScan(t, nativeAdapter(t), scan)
	if nativeResponse.Status != protocol.StatusComplete || len(nativeResponse.Matches) < 20 {
		t.Fatalf("native scan of the synthetic input: %s with %d matches", nativeResponse.Status, len(nativeResponse.Matches))
	}
	requireSameScan(t, "synthetic", helperResponse, nativeResponse)
	t.Logf("1 MiB single request: %v, %d matches", run.elapsed, len(helperResponse.Matches))
}

// TestDenseAndLimitRequestsEndAsTheNativeScannerDoes sends finding-dense
// requests, up to the protocol's request size and source count, through one
// helper session and requires the native scanner's status and matches for
// each, including the requests the native scanner stops at the match limit.
func TestDenseAndLimitRequestsEndAsTheNativeScannerDoes(t *testing.T) {
	if raceDetector {
		t.Skip("the native reference scan misses its deadline under the race detector")
	}
	binaries(t)
	fixtures, _ := readQualification(t)
	dense := repeatedFixtures(fixtures, reviewSourceBytes)
	cases := []struct {
		name    string
		sources []protocol.Source
		status  string
	}{
		{"fixtures repeated in one source", repeatedSources(dense, 1), protocol.StatusComplete},
		{"fixtures repeated in two sources", repeatedSources(dense, 2), protocol.StatusComplete},
		{"fixtures repeated to the request size limit", repeatedSources(dense, 8), protocol.StatusResourceExhausted},
		{"assignments in one source", assignmentSources(1, reviewSourceBytes), protocol.StatusComplete},
		{"assignments in the most sources", assignmentSources(256, 8*1024), protocol.StatusResourceExhausted},
	}
	native := nativeAdapter(t)
	var frames [][]byte
	requests := make([]protocol.Request, len(cases))
	for index, test := range cases {
		requests[index] = request(test.name, nil)
		requests[index].Sources = test.sources
		frames = append(frames, encodeRequest(t, requests[index]))
	}
	for _, limit := range []protocol.Request{requests[2], requests[4]} {
		total := 0
		for _, source := range limit.Sources {
			total += len(source.Content)
		}
		if total != 2*1024*1024 {
			t.Fatalf("request at the limits holds %d bytes, want 2 MiB", total)
		}
	}
	if len(requests[4].Sources) != 256 {
		t.Fatal("request at the source limit does not have 256 sources")
	}
	run := runSession(t, built.helper, built.cache, frames, nil)
	if run.code != 0 {
		t.Fatalf("session exited %d", run.code)
	}
	responses := splitFrames(t, run.stdout)
	if len(responses) != len(requests) {
		t.Fatalf("%d responses for %d requests", len(responses), len(requests))
	}
	for index, test := range cases {
		helperResponse := parseResponse(t, requests[index], responses[index])
		nativeResponse := nativeScan(t, native, requests[index])
		if nativeResponse.Status != test.status {
			t.Fatalf("%s: native status %s, want %s", test.name, nativeResponse.Status, test.status)
		}
		if helperResponse.BuildProfile != protocol.HostRE2BuildProfile {
			t.Fatalf("%s: helper build profile %q", test.name, helperResponse.BuildProfile)
		}
		helperResponse.BuildProfile = nativeResponse.BuildProfile
		if !reflect.DeepEqual(helperResponse, nativeResponse) {
			t.Fatalf("%s: helper %s with %d matches, native %s with %d matches", test.name, helperResponse.Status, len(helperResponse.Matches), nativeResponse.Status, len(nativeResponse.Matches))
		}
	}
	t.Logf("%d dense requests: %v", len(requests), run.elapsed)
}

// repeatedFixtures is size bytes of the qualification fixtures repeated, one
// per line, padded with spaces.
func repeatedFixtures(fixtures []fixture, size int) []byte {
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

func repeatedSources(content []byte, count int) []protocol.Source {
	sources := make([]protocol.Source, count)
	for index := range sources {
		sources[index] = protocol.Source{Ordinal: index, Content: content}
	}
	return sources
}

// assignmentSources returns count sources of size bytes of seeded random
// secret-like assignments, which the generic rules and their filters
// examine one by one.
func assignmentSources(count, size int) []protocol.Source {
	random := rand.New(rand.NewPCG(uint64(count), uint64(size)))
	names := []string{"api_key", "secret", "token", "password", "auth", "client_secret", "access_key", "private_key"}
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	sources := make([]protocol.Source, count)
	for index := range sources {
		var text bytes.Buffer
		for text.Len() < size-128 {
			value := make([]byte, 16+random.IntN(32))
			for position := range value {
				value[position] = alphabet[random.IntN(len(alphabet))]
			}
			fmt.Fprintf(&text, "%s_%d = %q\n", names[random.IntN(len(names))], random.IntN(1000), value)
		}
		text.WriteString(strings.Repeat(" ", size-text.Len()-1))
		text.WriteByte('\n')
		sources[index] = protocol.Source{Ordinal: index, Content: text.Bytes()}
	}
	return sources
}

func TestSingleModeRequiresExactlyOneFrame(t *testing.T) {
	binaries(t)
	frame := encodeRequest(t, request("single", []byte("ordinary text")))
	run := runHelper(t, built.helper, built.cache, frame, scanhelper.SingleArgument)
	if run.code != 0 || len(splitFrames(t, run.stdout)) != 1 {
		t.Fatalf("one frame: exit %d", run.code)
	}
	oversized := []byte{0, 0, 0, 0}
	binary.BigEndian.PutUint32(oversized, 3*1024*1024+1)
	for name, input := range map[string][]byte{
		"no input":      nil,
		"short prefix":  frame[:3],
		"short payload": frame[:len(frame)-1],
		"second frame":  append(append([]byte(nil), frame...), frame...),
		"trailing byte": append(append([]byte(nil), frame...), '\n'),
		"zero length":   {0, 0, 0, 0},
		"oversized":     oversized,
	} {
		t.Run(name, func(t *testing.T) {
			requireFailure(t, runHelper(t, built.helper, built.cache, input, scanhelper.SingleArgument), scanhelper.ExitBadFrame)
		})
	}
}

func TestSessionStopsAtTheFirstBadFrame(t *testing.T) {
	binaries(t)
	first := encodeRequest(t, request("first", []byte("first text")))
	second := encodeRequest(t, request("second", []byte("second text")))
	run := runSession(t, built.helper, built.cache, [][]byte{first, second}, second[:7])
	if run.code != scanhelper.ExitBadFrame {
		t.Fatalf("session with a cut final frame exited %d", run.code)
	}
	if responses := splitFrames(t, run.stdout); len(responses) != 2 {
		t.Fatalf("%d responses before the bad frame, want 2", len(responses))
	}
	run = runSession(t, built.helper, built.cache, [][]byte{first}, []byte{0, 0, 0, 0})
	if run.code != scanhelper.ExitBadFrame || len(splitFrames(t, run.stdout)) != 1 {
		t.Fatalf("session with a zero-length frame exited %d", run.code)
	}
}

func TestArgumentsAreExactlyOneMode(t *testing.T) {
	binaries(t)
	for _, arguments := range [][]string{nil, {"--stdio"}, {scanhelper.SingleArgument, "extra"}, {scanhelper.SessionArgument, scanhelper.SingleArgument}, {"-max-calls=1"}} {
		requireFailure(t, runHelper(t, built.helper, built.cache, nil, arguments...), scanhelper.ExitUsage)
	}
}

func TestCacheDirectoryMustBePrivate(t *testing.T) {
	binaries(t)
	for _, mode := range []fs.FileMode{0o755, 0o770, 0o701, 0o707} {
		directory := filepath.Join(t.TempDir(), "cache")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, mode); err != nil {
			t.Fatal(err)
		}
		requireFailure(t, runHelper(t, built.helper, directory, nil, scanhelper.SessionArgument), scanhelper.ExitCacheDirectory)
	}
	if os.Geteuid() != 0 {
		requireFailure(t, runHelper(t, built.helper, "/", nil, scanhelper.SessionArgument), scanhelper.ExitCacheDirectory)
	}
}

func TestGuestDigestIsCheckedBeforeAnyScan(t *testing.T) {
	binaries(t)
	frame := encodeRequest(t, request("digest", []byte("text")))
	requireFailure(t, runHelper(t, built.wrongPin, built.cache, frame, scanhelper.SingleArgument), scanhelper.ExitInternal)
	requireFailure(t, runHelper(t, built.unpinned, built.cache, frame, scanhelper.SingleArgument), scanhelper.ExitInternal)
}

// Hostile guest behaviours, selected by the first payload byte of a request.
const (
	hostileRefusedThenAnswers = 'r'
	hostileBridgeExit         = 'b'
	hostileOtherExit          = 'x'
	hostileMalformedFrame     = 'm'
	hostileNoOutput           = 'e'
	hostileValidFrame         = 'g'
	hostileOversizedOutput    = 'o'
	hostileTrap               = 't'
	hostileSpin               = 'l'
)

var hostileFrame = []byte{0, 0, 0, 2, '{', '}'}

// hostileModule is a guest that reads the start of its request and then does
// what the selector byte says, including calling the host with an unpinned
// pattern, ignoring the refusal and answering anyway.
func hostileModule() []byte {
	const (
		patternAt   = 0
		readVector  = 16
		countAt     = 32
		goodVector  = 48
		badVector   = 64
		hugeVector  = 80
		goodFrameAt = 256
		badFrameAt  = 512
		inputAt     = 1024
		hugeAt      = 65536
	)
	vector := func(pointer, length uint32) []byte {
		encoded := binary.LittleEndian.AppendUint32(nil, pointer)
		return binary.LittleEndian.AppendUint32(encoded, length)
	}
	const fdRead, fdWrite, procExit, compile = 0, 1, 2, 3
	write := func(vectorAt int32) []byte {
		return wasmtest.Concat(wasmtest.I32Const(1), wasmtest.I32Const(vectorAt), wasmtest.I32Const(1), wasmtest.I32Const(countAt), wasmtest.Call(fdWrite), wasmtest.Drop)
	}
	exit := func(code int32) []byte {
		return wasmtest.Concat(wasmtest.I32Const(code), wasmtest.Call(procExit))
	}
	scenarios := map[byte][]byte{
		hostileRefusedThenAnswers: wasmtest.Concat(wasmtest.I32Const(patternAt), wasmtest.I32Const(6), wasmtest.Call(compile), wasmtest.Drop, write(goodVector), exit(0)),
		hostileBridgeExit:         exit(regexabi.GuestBridgeFailureExitCode),
		hostileOtherExit:          exit(3),
		hostileMalformedFrame:     wasmtest.Concat(write(badVector), exit(0)),
		hostileNoOutput:           exit(0),
		hostileValidFrame:         wasmtest.Concat(write(goodVector), exit(0)),
		hostileOversizedOutput:    wasmtest.Concat(write(hugeVector), exit(0)),
		hostileTrap:               wasmtest.Unreachable,
		hostileSpin:               wasmtest.Concat(wasmtest.LoopEmpty, wasmtest.Branch(0), wasmtest.End),
	}
	body := wasmtest.Concat(wasmtest.I32Const(0), wasmtest.I32Const(readVector), wasmtest.I32Const(1), wasmtest.I32Const(countAt), wasmtest.Call(fdRead), wasmtest.Drop)
	for selector, scenario := range scenarios {
		body = wasmtest.Concat(body, wasmtest.I32Const(inputAt+4), wasmtest.Load8U(0), wasmtest.I32Const(int32(selector)), wasmtest.I32Equal, wasmtest.IfEmpty, scenario, wasmtest.End)
	}
	body = wasmtest.Concat(body, exit(9))
	i32 := []byte{wasmtest.I32}
	return wasmtest.Module{
		Types: []wasmtest.FunctionType{
			{Parameters: bytes.Repeat(i32, 4), Results: i32},
			{Parameters: i32},
			{Parameters: bytes.Repeat(i32, 2), Results: i32},
			{},
		},
		Imports: []wasmtest.Import{
			{Module: "wasi_snapshot_preview1", Name: "fd_read", Type: 0},
			{Module: "wasi_snapshot_preview1", Name: "fd_write", Type: 0},
			{Module: "wasi_snapshot_preview1", Name: "proc_exit", Type: 1},
			{Module: regexabi.ModuleName, Name: regexabi.FunctionCompile, Type: 2},
		},
		Functions:   []wasmtest.Function{{Type: 3, Body: body}},
		MemoryPages: 96,
		Exports: []wasmtest.Export{
			{Name: "_start", Kind: wasmtest.ExportFunction, Index: 4},
			{Name: "memory", Kind: wasmtest.ExportMemory},
		},
		Data: []wasmtest.Data{
			{Offset: patternAt, Bytes: []byte("(a+)+$")},
			{Offset: readVector, Bytes: vector(inputAt, 64)},
			{Offset: goodVector, Bytes: vector(goodFrameAt, uint32(len(hostileFrame)))},
			{Offset: badVector, Bytes: vector(badFrameAt, 6)},
			{Offset: hugeVector, Bytes: vector(hugeAt, 5<<20)},
			{Offset: goodFrameAt, Bytes: hostileFrame},
			{Offset: badFrameAt, Bytes: []byte{0, 0, 0, 9, '{', '}'}},
		},
	}.Encode()
}

func hostileRequest(selector byte) []byte {
	return []byte{0, 0, 0, 1, selector}
}

func TestGuestFailuresProduceNoResponse(t *testing.T) {
	binaries(t)
	for selector, code := range map[byte]int{
		hostileRefusedThenAnswers: scanhelper.ExitGuestBridge,
		hostileBridgeExit:         scanhelper.ExitGuestBridge,
		hostileOtherExit:          scanhelper.ExitGuestFailure,
		hostileMalformedFrame:     scanhelper.ExitGuestFailure,
		hostileNoOutput:           scanhelper.ExitGuestFailure,
		hostileOversizedOutput:    scanhelper.ExitGuestFailure,
		hostileTrap:               scanhelper.ExitGuestFailure,
	} {
		t.Run(string(selector), func(t *testing.T) {
			requireFailure(t, runHelper(t, built.hostile, built.cache, hostileRequest(selector), scanhelper.SingleArgument), code)
		})
	}
	run := runHelper(t, built.hostile, built.cache, hostileRequest(hostileValidFrame), scanhelper.SingleArgument)
	if run.code != 0 || !bytes.Equal(run.stdout, hostileFrame) {
		t.Fatalf("valid hostile frame: exit %d output %q", run.code, run.stdout)
	}
	frames := [][]byte{hostileRequest(hostileValidFrame), hostileRequest(hostileRefusedThenAnswers), hostileRequest(hostileValidFrame)}
	run = runSession(t, built.hostile, built.cache, frames, nil)
	if run.code != scanhelper.ExitGuestBridge || !bytes.Equal(run.stdout, hostileFrame) {
		t.Fatalf("session with a bridge failure: exit %d output %q, want exit %d after one response", run.code, run.stdout, scanhelper.ExitGuestBridge)
	}
}

// TestSessionExitsWhenInputHangsUpDuringAScan closes the helper's standard
// input while its guest spins forever, as a parent that died mid-scan would.
// The test process, the helper's parent, stays alive, so the helper's parent
// process ID does not change and only the hangup can stop it.
func TestSessionExitsWhenInputHangsUpDuringAScan(t *testing.T) {
	binaries(t)
	command := exec.Command(built.hostile, scanhelper.SessionArgument)
	command.Env = []string{}
	command.Dir = built.cache
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- command.Wait() }()
	if _, err := stdin.Write(hostileRequest(hostileSpin)); err != nil {
		t.Fatal(err)
	}
	// The frame stays in the pipe after the write end closes, so the helper
	// reads it and starts the scan whether or not it already has.
	closed := time.Now()
	if err := stdin.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-exited:
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != scanhelper.ExitInternal || stdout.Len() != 0 || stderr.Len() != 0 {
			t.Fatalf("helper ended with %v and %d output bytes, want exit %d and none", err, stdout.Len()+stderr.Len(), scanhelper.ExitInternal)
		}
		if elapsed := time.Since(closed); elapsed > 5*time.Second {
			t.Fatalf("helper took %v to notice the hangup", elapsed)
		}
	case <-time.After(30 * time.Second):
		_ = command.Process.Kill()
		<-exited
		t.Fatal("helper kept scanning after its input hung up")
	}
}

// TestHelperClosesDescriptorsItInherited opens a file, a pipe and a socket
// in this process without close-on-exec, so that every child inherits them,
// starts the real helper, and checks after a scan that the helper holds none
// of them while a child that does not close them, /bin/sleep, holds all.
func TestHelperClosesDescriptorsItInherited(t *testing.T) {
	binaries(t)
	file, err := syscall.Open(built.guest, syscall.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	var pipe [2]int
	if err := syscall.Pipe(pipe[:]); err != nil {
		t.Fatal(err)
	}
	socket, err := syscall.Socket(syscall.AF_UNIX, syscall.SOCK_STREAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	inherited := []int{file, pipe[0], pipe[1], socket}
	defer func() {
		for _, descriptor := range inherited {
			_ = syscall.Close(descriptor)
		}
	}()
	targets := map[string]bool{}
	for _, descriptor := range inherited {
		target, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", descriptor))
		if err != nil {
			t.Fatal(err)
		}
		targets[target] = true
	}
	held := func(pid int) int {
		entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, entry := range entries {
			if target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, entry.Name())); err == nil && targets[target] {
				count++
			}
		}
		return count
	}
	sleeper := exec.Command("/bin/sleep", "60")
	if err := sleeper.Start(); err != nil {
		t.Fatal(err)
	}
	sleeperHeld := held(sleeper.Process.Pid)
	_ = sleeper.Process.Kill()
	_ = sleeper.Wait()
	if sleeperHeld != len(inherited) {
		t.Fatalf("a plain child holds %d of the %d descriptors, so the test does not create inherited descriptors", sleeperHeld, len(inherited))
	}
	command := exec.Command(built.helper, scanhelper.SessionArgument)
	command.Env = []string{}
	command.Dir = built.cache
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = command.Process.Kill()
		_ = command.Wait()
	}()
	scan := request("descriptors", []byte("ordinary text"))
	if _, err := stdin.Write(encodeRequest(t, scan)); err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	if _, err := io.ReadFull(stdout, prefix[:]); err != nil {
		t.Fatalf("helper did not answer: %v", err)
	}
	response := make([]byte, 4+int(binary.BigEndian.Uint32(prefix[:])))
	copy(response, prefix[:])
	if _, err := io.ReadFull(stdout, response[4:]); err != nil {
		t.Fatal(err)
	}
	if parsed := parseResponse(t, scan, response); parsed.Status != protocol.StatusComplete {
		t.Fatalf("scan after closing descriptors: %s", parsed.Status)
	}
	if count := held(command.Process.Pid); count != 0 {
		t.Fatalf("helper still holds %d inherited descriptors", count)
	}
	_ = stdin.Close()
	if rest, err := io.ReadAll(stdout); err != nil || len(rest) != 0 {
		t.Fatalf("output after the last response: %d bytes, %v", len(rest), err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("helper did not exit cleanly: %v", err)
	}
}

// TestStandardStreamsAreIsolated runs this test binary as a child that sets
// up its streams and limits as the helper does and then writes to every
// standard stream.
func TestStandardStreamsAreIsolated(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the scan helper is tested on Linux")
	}
	command := exec.Command(os.Args[0], "-test.run=^$")
	command.Env = []string{isolationChild + "=1"}
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	if err := command.Run(); err != nil {
		t.Fatalf("child: %v", err)
	}
	if stdout.String() != "protocol core=0/0 files=16/16" || stderr.Len() != 0 {
		t.Fatalf("stdout %q, stderr %q", stdout.String(), stderr.String())
	}
}

func isolationChildMain() int {
	protocolOutput, err := scanhelper.IsolateStandardStreams()
	if err != nil {
		return 10
	}
	if err := scanhelper.LimitResources(); err != nil {
		return 11
	}
	fmt.Fprint(os.Stdout, "stdout leak")
	fmt.Fprint(os.Stderr, "stderr leak")
	_, _ = syscall.Write(1, []byte("fd 1 leak"))
	_, _ = syscall.Write(2, []byte("fd 2 leak"))
	var core, files unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_CORE, &core) != nil || unix.Getrlimit(unix.RLIMIT_NOFILE, &files) != nil {
		return 12
	}
	fmt.Fprintf(protocolOutput, "protocol core=%d/%d files=%d/%d", core.Cur, core.Max, files.Cur, files.Max)
	return 0
}

const reviewSourceBytes = 256 * 1024

// BenchmarkReviewOfFourScansThroughOneHelperSession measures one review: one
// helper process, prepared cache, four requests of one 256 KiB source each.
func BenchmarkReviewOfFourScansThroughOneHelperSession(b *testing.B) {
	binaries(b)
	frames := reviewFrames(b)
	b.ResetTimer()
	for range b.N {
		if run := runSession(b, built.helper, built.cache, frames, nil); run.code != 0 || len(run.stdout) == 0 {
			b.Fatalf("session exited %d", run.code)
		}
	}
}

// BenchmarkReviewOfFourScansNativeInProcess measures the same four scans with
// the native adapter in this process, created once.
func BenchmarkReviewOfFourScansNativeInProcess(b *testing.B) {
	native, err := adapter.New()
	if err != nil {
		b.Fatal(err)
	}
	requests := reviewRequests(b)
	b.ResetTimer()
	for range b.N {
		for _, scan := range requests {
			if response := native.Scan(context.Background(), scan); response.Status != protocol.StatusComplete {
				b.Fatal(response.Status)
			}
		}
	}
}

// BenchmarkReviewOfFourScansNativeWorkerProcesses measures the same four
// scans as four native worker processes behind a test build of the launcher,
// the shape of a native review today.
func BenchmarkReviewOfFourScansNativeWorkerProcesses(b *testing.B) {
	if _, err := os.Stat("/usr/bin/gcc"); err != nil {
		b.Skip("the test launcher needs /usr/bin/gcc")
	}
	directory := b.TempDir()
	worker := filepath.Join(directory, "worker")
	build := exec.Command("go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", worker, "../open-trestle-secret-scanner")
	build.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		b.Fatalf("worker build: %v: %s", err, output)
	}
	launcher := filepath.Join(directory, "launcher")
	compile := exec.Command("/usr/bin/gcc", "-DOPEN_TRESTLE_TEST_WORKER_PATH="+strconvQuote(worker), "-std=c17", "-O2", "-static-pie", "-o", launcher, filepath.Join("..", "..", "launcher", "launcher.c"))
	if output, err := compile.CombinedOutput(); err != nil {
		b.Fatalf("launcher build: %v: %s", err, output)
	}
	var frames [][]byte
	for _, scan := range reviewRequests(b) {
		frames = append(frames, encodeRequest(b, scan))
	}
	b.ResetTimer()
	for range b.N {
		for _, frame := range frames {
			command := exec.Command(launcher, "--stdio-v1")
			command.Env = []string{}
			command.Stdin = bytes.NewReader(frame)
			if err := command.Run(); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func strconvQuote(value string) string {
	encoded, _ := json.Marshal(value)
	return string(encoded)
}

func reviewRequests(b *testing.B) []protocol.Request {
	fixtures := readFixturesForBenchmark(b)
	requests := make([]protocol.Request, 4)
	for index := range requests {
		requests[index] = request(fmt.Sprintf("review-%d", index), nil)
		requests[index].Sources = syntheticSourcesSeeded(fixtures, 1, reviewSourceBytes, uint64(index/2))
	}
	return requests
}

func reviewFrames(b *testing.B) [][]byte {
	var frames [][]byte
	for _, scan := range reviewRequests(b) {
		frames = append(frames, encodeRequest(b, scan))
	}
	return frames
}

type fixture struct {
	id      string
	content []byte
}

type expectedSpan struct {
	RuleID           string `json:"rule_id"`
	StartByte        int    `json:"start_byte"`
	EndByteExclusive int    `json:"end_byte_exclusive"`
	FixtureID        string `json:"fixture_id"`
}

func readQualification(t testing.TB) ([]fixture, map[string][]expectedSpan) {
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
	var spans struct {
		Spans []expectedSpan `json:"spans"`
	}
	for name, target := range map[string]any{"coverage-manifest.json": &coverage, "expected-spans.json": &spans} {
		encoded, err := os.ReadFile(filepath.Join("..", "..", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(encoded, target); err != nil {
			t.Fatal(err)
		}
	}
	entries := append(coverage.Fixtures, coverage.NearMiss)
	fixtures := make([]fixture, 0, len(entries))
	for _, entry := range entries {
		content, err := base64.StdEncoding.DecodeString(entry.ContentBase64)
		if err != nil {
			t.Fatal(err)
		}
		fixtures = append(fixtures, fixture{id: entry.ID, content: content})
	}
	byFixture := map[string][]expectedSpan{}
	for _, span := range spans.Spans {
		byFixture[span.FixtureID] = append(byFixture[span.FixtureID], span)
	}
	if len(fixtures) != 12 || len(spans.Spans) != 12 {
		t.Fatalf("%d fixtures and %d spans, want 12 and 12", len(fixtures), len(spans.Spans))
	}
	return fixtures, byFixture
}

func readFixturesForBenchmark(b *testing.B) []fixture {
	fixtures, _ := readQualification(b)
	return fixtures
}

// syntheticSources returns count sources of exactly size bytes each: seeded
// pseudo-random code-like text with the qualification fixtures embedded.
func syntheticSources(fixtures []fixture, count, size int) []protocol.Source {
	return syntheticSourcesSeeded(fixtures, count, size, 1)
}

func syntheticSourcesSeeded(fixtures []fixture, count, size int, seed uint64) []protocol.Source {
	random := rand.New(rand.NewPCG(seed, 0x5ca1ab1e))
	words := []string{"func", "return", "config", "value", "token", "client", "request", "handler", "secret", "key", "id", "name", "error", "β", "ü", "数据"}
	sources := make([]protocol.Source, count)
	for index := range sources {
		var text bytes.Buffer
		for text.Len() < size-512 {
			switch choice := random.IntN(400); {
			case choice == 0:
				embedded := fixtures[random.IntN(len(fixtures))].content
				if text.Len()+len(embedded)+1 < size-512 {
					text.Write(embedded)
					text.WriteByte('\n')
				}
			case choice < 10:
				fmt.Fprintf(&text, "\t%s_hash := %q\n", words[random.IntN(len(words))], hex.EncodeToString(binary.BigEndian.AppendUint64(nil, random.Uint64())))
			case choice < 30:
				fmt.Fprintf(&text, "// %s %s %s\n", words[random.IntN(len(words))], words[random.IntN(len(words))], words[random.IntN(len(words))])
			default:
				fmt.Fprintf(&text, "\t%s%d = %s(%s, %d)\n", words[random.IntN(len(words))], random.IntN(100), words[random.IntN(len(words))], words[random.IntN(len(words))], random.IntN(1<<20))
			}
		}
		text.WriteString(strings.Repeat(" ", size-text.Len()-1))
		text.WriteByte('\n')
		sources[index] = protocol.Source{Ordinal: index, Content: text.Bytes()}
	}
	return sources
}

func request(name string, content []byte) protocol.Request {
	digest := sha256.Sum256([]byte(name))
	scan := protocol.Request{SchemaVersion: 1, RequestID: hex.EncodeToString(digest[:])}
	if content != nil {
		scan.Sources = []protocol.Source{{Ordinal: 0, Content: content}}
	}
	return scan
}

func encodeRequest(t testing.TB, scan protocol.Request) []byte {
	t.Helper()
	frame, err := protocol.EncodeRequestFrame(scan)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func splitFrames(t *testing.T, output []byte) [][]byte {
	t.Helper()
	var frames [][]byte
	for len(output) > 0 {
		if len(output) < 4 {
			t.Fatalf("%d trailing output bytes", len(output))
		}
		length := int(binary.BigEndian.Uint32(output[:4]))
		if length == 0 || 4+length > len(output) {
			t.Fatalf("bad response frame length %d", length)
		}
		frames = append(frames, output[:4+length])
		output = output[4+length:]
	}
	return frames
}

func expectation(scan protocol.Request) protocol.ResponseExpectation {
	return protocol.ResponseExpectation{Request: scan, RulesetIdentity: protocol.RulesetIdentity, RuleIDs: adapter.PinnedRuleIDs()}
}

func parseResponse(t *testing.T, scan protocol.Request, frame []byte) protocol.Response {
	t.Helper()
	response, err := protocol.ParseResponseFrame(frame, expectation(scan))
	if err != nil {
		t.Fatalf("invalid helper response: %v", err)
	}
	return response
}

var (
	nativeOnce    sync.Once
	nativeScanner *adapter.Adapter
	nativeErr     error
)

func nativeAdapter(t *testing.T) *adapter.Adapter {
	t.Helper()
	nativeOnce.Do(func() { nativeScanner, nativeErr = adapter.New() })
	if nativeErr != nil {
		t.Fatal(nativeErr)
	}
	return nativeScanner
}

// nativeScan scans in this process with the native adapter and round-trips
// the response through the protocol encoding, as the native worker does.
func nativeScan(t *testing.T, native *adapter.Adapter, scan protocol.Request) protocol.Response {
	t.Helper()
	frame, err := protocol.EncodeResponseFrame(native.Scan(context.Background(), scan), expectation(scan))
	if err != nil {
		t.Fatal(err)
	}
	return parseResponse(t, scan, frame)
}

// requireSameScan requires identical responses except for the build profile,
// which names the scanner that ran.
func requireSameScan(t *testing.T, name string, helperResponse, nativeResponse protocol.Response) {
	t.Helper()
	if helperResponse.BuildProfile != protocol.HostRE2BuildProfile || nativeResponse.BuildProfile != protocol.BuildProfile {
		t.Fatalf("%s: build profiles %q and %q", name, helperResponse.BuildProfile, nativeResponse.BuildProfile)
	}
	if helperResponse.Status != protocol.StatusComplete {
		t.Fatalf("%s: helper scan status %s", name, helperResponse.Status)
	}
	helperResponse.BuildProfile = nativeResponse.BuildProfile
	if !reflect.DeepEqual(helperResponse, nativeResponse) {
		t.Fatalf("%s: helper response differs from the native scanner:\n%+v\n%+v", name, helperResponse, nativeResponse)
	}
}

func directorySize(t *testing.T, directory string) int64 {
	t.Helper()
	var size int64
	err := filepath.WalkDir(directory, func(_ string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.Type().IsRegular() {
			info, err := entry.Info()
			if err != nil {
				return err
			}
			size += info.Size()
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return size
}
