//go:build linux

package secretscan

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	scannerLauncherPath       = "/usr/local/libexec/open-trestle/open-trestle-secret-scanner"
	scannerWorkerPath         = "/usr/local/libexec/open-trestle/open-trestle-secret-scanner-worker"
	scannerLauncherArgument   = "--stdio-v1"
	scannerWatchdog           = 6 * time.Second
	scannerExecutableMode     = 0555
	maximumStandardErrorBytes = 64 * 1024
)

var (
	expectedSecretScannerLauncherSHA256 string
	expectedSecretScannerWorkerSHA256   string
)

type commandFactory func(string, string) *exec.Cmd

type clientConfig struct {
	launcherPath           string
	workerPath             string
	expectedLauncherSHA256 string
	expectedWorkerSHA256   string
	expectedUID            uint32
	expectedGID            uint32
	expectedMode           os.FileMode
	trustRoot              string
	watchdog               time.Duration
	command                commandFactory
	random                 io.Reader
}

type Client struct {
	config clientConfig
}

func NewClient() *Client {
	return newClient(clientConfig{
		launcherPath:           scannerLauncherPath,
		workerPath:             scannerWorkerPath,
		expectedLauncherSHA256: expectedSecretScannerLauncherSHA256,
		expectedWorkerSHA256:   expectedSecretScannerWorkerSHA256,
		expectedUID:            0,
		expectedGID:            0,
		expectedMode:           scannerExecutableMode,
		trustRoot:              "/",
		watchdog:               scannerWatchdog,
		command: func(path string, argument string) *exec.Cmd {
			return exec.Command(path, argument)
		},
		random: rand.Reader,
	})
}

// BinaryDigests returns the compiled scanner executable identities.
func (client *Client) BinaryDigests() (string, string) {
	if client == nil {
		return "", ""
	}
	return client.config.expectedLauncherSHA256, client.config.expectedWorkerSHA256
}

func newClient(config clientConfig) *Client {
	if config.random == nil {
		config.random = rand.Reader
	}
	return &Client{config: config}
}

func (client *Client) scan(ctx context.Context, sources [][]byte) ScanResult {
	started := time.Now()
	if client == nil {
		return ScanResult{metadata: ScanMetadata{Duration: time.Since(started)}, failure: FailurePolicy}
	}
	metadata := client.metadata(sources)
	finish := func(result ScanResult) ScanResult {
		result.metadata.Duration = time.Since(started)
		return result
	}
	if ctx == nil || client.config.command == nil || client.config.watchdog <= 0 {
		return finish(ScanResult{metadata: metadata, failure: FailurePolicy})
	}
	if ctx.Err() != nil {
		return finish(ScanResult{metadata: metadata, failure: FailureCanceled})
	}
	if !validateSourceInputs(sources) {
		return finish(ScanResult{metadata: metadata, failure: FailureInvalidInput})
	}
	request, frame, requestFailure := client.request(sources)
	if requestFailure != FailureNone {
		return finish(ScanResult{metadata: metadata, failure: requestFailure})
	}
	defer clearRequestCopy(&request)
	defer clear(frame)

	if !validDigest(client.config.expectedLauncherSHA256) || !validDigest(client.config.expectedWorkerSHA256) ||
		verifyTrustedExecutable(client.config, client.config.launcherPath, client.config.expectedLauncherSHA256) != nil ||
		verifyTrustedExecutable(client.config, client.config.workerPath, client.config.expectedWorkerSHA256) != nil {
		return finish(ScanResult{metadata: metadata, failure: FailurePolicy})
	}
	if ctx.Err() != nil {
		return finish(ScanResult{metadata: metadata, failure: FailureCanceled})
	}
	response, failure := client.invoke(ctx, frame, request)
	if failure != FailureNone {
		return finish(ScanResult{metadata: metadata, failure: failure})
	}
	switch response.Status {
	case StatusComplete:
		metadata.MatchCount = len(response.Matches)
		return finish(ScanResult{matches: append([]Match(nil), response.Matches...), metadata: metadata, complete: true})
	case StatusInputRejected:
		return finish(ScanResult{metadata: metadata, failure: FailureInvalidInput})
	case StatusResourceExhausted:
		return finish(ScanResult{metadata: metadata, failure: FailureResourceLimit})
	case StatusScanFailed:
		return finish(ScanResult{metadata: metadata, failure: FailurePolicy})
	default:
		return finish(ScanResult{metadata: metadata, failure: FailurePolicy})
	}
}

func (client *Client) metadata(sources [][]byte) ScanMetadata {
	metadata := ScanMetadata{
		Scanner:         ScannerName,
		ScannerVersion:  ScannerVersion,
		ScannerCommit:   ScannerCommit,
		RulesetIdentity: RulesetIdentity,
		BuildProfile:    BuildProfile,
		LauncherSHA256:  client.config.expectedLauncherSHA256,
		WorkerSHA256:    client.config.expectedWorkerSHA256,
		SourceCount:     len(sources),
	}
	for _, source := range sources {
		metadata.ScannedByteCount += len(source)
	}
	return metadata
}

func (client *Client) request(sources [][]byte) (Request, []byte, FailureClass) {
	requestID := make([]byte, sha256.Size)
	if _, err := io.ReadFull(client.config.random, requestID); err != nil {
		clear(requestID)
		return Request{}, nil, FailurePolicy
	}
	request := Request{SchemaVersion: 1, RequestID: hex.EncodeToString(requestID), Sources: make([]Source, len(sources))}
	clear(requestID)
	for index := range sources {
		var content []byte
		if sources[index] != nil {
			content = make([]byte, len(sources[index]))
			copy(content, sources[index])
		}
		request.Sources[index] = Source{Ordinal: index, Content: content}
	}
	frame, err := encodeClientRequestFrame(request)
	if err != nil {
		clearRequestCopy(&request)
		return Request{}, nil, FailureInvalidInput
	}
	return request, frame, FailureNone
}

func encodeClientRequestFrame(request Request) ([]byte, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	payloadLength := len(`{"schema_version":1,"request_id":"`) + len(request.RequestID) + len(`","sources":[`) + len(`]}`)
	for index, source := range request.Sources {
		if index != 0 {
			payloadLength++
		}
		payloadLength += len(`{"ordinal":`) + decimalDigits(source.Ordinal) + len(`,"content_base64":"`) + base64.StdEncoding.EncodedLen(len(source.Content)) + len(`"}`)
	}
	if payloadLength < 1 || payloadLength > maxRequestFrameBytes {
		return nil, ErrInvalidProtocol
	}
	frame := make([]byte, framePrefixBytes, framePrefixBytes+payloadLength)
	frame = append(frame, `{"schema_version":1,"request_id":"`...)
	frame = append(frame, request.RequestID...)
	frame = append(frame, `","sources":[`...)
	for index, source := range request.Sources {
		if index != 0 {
			frame = append(frame, ',')
		}
		frame = append(frame, `{"ordinal":`...)
		frame = strconv.AppendInt(frame, int64(source.Ordinal), 10)
		frame = append(frame, `,"content_base64":"`...)
		start := len(frame)
		frame = append(frame, make([]byte, base64.StdEncoding.EncodedLen(len(source.Content)))...)
		base64.StdEncoding.Encode(frame[start:], source.Content)
		frame = append(frame, `"}`...)
	}
	frame = append(frame, `]}`...)
	if len(frame) != framePrefixBytes+payloadLength {
		clear(frame)
		return nil, ErrInvalidProtocol
	}
	binary.BigEndian.PutUint32(frame[:framePrefixBytes], uint32(payloadLength))
	return frame, nil
}

func decimalDigits(value int) int {
	digits := 1
	for value >= 10 {
		value /= 10
		digits++
	}
	return digits
}

func (client *Client) invoke(ctx context.Context, requestFrame []byte, request Request) (Response, FailureClass) {
	command := client.config.command(client.config.launcherPath, scannerLauncherArgument)
	if command == nil || command.Path != client.config.launcherPath || len(command.Args) != 2 || command.Args[0] != client.config.launcherPath || command.Args[1] != scannerLauncherArgument {
		return Response{}, FailurePolicy
	}
	command.Dir = "/"
	command.Env = []string{}
	command.ExtraFiles = nil
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	stderr := &boundedDiscard{}
	command.Stderr = stderr
	stdin, err := command.StdinPipe()
	if err != nil {
		return Response{}, FailurePolicy
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return Response{}, FailurePolicy
	}
	watchdogDeadline := time.Now().Add(client.config.watchdog)
	if err := command.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return Response{}, FailurePolicy
	}

	runContext, cancel := context.WithDeadline(ctx, watchdogDeadline)
	defer cancel()
	processDone := make(chan struct{})
	watcherDone := make(chan struct{})
	killCause := make(chan FailureClass, 1)
	go func() {
		defer close(watcherDone)
		select {
		case <-runContext.Done():
			failure := FailurePolicy
			if ctx.Err() != nil {
				failure = FailureCanceled
			}
			killProcessGroup(command.Process)
			killCause <- failure
		case <-processDone:
		}
	}()

	writeResult := make(chan error, 1)
	go func() {
		writeResult <- writeAllAndClose(stdin, requestFrame)
	}()
	output, readError := io.ReadAll(io.LimitReader(stdout, maxResponseFrameBytes+framePrefixBytes+1))
	outputFailure := readError != nil || len(output) > maxResponseFrameBytes+framePrefixBytes
	if outputFailure {
		killProcessGroup(command.Process)
	}
	runErrorAtEOF := runContext.Err()
	close(processDone)
	<-watcherDone

	failure := FailureNone
	if outputFailure {
		failure = FailurePolicy
	}
	select {
	case failure = <-killCause:
	default:
	}
	if runErrorAtEOF != nil && failure == FailureNone {
		failure = FailurePolicy
		if ctx.Err() != nil {
			failure = FailureCanceled
		}
		killProcessGroup(command.Process)
	}
	waitError := command.Wait()
	writeError := <-writeResult
	defer clear(output)
	if failure != FailureNone {
		return Response{}, failure
	}
	if writeError != nil || readError != nil || waitError != nil || stderr.Count() != 0 || len(output) > maxResponseFrameBytes+framePrefixBytes {
		return Response{}, FailurePolicy
	}
	response, err := ParseResponseFrame(output, ResponseExpectation{Request: request, RulesetIdentity: RulesetIdentity, RuleIDs: pinnedRuleIDSetProduction()})
	if err != nil {
		return Response{}, FailurePolicy
	}
	return response, FailureNone
}

func writeAllAndClose(writer io.WriteCloser, content []byte) error {
	defer writer.Close()
	for len(content) > 0 {
		written, err := writer.Write(content)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		content = content[written:]
	}
	return nil
}

func killProcessGroup(process *os.Process) {
	if process == nil {
		return
	}
	_ = syscall.Kill(-process.Pid, syscall.SIGKILL)
	_ = process.Kill()
}

type boundedDiscard struct {
	count atomic.Int64
}

func (writer *boundedDiscard) Write(content []byte) (int, error) {
	count := writer.count.Add(int64(len(content)))
	if count > maximumStandardErrorBytes {
		return 0, io.ErrShortWrite
	}
	return len(content), nil
}

func (writer *boundedDiscard) Count() int64 {
	return writer.count.Load()
}

func verifyTrustedExecutable(config clientConfig, path string, expectedDigest string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || !pathWithinTrustRoot(path, config.trustRoot) {
		return ErrInvalidProtocol
	}
	if err := verifyTrustedDirectories(filepath.Dir(path), config); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != config.expectedMode || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return ErrInvalidProtocol
	}
	status, ok := info.Sys().(*syscall.Stat_t)
	if !ok || status.Uid != config.expectedUID || status.Gid != config.expectedGID {
		return ErrInvalidProtocol
	}
	descriptor, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return ErrInvalidProtocol
	}
	file := os.NewFile(uintptr(descriptor), path)
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != config.expectedMode || opened.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return ErrInvalidProtocol
	}
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil || hex.EncodeToString(digest.Sum(nil)) != expectedDigest {
		return ErrInvalidProtocol
	}
	return nil
}

func pathWithinTrustRoot(path string, root string) bool {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false
	}
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !filepath.IsAbs(relative) && relative != "" && relative[:1] != string(filepath.Separator)
}

func verifyTrustedDirectories(directory string, config clientConfig) error {
	for {
		info, err := os.Lstat(directory)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0022 != 0 {
			return ErrInvalidProtocol
		}
		status, ok := info.Sys().(*syscall.Stat_t)
		if !ok || status.Uid != config.expectedUID || status.Gid != config.expectedGID {
			return ErrInvalidProtocol
		}
		if directory == config.trustRoot {
			return nil
		}
		parent := filepath.Dir(directory)
		if parent == directory || !pathWithinTrustRoot(directory, config.trustRoot) {
			return ErrInvalidProtocol
		}
		directory = parent
	}
}

func validDigest(value string) bool {
	return validLowerHex(value, sha256.Size*2)
}

func pinnedRuleIDSetProduction() map[string]struct{} {
	ruleIDs := make(map[string]struct{}, len(betterleaksRuleIDsV1))
	for _, ruleID := range betterleaksRuleIDsV1 {
		ruleIDs[ruleID] = struct{}{}
	}
	return ruleIDs
}

func clearRequestCopy(request *Request) {
	if request == nil {
		return
	}
	for index := range request.Sources {
		clear(request.Sources[index].Content)
	}
	clear(request.Sources)
	*request = Request{}
}
