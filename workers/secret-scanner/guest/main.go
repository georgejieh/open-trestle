// Command open-trestle-scan-guest is the secret scanner built for
// GOOS=wasip1 GOARCH=wasm. It runs inside the scan helper, which evaluates
// its regular expressions through the host regex interface.
//
//	--sandboxed-stdio-v1          one request frame, then end of input; one response frame
//	--sandboxed-stdio-v1-session  request frames until end of input at a frame boundary; one response frame each
//
// Exit status: 0 on success, 64 for bad arguments, 65 for a bad request
// frame, 70 for an initialization or encoding failure, 71 when the host
// refused a regex call, 74 when a response cannot be written.
package main

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime/debug"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/guest/internal/bpe"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/guest/internal/hostre2"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/adapter"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/sandbox"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/workerio"
)

const (
	singleArgument  = "--sandboxed-stdio-v1"
	sessionArgument = "--sandboxed-stdio-v1-session"
)

func main() {
	os.Exit(runSafely(os.Args, os.Stdin, os.Stdout))
}

func runSafely(arguments []string, input io.Reader, output io.Writer) (exitCode int) {
	debug.SetTraceback("none")
	defer func() {
		if recover() != nil {
			exitCode = 1
		}
	}()
	return run(arguments, input, output)
}

func run(arguments []string, input io.Reader, output io.Writer) int {
	if len(arguments) != 2 || arguments[1] != singleArgument && arguments[1] != sessionArgument {
		return 64
	}
	if err := sandbox.Install(); err != nil {
		return 70
	}
	if err := sandbox.SilenceStandardError(); err != nil {
		return 70
	}
	detect.BpeLoader = bpe.Loader{}
	scanner, err := adapter.NewWithHostEngine(hostre2.Engine{})
	if err != nil {
		return 70
	}
	if arguments[1] == singleArgument {
		request, frame, err := workerio.ReadRequest(input)
		defer clear(frame)
		if err != nil {
			return 65
		}
		return respond(scanner, &request, output)
	}
	for {
		request, frame, err := workerio.ReadSessionRequest(input)
		if errors.Is(err, io.EOF) {
			return 0
		}
		if err != nil {
			clear(frame)
			return 65
		}
		code := respond(scanner, &request, output)
		clear(frame)
		if code != 0 {
			return code
		}
	}
}

func respond(scanner *adapter.Adapter, request *protocol.Request, output io.Writer) int {
	defer workerio.ClearRequest(request)
	response := scanner.Scan(context.Background(), *request)
	frame, err := protocol.EncodeResponseFrame(response, protocol.ResponseExpectation{
		Request:         *request,
		RulesetIdentity: protocol.RulesetIdentity,
		RuleIDs:         adapter.PinnedRuleIDs(),
	})
	if err != nil {
		return 70
	}
	defer clear(frame)
	if err := workerio.WriteAll(output, frame); err != nil {
		return 74
	}
	return 0
}
