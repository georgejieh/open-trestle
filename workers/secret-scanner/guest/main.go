// Command open-trestle-scan-guest is the secret scanner built for
// GOOS=wasip1 GOARCH=wasm. It runs inside the scan helper, which evaluates
// its regular expressions through the host regex interface.
//
//	--sandboxed-stdio-v1  one request frame, then end of input; one response frame
//
// The helper runs a fresh instance of the guest for every request.
//
// Exit status: 0 on success, 64 for bad arguments, 65 for a bad request
// frame, 70 for an initialization or encoding failure, 71 when the host
// refused a regex call, 74 when a response cannot be written.
package main

import (
	"context"
	"io"
	"os"
	"runtime/debug"

	"github.com/betterleaks/betterleaks/detect"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/guest/internal/bpe"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/guest/internal/hostre2"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/adapter"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/workerio"
)

const singleArgument = "--sandboxed-stdio-v1"

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
	if len(arguments) != 2 || arguments[1] != singleArgument {
		return 64
	}
	detect.BpeLoader = bpe.Loader{}
	scanner, err := adapter.NewWithHostEngine(hostre2.Engine{})
	if err != nil {
		return 70
	}
	request, frame, err := workerio.ReadRequest(input)
	defer clear(frame)
	if err != nil {
		return 65
	}
	return respond(scanner, &request, output)
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
