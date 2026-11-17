package main

import (
	"context"
	"os"
	"runtime/debug"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/adapter"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/sandbox"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/workerio"
)

const workerArgument = "--sandboxed-stdio-v1"

func main() {
	os.Exit(runSafely())
}

func runSafely() (exitCode int) {
	debug.SetTraceback("none")
	defer func() {
		if recover() != nil {
			exitCode = 1
		}
	}()
	return run()
}

func run() int {
	if len(os.Args) != 2 || os.Args[1] != workerArgument {
		return 64
	}
	if err := sandbox.Install(); err != nil {
		return 70
	}
	if err := sandbox.SilenceStandardError(); err != nil {
		return 70
	}
	scanner, err := adapter.New()
	if err != nil {
		return 70
	}
	request, frame, err := workerio.ReadRequest(os.Stdin)
	defer clear(frame)
	if err != nil {
		return 65
	}
	defer workerio.ClearRequest(&request)

	response := scanner.Scan(context.Background(), request)
	responseFrame, err := protocol.EncodeResponseFrame(response, protocol.ResponseExpectation{
		Request:         request,
		RulesetIdentity: protocol.RulesetIdentity,
		RuleIDs:         adapter.PinnedRuleIDs(),
	})
	if err != nil {
		return 70
	}
	defer clear(responseFrame)
	if err := workerio.WriteAll(os.Stdout, responseFrame); err != nil {
		return 74
	}
	return 0
}
