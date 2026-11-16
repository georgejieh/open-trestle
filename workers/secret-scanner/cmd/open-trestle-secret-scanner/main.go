package main

import (
	"context"
	"encoding/binary"
	"io"
	"os"
	"runtime/debug"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/adapter"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/sandbox"
)

const (
	workerArgument           = "--sandboxed-stdio-v1"
	maximumRequestFrameBytes = 3 * 1024 * 1024
)

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
	request, frame, err := readRequest(os.Stdin)
	defer clear(frame)
	if err != nil {
		return 65
	}
	defer clearRequest(&request)

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
	if err := writeAll(os.Stdout, responseFrame); err != nil {
		return 74
	}
	return 0
}

func readRequest(reader io.Reader) (protocol.Request, []byte, error) {
	prefix := make([]byte, 4)
	if _, err := io.ReadFull(reader, prefix); err != nil {
		return protocol.Request{}, prefix, err
	}
	length := binary.BigEndian.Uint32(prefix)
	if length == 0 || length > maximumRequestFrameBytes {
		return protocol.Request{}, prefix, protocol.ErrInvalidProtocol
	}
	frame := make([]byte, 4+int(length))
	copy(frame, prefix)
	clear(prefix)
	if _, err := io.ReadFull(reader, frame[4:]); err != nil {
		return protocol.Request{}, frame, err
	}
	var trailing [1]byte
	count, err := reader.Read(trailing[:])
	if count != 0 || err != io.EOF {
		return protocol.Request{}, frame, protocol.ErrInvalidProtocol
	}
	request, err := protocol.ParseRequestFrame(frame)
	return request, frame, err
}

func writeAll(writer io.Writer, content []byte) error {
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

func clearRequest(request *protocol.Request) {
	if request == nil {
		return
	}
	for index := range request.Sources {
		clear(request.Sources[index].Content)
	}
	clear(request.Sources)
	*request = protocol.Request{}
}
