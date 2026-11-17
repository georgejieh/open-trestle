// Package workerio reads request frames and writes response frames for the
// scanner worker and its WebAssembly guest.
package workerio

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/georgejieh/open-trestle/workers/secret-scanner/internal/protocol"
)

// MaximumRequestFrameBytes is the largest request payload a worker accepts.
const MaximumRequestFrameBytes = 3 * 1024 * 1024

// ReadRequest reads exactly one request frame, requires end of input after
// it and then parses it. The returned frame holds the request bytes and must
// be cleared by the caller, also when an error is returned.
func ReadRequest(reader io.Reader) (protocol.Request, []byte, error) {
	frame, err := readFrame(reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
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

func readFrame(reader io.Reader) ([]byte, error) {
	prefix := make([]byte, 4)
	if count, err := io.ReadFull(reader, prefix); err != nil {
		if count == 0 && errors.Is(err, io.EOF) {
			return prefix, io.EOF
		}
		return prefix, io.ErrUnexpectedEOF
	}
	length := binary.BigEndian.Uint32(prefix)
	if length == 0 || length > MaximumRequestFrameBytes {
		return prefix, protocol.ErrInvalidProtocol
	}
	frame := make([]byte, 4+int(length))
	copy(frame, prefix)
	clear(prefix)
	if _, err := io.ReadFull(reader, frame[4:]); err != nil {
		return frame, io.ErrUnexpectedEOF
	}
	return frame, nil
}

// WriteAll writes content completely or returns an error.
func WriteAll(writer io.Writer, content []byte) error {
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

// ClearRequest overwrites the source contents of request and resets it.
func ClearRequest(request *protocol.Request) {
	if request == nil {
		return
	}
	for index := range request.Sources {
		clear(request.Sources[index].Content)
	}
	clear(request.Sources)
	*request = protocol.Request{}
}
