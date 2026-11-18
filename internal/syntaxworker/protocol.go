// Package syntaxworker runs syntax analysis in worker processes that the
// parent can kill. A parser that never reaches a stop check cannot be
// interrupted inside a process, so the parent bounds every file with a hard
// wall-clock limit and replaces a worker that overruns it, crashes, answers
// malformed output or reports an abandoned guest call.
//
// The protocol is framed on the worker's standard input and output. Each
// frame is a four-byte little-endian length and a payload. The parent sends
// one request at a time and the worker answers it before reading the next;
// the worker exits when its input ends. A worker holds no secret: it reads
// only the files it is sent and starts with an empty environment.
package syntaxworker

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"

	"github.com/georgejieh/open-trestle/internal/varcodec"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// maxFrameBytes bounds one frame: a file within the largest per-file limit,
// or an encoded analysis of the most records the limits allow.
const maxFrameBytes = 64 << 20

var errProtocol = errors.New("malformed syntax worker frame")

const (
	statusAnalysed     byte = 0
	statusInvalidInput byte = 1
)

type request struct {
	id       uint64
	path     string
	language syntaxanalysis.Language
	content  []byte
}

type response struct {
	id        uint64
	abandoned uint64
	status    byte
	analysis  []byte
}

func writeFrame(w io.Writer, payload []byte) error {
	if len(payload) > maxFrameBytes {
		return errProtocol
	}
	frame := binary.LittleEndian.AppendUint32(make([]byte, 0, 4+len(payload)), uint32(len(payload)))
	_, err := w.Write(append(frame, payload...))
	return err
}

// readFrame returns io.EOF only when the stream ends before a frame starts.
func readFrame(r *bufio.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, errProtocol
	}
	n := binary.LittleEndian.Uint32(header[:])
	if n > maxFrameBytes {
		return nil, errProtocol
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, errProtocol
	}
	return payload, nil
}

func (q request) encode() []byte {
	out := varcodec.AppendUvarint(nil, q.id)
	out = varcodec.AppendString(out, q.path)
	out = varcodec.AppendString(out, string(q.language))
	return varcodec.AppendBytes(out, q.content)
}

func decodeRequest(payload []byte) (request, error) {
	r := varcodec.NewReader(payload)
	q := request{id: r.Uvarint(), path: r.String(), language: syntaxanalysis.Language(r.String()), content: r.Bytes()}
	if r.Done() != nil {
		return request{}, errProtocol
	}
	return q, nil
}

func (s response) encode() []byte {
	out := varcodec.AppendUvarint(nil, s.id)
	out = varcodec.AppendUvarint(out, s.abandoned)
	out = append(out, s.status)
	return varcodec.AppendBytes(out, s.analysis)
}

func decodeResponse(payload []byte) (response, error) {
	r := varcodec.NewReader(payload)
	s := response{id: r.Uvarint(), abandoned: r.Uvarint(), status: r.Byte(), analysis: r.Bytes()}
	if r.Done() != nil || s.status > statusInvalidInput {
		return response{}, errProtocol
	}
	return s, nil
}
