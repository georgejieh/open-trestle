// Package frame decodes length-prefixed payloads.
package frame

import (
	"encoding/binary"
	"errors"
	"io"
)

const maxPayload = 16 << 20

// ErrTooLarge reports a frame whose payload exceeds the decoder limit.
var ErrTooLarge = errors.New("frame: payload too large")

// ReadPayload reads one frame: a big-endian uint32 payload length followed by
// that many payload bytes.
func ReadPayload(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length > maxPayload {
		return nil, ErrTooLarge
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
