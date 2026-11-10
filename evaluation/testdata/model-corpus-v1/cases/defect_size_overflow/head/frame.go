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

// ReadPayload reads one frame: a big-endian uint32 record count and a
// big-endian uint32 record size, followed by count*size payload bytes.
func ReadPayload(r io.Reader) ([]byte, error) {
	var header [8]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	count := binary.BigEndian.Uint32(header[0:4])
	size := binary.BigEndian.Uint32(header[4:8])
	total := count * size
	if total > maxPayload {
		return nil, ErrTooLarge
	}
	payload := make([]byte, int(count)*int(size))
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
