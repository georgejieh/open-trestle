// Package varcodec writes and reads the compact binary encodings of the
// syntax records and the repository index: unsigned varints, length-prefixed
// bytes and fixed-size fields. A Reader never reads past its input and never
// allocates more than the input could describe.
package varcodec

import (
	"encoding/binary"
	"errors"
	"math"
)

// ErrMalformed reports input that does not decode.
var ErrMalformed = errors.New("malformed binary encoding")

// AppendUvarint appends v as an unsigned varint.
func AppendUvarint(dst []byte, v uint64) []byte { return binary.AppendUvarint(dst, v) }

// AppendBytes appends a length-prefixed byte string.
func AppendBytes(dst, value []byte) []byte {
	return append(binary.AppendUvarint(dst, uint64(len(value))), value...)
}

// AppendString appends a length-prefixed string.
func AppendString(dst []byte, value string) []byte {
	return append(binary.AppendUvarint(dst, uint64(len(value))), value...)
}

// AppendBool appends one byte, 1 for true.
func AppendBool(dst []byte, value bool) []byte {
	if value {
		return append(dst, 1)
	}
	return append(dst, 0)
}

// Reader decodes from a byte slice. The first failure sticks: later reads
// return zero values and Err reports it.
type Reader struct {
	data []byte
	err  error
}

// NewReader reads data, which it does not copy.
func NewReader(data []byte) *Reader { return &Reader{data: data} }

// Err returns the first failure.
func (r *Reader) Err() error { return r.err }

// Len returns the number of bytes not read yet.
func (r *Reader) Len() int { return len(r.data) }

// Done reports a failure, or ErrMalformed when bytes are left over.
func (r *Reader) Done() error {
	if r.err == nil && len(r.data) != 0 {
		r.err = ErrMalformed
	}
	return r.err
}

func (r *Reader) fail() { r.err, r.data = ErrMalformed, nil }

// Uvarint reads an unsigned varint.
func (r *Reader) Uvarint() uint64 {
	if r.err != nil {
		return 0
	}
	v, n := binary.Uvarint(r.data)
	if n <= 0 {
		r.fail()
		return 0
	}
	r.data = r.data[n:]
	return v
}

// Int reads an unsigned varint that must fit in max.
func (r *Reader) Int(max int) int {
	v := r.Uvarint()
	if v > uint64(max) || v > math.MaxInt32 {
		r.fail()
		return 0
	}
	return int(v)
}

// Count reads an element count. Each element takes at least minBytes bytes,
// so a count the remaining input cannot hold is malformed.
func (r *Reader) Count(minBytes int) int {
	n := r.Uvarint()
	if minBytes < 1 {
		minBytes = 1
	}
	if n > uint64(len(r.data)/minBytes) {
		r.fail()
		return 0
	}
	return int(n)
}

// Byte reads one byte.
func (r *Reader) Byte() byte {
	if r.err != nil {
		return 0
	}
	if len(r.data) == 0 {
		r.fail()
		return 0
	}
	b := r.data[0]
	r.data = r.data[1:]
	return b
}

// Bool reads a byte that must be 0 or 1.
func (r *Reader) Bool() bool {
	switch r.Byte() {
	case 0:
		return false
	case 1:
		return true
	}
	r.fail()
	return false
}

// Fixed reads n bytes; the result aliases the input.
func (r *Reader) Fixed(n int) []byte {
	if r.err != nil {
		return nil
	}
	if n < 0 || n > len(r.data) {
		r.fail()
		return nil
	}
	value := r.data[:n:n]
	r.data = r.data[n:]
	return value
}

// Bytes reads a length-prefixed byte string; the result aliases the input.
func (r *Reader) Bytes() []byte {
	n := r.Uvarint()
	if n > uint64(len(r.data)) {
		r.fail()
		return nil
	}
	return r.Fixed(int(n))
}

// String reads a length-prefixed string.
func (r *Reader) String() string { return string(r.Bytes()) }

// Uint32 reads a little-endian uint32.
func (r *Reader) Uint32() uint32 {
	b := r.Fixed(4)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(b)
}

// Uint64 reads a little-endian uint64.
func (r *Reader) Uint64() uint64 {
	b := r.Fixed(8)
	if b == nil {
		return 0
	}
	return binary.LittleEndian.Uint64(b)
}

// Fail marks the input malformed, for a value that decoded but is invalid.
func (r *Reader) Fail() { r.fail() }
