// Package bpe loads the cl100k_base BPE ranks from a precomputed flat table.
// Betterleaks' own loader decompresses and base64-decodes the upstream file
// and allocates every token; in a WebAssembly guest that costs more than the
// rest of a small scan. The flat table holds the same ranks and is read in
// place.
//
// Format: a uvarint count, then count records of a uvarint token length, the
// token bytes and a uvarint rank, in strictly increasing rank order.
package bpe

import (
	_ "embed"
	"encoding/binary"
	"errors"
	"os"
	"sort"
	"strings"
)

//go:embed cl100k_base.bin
var table string

// encodingFile is the name tiktoken-go asks for when it loads cl100k_base.
const encodingFile = "cl100k_base.tiktoken"

var errInvalidTable = errors.New("invalid flat BPE table")

// Loader implements tiktoken-go's BpeLoader for cl100k_base.
type Loader struct{}

// LoadTiktokenBpe returns the ranks for cl100k_base. Betterleaks treats a
// loader error as "no tokenizer" and keeps scanning without the token
// filters, which would change results, so an invalid table or a request for
// another encoding ends the process instead of returning an error.
func (Loader) LoadTiktokenBpe(file string) (map[string]int, error) {
	if !strings.HasSuffix(file, encodingFile) {
		os.Exit(70)
	}
	ranks, err := Decode(table)
	if err != nil {
		os.Exit(70)
	}
	return ranks, nil
}

// Decode parses a flat table. Token keys are substrings of encoded, so the
// map allocates no token memory.
func Decode(encoded string) (map[string]int, error) {
	count, position := uvarint(encoded, 0)
	if position <= 0 || count > uint64(len(encoded)) {
		return nil, errInvalidTable
	}
	ranks := make(map[string]int, count)
	previous := int64(-1)
	for range count {
		length, read := uvarint(encoded, position)
		if read <= 0 || length == 0 || length > uint64(len(encoded)-position-read) {
			return nil, errInvalidTable
		}
		position += read
		token := encoded[position : position+int(length)]
		position += int(length)
		rank, read := uvarint(encoded, position)
		if read <= 0 || rank > 1<<31 || int64(rank) <= previous {
			return nil, errInvalidTable
		}
		position += read
		previous = int64(rank)
		if _, duplicate := ranks[token]; duplicate {
			return nil, errInvalidTable
		}
		ranks[token] = int(rank)
	}
	if position != len(encoded) {
		return nil, errInvalidTable
	}
	return ranks, nil
}

// Encode returns the flat table of ranks. Ranks must be distinct and
// non-negative and tokens non-empty.
func Encode(ranks map[string]int) ([]byte, error) {
	tokens := make([]string, 0, len(ranks))
	for token, rank := range ranks {
		if token == "" || rank < 0 {
			return nil, errInvalidTable
		}
		tokens = append(tokens, token)
	}
	sort.Slice(tokens, func(i, j int) bool { return ranks[tokens[i]] < ranks[tokens[j]] })
	encoded := binary.AppendUvarint(nil, uint64(len(tokens)))
	for index, token := range tokens {
		if index > 0 && ranks[tokens[index-1]] == ranks[token] {
			return nil, errInvalidTable
		}
		encoded = binary.AppendUvarint(encoded, uint64(len(token)))
		encoded = append(encoded, token...)
		encoded = binary.AppendUvarint(encoded, uint64(ranks[token]))
	}
	return encoded, nil
}

// uvarint reads a uvarint from s at position without converting s to bytes.
// It returns the number of bytes read, or 0 when the value is truncated or
// longer than ten bytes.
func uvarint(s string, position int) (uint64, int) {
	var value uint64
	var shift uint
	for index := 0; index < binary.MaxVarintLen64 && position+index < len(s); index++ {
		next := s[position+index]
		if next < 0x80 {
			if index == binary.MaxVarintLen64-1 && next > 1 {
				return 0, 0
			}
			return value | uint64(next)<<shift, index + 1
		}
		value |= uint64(next&0x7f) << shift
		shift += 7
	}
	return 0, 0
}
