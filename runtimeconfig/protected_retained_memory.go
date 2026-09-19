package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/memory"
)

// LoadProtectedRetainedMemoryInput admits one explicitly selected protected file
// as advisory data. Local endpoint syntax is checked here; inventory, egress,
// investigation exclusion, and freshness through a run remain caller obligations.
func LoadProtectedRetainedMemoryInput(ctx context.Context, path string, scope memory.Scope, repository evidence.RepositoryIdentity, policy RuntimePolicy, at time.Time) (RetainedMemoryInput, error) {
	if ctx == nil || ctx.Err() != nil || path == "" {
		return RetainedMemoryInput{}, ErrInvalidRetainedMemoryInput
	}
	instant, ok := retainedArguments(scope, repository, policy, at)
	if !ok || ctx.Err() != nil {
		return RetainedMemoryInput{}, ErrInvalidRetainedMemoryInput
	}
	opener := func(name string) (protectedConfigurationFile, error) {
		return fileauthority.OpenReadOnly(name)
	}
	// The helper completes both bounded reads before any JSON parsing.
	encoded, err := readProtectedConfiguration(ctx, path, retainedRawLimit, opener)
	if err != nil || ctx.Err() != nil {
		return RetainedMemoryInput{}, ErrInvalidRetainedMemoryInput
	}
	scanner := retainedScanner{encoded: encoded, ctx: ctx}
	if len(encoded) == 0 || len(encoded) > retainedRawLimit || !utf8.Valid(encoded) || !scanner.object(retainedEnvelopeObject) {
		return RetainedMemoryInput{}, ErrInvalidRetainedMemoryInput
	}
	scanner.space()
	if scanner.offset != len(encoded) || ctx.Err() != nil {
		return RetainedMemoryInput{}, ErrInvalidRetainedMemoryInput
	}
	// Array cardinalities and all string tokens have passed the strict preflight.
	var wire retainedEnvelope
	if json.Unmarshal(encoded, &wire) != nil || ctx.Err() != nil || !validRetainedShape(wire, false) || ctx.Err() != nil {
		return RetainedMemoryInput{}, ErrInvalidRetainedMemoryInput
	}
	declaredScope, records, ok := reconstructRetained(ctx, wire)
	if !ok || ctx.Err() != nil || !fixedRetainedSlice(wire, declaredScope, records) || ctx.Err() != nil {
		return RetainedMemoryInput{}, ErrInvalidRetainedMemoryInput
	}
	if !retainedBindings(wire, declaredScope, scope, repository, policy) || ctx.Err() != nil || !freshRetained(records, instant) || ctx.Err() != nil {
		return RetainedMemoryInput{}, ErrInvalidRetainedMemoryInput
	}
	identity, ok := retainedInputIdentity(wire)
	if !ok || ctx.Err() != nil {
		return RetainedMemoryInput{}, ErrInvalidRetainedMemoryInput
	}
	// Each pair pins metadata/file identity; across pairs only protected authority
	// and exact bytes are rechecked. This is not an atomic cross-pair inode pin.
	again, err := readProtectedConfiguration(ctx, path, retainedRawLimit, opener)
	if err != nil || !bytes.Equal(encoded, again) || ctx.Err() != nil {
		return RetainedMemoryInput{}, ErrInvalidRetainedMemoryInput
	}
	return RetainedMemoryInput{declared: wire, scope: declaredScope, records: records, identity: identity}, nil
}

type retainedObject uint8

const (
	retainedEnvelopeObject retainedObject = iota
	retainedScopeObject
	retainedHeadObject
	retainedRecordObject
)

// The schema has a fixed depth. No unknown object or array can recurse.
func retainedKeys(object retainedObject) []string {
	switch object {
	case retainedEnvelopeObject:
		return []string{"contract", "schema_version", "attestation", "scope", "repository_identity", "head_revision", "runtime_policy_identity", "allowed_paths", "records"}
	case retainedScopeObject:
		return []string{"identity", "tenant_id", "repository_id", "actor_id", "ref_visibility", "ref_set_identity", "path_prefixes"}
	case retainedHeadObject:
		return []string{"kind", "algorithm", "digest", "identity"}
	case retainedRecordObject:
		return []string{"record_identity", "kind", "taint", "path", "symbols", "text", "evidence_ids", "producer_identity", "observed_at", "valid_from", "valid_until"}
	default:
		return nil
	}
}

type retainedScanner struct {
	encoded     []byte
	ctx         context.Context
	offset      int
	stringBytes int
	textBytes   int
}

func (s *retainedScanner) space() {
	for s.offset < len(s.encoded) {
		switch s.encoded[s.offset] {
		case ' ', '\t', '\r', '\n':
			s.offset++
		default:
			return
		}
	}
}

func (s *retainedScanner) take(value byte) bool {
	s.space()
	if s.offset >= len(s.encoded) || s.encoded[s.offset] != value {
		return false
	}
	s.offset++
	return true
}

func (s *retainedScanner) object(object retainedObject) bool {
	if s.ctx.Err() != nil || !s.take('{') {
		return false
	}
	keys := retainedKeys(object)
	if len(keys) == 0 {
		return false
	}
	var seen uint16
	for {
		if s.ctx.Err() != nil {
			return false
		}
		s.space()
		start := s.offset
		if _, ok := s.stringToken(); !ok {
			return false
		}
		var key string
		if json.Unmarshal(s.encoded[start:s.offset], &key) != nil {
			return false
		}
		index := -1
		for i, required := range keys {
			if key == required {
				index = i
				break
			}
		}
		if index < 0 || seen&(1<<index) != 0 || !s.take(':') {
			return false
		}
		seen |= 1 << index
		if !s.field(object, index) {
			return false
		}
		if s.take('}') {
			return seen == (1<<len(keys))-1
		}
		if !s.take(',') {
			return false
		}
	}
}

func (s *retainedScanner) field(object retainedObject, index int) bool {
	switch object {
	case retainedEnvelopeObject:
		switch index {
		case 1:
			value, ok := s.number()
			return ok && value == 1
		case 3:
			return s.object(retainedScopeObject)
		case 5:
			return s.object(retainedHeadObject)
		case 7:
			return s.array(1, retainedPathLimit, false)
		case 8:
			return s.array(1, retainedRecordLimit, true)
		}
	case retainedScopeObject:
		if index == 6 {
			return s.array(1, 1, false)
		}
	case retainedRecordObject:
		switch index {
		case 4:
			return s.array(0, 0, false)
		case 5:
			length, ok := s.stringToken()
			if !ok || length > retainedTextLimit || length > retainedTotalTextLimit-s.textBytes {
				return false
			}
			s.textBytes += length
			return true
		case 6:
			return s.array(1, 1, false)
		case 8, 9, 10:
			_, ok := s.number()
			return ok
		}
	}
	_, ok := s.stringToken()
	return ok
}

func (s *retainedScanner) array(minimum, maximum int, records bool) bool {
	if !s.take('[') {
		return false
	}
	if s.take(']') {
		return minimum == 0
	}
	count := 0
	for {
		// Check cardinality before parsing or copying the next element.
		if s.ctx.Err() != nil || count >= maximum {
			return false
		}
		if records {
			if !s.object(retainedRecordObject) {
				return false
			}
		} else if _, ok := s.stringToken(); !ok {
			return false
		}
		count++
		if s.take(']') {
			return count >= minimum
		}
		if !s.take(',') {
			return false
		}
	}
}

func (s *retainedScanner) number() (int64, bool) {
	s.space()
	if s.offset >= len(s.encoded) || s.encoded[s.offset] < '1' || s.encoded[s.offset] > '9' {
		return 0, false
	}
	var value int64
	for s.offset < len(s.encoded) {
		b := s.encoded[s.offset]
		if b < '0' || b > '9' {
			break
		}
		digit := int64(b - '0')
		if value > (retainedMaximumMilliseconds-digit)/10 {
			return 0, false
		}
		value = value*10 + digit
		s.offset++
	}
	// Only JSON whitespace or the enclosing object's delimiters may follow.
	if s.offset < len(s.encoded) {
		switch s.encoded[s.offset] {
		case ' ', '\t', '\r', '\n', ',', '}':
		default:
			return 0, false
		}
	}
	return value, retainedMilliseconds(value)
}

// Scan Unicode and count decoded bytes before allocating a decoded string.
// encoding/json alone replaces malformed surrogates, so it is not this oracle.
func (s *retainedScanner) stringToken() (int, bool) {
	if !s.take('"') {
		return 0, false
	}
	length := 0
	for s.offset < len(s.encoded) {
		b := s.encoded[s.offset]
		if b == '"' {
			s.offset++
			if length == 0 {
				return 0, false
			}
			s.stringBytes += length
			return length, true
		}
		if b < 0x20 {
			return 0, false
		}
		decoded := 0
		if b == '\\' {
			s.offset++
			if s.offset >= len(s.encoded) {
				return 0, false
			}
			escaped := s.encoded[s.offset]
			s.offset++
			switch escaped {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				decoded = 1
			case 'u':
				first, ok := s.hexQuad()
				if !ok || first >= 0xdc00 && first <= 0xdfff {
					return 0, false
				}
				value := rune(first)
				if first >= 0xd800 && first <= 0xdbff {
					if len(s.encoded)-s.offset < 6 || s.encoded[s.offset] != '\\' || s.encoded[s.offset+1] != 'u' {
						return 0, false
					}
					s.offset += 2
					second, ok := s.hexQuad()
					if !ok || second < 0xdc00 || second > 0xdfff {
						return 0, false
					}
					value = utf16.DecodeRune(rune(first), rune(second))
				}
				decoded = utf8.RuneLen(value)
			default:
				return 0, false
			}
		} else {
			value, size := utf8.DecodeRune(s.encoded[s.offset:])
			if value == utf8.RuneError && size == 1 {
				return 0, false
			}
			decoded = size
			s.offset += size
		}
		if decoded > retainedStringLimit-s.stringBytes-length {
			return 0, false
		}
		length += decoded
	}
	return 0, false
}

func (s *retainedScanner) hexQuad() (uint16, bool) {
	if len(s.encoded)-s.offset < 4 {
		return 0, false
	}
	var value uint16
	for i := 0; i < 4; i++ {
		b := s.encoded[s.offset]
		s.offset++
		var digit uint16
		switch {
		case b >= '0' && b <= '9':
			digit = uint16(b - '0')
		case b >= 'a' && b <= 'f':
			digit = uint16(b-'a') + 10
		case b >= 'A' && b <= 'F':
			digit = uint16(b-'A') + 10
		default:
			return 0, false
		}
		value = value*16 + digit
	}
	return value, true
}
