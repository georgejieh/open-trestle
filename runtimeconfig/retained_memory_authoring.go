package runtimeconfig

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/memory"
)

// RetainedMemoryFeedback is an inert protected convenience input for retained
// advisory authoring. Formatting never prints paths or advice text.
type RetainedMemoryFeedback struct {
	Path string
	Text string
}

func (f RetainedMemoryFeedback) String() string { return "retained memory feedback" }
func (f RetainedMemoryFeedback) GoString() string {
	return "runtimeconfig.RetainedMemoryFeedback{<redacted>}"
}
func (f RetainedMemoryFeedback) Format(state fmt.State, verb rune) {
	formatted := f.String()
	if verb == 'q' {
		formatted = `"retained memory feedback"`
	} else if verb == 'v' && state.Flag('#') {
		formatted = f.GoString()
	}
	_, _ = state.Write([]byte(formatted))
}

// LoadProtectedRetainedMemoryFeedback reads the narrow operator feedback helper
// JSON. The helper is not the retained-memory wire contract.
func LoadProtectedRetainedMemoryFeedback(ctx context.Context, path string) ([]RetainedMemoryFeedback, error) {
	if ctx == nil || ctx.Err() != nil || path == "" {
		return nil, ErrInvalidRetainedMemoryInput
	}
	opener := func(name string) (protectedConfigurationFile, error) {
		return fileauthority.OpenReadOnly(name)
	}
	encoded, err := readProtectedConfiguration(ctx, path, retainedRawLimit, opener)
	if err != nil || ctx.Err() != nil || len(encoded) == 0 || len(encoded) > retainedRawLimit || !utf8.Valid(encoded) {
		return nil, ErrInvalidRetainedMemoryInput
	}
	scanner := retainedFeedbackScanner{encoded: encoded, ctx: ctx}
	feedback, ok := scanner.parse()
	if !ok || ctx.Err() != nil {
		return nil, ErrInvalidRetainedMemoryInput
	}
	scanner.space()
	if scanner.offset != len(encoded) || !validRetainedFeedback(feedback) || ctx.Err() != nil {
		return nil, ErrInvalidRetainedMemoryInput
	}
	return feedback, nil
}

// EncodeRetainedMemoryInput builds canonical retained-memory JSON bytes only.
// It does not publish a usable RetainedMemoryInput snapshot; only the protected
// loader can do that after the bytes are written and reopened.
func EncodeRetainedMemoryInput(ctx context.Context, scope memory.Scope, repository evidence.RepositoryIdentity, head evidence.RevisionIdentity, policy RuntimePolicy, feedback []RetainedMemoryFeedback, observedAt time.Time, validUntil time.Time) ([]byte, error) {
	fail := func() ([]byte, error) { return nil, ErrInvalidRetainedMemoryInput }
	if ctx == nil || ctx.Err() != nil || !validRetainedFeedback(feedback) {
		return fail()
	}
	observed, ok := retainedAuthoringInstant(observedAt)
	if !ok {
		return fail()
	}
	until, ok := retainedAuthoringInstant(validUntil)
	if !ok || !observed.Before(until) || until.UnixMilli()-observed.UnixMilli() > retainedLifetimeMilliseconds {
		return fail()
	}
	instant, ok := retainedArguments(scope, repository, policy, observed)
	if !ok || !instant.Equal(observed) || ctx.Err() != nil {
		return fail()
	}
	rebuiltScope, err := memory.NewScope(scope.TenantID(), scope.RepositoryID(), scope.ActorID(), scope.RefVisibility(), scope.RefSetIdentity(), scope.PathPrefixes())
	if err != nil || !sameRetainedScope(scope, rebuiltScope) || ctx.Err() != nil {
		return fail()
	}
	rebuiltRepository, err := evidence.NewRepositoryIdentity(repository.Authority(), repository.Namespace(), repository.Name())
	if err != nil || rebuiltRepository.Identity() != repository.Identity() || ctx.Err() != nil {
		return fail()
	}
	rebuiltHead, err := evidence.NewRevisionIdentity(head.Kind(), head.Algorithm(), head.Digest())
	if err != nil || rebuiltHead.Identity() != head.Identity() || scope.RefSetIdentity() != rebuiltHead.Identity() || ctx.Err() != nil {
		return fail()
	}
	paths := make([]string, 0, len(feedback))
	for _, item := range feedback {
		paths = append(paths, item.Path)
	}
	sort.Strings(paths)
	records := make([]retainedRecord, 0, len(feedback))
	for _, item := range feedback {
		if ctx.Err() != nil {
			return fail()
		}
		note, err := json.Marshal([]any{"open-trestle/operator-feedback-note", 1, rebuiltScope.Identity(), item.Path, item.Text, observed.UnixMilli(), observed.UnixMilli(), until.UnixMilli()})
		if err != nil {
			return fail()
		}
		record, err := memory.NewRecord(rebuiltScope, memory.RecordInput{
			Kind:             memory.RecordHumanFeedback,
			Taint:            memory.TaintUserControlled,
			Path:             item.Path,
			Text:             item.Text,
			EvidenceIDs:      []string{"operator-note:" + retainedDigest(note)},
			ProducerIdentity: retainedProducer,
			ObservedAt:       observed,
			ValidFrom:        observed,
			ValidUntil:       until,
		})
		if err != nil || record.Validate() != nil || ctx.Err() != nil {
			return fail()
		}
		records = append(records, retainedRecord{
			Identity: record.Identity(),
			Kind:     record.Kind().String(),
			Taint:    record.Taint().String(),
			Path:     record.Path(),
			Symbols:  []string{},
			Text:     record.Text(),
			Evidence: record.EvidenceIDs(),
			Producer: record.ProducerIdentity(),
			Observed: record.ObservedAtUnixMilliseconds(),
			From:     record.ValidFromUnixMilliseconds(),
			Until:    record.ValidUntilUnixMilliseconds(),
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Identity < records[j].Identity })
	wire := retainedEnvelope{
		Contract:    "open-trestle/retained-memory-input",
		Version:     1,
		Attestation: "operator_attested_advisory_feedback",
		Scope: retainedScope{
			Identity:   rebuiltScope.Identity(),
			Tenant:     rebuiltScope.TenantID(),
			Repository: rebuiltScope.RepositoryID(),
			Actor:      rebuiltScope.ActorID(),
			Visibility: rebuiltScope.RefVisibility().String(),
			RefSet:     rebuiltScope.RefSetIdentity(),
			Prefixes:   rebuiltScope.PathPrefixes(),
		},
		Repository: rebuiltRepository.Identity(),
		Head: retainedHead{
			Kind:      string(rebuiltHead.Kind()),
			Algorithm: string(rebuiltHead.Algorithm()),
			Digest:    rebuiltHead.Digest(),
			Identity:  rebuiltHead.Identity(),
		},
		Policy:  policy.Identity(),
		Paths:   paths,
		Records: records,
	}
	declaredScope, nativeRecords, ok := reconstructRetained(ctx, wire)
	if !ok || !validRetainedShape(wire, true) || !fixedRetainedSlice(wire, declaredScope, nativeRecords) || !retainedBindings(wire, declaredScope, rebuiltScope, rebuiltRepository, policy) || !freshRetained(nativeRecords, observed) || ctx.Err() != nil {
		return fail()
	}
	if _, ok := retainedInputIdentity(wire); !ok {
		return fail()
	}
	encoded, err := json.Marshal(wire)
	if err != nil || len(encoded) == 0 || len(encoded) > retainedRawLimit || ctx.Err() != nil {
		return fail()
	}
	return encoded, nil
}

// MatchesEncoding reports whether encoded is exactly the canonical declaration
// bytes for this already loaded snapshot. It returns false for zero or invalid
// snapshots and does not publish any authority.
func (v RetainedMemoryInput) MatchesEncoding(encoded []byte) bool {
	if len(encoded) == 0 || len(encoded) > retainedRawLimit || v.identity == "" || len(v.records) == 0 || len(v.records) != len(v.declared.Records) || !validRetainedShape(v.declared, true) {
		return false
	}
	declaredScope, records, ok := reconstructRetained(context.Background(), v.declared)
	if !ok || v.scope.Validate() != nil || !sameRetainedScope(v.scope, declaredScope) || !fixedRetainedSlice(v.declared, declaredScope, records) {
		return false
	}
	for i := range records {
		if v.records[i].Validate() != nil || !sameRetainedRecord(v.records[i], records[i]) {
			return false
		}
	}
	identity, ok := retainedInputIdentity(v.declared)
	if !ok || identity != v.identity {
		return false
	}
	canonical, err := json.Marshal(v.declared)
	return err == nil && bytes.Equal(encoded, canonical)
}

func retainedAuthoringInstant(value time.Time) (time.Time, bool) {
	instant := value.Round(0)
	if instant.Location() != time.UTC || instant.Nanosecond()%int(time.Millisecond) != 0 || instant.Before(time.UnixMilli(1).UTC()) || !instant.Before(time.UnixMilli(retainedMaximumMilliseconds+1).UTC()) {
		return time.Time{}, false
	}
	return instant, true
}

func validRetainedFeedback(feedback []RetainedMemoryFeedback) bool {
	if len(feedback) < 1 || len(feedback) > retainedRecordLimit {
		return false
	}
	seen := make(map[string]struct{}, len(feedback))
	totalText := 0
	for _, item := range feedback {
		if !validRetainedFeedbackPath(item.Path) || !validRetainedFeedbackText(item.Text) || len(item.Text) > retainedTotalTextLimit-totalText {
			return false
		}
		totalText += len(item.Text)
		if _, ok := seen[item.Path]; ok {
			return false
		}
		seen[item.Path] = struct{}{}
	}
	return true
}

func validRetainedFeedbackPath(value string) bool {
	if len(value) == 0 || len(value) > 1024 || !utf8.ValidString(value) || path.IsAbs(value) || path.Clean(value) != value || strings.ContainsRune(value, '\\') || value == "." || value == ".." || strings.HasPrefix(value, "../") {
		return false
	}
	for _, character := range value {
		if !unicode.IsPrint(character) || unicode.In(character, unicode.Cf) {
			return false
		}
	}
	return true
}

func validRetainedFeedbackText(value string) bool {
	return len(value) > 0 && len(value) <= retainedTextLimit && utf8.ValidString(value) && strings.TrimSpace(value) != "" && strings.IndexFunc(value, retainedFeedbackTextDisallowed) < 0
}

func retainedFeedbackTextDisallowed(value rune) bool {
	if value == '\n' || value == '\t' {
		return false
	}
	return unicode.IsControl(value) || unicode.In(value, unicode.Cf)
}

type retainedFeedbackScanner struct {
	encoded     []byte
	ctx         context.Context
	offset      int
	stringBytes int
}

func (s *retainedFeedbackScanner) space() {
	for s.offset < len(s.encoded) {
		switch s.encoded[s.offset] {
		case ' ', '\t', '\r', '\n':
			s.offset++
		default:
			return
		}
	}
}

func (s *retainedFeedbackScanner) take(value byte) bool {
	s.space()
	if s.offset >= len(s.encoded) || s.encoded[s.offset] != value {
		return false
	}
	s.offset++
	return true
}

func (s *retainedFeedbackScanner) parse() ([]RetainedMemoryFeedback, bool) {
	if s.ctx.Err() != nil || !s.take('[') {
		return nil, false
	}
	if s.take(']') {
		return nil, false
	}
	feedback := make([]RetainedMemoryFeedback, 0, retainedRecordLimit)
	for {
		if s.ctx.Err() != nil || len(feedback) >= retainedRecordLimit {
			return nil, false
		}
		item, ok := s.object()
		if !ok {
			return nil, false
		}
		feedback = append(feedback, item)
		if s.take(']') {
			return feedback, true
		}
		if !s.take(',') {
			return nil, false
		}
	}
}

func (s *retainedFeedbackScanner) object() (RetainedMemoryFeedback, bool) {
	if s.ctx.Err() != nil || !s.take('{') {
		return RetainedMemoryFeedback{}, false
	}
	item := RetainedMemoryFeedback{}
	seenPath, seenText := false, false
	for field := 0; ; field++ {
		if s.ctx.Err() != nil || field >= 2 {
			return RetainedMemoryFeedback{}, false
		}
		key, ok := s.stringToken(false)
		if !ok || !s.take(':') {
			return RetainedMemoryFeedback{}, false
		}
		switch key {
		case "path":
			if seenPath {
				return RetainedMemoryFeedback{}, false
			}
			value, ok := s.stringToken(false)
			if !ok {
				return RetainedMemoryFeedback{}, false
			}
			item.Path = value
			seenPath = true
		case "text":
			if seenText {
				return RetainedMemoryFeedback{}, false
			}
			value, ok := s.stringToken(true)
			if !ok || len(value) > retainedTextLimit {
				return RetainedMemoryFeedback{}, false
			}
			item.Text = value
			seenText = true
		default:
			return RetainedMemoryFeedback{}, false
		}
		if s.take('}') {
			return item, seenPath && seenText
		}
		if !s.take(',') {
			return RetainedMemoryFeedback{}, false
		}
	}
}

func (s *retainedFeedbackScanner) stringToken(allowTextControls bool) (string, bool) {
	if !s.take('"') {
		return "", false
	}
	start := s.offset - 1
	length := 0
	for s.offset < len(s.encoded) {
		b := s.encoded[s.offset]
		if b == '"' {
			s.offset++
			if length > retainedStringLimit || length > retainedStringLimit-s.stringBytes {
				return "", false
			}
			s.stringBytes += length
			if s.stringBytes > retainedStringLimit {
				return "", false
			}
			var value string
			if json.Unmarshal(s.encoded[start:s.offset], &value) != nil {
				return "", false
			}
			return value, true
		}
		if b < 0x20 {
			return "", false
		}
		decoded := 0
		if b == '\\' {
			s.offset++
			if s.offset >= len(s.encoded) {
				return "", false
			}
			escaped := s.encoded[s.offset]
			s.offset++
			switch escaped {
			case '"', '\\', '/':
				decoded = 1
			case 'b', 'f', 'r':
				return "", false
			case 'n':
				if !allowTextControls {
					return "", false
				}
				decoded = 1
			case 't':
				if !allowTextControls {
					return "", false
				}
				decoded = 1
			case 'u':
				first, ok := s.hexQuad()
				if !ok || first >= 0xdc00 && first <= 0xdfff {
					return "", false
				}
				value := rune(first)
				if first >= 0xd800 && first <= 0xdbff {
					if len(s.encoded)-s.offset < 6 || s.encoded[s.offset] != '\\' || s.encoded[s.offset+1] != 'u' {
						return "", false
					}
					s.offset += 2
					second, ok := s.hexQuad()
					if !ok || second < 0xdc00 || second > 0xdfff {
						return "", false
					}
					value = utf16.DecodeRune(rune(first), rune(second))
				}
				if retainedFeedbackRuneDisallowed(value, allowTextControls) {
					return "", false
				}
				decoded = utf8.RuneLen(value)
			default:
				return "", false
			}
		} else {
			value, size := utf8.DecodeRune(s.encoded[s.offset:])
			if value == utf8.RuneError && size == 1 || retainedFeedbackRuneDisallowed(value, allowTextControls) {
				return "", false
			}
			decoded = size
			s.offset += size
		}
		if decoded > retainedStringLimit-s.stringBytes-length {
			return "", false
		}
		length += decoded
	}
	return "", false
}

func retainedFeedbackRuneDisallowed(value rune, allowTextControls bool) bool {
	if allowTextControls && (value == '\n' || value == '\t') {
		return false
	}
	return unicode.IsControl(value) || unicode.In(value, unicode.Cf)
}

func (s *retainedFeedbackScanner) hexQuad() (uint16, bool) {
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
