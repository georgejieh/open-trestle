package review

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maximumInvestigationProposalBytes = 64 << 10

var ErrInvalidInvestigationProposal = errors.New("invalid investigation proposal")

// InvestigationProposal is untrusted syntax, not snapshot or execution authority.
type InvestigationProposal struct {
	identity, tool, callID, snapshotRef, fileRef, literal string
	startLine, endLine                                    int
	fileRefs                                              []string
}

func ParseInvestigationProposal(encoded []byte) (InvestigationProposal, error) {
	if len(encoded) == 0 || len(encoded) > maximumInvestigationProposalBytes || !utf8.Valid(encoded) {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	if !preflightInvestigationProposal(encoded) || !validProposalUnicode(encoded) {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if !consumeProposalJSON(decoder, 0) {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(encoded, &root) != nil || !exactJSONKeys(root, "schema_version", "tool_calls") {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	version, ok := proposalInteger(root["schema_version"])
	if !ok || version != 1 {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	var calls []json.RawMessage
	if json.Unmarshal(root["tool_calls"], &calls) != nil || len(calls) != 1 {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	var call map[string]json.RawMessage
	if json.Unmarshal(calls[0], &call) != nil {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	value := InvestigationProposal{}
	value.tool, ok = proposalString(call["tool"], 32)
	if !ok {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	value.callID, ok = proposalString(call["call_id"], 64)
	if !ok {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	value.snapshotRef, ok = proposalString(call["snapshot_ref"], 64)
	if !ok {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	switch value.tool {
	case "snapshot.list":
		if !exactJSONKeys(call, "tool", "call_id", "snapshot_ref") {
			return InvestigationProposal{}, ErrInvalidInvestigationProposal
		}
	case "snapshot.read":
		if !exactJSONKeys(call, "tool", "call_id", "snapshot_ref", "file_ref", "start_line", "end_line") {
			return InvestigationProposal{}, ErrInvalidInvestigationProposal
		}
		value.fileRef, ok = proposalString(call["file_ref"], 64)
		if !ok {
			return InvestigationProposal{}, ErrInvalidInvestigationProposal
		}
		value.startLine, ok = proposalInteger(call["start_line"])
		if !ok {
			return InvestigationProposal{}, ErrInvalidInvestigationProposal
		}
		value.endLine, ok = proposalInteger(call["end_line"])
		if !ok {
			return InvestigationProposal{}, ErrInvalidInvestigationProposal
		}
	case "snapshot.search":
		if !exactJSONKeys(call, "tool", "call_id", "snapshot_ref", "file_refs", "literal") {
			return InvestigationProposal{}, ErrInvalidInvestigationProposal
		}
		var refs []json.RawMessage
		if json.Unmarshal(call["file_refs"], &refs) != nil || len(refs) == 0 || len(refs) > 64 {
			return InvestigationProposal{}, ErrInvalidInvestigationProposal
		}
		value.fileRefs = make([]string, 0, len(refs))
		for _, raw := range refs {
			ref, valid := proposalString(raw, 64)
			if !valid {
				return InvestigationProposal{}, ErrInvalidInvestigationProposal
			}
			value.fileRefs = append(value.fileRefs, ref)
		}
		value.literal, ok = proposalString(call["literal"], 256)
		if !ok {
			return InvestigationProposal{}, ErrInvalidInvestigationProposal
		}
	default:
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	if !value.validFields() {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	canonical, err := value.canonical()
	if err != nil {
		return InvestigationProposal{}, ErrInvalidInvestigationProposal
	}
	sum := sha256.Sum256(canonical)
	value.identity = hex.EncodeToString(sum[:])
	return value, nil
}

func EncodeInvestigationProposal(value InvestigationProposal) ([]byte, error) {
	if value.Validate() != nil {
		return nil, ErrInvalidInvestigationProposal
	}
	return value.canonical()
}
func (p InvestigationProposal) canonical() ([]byte, error) {
	call := map[string]any{"tool": p.tool, "call_id": p.callID, "snapshot_ref": p.snapshotRef}
	switch p.tool {
	case "snapshot.list":
	case "snapshot.read":
		call["file_ref"] = p.fileRef
		call["start_line"] = p.startLine
		call["end_line"] = p.endLine
	case "snapshot.search":
		call["file_refs"] = p.fileRefs
		call["literal"] = p.literal
	default:
		return nil, ErrInvalidInvestigationProposal
	}
	encoded, err := json.Marshal(map[string]any{"schema_version": 1, "tool_calls": []any{call}})
	if err != nil || len(encoded) > maximumInvestigationProposalBytes {
		return nil, ErrInvalidInvestigationProposal
	}
	return encoded, nil
}
func (p InvestigationProposal) validFields() bool {
	if !validProposalCallID(p.callID) || !validProposalRef(p.snapshotRef) {
		return false
	}
	switch p.tool {
	case "snapshot.list":
		return p.fileRef == "" && p.startLine == 0 && p.endLine == 0 && len(p.fileRefs) == 0 && p.literal == ""
	case "snapshot.read":
		return validProposalRef(p.fileRef) && p.startLine >= 1 && p.endLine >= p.startLine && p.endLine <= 1000000 && len(p.fileRefs) == 0 && p.literal == ""
	case "snapshot.search":
		if p.fileRef != "" || p.startLine != 0 || p.endLine != 0 || len(p.fileRefs) == 0 || len(p.fileRefs) > 64 || len(p.literal) == 0 || len(p.literal) > 256 || !utf8.ValidString(p.literal) || strings.ContainsAny(p.literal, "\x00\r\n") {
			return false
		}
		seen := make(map[string]bool, len(p.fileRefs))
		for _, ref := range p.fileRefs {
			if !validProposalRef(ref) || seen[ref] {
				return false
			}
			seen[ref] = true
		}
		return true
	}
	return false
}
func (p InvestigationProposal) Validate() error {
	if !p.validFields() {
		return ErrInvalidInvestigationProposal
	}
	encoded, err := p.canonical()
	if err != nil {
		return ErrInvalidInvestigationProposal
	}
	sum := sha256.Sum256(encoded)
	if p.identity != hex.EncodeToString(sum[:]) {
		return ErrInvalidInvestigationProposal
	}
	return nil
}
func proposalString(raw []byte, maximum int) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) < 2 || len(raw) > 6*maximum+2 || raw[0] != '"' {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || len(value) > maximum || !utf8.ValidString(value) {
		return "", false
	}
	return value, true
}
func proposalInteger(raw []byte) (int, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || len(raw) > 7 {
		return 0, false
	}
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseUint(string(raw), 10, 32)
	return int(value), err == nil && value <= 1000000
}
func validProposalRef(value string) bool {
	if len(value) != 64 || strings.Trim(value, "0") == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		if !(value[i] >= 'a' && value[i] <= 'f' || value[i] >= '0' && value[i] <= '9') {
			return false
		}
	}
	return true
}
func validProposalCallID(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for i := 0; i < len(value); i++ {
		ch := value[i]
		alpha := ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9'
		if !alpha && (i == 0 || ch != '.' && ch != '_' && ch != ':' && ch != '-') {
			return false
		}
	}
	return true
}

func consumeProposalJSON(d *json.Decoder, depth int) bool {
	if depth > 4 {
		return false
	}
	token, err := d.Token()
	if err != nil || token == nil {
		return false
	}
	delim, container := token.(json.Delim)
	if !container {
		return true
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return false
			}
			name, ok := key.(string)
			if !ok || seen[name] || len(seen) >= 8 {
				return false
			}
			seen[name] = true
			if !consumeProposalJSON(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim('}')
	case '[':
		count := 0
		for d.More() {
			count++
			if count > 64 || !consumeProposalJSON(d, depth+1) {
				return false
			}
		}
		end, err := d.Token()
		return err == nil && end == json.Delim(']')
	}
	return false
}

const (
	proposalFieldTool uint16 = 1 << iota
	proposalFieldCallID
	proposalFieldSnapshotRef
	proposalFieldFileRef
	proposalFieldStartLine
	proposalFieldEndLine
	proposalFieldFileRefs
	proposalFieldLiteral
)

const proposalBaseFields = proposalFieldTool | proposalFieldCallID | proposalFieldSnapshotRef

// Model objects permit whitespace, shuffled keys and equivalent JSON escapes.
type proposalRawScan struct {
	input  []byte
	offset int
}

func preflightInvestigationProposal(encoded []byte) bool {
	scan := proposalRawScan{input: encoded}
	if !scan.root() {
		return false
	}
	scan.space()
	return scan.offset == len(encoded)
}

func (s *proposalRawScan) space() {
	for s.offset < len(s.input) {
		switch s.input[s.offset] {
		case ' ', '\t', '\r', '\n':
			s.offset++
		default:
			return
		}
	}
}

func (s *proposalRawScan) take(value byte) bool {
	s.space()
	if s.offset >= len(s.input) || s.input[s.offset] != value {
		return false
	}
	s.offset++
	return true
}

func (s *proposalRawScan) key() (string, bool) {
	raw, ok := s.text(14)
	if !ok || !s.take(':') {
		return "", false
	}
	// Only this bounded small key is materialized before the whole shape passes.
	return proposalString(raw, 14)
}

func (s *proposalRawScan) root() bool {
	if !s.take('{') {
		return false
	}
	var seen uint8
	for count := 0; ; count++ {
		if s.take('}') {
			return seen == 3
		}
		if count >= 2 || count > 0 && !s.take(',') {
			return false
		}
		key, ok := s.key()
		if !ok {
			return false
		}
		switch key {
		case "schema_version":
			if seen&1 != 0 {
				return false
			}
			seen |= 1
			version, ok := s.integer()
			if !ok || version != 1 {
				return false
			}
		case "tool_calls":
			if seen&2 != 0 || !s.take('[') || !s.call() || !s.take(']') {
				return false
			}
			seen |= 2
		default:
			return false
		}
	}
}

func (s *proposalRawScan) call() bool {
	if !s.take('{') {
		return false
	}
	var seen, required uint16
	for count := 0; ; count++ {
		if s.take('}') {
			return required != 0 && seen == required
		}
		if count >= 8 || count > 0 && !s.take(',') {
			return false
		}
		key, ok := s.key()
		if !ok {
			return false
		}
		var field uint16
		switch key {
		case "tool":
			field = proposalFieldTool
		case "call_id":
			field = proposalFieldCallID
		case "snapshot_ref":
			field = proposalFieldSnapshotRef
		case "file_ref":
			field = proposalFieldFileRef
		case "start_line":
			field = proposalFieldStartLine
		case "end_line":
			field = proposalFieldEndLine
		case "file_refs":
			field = proposalFieldFileRefs
		case "literal":
			field = proposalFieldLiteral
		default:
			return false
		}
		if seen&field != 0 {
			return false
		}
		seen |= field
		switch field {
		case proposalFieldTool:
			raw, ok := s.text(32)
			var tool [32]byte
			length, copied := proposalRawASCII(raw, tool[:])
			if !ok || !copied {
				return false
			}
			switch string(tool[:length]) {
			case "snapshot.list":
				required = proposalBaseFields
			case "snapshot.read":
				required = proposalBaseFields | proposalFieldFileRef | proposalFieldStartLine | proposalFieldEndLine
			case "snapshot.search":
				required = proposalBaseFields | proposalFieldFileRefs | proposalFieldLiteral
			default:
				return false
			}
		case proposalFieldCallID:
			if _, ok := s.text(64); !ok {
				return false
			}
		case proposalFieldSnapshotRef, proposalFieldFileRef:
			if _, ok := s.ref(); !ok {
				return false
			}
		case proposalFieldStartLine, proposalFieldEndLine:
			if _, ok := s.integer(); !ok {
				return false
			}
		case proposalFieldFileRefs:
			if !s.refs() {
				return false
			}
		case proposalFieldLiteral:
			if _, ok := s.text(256); !ok {
				return false
			}
		}
	}
}

func (s *proposalRawScan) ref() ([64]byte, bool) {
	raw, ok := s.text(64)
	var value [64]byte
	if !ok {
		return value, false
	}
	length, ok := proposalRawASCII(raw, value[:])
	if !ok || length != len(value) {
		return value, false
	}
	nonzero := false
	for _, char := range value {
		if !(char >= 'a' && char <= 'f' || char >= '0' && char <= '9') {
			return value, false
		}
		nonzero = nonzero || char != '0'
	}
	return value, nonzero
}

func (s *proposalRawScan) refs() bool {
	if !s.take('[') {
		return false
	}
	var seen [64][64]byte
	for count := 0; ; count++ {
		if s.take(']') {
			return count != 0
		}
		if count >= len(seen) || count > 0 && !s.take(',') {
			return false
		}
		value, ok := s.ref()
		if !ok {
			return false
		}
		for i := 0; i < count; i++ {
			if seen[i] == value {
				return false
			}
		}
		seen[count] = value
	}
}

func (s *proposalRawScan) integer() (int, bool) {
	s.space()
	start, value := s.offset, 0
	for s.offset < len(s.input) && s.input[s.offset] >= '0' && s.input[s.offset] <= '9' {
		if s.offset-start >= 7 {
			return 0, false
		}
		value = value*10 + int(s.input[s.offset]-'0')
		s.offset++
	}
	if s.offset == start || s.input[start] == '0' && s.offset-start > 1 {
		return 0, false
	}
	return value, value <= 1000000
}

func (s *proposalRawScan) text(maximum int) ([]byte, bool) {
	s.space()
	start := s.offset
	if !s.take('"') {
		return nil, false
	}
	decoded := 0
	for s.offset < len(s.input) && s.offset-start < 6*maximum+2 {
		char := s.input[s.offset]
		s.offset++
		if char == '"' {
			return s.input[start:s.offset], decoded <= maximum
		}
		if char < 0x20 {
			return nil, false
		}
		if char != '\\' {
			decoded++
		} else {
			if s.offset >= len(s.input) {
				return nil, false
			}
			escape := s.input[s.offset]
			s.offset++
			switch escape {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				decoded++
			case 'u':
				code, ok := proposalRawHex(s.input[s.offset:])
				if !ok {
					return nil, false
				}
				s.offset += 4
				if code >= 0xd800 && code <= 0xdbff {
					if len(s.input)-s.offset < 6 || s.input[s.offset] != '\\' || s.input[s.offset+1] != 'u' {
						return nil, false
					}
					low, ok := proposalRawHex(s.input[s.offset+2:])
					if !ok || low < 0xdc00 || low > 0xdfff {
						return nil, false
					}
					s.offset += 6
					code = 0x10000 + (code-0xd800)*0x400 + low - 0xdc00
				} else if code >= 0xdc00 && code <= 0xdfff {
					return nil, false
				}
				decoded += utf8.RuneLen(code)
			default:
				return nil, false
			}
		}
		if decoded > maximum {
			return nil, false
		}
	}
	return nil, false
}

func proposalRawHex(raw []byte) (rune, bool) {
	if len(raw) < 4 {
		return 0, false
	}
	var value rune
	for _, char := range raw[:4] {
		var digit byte
		switch {
		case char >= '0' && char <= '9':
			digit = char - '0'
		case char >= 'a' && char <= 'f':
			digit = char - 'a' + 10
		case char >= 'A' && char <= 'F':
			digit = char - 'A' + 10
		default:
			return 0, false
		}
		value = value*16 + rune(digit)
	}
	return value, true
}

// Decode only a fixed-size ASCII tool or reference after its raw string passes.
func proposalRawASCII(raw, destination []byte) (int, bool) {
	if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
		return 0, false
	}
	count := 0
	for i := 1; i < len(raw)-1; i++ {
		char := raw[i]
		if char == '\\' {
			i++
			if i >= len(raw)-1 {
				return 0, false
			}
			switch raw[i] {
			case '"', '\\', '/':
				char = raw[i]
			case 'b':
				char = '\b'
			case 'f':
				char = '\f'
			case 'n':
				char = '\n'
			case 'r':
				char = '\r'
			case 't':
				char = '\t'
			case 'u':
				value, ok := proposalRawHex(raw[i+1:])
				if !ok || value > 127 {
					return 0, false
				}
				char = byte(value)
				i += 4
			default:
				return 0, false
			}
		}
		if char > 127 || count >= len(destination) {
			return 0, false
		}
		destination[count] = char
		count++
	}
	return count, true
}

// Refuse escaped unpaired surrogates before encoding/json can replace them.
func validProposalUnicode(encoded []byte) bool {
	quoted := false
	for i := 0; i < len(encoded); i++ {
		if encoded[i] == '"' {
			quoted = !quoted
			continue
		}
		if !quoted || encoded[i] != '\\' {
			continue
		}
		if i+1 >= len(encoded) {
			return false
		}
		if encoded[i+1] != 'u' {
			i++
			continue
		}
		if i+6 > len(encoded) {
			return false
		}
		value, err := strconv.ParseUint(string(encoded[i+2:i+6]), 16, 16)
		if err != nil {
			return false
		}
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+12 > len(encoded) || encoded[i+6] != '\\' || encoded[i+7] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(encoded[i+8:i+12]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 11
		} else {
			i += 5
		}
	}
	return true
}

func (p InvestigationProposal) Identity() string    { return p.identity }
func (p InvestigationProposal) Tool() string        { return p.tool }
func (p InvestigationProposal) CallID() string      { return p.callID }
func (p InvestigationProposal) SnapshotRef() string { return p.snapshotRef }
func (p InvestigationProposal) FileRef() string     { return p.fileRef }
func (p InvestigationProposal) StartLine() int      { return p.startLine }
func (p InvestigationProposal) EndLine() int        { return p.endLine }
func (p InvestigationProposal) FileRefs() []string  { return append([]string(nil), p.fileRefs...) }
func (p InvestigationProposal) Literal() string     { return p.literal }
func (p InvestigationProposal) String() string      { return "investigation proposal" }
func (p InvestigationProposal) GoString() string    { return "review.InvestigationProposal{<redacted>}" }
func (p InvestigationProposal) Format(s fmt.State, verb rune) {
	_, _ = s.Write([]byte("investigation proposal"))
}
