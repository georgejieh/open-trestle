package secretscan

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const (
	RequestContract  = "open-trestle/secret-scan-request"
	ResponseContract = "open-trestle/secret-scan-response"

	ScannerName      = "betterleaks"
	ScannerVersion   = "v1.8.1"
	ScannerCommit    = "5eab48332cc48565864514e3bc6de89df091a7c4"
	RulesetIdentity  = "27ded783c81940d13c22cc46556a3f8184baf397bff08a69fcfae87991925f42"
	RulesetRuleCount = 417
	BuildProfile     = "public_detect_run_re2_purego_go1.26.11_linux_amd64_v1"

	StatusComplete          = "complete"
	StatusInputRejected     = "input_rejected"
	StatusScanFailed        = "scan_failed"
	StatusResourceExhausted = "resource_exhausted"

	framePrefixBytes        = 4
	maxRequestFrameBytes    = 3 * 1024 * 1024
	maxResponseFrameBytes   = 4 * 1024 * 1024
	maxSources              = 256
	maxSourceBytes          = 256 * 1024
	maxAggregateSourceBytes = 2 * 1024 * 1024
	maxMatches              = 8192
	maxRuleIDBytes          = 256
)

// go12610BuildProfile is the scanner profile that preceded BuildProfile. No
// new scan emits it, but responses and receipts recorded under it stay valid.
const go12610BuildProfile = "public_detect_run_re2_purego_go1.26.10_linux_amd64_v1"

var ErrInvalidProtocol = errors.New("invalid secret scan protocol")

// KnownBuildProfile reports whether a recorded response or receipt names one
// of the exactly two readable scanner profiles: BuildProfile, which new scans
// emit, or the go1.26.10 profile. Live scans require BuildProfile itself.
func KnownBuildProfile(profile string) bool {
	return profile == BuildProfile || profile == go12610BuildProfile
}

type Source struct {
	Ordinal int    `json:"ordinal"`
	Content []byte `json:"content_base64"`
}

type Request struct {
	SchemaVersion int      `json:"schema_version"`
	RequestID     string   `json:"request_id"`
	Sources       []Source `json:"sources"`
}

type Match struct {
	SourceOrdinal    int    `json:"source_ordinal"`
	RuleID           string `json:"rule_id"`
	StartByte        int    `json:"start_byte"`
	EndByteExclusive int    `json:"end_byte_exclusive"`
	OccurrenceID     string `json:"occurrence_id"`
}

type Response struct {
	SchemaVersion   int     `json:"schema_version"`
	RequestID       string  `json:"request_id"`
	Status          string  `json:"status"`
	Scanner         string  `json:"scanner"`
	ScannerVersion  string  `json:"scanner_version"`
	ScannerCommit   string  `json:"scanner_commit"`
	RulesetIdentity string  `json:"ruleset_identity"`
	BuildProfile    string  `json:"build_profile"`
	Matches         []Match `json:"matches"`
}

type ResponseExpectation struct {
	Request         Request
	RulesetIdentity string
	RuleIDs         map[string]struct{}
}

type occurrenceTuple struct {
	Version          int    `json:"version"`
	Scanner          string `json:"scanner"`
	ScannerVersion   string `json:"scanner_version"`
	ScannerCommit    string `json:"scanner_commit"`
	RuleID           string `json:"rule_id"`
	SourceOrdinal    int    `json:"source_ordinal"`
	StartByte        int    `json:"start_byte"`
	EndByteExclusive int    `json:"end_byte_exclusive"`
}

func OccurrenceID(match Match) string {
	encoded, err := json.Marshal(occurrenceTuple{
		Version:          1,
		Scanner:          ScannerName,
		ScannerVersion:   ScannerVersion,
		ScannerCommit:    ScannerCommit,
		RuleID:           match.RuleID,
		SourceOrdinal:    match.SourceOrdinal,
		StartByte:        match.StartByte,
		EndByteExclusive: match.EndByteExclusive,
	})
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func EncodeRequestFrame(request Request) ([]byte, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	return encodeFrame(request, maxRequestFrameBytes)
}

func ParseRequestFrame(frame []byte) (Request, error) {
	payload, err := decodeFrame(frame, maxRequestFrameBytes)
	if err != nil {
		return Request{}, err
	}
	var request Request
	if err := decodeCanonicalJSON(payload, &request); err != nil || validateRequest(request) != nil {
		return Request{}, ErrInvalidProtocol
	}
	return request, nil
}

func EncodeResponseFrame(response Response, expectation ResponseExpectation) ([]byte, error) {
	if err := validateResponse(response, expectation); err != nil {
		return nil, err
	}
	return encodeFrame(response, maxResponseFrameBytes)
}

func ParseResponseFrame(frame []byte, expectation ResponseExpectation) (Response, error) {
	payload, err := decodeFrame(frame, maxResponseFrameBytes)
	if err != nil {
		return Response{}, err
	}
	var response Response
	if err := decodeCanonicalJSON(payload, &response); err != nil || validateResponse(response, expectation) != nil {
		return Response{}, ErrInvalidProtocol
	}
	return response, nil
}

func encodeFrame(value any, maximum int) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil || len(payload) == 0 || len(payload) > maximum {
		return nil, ErrInvalidProtocol
	}
	frame := make([]byte, framePrefixBytes+len(payload))
	binary.BigEndian.PutUint32(frame, uint32(len(payload)))
	copy(frame[framePrefixBytes:], payload)
	return frame, nil
}

func decodeFrame(frame []byte, maximum int) ([]byte, error) {
	if len(frame) < framePrefixBytes {
		return nil, ErrInvalidProtocol
	}
	declared := binary.BigEndian.Uint32(frame[:framePrefixBytes])
	if declared == 0 || declared > uint32(maximum) || uint64(declared)+framePrefixBytes != uint64(len(frame)) {
		return nil, ErrInvalidProtocol
	}
	return frame[framePrefixBytes:], nil
}

func decodeCanonicalJSON(payload []byte, target any) error {
	if len(payload) == 0 || !utf8.Valid(payload) {
		return ErrInvalidProtocol
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return ErrInvalidProtocol
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return ErrInvalidProtocol
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(payload, canonical) {
		return ErrInvalidProtocol
	}
	return nil
}

func validateRequest(request Request) error {
	if request.SchemaVersion != 1 || !validLowerHex(request.RequestID, sha256.Size*2) || request.Sources == nil || len(request.Sources) < 1 || len(request.Sources) > maxSources {
		return ErrInvalidProtocol
	}
	total := 0
	for index, source := range request.Sources {
		if source.Ordinal != index || source.Content == nil || len(source.Content) > maxSourceBytes || !utf8.Valid(source.Content) {
			return ErrInvalidProtocol
		}
		total += len(source.Content)
		if total > maxAggregateSourceBytes {
			return ErrInvalidProtocol
		}
	}
	return nil
}

func validateResponse(response Response, expectation ResponseExpectation) error {
	if validateRequest(expectation.Request) != nil || expectation.RulesetIdentity != RulesetIdentity {
		return ErrInvalidProtocol
	}
	if response.SchemaVersion != 1 || response.RequestID != expectation.Request.RequestID || response.Status != StatusComplete && response.Status != StatusInputRejected && response.Status != StatusScanFailed && response.Status != StatusResourceExhausted ||
		response.Scanner != ScannerName || response.ScannerVersion != ScannerVersion || response.ScannerCommit != ScannerCommit || response.RulesetIdentity != expectation.RulesetIdentity || !KnownBuildProfile(response.BuildProfile) ||
		response.Matches == nil || len(response.Matches) > maxMatches || response.Status != StatusComplete && len(response.Matches) != 0 {
		return ErrInvalidProtocol
	}
	for index, match := range response.Matches {
		if !validMatch(match, expectation) {
			return ErrInvalidProtocol
		}
		if index > 0 && compareMatches(response.Matches[index-1], match) >= 0 {
			return ErrInvalidProtocol
		}
	}
	return nil
}

func validMatch(match Match, expectation ResponseExpectation) bool {
	if match.SourceOrdinal < 0 || match.SourceOrdinal >= len(expectation.Request.Sources) || len(match.RuleID) < 1 || len(match.RuleID) > maxRuleIDBytes || !utf8.ValidString(match.RuleID) {
		return false
	}
	if _, known := expectation.RuleIDs[match.RuleID]; !known {
		return false
	}
	content := expectation.Request.Sources[match.SourceOrdinal].Content
	if match.StartByte < 0 || match.EndByteExclusive <= match.StartByte || match.EndByteExclusive > len(content) || !utf8Boundary(content, match.StartByte) || !utf8Boundary(content, match.EndByteExclusive) {
		return false
	}
	return validLowerHex(match.OccurrenceID, sha256.Size*2) && match.OccurrenceID == OccurrenceID(match)
}

func utf8Boundary(content []byte, offset int) bool {
	return offset == 0 || offset == len(content) || utf8.RuneStart(content[offset])
}

func compareMatches(left, right Match) int {
	if left.SourceOrdinal != right.SourceOrdinal {
		return compareInt(left.SourceOrdinal, right.SourceOrdinal)
	}
	if left.StartByte != right.StartByte {
		return compareInt(left.StartByte, right.StartByte)
	}
	if left.EndByteExclusive != right.EndByteExclusive {
		return compareInt(left.EndByteExclusive, right.EndByteExclusive)
	}
	if left.RuleID < right.RuleID {
		return -1
	}
	if left.RuleID > right.RuleID {
		return 1
	}
	if left.OccurrenceID < right.OccurrenceID {
		return -1
	}
	if left.OccurrenceID > right.OccurrenceID {
		return 1
	}
	return 0
}

func compareInt(left, right int) int {
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func validLowerHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, character := range []byte(value) {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}
