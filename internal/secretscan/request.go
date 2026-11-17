package secretscan

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"strconv"
)

// newScanRequest builds a request with a fresh random request ID and private
// copies of sources, plus its encoded frame. The caller clears both after use.
func newScanRequest(random io.Reader, sources [][]byte) (Request, []byte, FailureClass) {
	if random == nil {
		return Request{}, nil, FailurePolicy
	}
	requestID := make([]byte, sha256.Size)
	if _, err := io.ReadFull(random, requestID); err != nil {
		clear(requestID)
		return Request{}, nil, FailurePolicy
	}
	request := Request{SchemaVersion: 1, RequestID: hex.EncodeToString(requestID), Sources: make([]Source, len(sources))}
	clear(requestID)
	for index := range sources {
		var content []byte
		if sources[index] != nil {
			content = make([]byte, len(sources[index]))
			copy(content, sources[index])
		}
		request.Sources[index] = Source{Ordinal: index, Content: content}
	}
	frame, err := encodeClientRequestFrame(request)
	if err != nil {
		clearRequestCopy(&request)
		return Request{}, nil, FailureInvalidInput
	}
	return request, frame, FailureNone
}

func encodeClientRequestFrame(request Request) ([]byte, error) {
	if err := validateRequest(request); err != nil {
		return nil, err
	}
	payloadLength := len(`{"schema_version":1,"request_id":"`) + len(request.RequestID) + len(`","sources":[`) + len(`]}`)
	for index, source := range request.Sources {
		if index != 0 {
			payloadLength++
		}
		payloadLength += len(`{"ordinal":`) + decimalDigits(source.Ordinal) + len(`,"content_base64":"`) + base64.StdEncoding.EncodedLen(len(source.Content)) + len(`"}`)
	}
	if payloadLength < 1 || payloadLength > maxRequestFrameBytes {
		return nil, ErrInvalidProtocol
	}
	frame := make([]byte, framePrefixBytes, framePrefixBytes+payloadLength)
	frame = append(frame, `{"schema_version":1,"request_id":"`...)
	frame = append(frame, request.RequestID...)
	frame = append(frame, `","sources":[`...)
	for index, source := range request.Sources {
		if index != 0 {
			frame = append(frame, ',')
		}
		frame = append(frame, `{"ordinal":`...)
		frame = strconv.AppendInt(frame, int64(source.Ordinal), 10)
		frame = append(frame, `,"content_base64":"`...)
		start := len(frame)
		frame = append(frame, make([]byte, base64.StdEncoding.EncodedLen(len(source.Content)))...)
		base64.StdEncoding.Encode(frame[start:], source.Content)
		frame = append(frame, `"}`...)
	}
	frame = append(frame, `]}`...)
	if len(frame) != framePrefixBytes+payloadLength {
		clear(frame)
		return nil, ErrInvalidProtocol
	}
	binary.BigEndian.PutUint32(frame[:framePrefixBytes], uint32(payloadLength))
	return frame, nil
}

func decimalDigits(value int) int {
	digits := 1
	for value >= 10 {
		value /= 10
		digits++
	}
	return digits
}

func validDigest(value string) bool {
	return validLowerHex(value, sha256.Size*2)
}

func pinnedRuleIDSetProduction() map[string]struct{} {
	ruleIDs := make(map[string]struct{}, len(betterleaksRuleIDsV1))
	for _, ruleID := range betterleaksRuleIDsV1 {
		ruleIDs[ruleID] = struct{}{}
	}
	return ruleIDs
}

func clearRequestCopy(request *Request) {
	if request == nil {
		return
	}
	for index := range request.Sources {
		clear(request.Sources[index].Content)
	}
	clear(request.Sources)
	*request = Request{}
}
