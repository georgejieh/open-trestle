package review

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/georgejieh/open-trestle/internal/provider"
)

// answerDocument returns the JSON document of a reply that stopped normally
// with one part. A structured part is the document. A text part is accepted
// only when it is one complete JSON object followed by text that is not JSON,
// such as a stray template token; the tail is dropped. Leading text, a second
// document or an incomplete one leave the reply refused with envelope.
func answerDocument(response provider.Response, envelope error) ([]byte, error) {
	parts := response.Parts()
	if response.FinishReason() != provider.ResponseFinishStop || len(parts) != 1 {
		return nil, envelopeFailure(envelope, parts)
	}
	switch parts[0].Kind() {
	case provider.ResponsePartStructuredData:
		return parts[0].Payload(), nil
	case provider.ResponsePartAssistantText:
		if document, ok := documentBeforeTail(parts[0].Payload()); ok {
			return document, nil
		}
	}
	return nil, envelopeFailure(envelope, parts)
}

// documentBeforeTail splits text into a leading JSON object and a non-JSON
// tail. It is false when text does not start with an object, the object is
// incomplete, or the tail is empty, JSON, or starts another object or array.
func documentBeforeTail(text []byte) ([]byte, bool) {
	trimmed := bytes.TrimLeft(text, " \t\r\n")
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, false
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	var document json.RawMessage
	if decoder.Decode(&document) != nil {
		return nil, false
	}
	end := decoder.InputOffset()
	tail := bytes.TrimSpace(trimmed[end:])
	if len(tail) == 0 || tail[0] == '{' || tail[0] == '[' || json.Valid(tail) {
		return nil, false
	}
	return trimmed[:end], true
}

// verificationCandidateLabel is the short label a verifier request gives the
// candidate at index, and that a verdict echoes: c1, c2, and so on.
func verificationCandidateLabel(index int) string {
	return "c" + strconv.Itoa(index+1)
}

// validVerificationCandidateLabel reports whether value has the syntax of a
// candidate label of a batch of at most maxCandidateFindings.
func validVerificationCandidateLabel(value string) bool {
	number, found := strings.CutPrefix(value, "c")
	n, err := strconv.Atoi(number)
	return found && err == nil && n >= 1 && n <= maxCandidateFindings && strconv.Itoa(n) == number
}
