package provider

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestResponsePartKindsRoundTrip(t *testing.T) {
	for _, value := range []string{"assistant_text", "tool_call", "tool_result", "refusal", "citation", "structured_data"} {
		kind, err := ParseResponsePartKind(value)
		if err != nil || kind.String() != value || kind.Validate() != nil {
			t.Fatalf("ParseResponsePartKind(%q) = (%v, %v)", value, kind, err)
		}
	}
	if kind, err := ParseResponsePartKind("other"); !errors.Is(err, ErrInvalidResponsePartKind) || kind != 0 {
		t.Fatalf("invalid response part kind = (%v, %v)", kind, err)
	}
}

func TestNewResponsePartCopiesAndValidatesPayload(t *testing.T) {
	payload := []byte("review summary")
	part, err := NewResponsePart(ResponsePartAssistantText, "text/plain; charset=utf-8", payload)
	if err != nil {
		t.Fatal(err)
	}
	payload[0] = 'X'
	copyReturned := part.Payload()
	copyReturned[0] = 'Y'
	if string(part.Payload()) != "review summary" || part.MediaType() != "text/plain; charset=utf-8" || part.Kind() != ResponsePartAssistantText || part.SizeBytes() != len("review summary") || part.Validate() != nil {
		t.Fatalf("response part did not remain immutable: %#v", part)
	}
	if fmt.Sprint(part) != "provider response part" || fmt.Sprintf("%#v", part) != "provider.ResponsePart{<redacted>}" {
		t.Fatalf("response part formatting leaked: %s / %#v", part, part)
	}
}

func TestNewResponsePartRejectsMalformedContent(t *testing.T) {
	tests := []struct {
		name    string
		kind    ResponsePartKind
		media   string
		payload []byte
		want    error
	}{
		{"kind", 0, "text/plain", []byte("x"), ErrInvalidResponsePartKind},
		{"media", ResponsePartAssistantText, "not a type", []byte("x"), ErrInvalidResponsePartMediaType},
		{"text media", ResponsePartAssistantText, "application/json", []byte(`{"x":1}`), ErrInvalidResponsePartMediaType},
		{"structured media", ResponsePartStructuredData, "text/plain", []byte("x"), ErrInvalidResponsePartMediaType},
		{"invalid json", ResponsePartToolCall, "application/json", []byte("{"), ErrInvalidResponsePartPayload},
		{"invalid utf8", ResponsePartRefusal, "text/plain", []byte{0xff}, ErrInvalidResponsePartPayload},
		{"empty", ResponsePartCitation, "application/json", nil, ErrInvalidResponsePartPayload},
		{"large", ResponsePartAssistantText, "text/plain", bytes.Repeat([]byte("x"), maxProviderResponsePartPayloadBytes+1), ErrResponsePartPayloadTooLarge},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			part, err := NewResponsePart(test.kind, test.media, test.payload)
			if !errors.Is(err, test.want) || part.Validate() == nil {
				t.Fatalf("NewResponsePart() = (%#v, %v), want %v", part, err, test.want)
			}
		})
	}
}

func TestNewResponseIsImmutableAndContentAddressed(t *testing.T) {
	text, _ := NewResponsePart(ResponsePartAssistantText, "text/markdown", []byte(`## Review
Looks good.`))
	usage, _ := NewRouteTokenUsage(120, 30, 20)
	parts := []ResponsePart{text}
	response, err := NewResponse(CapabilityReviewV1, ResponseFinishStop, parts, usage)
	if err != nil {
		t.Fatal(err)
	}
	parts[0] = ResponsePart{}
	returned := response.Parts()
	returned[0] = ResponsePart{}
	if response.Identity() == "" || response.Capability() != CapabilityReviewV1 || response.FinishReason() != ResponseFinishStop || response.PartCount() != 1 || string(response.Parts()[0].Payload()) != `## Review
Looks good.` || response.Usage() != usage || response.Validate() != nil {
		t.Fatalf("response did not round trip: %#v", response)
	}
	otherText, _ := NewResponsePart(ResponsePartAssistantText, "text/markdown", []byte("Different"))
	other, _ := NewResponse(CapabilityReviewV1, ResponseFinishStop, []ResponsePart{otherText}, usage)
	if other.Identity() == response.Identity() {
		t.Fatal("response identity ignored content")
	}
	forged := response
	forged.identity = strings.Repeat("f", 64)
	if !errors.Is(forged.Validate(), ErrInvalidProviderResponseIdentity) {
		t.Fatal("forged response identity accepted")
	}
	if fmt.Sprint(response) != "provider response" || fmt.Sprintf("%#v", response) != "provider.Response{<redacted>}" || strings.Contains(fmt.Sprintf("%v", response), "Review") {
		t.Fatalf("response formatting leaked: %v / %#v", response, response)
	}
}

func TestNewResponseEnforcesFinishAndAggregateBounds(t *testing.T) {
	text, _ := NewResponsePart(ResponsePartAssistantText, "text/plain", []byte("x"))
	tool, _ := NewResponsePart(ResponsePartToolCall, "application/json", []byte(`{"id":"call-1","name":"read_file","arguments":{}}`))
	large, _ := NewResponsePart(ResponsePartAssistantText, "text/plain", bytes.Repeat([]byte("x"), maxProviderResponsePartPayloadBytes))
	usage := NewUnknownRouteTokenUsage()
	tests := []struct {
		name   string
		finish ResponseFinishReason
		parts  []ResponsePart
		want   error
	}{
		{"empty", ResponseFinishStop, nil, ErrInvalidProviderResponseParts},
		{"too many", ResponseFinishStop, make([]ResponsePart, maxProviderResponseParts+1), ErrTooManyProviderResponseParts},
		{"aggregate", ResponseFinishStop, []ResponsePart{large, large, large, large, large}, ErrProviderResponseTooLarge},
		{"tool finish without tool", ResponseFinishToolCalls, []ResponsePart{text}, ErrProviderResponseFinishMismatch},
		{"tool with stop", ResponseFinishStop, []ResponsePart{tool}, ErrProviderResponseFinishMismatch},
		{"invalid finish", 0, []ResponsePart{text}, ErrInvalidResponseFinishReason},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response, err := NewResponse(CapabilityReviewV1, test.finish, test.parts, usage)
			if !errors.Is(err, test.want) || response.Identity() != "" {
				t.Fatalf("NewResponse() = (%#v, %v), want %v", response, err, test.want)
			}
		})
	}
	valid, err := NewResponse(CapabilityReviewV1, ResponseFinishToolCalls, []ResponsePart{text, tool}, usage)
	if err != nil || valid.Validate() != nil {
		t.Fatalf("valid tool response = (%#v, %v)", valid, err)
	}
}

func TestResponseHasClosedRepresentation(t *testing.T) {
	part, _ := NewResponsePart(ResponsePartAssistantText, "text/plain", []byte("x"))
	response, _ := NewResponse(CapabilityReviewV1, ResponseFinishStop, []ResponsePart{part}, NewUnknownRouteTokenUsage())
	if reflect.TypeOf(part).NumField() != 3 || reflect.TypeOf(response).NumField() != 5 {
		t.Fatal("response values gained an unexpected field")
	}
	for _, value := range []string{"stop", "length", "tool_calls", "content_filter"} {
		finish, err := ParseResponseFinishReason(value)
		if err != nil || finish.String() != value || finish.Validate() != nil {
			t.Fatalf("ParseResponseFinishReason(%q) = (%v, %v)", value, finish, err)
		}
	}
}
