package provider

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
)

func TestCapabilityReviewV1RoundTrips(t *testing.T) {
	capability, err := ParseCapability("review.v1")
	if err != nil || capability != CapabilityReviewV1 || capability.String() != "review.v1" {
		t.Fatalf("ParseCapability() = (%q, %v), String() = %q", capability, err, capability.String())
	}
	for _, value := range []string{"", "review", "review.v2", " review.v1 ", "REVIEW.V1"} {
		if capability, err := ParseCapability(value); !errors.Is(err, ErrInvalidCapability) || capability != 0 {
			t.Fatalf("ParseCapability(%q) = (%q, %v)", value, capability, err)
		}
	}
	if Capability(99).String() != "" || Capability(0).String() != "" {
		t.Fatal("unknown capability has a string token")
	}
}

func TestNewRequestPreservesCanonicalFields(t *testing.T) {
	source := []byte("review payload")
	request, err := NewRequest(CapabilityReviewV1, " application/json ", source)
	if err != nil {
		t.Fatal(err)
	}
	if request.Capability() != CapabilityReviewV1 || request.MediaType() != "application/json" || !bytes.Equal(request.Payload(), source) || request.Validate() != nil {
		t.Fatalf("request = %#v", request)
	}
	source[0] = 'X'
	if string(request.Payload()) != "review payload" {
		t.Fatal("constructor source mutation changed request")
	}
	returned := request.Payload()
	returned[0] = 'Y'
	if string(request.Payload()) != "review payload" {
		t.Fatal("returned payload mutation changed request")
	}
	copied := request
	copyPayload := copied.Payload()
	copyPayload[0] = 'Z'
	if string(request.Payload()) != "review payload" || string(copied.Payload()) != "review payload" {
		t.Fatal("copied request exposed mutable state")
	}
}

func TestNewRequestRejectsInvalidFields(t *testing.T) {
	for _, test := range []struct {
		name       string
		capability Capability
		mediaType  string
		payload    []byte
		want       error
	}{
		{name: "capability", mediaType: "application/json", payload: []byte("x"), want: ErrInvalidCapability},
		{name: "unknown capability", capability: Capability(99), mediaType: "application/json", payload: []byte("x"), want: ErrInvalidCapability},
		{name: "empty media type", capability: CapabilityReviewV1, payload: []byte("x"), want: ErrInvalidMediaType},
		{name: "blank media type", capability: CapabilityReviewV1, mediaType: " \t\n", payload: []byte("x"), want: ErrInvalidMediaType},
		{name: "oversized media type", capability: CapabilityReviewV1, mediaType: "application/" + string(bytes.Repeat([]byte{'a'}, maxProviderMediaTypeBytes-len("application/")+1)), payload: []byte("x"), want: ErrInvalidMediaType},
		{name: "padded valid media type", capability: CapabilityReviewV1, mediaType: string(bytes.Repeat([]byte{' '}, maxProviderMediaTypeBytes)) + "application/json", payload: []byte("x"), want: ErrInvalidMediaType},
		{name: "malformed media type", capability: CapabilityReviewV1, mediaType: "not a media type", payload: []byte("x"), want: ErrInvalidMediaType},
		{name: "media control", capability: CapabilityReviewV1, mediaType: "application/json\nsecret", payload: []byte("x"), want: ErrInvalidMediaType},
		{name: "empty payload", capability: CapabilityReviewV1, mediaType: "application/json", want: ErrInvalidPayload},
		{name: "oversized payload", capability: CapabilityReviewV1, mediaType: "application/json", payload: make([]byte, maxProviderRequestPayloadBytes+1), want: ErrPayloadTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			request, err := NewRequest(test.capability, test.mediaType, test.payload)
			if !errors.Is(err, test.want) || request.Capability() != 0 || request.MediaType() != "" || request.Payload() != nil {
				t.Fatalf("NewRequest() = (%#v, %v), want %v", request, err, test.want)
			}
		})
	}
}

func TestRequestPayloadLimitBoundary(t *testing.T) {
	payload := make([]byte, maxProviderRequestPayloadBytes)
	mediaType := "application/" + string(bytes.Repeat([]byte{'a'}, maxProviderMediaTypeBytes-len("application/")))
	request, err := NewRequest(CapabilityReviewV1, mediaType, payload)
	if err != nil || request.MediaType() != mediaType || len(request.Payload()) != maxProviderRequestPayloadBytes {
		t.Fatalf("NewRequest() = (%#v, %v)", request, err)
	}
}

func TestRequestZeroValueAndForgedValuesFailValidation(t *testing.T) {
	for _, test := range []struct {
		name    string
		request Request
		want    error
	}{
		{name: "zero", want: ErrInvalidCapability},
		{name: "media", request: Request{capability: CapabilityReviewV1, mediaType: " ", payload: "x"}, want: ErrInvalidMediaType},
		{name: "noncanonical media", request: Request{capability: CapabilityReviewV1, mediaType: " application/json ", payload: "x"}, want: ErrInvalidMediaType},
		{name: "payload", request: Request{capability: CapabilityReviewV1, mediaType: "application/json"}, want: ErrInvalidPayload},
		{name: "large", request: Request{capability: CapabilityReviewV1, mediaType: "application/json", payload: string(make([]byte, maxProviderRequestPayloadBytes+1))}, want: ErrPayloadTooLarge},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.request.Validate(); !errors.Is(err, test.want) {
				t.Fatalf("Validate() = %v, want %v", err, test.want)
			}
		})
	}
}

func TestRequestSurfaceContainsNoRoutingOrCredentialState(t *testing.T) {
	typeOfRequest := reflect.TypeOf(Request{})
	want := []string{"capability", "mediaType", "payload"}
	if typeOfRequest.NumField() != len(want) {
		t.Fatalf("Request has %d fields, want %d", typeOfRequest.NumField(), len(want))
	}
	for index, name := range want {
		if typeOfRequest.Field(index).Name != name {
			t.Fatalf("field %d = %q, want %q", index, typeOfRequest.Field(index).Name, name)
		}
	}
	if typeOfRequest.Field(2).Type.Kind() != reflect.String {
		t.Fatalf("payload field type = %s, want immutable string", typeOfRequest.Field(2).Type)
	}
}
