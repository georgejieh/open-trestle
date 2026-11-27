package review

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/georgejieh/open-trestle/internal/provider"
)

func recordedTransportRequest(t *testing.T, payload []byte) provider.Request {
	t.Helper()
	request, err := provider.NewRequest(provider.CapabilityReviewV1, "application/json", payload)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

// recordedLocalEnvelope wraps raw verification bytes exactly as
// NewLocalVerificationRequest does, without requiring the executable version.
func recordedLocalEnvelope(t *testing.T, raw []byte, scope string) provider.Request {
	t.Helper()
	inner := recordedTransportRequest(t, raw)
	encoded, err := json.Marshal(localVerificationEnvelopeWire{Contract: "open-trestle/local-verification-envelope", SchemaVersion: 1, ReviewScopeIdentity: scope, RawRequestIdentity: inner.Identity(), Capability: inner.Capability().String(), MediaType: inner.MediaType(), Payload: inner.Payload()})
	if err != nil {
		t.Fatal(err)
	}
	return recordedTransportRequest(t, encoded)
}

func TestRecordedInvestigationTurnTransportBytesMeasureTheRequestContract(t *testing.T) {
	f := newV4FixtureAt(t, "func Changed(x int) int { return 10 / x }\n", "zero requests enabled\n", "AGENTS.md")
	state, _ := v4ResultStateWith(t, f, "quoted tool result")
	binding, err := NewInvestigationContextBinding(f.binding)
	v4Check(t, err)
	context, err := NewInvestigationGenerationContext(binding, f.expanded, f.expandedSnapshot, state)
	v4Check(t, err)
	investigation, err := context.ProviderRequest()
	v4Check(t, err)
	generation, candidates := verificationContextFixture(t)
	verification, err := NewVerificationContextPacket(generation, candidates)
	if err != nil {
		t.Fatal(err)
	}
	scope := generation.ReviewScopeIdentity()
	rawVerification, err := verification.ProviderRequest()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := NewLocalVerificationRequest(rawVerification, scope)
	if err != nil {
		t.Fatal(err)
	}
	v9Verification := bytes.Replace(rawVerification.Payload(), []byte(`"schema_version":11`), []byte(`"schema_version":10`), 1)
	v5Investigation := bytes.Replace(investigation.Payload(), []byte(`"schema_version":6`), []byte(`"schema_version":5`), 1)
	cases := []struct {
		name           string
		request        provider.Request
		system, format uint32
	}{
		{"executable investigation", investigation, ModelRequestSystemChannelBytes(investigation), ModelRequestResponseFormatBytes(investigation)},
		{"executable local verification envelope", envelope, ModelRequestSystemChannelBytes(envelope), ModelRequestResponseFormatBytes(envelope)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			system, format, err := RecordedInvestigationTurnTransportBytes(tc.request)
			if err != nil || system != tc.system || format != tc.format || system == 0 || format == 0 {
				t.Fatalf("recorded counts = (%d, %d, %v), want (%d, %d)", system, format, err, tc.system, tc.format)
			}
		})
	}
	tampered := bytes.Replace(envelope.Payload(), []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1)
	for name, request := range map[string]provider.Request{
		"version 4 investigation":              recordedTransportRequest(t, recordedInvestigationV4(t, investigation.Payload())),
		"version 5 investigation":              recordedTransportRequest(t, v5Investigation),
		"version 9 verification envelope":      recordedLocalEnvelope(t, v9Verification, scope),
		"tampered local verification envelope": recordedTransportRequest(t, tampered),
		"foreign envelope scope":               recordedLocalEnvelope(t, rawVerification.Payload(), string(bytes.Repeat([]byte("f"), 64))),
		"no trusted contract":                  recordedTransportRequest(t, []byte(`{"contract":"other"}`)),
		"sanitized-shaped opaque":              recordedTransportRequest(t, []byte(`{"contract":"open-trestle/review-context-packet","schema_version":6}`)),
	} {
		t.Run(name, func(t *testing.T) {
			if system, format, err := RecordedInvestigationTurnTransportBytes(request); err == nil || system != 0 || format != 0 {
				t.Fatalf("unmeasurable request measured as (%d, %d)", system, format)
			}
		})
	}
}
