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

func TestRecordedInvestigationTurnTransportBytesMeasureTheRecordedContract(t *testing.T) {
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
	// Version 6 verification bytes: version 7 without its sentence, bound to the
	// version 6 contract identity.
	v6Verification := bytes.Replace(bytes.Replace(rawVerification.Payload(), []byte(`"schema_version":8`), []byte(`"schema_version":6`), 1), []byte(modelInstructionsIdentity(verificationOutputInstructionsV8)), []byte(modelInstructionsIdentity(verificationOutputInstructionsV6)), 1)
	if _, err := LocalVerificationPayload(recordedLocalEnvelope(t, v6Verification, scope), scope, provider.ProviderZoneLocal); bytes.Equal(v6Verification, rawVerification.Payload()) || err == nil {
		t.Fatal("fixture is not a recorded-only version 6 verification envelope")
	}
	verificationSchema, err := TrustedModelRequestOutputSchema(rawVerification.Payload())
	if err != nil {
		t.Fatal(err)
	}
	recordedV5 := recordedTransportRequest(t, recordedInvestigationV5(t, investigation.Payload()))
	if _, err := TrustedModelRequestInstructions(recordedV5.Payload()); err == nil {
		t.Fatal("fixture version 5 investigation context is executable")
	}
	cases := []struct {
		name           string
		request        provider.Request
		system, format uint32
	}{
		{"executable investigation", investigation, ModelRequestSystemChannelBytes(investigation), ModelRequestResponseFormatBytes(investigation)},
		{"executable local verification envelope", envelope, ModelRequestSystemChannelBytes(envelope), ModelRequestResponseFormatBytes(envelope)},
		{"recorded version 5 investigation", recordedV5, uint32(len(investigationInstructionsV5)), localStructuredOutputFramingBytes(InvestigationOutputSchema())},
		{"recorded version 6 verification envelope", recordedLocalEnvelope(t, v6Verification, scope), uint32(len(verificationOutputInstructionsV6)), localStructuredOutputFramingBytes(verificationSchema)},
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
		"tampered local verification envelope": recordedTransportRequest(t, tampered),
		"foreign envelope scope":               recordedLocalEnvelope(t, v6Verification, string(bytes.Repeat([]byte("f"), 64))),
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

// Every investigation context version from the first whose turns record
// transport counts through the executable one needs its contract in the
// recorded measurement table, so a new version cannot ship without one and a
// superseded version keeps reading back.
func TestRecordedInvestigationInstructionsCoverEveryCountedVersion(t *testing.T) {
	f := newV4FixtureAt(t, "func Changed(x int) int { return 10 / x }\n", "zero requests enabled\n", "AGENTS.md")
	state, _ := v4ResultStateWith(t, f, "quoted tool result")
	binding, err := NewInvestigationContextBinding(f.binding)
	v4Check(t, err)
	context, err := NewInvestigationGenerationContext(binding, f.expanded, f.expandedSnapshot, state)
	v4Check(t, err)
	executable, err := context.ProviderRequest()
	v4Check(t, err)
	current, err := TrustedModelRequestInstructions(executable.Payload())
	if err != nil {
		t.Fatal(err)
	}
	if recordedInvestigationInstructions[investigationContextVersion] != current {
		t.Fatalf("executable investigation context version %d has no matching recorded transport-measurement entry", investigationContextVersion)
	}
	for version := investigationContextVersionV5; version <= investigationContextVersion; version++ {
		instructions, ok := recordedInvestigationInstructions[version]
		if !ok {
			t.Fatalf("investigation context version %d has no recorded transport-measurement entry", version)
		}
		var wire map[string]json.RawMessage
		if err := json.Unmarshal(executable.Payload(), &wire); err != nil {
			t.Fatal(err)
		}
		wire["schema_version"] = mustJSON(version)
		wire["instructions_identity"] = mustJSON(modelInstructionsIdentity(instructions))
		recorded, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		// The entry is the contract that version's readback binds.
		if ValidateRecordedInvestigationContext(recorded) != nil {
			t.Fatalf("recorded entry for investigation context version %d is not the contract it binds", version)
		}
		if system, _, err := RecordedInvestigationTurnTransportBytes(recordedTransportRequest(t, recorded)); err != nil || system != uint32(len(instructions)) {
			t.Fatalf("version %d measured (%d, %v)", version, system, err)
		}
	}
	for version := range recordedInvestigationInstructions {
		if version < investigationContextVersionV5 || version > investigationContextVersion {
			t.Fatalf("recorded entry for investigation context version %d that no turn can record", version)
		}
	}
}
