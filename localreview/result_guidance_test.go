package localreview

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// assertFindingGuidance checks that a completed version 7 review reports the
// verified finding's category and unverified fix guidance in text and JSON, and
// that the version 4 result still imports.
func assertFindingGuidance(t *testing.T, r Result) {
	t.Helper()
	findings := r.diagnostics.Findings()
	if r.wire.Version != guidanceResultVersion || len(findings) == 0 || len(r.wire.Guidance) != len(findings) {
		t.Fatalf("result version=%d guidance=%d findings=%d", r.wire.Version, len(r.wire.Guidance), len(findings))
	}
	for index, value := range r.wire.Guidance {
		if value.FindingIdentity != findings[index].SourceIdentity() || value.Category != "correctness" || value.Fix != "Restore the zero guard before dividing." || value.FixAuthority != "unverified_model_guidance" {
			t.Fatalf("guidance does not bind the verified finding: %+v", value)
		}
	}
	encoded, err := EncodeResult(r)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &wire); err != nil || string(wire["schema_version"]) != "4" || wire["finding_guidance"] == nil {
		t.Fatal("JSON result lacks version 4 finding_guidance")
	}
	var text bytes.Buffer
	if err := RenderResult(&text, r); err != nil {
		t.Fatal(err)
	}
	rendered := text.String()
	finding := strings.Index(rendered, "finding: ")
	category := strings.Index(rendered, "\ncategory: correctness\n")
	fix := strings.Index(rendered, "\nfix: Restore the zero guard before dividing.\n")
	if finding < 0 || category < finding || fix < category {
		t.Fatalf("text result lacks ordered category and fix lines:\n%s", rendered)
	}
	imported, err := ParseCompletedResult(encoded)
	if err != nil || len(imported.wire.Guidance) != len(r.wire.Guidance) {
		t.Fatalf("version 4 result does not import: %v", err)
	}
	if _, err := imported.CompletedMetadata(); err != nil {
		t.Fatal(err)
	}
	for name, tampered := range map[string][]byte{
		"version 1 with guidance": bytes.Replace(encoded, []byte(`"schema_version":4`), []byte(`"schema_version":1`), 1),
		"unknown category":        bytes.Replace(encoded, []byte(`"category":"correctness"`), []byte(`"category":"bug"`), 1),
		"unlabeled fix":           bytes.Replace(encoded, []byte(`,"fix_authority":"unverified_model_guidance"`), nil, 1),
		"foreign finding":         bytes.Replace(encoded, []byte(`"finding_identity":"`+r.wire.Guidance[0].FindingIdentity), []byte(`"finding_identity":"`+strings.Repeat("e", 64)), 1),
	} {
		if bytes.Equal(tampered, encoded) {
			t.Fatalf("%s fixture did not change the result", name)
		}
		if _, err := ParseCompletedResult(tampered); err == nil {
			t.Fatalf("%s imported", name)
		}
	}
}
