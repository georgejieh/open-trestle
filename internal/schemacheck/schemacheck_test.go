package schemacheck

import (
	"os"
	"path/filepath"
	"testing"
)

const fixture = `{"$schema":"https://json-schema.org/draft/2020-12/schema","$id":"urn:test:record","type":"object","additionalProperties":false,"required":["name","count"],
"properties":{"name":{"type":"string","pattern":"^[a-z]+$","maxLength":5},"count":{"type":"integer","minimum":1,"maximum":3},"tags":{"type":"array","items":{"enum":["a","b"]},"uniqueItems":true},"detail":{"$ref":"#/$defs/detail"}},
"$defs":{"detail":{"type":"object","required":["kind"],"properties":{"kind":{"const":"x"}}}},
"allOf":[{"if":{"required":["detail"]},"then":{"properties":{"count":{"const":2}}},"else":{"not":{"required":["tags"]}}}]}`

// The validator enforces every keyword it accepts, including conditionals.
func TestValidatorEnforcesKeywords(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "record.schema.json"), []byte(fixture), 0600); err != nil {
		t.Fatal(err)
	}
	registry, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, valid := range []string{`{"name":"ab","count":1}`, `{"name":"ab","count":2,"detail":{"kind":"x"},"tags":["a","b"]}`} {
		if err := registry.Validate("urn:test:record", []byte(valid)); err != nil {
			t.Fatalf("%s: %v", valid, err)
		}
	}
	for _, invalid := range []string{
		`{"name":"ab"}`, `{"name":"AB","count":1}`, `{"name":"abcdef","count":1}`, `{"name":"ab","count":4}`,
		`{"name":"ab","count":1.5}`, `{"name":"ab","count":1,"extra":true}`, `{"name":"ab","count":2,"detail":{"kind":"y"}}`,
		`{"name":"ab","count":1,"detail":{"kind":"x"}}`, `{"name":"ab","count":1,"tags":["a"]}`, `{"name":"ab","count":2,"detail":{"kind":"x"},"tags":["a","a"]}`,
	} {
		if err := registry.Validate("urn:test:record", []byte(invalid)); err == nil {
			t.Fatalf("%s accepted", invalid)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "unknown.schema.json"), []byte(`{"$id":"urn:test:unknown","exclusiveMinimum":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	registry, err = Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.Validate("urn:test:unknown", []byte(`2`)); err == nil {
		t.Fatal("unsupported keyword silently ignored")
	}
}
