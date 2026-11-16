package analysiscodec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// publishedArtifactSchemas loads every artifact schema by $id so the
// conformance check can follow the semantic_impact reference.
func publishedArtifactSchemas(t *testing.T) map[string]map[string]any {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "schemas", "artifact", "*.schema.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("artifact schemas: %v", err)
	}
	schemas := make(map[string]map[string]any, len(paths))
	for _, path := range paths {
		encoded, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var schema map[string]any
		if err := json.Unmarshal(encoded, &schema); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		schemas[schema["$id"].(string)] = schema
	}
	return schemas
}

func deterministicEvidenceSchema(t *testing.T, schemas map[string]map[string]any, version int) map[string]any {
	t.Helper()
	schema, ok := schemas[fmt.Sprintf("urn:open-trestle:schema:artifact:deterministic-evidence-result:v%d", version)]
	if !ok {
		t.Fatalf("deterministic evidence result v%d schema is not published", version)
	}
	return schema
}

// validateSchemaDocument checks a decoded JSON document against the subset of
// JSON Schema 2020-12 that the artifact schemas use. It fails on any other
// keyword so that a schema cannot silently rely on unchecked rules.
func validateSchemaDocument(schemas map[string]map[string]any, schema map[string]any, value any, location string) error {
	for key := range schema {
		switch key {
		case "$schema", "$id", "title", "description", "type", "const", "enum", "required", "properties", "additionalProperties", "items", "minItems", "maxItems", "minimum", "maximum", "minLength", "maxLength", "pattern", "not", "$ref":
		default:
			return fmt.Errorf("%s: unsupported schema keyword %q", location, key)
		}
	}
	if reference, ok := schema["$ref"].(string); ok {
		target, exists := schemas[reference]
		if !exists {
			return fmt.Errorf("%s: unresolved reference %q", location, reference)
		}
		if err := validateSchemaDocument(schemas, target, value, location); err != nil {
			return err
		}
	}
	if expected, ok := schema["type"]; ok {
		types := []any{expected}
		if list, isList := expected.([]any); isList {
			types = list
		}
		matched := false
		for _, name := range types {
			matched = matched || schemaTypeMatches(name.(string), value)
		}
		if !matched {
			return fmt.Errorf("%s: type %v does not match %T", location, expected, value)
		}
	}
	if expected, ok := schema["const"]; ok && !reflect.DeepEqual(expected, value) {
		return fmt.Errorf("%s: %v is not const %v", location, value, expected)
	}
	if values, ok := schema["enum"].([]any); ok {
		found := false
		for _, candidate := range values {
			found = found || reflect.DeepEqual(candidate, value)
		}
		if !found {
			return fmt.Errorf("%s: %v is not in enum", location, value)
		}
	}
	if negated, ok := schema["not"].(map[string]any); ok && validateSchemaDocument(schemas, negated, value, location) == nil {
		return fmt.Errorf("%s: value matches a forbidden schema", location)
	}
	switch typed := value.(type) {
	case map[string]any:
		properties, _ := schema["properties"].(map[string]any)
		for _, name := range schemaStrings(schema["required"]) {
			if _, exists := typed[name]; !exists {
				return fmt.Errorf("%s: missing required property %q", location, name)
			}
		}
		names := make([]string, 0, len(typed))
		for name := range typed {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			property, declared := properties[name].(map[string]any)
			if !declared {
				if closed, ok := schema["additionalProperties"].(bool); ok && !closed {
					return fmt.Errorf("%s: undeclared property %q", location, name)
				}
				continue
			}
			if err := validateSchemaDocument(schemas, property, typed[name], location+"."+name); err != nil {
				return err
			}
		}
	case []any:
		if minimum, ok := schema["minItems"].(float64); ok && float64(len(typed)) < minimum {
			return fmt.Errorf("%s: %d items below minimum", location, len(typed))
		}
		if maximum, ok := schema["maxItems"].(float64); ok && float64(len(typed)) > maximum {
			return fmt.Errorf("%s: %d items above maximum", location, len(typed))
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for index, item := range typed {
				if err := validateSchemaDocument(schemas, items, item, fmt.Sprintf("%s[%d]", location, index)); err != nil {
					return err
				}
			}
		}
	case string:
		length := float64(utf8.RuneCountInString(typed))
		if minimum, ok := schema["minLength"].(float64); ok && length < minimum {
			return fmt.Errorf("%s: string shorter than %v", location, minimum)
		}
		if maximum, ok := schema["maxLength"].(float64); ok && length > maximum {
			return fmt.Errorf("%s: string longer than %v", location, maximum)
		}
		if pattern, ok := schema["pattern"].(string); ok && !regexp.MustCompile(pattern).MatchString(typed) {
			return fmt.Errorf("%s: %q does not match %s", location, typed, pattern)
		}
	case float64:
		if minimum, ok := schema["minimum"].(float64); ok && typed < minimum {
			return fmt.Errorf("%s: %v below minimum %v", location, typed, minimum)
		}
		if maximum, ok := schema["maximum"].(float64); ok && typed > maximum {
			return fmt.Errorf("%s: %v above maximum %v", location, typed, maximum)
		}
	}
	return nil
}

func schemaTypeMatches(name string, value any) bool {
	switch name {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	case "integer":
		number, ok := value.(float64)
		return ok && number == math.Trunc(number)
	case "number":
		_, ok := value.(float64)
		return ok
	}
	return false
}

func schemaStrings(value any) []string {
	list, _ := value.([]any)
	result := make([]string, 0, len(list))
	for _, item := range list {
		result = append(result, item.(string))
	}
	return result
}

func decodeSchemaDocument(t *testing.T, encoded []byte) any {
	t.Helper()
	var document any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(&document); err != nil {
		t.Fatal(err)
	}
	return document
}

// schemaWithout removes the fields that legitimately differ between two
// consecutive versions so the remainder can be compared exactly.
func schemaWithout(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	encoded, _ := json.Marshal(schema)
	var copied map[string]any
	if err := json.Unmarshal(encoded, &copied); err != nil {
		t.Fatal(err)
	}
	delete(copied, "$id")
	delete(copied, "title")
	properties := copied["properties"].(map[string]any)
	delete(properties, "schema_version")
	delete(properties["gaps"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any), "reason")
	return copied
}

func gapReasons(schema map[string]any) []string {
	gaps := schema["properties"].(map[string]any)["gaps"].(map[string]any)
	reason := gaps["items"].(map[string]any)["properties"].(map[string]any)["reason"].(map[string]any)
	return schemaStrings(reason["enum"])
}

func TestDeterministicEvidenceV5AndV6SchemasDescribeDeletionResults(t *testing.T) {
	schemas := publishedArtifactSchemas(t)
	v4, v5, v6 := deterministicEvidenceSchema(t, schemas, 4), deterministicEvidenceSchema(t, schemas, 5), deterministicEvidenceSchema(t, schemas, 6)
	for version, schema := range map[int]map[string]any{5: v5, 6: v6} {
		if schema["title"] != fmt.Sprintf("Open Trestle deterministic evidence result v%d", version) || !reflect.DeepEqual(schema["properties"].(map[string]any)["schema_version"], map[string]any{"const": float64(version)}) {
			t.Fatalf("v%d identity or version", version)
		}
		if !reflect.DeepEqual(schemaWithout(t, schema), schemaWithout(t, v4)) {
			t.Fatalf("v%d changes more than the version and gap reasons of v4", version)
		}
	}
	base := gapReasons(v4)
	if want := append(append([]string(nil), base...), "no_changed_head_lines"); !reflect.DeepEqual(gapReasons(v5), want) {
		t.Fatalf("v5 gap reasons=%v want %v", gapReasons(v5), want)
	}
	if want := append(append([]string(nil), base...), "no_changed_head_lines", "deleted_lines"); !reflect.DeepEqual(gapReasons(v6), want) {
		t.Fatalf("v6 gap reasons=%v want %v", gapReasons(v6), want)
	}

	for _, after := range []string{"keep\n", ""} {
		output, _, _, _, _, _ := deletionAnalysis(t, after)
		document := decodeSchemaDocument(t, output.Payload())
		if err := validateSchemaDocument(schemas, v5, document, "v5"); err != nil {
			t.Fatalf("encoded v5 result (head %q) does not match its schema: %v", after, err)
		}
		if err := validateSchemaDocument(schemas, v6, document, "v6"); err == nil || !strings.Contains(err.Error(), "const") {
			t.Fatalf("v5 result accepted by the v6 schema: %v", err)
		}
	}
	output, _, _, _, _, _ := deletionContextAnalysis(t)
	document := decodeSchemaDocument(t, output.Payload())
	if err := validateSchemaDocument(schemas, v6, document, "v6"); err != nil {
		t.Fatalf("encoded v6 result does not match its schema: %v", err)
	}
	relabeled := document.(map[string]any)
	relabeled["schema_version"] = float64(5)
	if err := validateSchemaDocument(schemas, v5, relabeled, "v5"); err == nil || !strings.Contains(err.Error(), "enum") {
		t.Fatalf("deleted_lines gap accepted by the v5 schema: %v", err)
	}
}

func TestDeterministicEvidenceV7SchemaDescribesRemovedLines(t *testing.T) {
	schemas := publishedArtifactSchemas(t)
	v6, v7 := deterministicEvidenceSchema(t, schemas, 6), deterministicEvidenceSchema(t, schemas, 7)
	properties := v7["properties"].(map[string]any)
	removed := properties["removed_lines"].(map[string]any)
	// A removed-lines record is an item record plus an optional head_line.
	encodedRemoved, _ := json.Marshal(schemaWithoutDescription(removed))
	var shared map[string]any
	if err := json.Unmarshal(encodedRemoved, &shared); err != nil {
		t.Fatal(err)
	}
	record := shared["items"].(map[string]any)["properties"].(map[string]any)
	headLine, ok := record["head_line"].(map[string]any)
	if !ok || headLine["minimum"] != float64(1) || containsSchemaName(schemaStrings(shared["items"].(map[string]any)["required"]), "head_line") {
		t.Fatal("v7 removed_lines records do not declare an optional head_line")
	}
	delete(record, "head_line")
	if removed["description"] == nil || !reflect.DeepEqual(shared, properties["items"]) {
		t.Fatal("v7 removed_lines records do not share the item record shape")
	}
	required := schemaStrings(v7["required"])
	wantRequired := []string{}
	for _, name := range schemaStrings(v6["required"]) {
		wantRequired = append(wantRequired, name)
		if name == "items" {
			wantRequired = append(wantRequired, "removed_lines")
		}
	}
	if !reflect.DeepEqual(required, wantRequired) {
		t.Fatalf("v7 required=%v want %v", required, wantRequired)
	}
	trimmed := schemaWithout(t, v7)
	delete(trimmed["properties"].(map[string]any), "removed_lines")
	trimmed["required"] = v6["required"]
	if !reflect.DeepEqual(trimmed, schemaWithout(t, v6)) {
		t.Fatal("v7 changes more than the version, removed_lines and the gap reasons of v6")
	}
	if want := append(gapReasons(v6), "removed_lines_limit"); !reflect.DeepEqual(gapReasons(v7), want) {
		t.Fatalf("v7 gap reasons=%v want %v", gapReasons(v7), want)
	}
	for _, limit := range []bool{false, true} {
		output, _, _, _, _, _ := removedLinesAnalysis(t, limit)
		document := decodeSchemaDocument(t, output.Payload())
		if err := validateSchemaDocument(schemas, v7, document, "v7"); err != nil {
			t.Fatalf("encoded v7 result (limit=%v) does not match its schema: %v", limit, err)
		}
		if err := validateSchemaDocument(schemas, v6, document, "v6"); err == nil {
			t.Fatalf("v7 result (limit=%v) accepted by the v6 schema", limit)
		}
	}
	v6Output, _, _, _, _, _ := deletionContextAnalysis(t)
	relabeled := decodeSchemaDocument(t, v6Output.Payload()).(map[string]any)
	relabeled["schema_version"] = float64(7)
	if err := validateSchemaDocument(schemas, v7, relabeled, "v7"); err == nil || !strings.Contains(err.Error(), "removed_lines") {
		t.Fatalf("v6 bytes without removed_lines accepted by the v7 schema: %v", err)
	}
}

func schemaWithoutDescription(schema map[string]any) map[string]any {
	copied := make(map[string]any, len(schema))
	for key, value := range schema {
		if key != "description" {
			copied[key] = value
		}
	}
	return copied
}

func containsSchemaName(values []string, name string) bool {
	for _, value := range values {
		if value == name {
			return true
		}
	}
	return false
}
