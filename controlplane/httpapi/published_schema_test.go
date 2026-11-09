package httpapi

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// publishedSchemas loads every published schema by its $id.
func publishedSchemas(t *testing.T) map[string]map[string]any {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "..", "schemas", "*", "*.schema.json"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("published schemas: %v", err)
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
		id, _ := schema["$id"].(string)
		schemas[id] = schema
	}
	return schemas
}

// validatePublished checks an encoded document against the published schema
// with the given $id.
func validatePublished(t *testing.T, schemas map[string]map[string]any, id string, encoded []byte) error {
	t.Helper()
	schema, ok := schemas[id]
	if !ok {
		t.Fatalf("schema %s is not published", id)
	}
	var value any
	if err := json.Unmarshal(encoded, &value); err != nil {
		t.Fatal(err)
	}
	return schemaValidator{schemas: schemas}.validate(schema, schema, value, "$")
}

// schemaValidator checks the subset of JSON Schema 2020-12 the published
// control-plane schemas use. It fails on any other keyword, so a schema
// cannot silently rely on a rule this check does not enforce.
type schemaValidator struct{ schemas map[string]map[string]any }

func (v schemaValidator) validate(root, schema map[string]any, value any, at string) error {
	for key := range schema {
		switch key {
		case "$schema", "$id", "$defs", "title", "description", "contentEncoding", "type", "const", "enum", "required", "properties", "additionalProperties", "items", "minItems", "maxItems", "uniqueItems", "contains", "minimum", "maximum", "minLength", "maxLength", "pattern", "not", "oneOf", "anyOf", "allOf", "if", "then", "else", "$ref":
		default:
			return fmt.Errorf("%s: unsupported schema keyword %q", at, key)
		}
	}
	if ref, ok := schema["$ref"].(string); ok {
		target, targetRoot, err := v.resolve(root, ref)
		if err != nil {
			return fmt.Errorf("%s: %w", at, err)
		}
		if err := v.validate(targetRoot, target, value, at); err != nil {
			return err
		}
	}
	if kind, ok := schema["type"].(string); ok && !schemaType(kind, value) {
		return fmt.Errorf("%s: want %s", at, kind)
	}
	if expected, ok := schema["const"]; ok && !reflect.DeepEqual(expected, value) {
		return fmt.Errorf("%s: want const %v, got %v", at, expected, value)
	}
	if values, ok := schema["enum"].([]any); ok {
		found := false
		for _, candidate := range values {
			found = found || reflect.DeepEqual(candidate, value)
		}
		if !found {
			return fmt.Errorf("%s: %v is not in the enum", at, value)
		}
	}
	if err := v.validateObject(root, schema, value, at); err != nil {
		return err
	}
	if err := v.validateArray(root, schema, value, at); err != nil {
		return err
	}
	if err := validateScalar(schema, value, at); err != nil {
		return err
	}
	return v.validateCombinators(root, schema, value, at)
}

func (v schemaValidator) resolve(root map[string]any, ref string) (map[string]any, map[string]any, error) {
	if name, local := strings.CutPrefix(ref, "#/$defs/"); local {
		definitions, _ := root["$defs"].(map[string]any)
		target, ok := definitions[name].(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("unresolved reference %s", ref)
		}
		return target, root, nil
	}
	target, ok := v.schemas[ref]
	if !ok {
		return nil, nil, fmt.Errorf("unresolved reference %s", ref)
	}
	return target, target, nil
}

func (v schemaValidator) validateObject(root, schema map[string]any, value any, at string) error {
	object, isObject := value.(map[string]any)
	if !isObject {
		return nil
	}
	if required, ok := schema["required"].([]any); ok {
		for _, name := range required {
			if _, present := object[name.(string)]; !present {
				return fmt.Errorf("%s: missing %s", at, name)
			}
		}
	}
	properties, _ := schema["properties"].(map[string]any)
	for name, member := range object {
		if property, declared := properties[name].(map[string]any); declared {
			if err := v.validate(root, property, member, at+"."+name); err != nil {
				return err
			}
			continue
		}
		switch additional := schema["additionalProperties"].(type) {
		case bool:
			if !additional {
				return fmt.Errorf("%s: unexpected member %s", at, name)
			}
		case map[string]any:
			if err := v.validate(root, additional, member, at+"."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (v schemaValidator) validateArray(root, schema map[string]any, value any, at string) error {
	array, isArray := value.([]any)
	if !isArray {
		return nil
	}
	if minimum, ok := schema["minItems"].(float64); ok && float64(len(array)) < minimum {
		return fmt.Errorf("%s: fewer than %v items", at, minimum)
	}
	if maximum, ok := schema["maxItems"].(float64); ok && float64(len(array)) > maximum {
		return fmt.Errorf("%s: more than %v items", at, maximum)
	}
	if unique, _ := schema["uniqueItems"].(bool); unique {
		for i := range array {
			for j := i + 1; j < len(array); j++ {
				if reflect.DeepEqual(array[i], array[j]) {
					return fmt.Errorf("%s: duplicate items", at)
				}
			}
		}
	}
	if items, ok := schema["items"].(map[string]any); ok {
		for index, item := range array {
			if err := v.validate(root, items, item, fmt.Sprintf("%s[%d]", at, index)); err != nil {
				return err
			}
		}
	}
	if contains, ok := schema["contains"].(map[string]any); ok {
		found := false
		for _, item := range array {
			found = found || v.validate(root, contains, item, at) == nil
		}
		if !found {
			return fmt.Errorf("%s: no item matches contains", at)
		}
	}
	return nil
}

func validateScalar(schema map[string]any, value any, at string) error {
	if number, isNumber := value.(float64); isNumber {
		if minimum, ok := schema["minimum"].(float64); ok && number < minimum {
			return fmt.Errorf("%s: %v below %v", at, number, minimum)
		}
		if maximum, ok := schema["maximum"].(float64); ok && number > maximum {
			return fmt.Errorf("%s: %v above %v", at, number, maximum)
		}
	}
	if text, isText := value.(string); isText {
		length := float64(utf8.RuneCountInString(text))
		if minimum, ok := schema["minLength"].(float64); ok && length < minimum {
			return fmt.Errorf("%s: shorter than %v", at, minimum)
		}
		if maximum, ok := schema["maxLength"].(float64); ok && length > maximum {
			return fmt.Errorf("%s: longer than %v", at, maximum)
		}
		if pattern, ok := schema["pattern"].(string); ok && !regexp.MustCompile(pattern).MatchString(text) {
			return fmt.Errorf("%s: %q does not match %s", at, text, pattern)
		}
	}
	return nil
}

func (v schemaValidator) validateCombinators(root, schema map[string]any, value any, at string) error {
	if not, ok := schema["not"].(map[string]any); ok && v.validate(root, not, value, at) == nil {
		return fmt.Errorf("%s: matches a forbidden schema", at)
	}
	if all, ok := schema["allOf"].([]any); ok {
		for _, branch := range all {
			if err := v.validate(root, branch.(map[string]any), value, at); err != nil {
				return err
			}
		}
	}
	if any_, ok := schema["anyOf"].([]any); ok {
		matched := false
		for _, branch := range any_ {
			matched = matched || v.validate(root, branch.(map[string]any), value, at) == nil
		}
		if !matched {
			return fmt.Errorf("%s: matches no anyOf branch", at)
		}
	}
	if one, ok := schema["oneOf"].([]any); ok {
		matches, last := 0, error(nil)
		for _, branch := range one {
			if err := v.validate(root, branch.(map[string]any), value, at); err == nil {
				matches++
			} else {
				last = err
			}
		}
		if matches != 1 {
			return fmt.Errorf("%s: matches %d oneOf branches (last mismatch: %v)", at, matches, last)
		}
	}
	if condition, ok := schema["if"].(map[string]any); ok {
		branch := "else"
		if v.validate(root, condition, value, at) == nil {
			branch = "then"
		}
		if next, ok := schema[branch].(map[string]any); ok {
			if err := v.validate(root, next, value, at); err != nil {
				return err
			}
		}
	}
	return nil
}

func schemaType(kind string, value any) bool {
	switch kind {
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
	case "integer":
		number, ok := value.(float64)
		return ok && number == math.Trunc(number)
	case "number":
		_, ok := value.(float64)
		return ok
	case "null":
		return value == nil
	}
	return false
}
