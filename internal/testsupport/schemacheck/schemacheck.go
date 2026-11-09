// Package schemacheck validates decoded JSON documents against the published
// schemas, for tests that compare an encoder with its contract. It implements
// the subset of JSON Schema 2020-12 that the published schemas use and fails
// on any other keyword, so a schema cannot silently rely on an unchecked rule.
package schemacheck

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
	"unicode/utf8"
)

// Schemas holds published schemas by $id.
type Schemas map[string]map[string]any

// Load reads every *.schema.json file in each directory and indexes it by $id.
func Load(directories ...string) (Schemas, error) {
	schemas := Schemas{}
	for _, directory := range directories {
		paths, err := filepath.Glob(filepath.Join(directory, "*.schema.json"))
		if err != nil {
			return nil, err
		}
		if len(paths) == 0 {
			return nil, fmt.Errorf("no schemas in %s", directory)
		}
		for _, path := range paths {
			encoded, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			var schema map[string]any
			if err := json.Unmarshal(encoded, &schema); err != nil {
				return nil, fmt.Errorf("%s: %w", path, err)
			}
			id, _ := schema["$id"].(string)
			if id == "" {
				return nil, fmt.Errorf("%s: no $id", path)
			}
			if _, exists := schemas[id]; exists {
				return nil, fmt.Errorf("%s: duplicate $id %s", path, id)
			}
			schemas[id] = schema
		}
	}
	return schemas, nil
}

// Decode decodes one JSON document with numbers as float64, as the validator
// expects.
func Decode(encoded []byte) (any, error) {
	var document any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	return document, nil
}

// ValidateID validates a document against the schema with the given $id.
func (s Schemas) ValidateID(id string, document any) error {
	schema, ok := s[id]
	if !ok {
		return fmt.Errorf("schema %s is not published", id)
	}
	return s.Validate(schema, document, "$")
}

// Validate validates a document against one schema or subschema.
func (s Schemas) Validate(schema map[string]any, value any, location string) error {
	for key := range schema {
		switch key {
		case "$schema", "$id", "title", "description", "type", "const", "enum", "required", "properties", "additionalProperties", "items", "minItems", "maxItems", "uniqueItems", "contains", "minimum", "maximum", "minLength", "maxLength", "pattern", "not", "$ref", "allOf", "anyOf", "oneOf", "if", "then", "else", "dependentRequired":
		default:
			return fmt.Errorf("%s: unsupported schema keyword %q", location, key)
		}
	}
	if reference, ok := schema["$ref"].(string); ok {
		target, exists := s[reference]
		if !exists {
			return fmt.Errorf("%s: unresolved reference %q", location, reference)
		}
		if err := s.Validate(target, value, location); err != nil {
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
			matched = matched || typeMatches(name.(string), value)
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
	if negated, ok := schema["not"].(map[string]any); ok && s.Validate(negated, value, location) == nil {
		return fmt.Errorf("%s: value matches a forbidden schema", location)
	}
	for _, subschema := range subschemas(schema["allOf"]) {
		if err := s.Validate(subschema, value, location); err != nil {
			return err
		}
	}
	if options := subschemas(schema["anyOf"]); len(options) > 0 {
		matched := false
		for _, subschema := range options {
			matched = matched || s.Validate(subschema, value, location) == nil
		}
		if !matched {
			return fmt.Errorf("%s: value matches no anyOf schema", location)
		}
	}
	if options := subschemas(schema["oneOf"]); len(options) > 0 {
		var matched int
		var first error
		for _, subschema := range options {
			if err := s.Validate(subschema, value, location); err == nil {
				matched++
			} else if first == nil {
				first = err
			}
		}
		if matched != 1 {
			return fmt.Errorf("%s: value matches %d oneOf schemas (first refusal: %v)", location, matched, first)
		}
	}
	if condition, ok := schema["if"].(map[string]any); ok {
		branch := "else"
		if s.Validate(condition, value, location) == nil {
			branch = "then"
		}
		if subschema, ok := schema[branch].(map[string]any); ok {
			if err := s.Validate(subschema, value, location); err != nil {
				return err
			}
		}
	}
	switch typed := value.(type) {
	case map[string]any:
		properties, _ := schema["properties"].(map[string]any)
		for _, name := range stringsOf(schema["required"]) {
			if _, exists := typed[name]; !exists {
				return fmt.Errorf("%s: missing required property %q", location, name)
			}
		}
		if dependencies, ok := schema["dependentRequired"].(map[string]any); ok {
			for name, required := range dependencies {
				if _, present := typed[name]; !present {
					continue
				}
				for _, dependency := range stringsOf(required) {
					if _, exists := typed[dependency]; !exists {
						return fmt.Errorf("%s: %q requires %q", location, name, dependency)
					}
				}
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
			if err := s.Validate(property, typed[name], location+"."+name); err != nil {
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
		if unique, ok := schema["uniqueItems"].(bool); ok && unique {
			for i := range typed {
				for j := i + 1; j < len(typed); j++ {
					if reflect.DeepEqual(typed[i], typed[j]) {
						return fmt.Errorf("%s: items %d and %d are equal", location, i, j)
					}
				}
			}
		}
		if items, ok := schema["items"].(map[string]any); ok {
			for index, item := range typed {
				if err := s.Validate(items, item, fmt.Sprintf("%s[%d]", location, index)); err != nil {
					return err
				}
			}
		}
		if contains, ok := schema["contains"].(map[string]any); ok {
			found := false
			for _, item := range typed {
				found = found || s.Validate(contains, item, location) == nil
			}
			if !found {
				return fmt.Errorf("%s: no item matches contains", location)
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

func subschemas(value any) []map[string]any {
	list, _ := value.([]any)
	result := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if schema, ok := item.(map[string]any); ok {
			result = append(result, schema)
		}
	}
	return result
}

func typeMatches(name string, value any) bool {
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

func stringsOf(value any) []string {
	list, _ := value.([]any)
	result := make([]string, 0, len(list))
	for _, item := range list {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}
