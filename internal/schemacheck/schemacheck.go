// Package schemacheck validates JSON documents against the repository's JSON
// Schemas in tests. It implements the draft 2020-12 keywords those schemas use
// ($ref by $id or local pointer, type, const, enum, string, number, object and
// array bounds, and the applicators allOf, anyOf, oneOf, not and if/then/else)
// and refuses any other keyword, so a schema cannot silently stop checking.
package schemacheck

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"
)

// Registry holds every schema under one directory, indexed by its $id.
type Registry struct {
	byID map[string]any
}

// Load reads every *.schema.json file under dir.
func Load(dir string) (*Registry, error) {
	r := &Registry{byID: map[string]any{}}
	err := filepath.WalkDir(dir, func(path string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() || !strings.HasSuffix(path, ".schema.json") {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		schema, err := decode(raw)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		document, ok := schema.(map[string]any)
		id, _ := document["$id"].(string)
		if !ok || id == "" {
			return fmt.Errorf("%s: schema has no $id", path)
		}
		if _, exists := r.byID[id]; exists {
			return fmt.Errorf("%s: duplicate $id %s", path, id)
		}
		r.byID[id] = schema
		return nil
	})
	return r, err
}

// Validate checks one encoded instance against the schema with the given $id.
func (r *Registry) Validate(id string, instance []byte) error {
	root, ok := r.byID[id]
	if !ok {
		return fmt.Errorf("unknown schema %s", id)
	}
	value, err := decode(instance)
	if err != nil {
		return err
	}
	return r.check(root, root, value, "$")
}

func decode(raw []byte) (any, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if decoder.More() {
		return nil, errors.New("trailing data")
	}
	return value, nil
}

var known = map[string]bool{
	"$schema": true, "$id": true, "$defs": true, "$ref": true, "title": true, "description": true,
	"type": true, "const": true, "enum": true, "minLength": true, "maxLength": true, "pattern": true,
	"minimum": true, "maximum": true, "required": true, "properties": true, "additionalProperties": true,
	"dependentRequired": true, "items": true, "minItems": true, "maxItems": true, "uniqueItems": true,
	"contains": true, "allOf": true, "anyOf": true, "oneOf": true, "not": true, "if": true, "then": true, "else": true,
}

func (r *Registry) check(schema, root, value any, at string) error {
	switch s := schema.(type) {
	case bool:
		if !s {
			return fmt.Errorf("%s: false schema", at)
		}
		return nil
	case map[string]any:
		for key := range s {
			if !known[key] {
				return fmt.Errorf("%s: unsupported schema keyword %q", at, key)
			}
		}
		if id, ok := s["$id"].(string); ok && id != "" {
			root = s
		}
		if ref, ok := s["$ref"].(string); ok {
			target, targetRoot, err := r.resolve(ref, root)
			if err != nil {
				return fmt.Errorf("%s: %w", at, err)
			}
			if err := r.check(target, targetRoot, value, at); err != nil {
				return err
			}
		}
		if err := checkType(s, value, at); err != nil {
			return err
		}
		if expected, ok := s["const"]; ok && !equal(expected, value) {
			return fmt.Errorf("%s: value is not the const", at)
		}
		if options, ok := s["enum"].([]any); ok {
			found := false
			for _, option := range options {
				found = found || equal(option, value)
			}
			if !found {
				return fmt.Errorf("%s: value %v not in enum", at, value)
			}
		}
		if err := checkString(s, value, at); err != nil {
			return err
		}
		if err := checkNumber(s, value, at); err != nil {
			return err
		}
		if err := r.checkObject(s, root, value, at); err != nil {
			return err
		}
		if err := r.checkArray(s, root, value, at); err != nil {
			return err
		}
		return r.checkApplicators(s, root, value, at)
	}
	return fmt.Errorf("%s: schema is neither an object nor a boolean", at)
}

func (r *Registry) resolve(ref string, root any) (any, any, error) {
	base, fragment, _ := strings.Cut(ref, "#")
	document := root
	if base != "" {
		found, ok := r.byID[base]
		if !ok {
			return nil, nil, fmt.Errorf("unresolved $ref %s", ref)
		}
		document = found
	}
	target := document
	if fragment != "" {
		for _, token := range strings.Split(strings.TrimPrefix(fragment, "/"), "/") {
			token = strings.ReplaceAll(strings.ReplaceAll(token, "~1", "/"), "~0", "~")
			object, ok := target.(map[string]any)
			if !ok {
				return nil, nil, fmt.Errorf("unresolved $ref %s", ref)
			}
			if target, ok = object[token]; !ok {
				return nil, nil, fmt.Errorf("unresolved $ref %s", ref)
			}
		}
	}
	return target, document, nil
}

func kind(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case json.Number:
		if rat, ok := new(big.Rat).SetString(v.String()); ok && rat.IsInt() {
			return "integer"
		}
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func checkType(s map[string]any, value any, at string) error {
	declared, ok := s["type"]
	if !ok {
		return nil
	}
	var names []any
	switch d := declared.(type) {
	case string:
		names = []any{d}
	case []any:
		names = d
	}
	actual := kind(value)
	for _, name := range names {
		if name == actual || name == "number" && actual == "integer" {
			return nil
		}
	}
	return fmt.Errorf("%s: %s is not of type %v", at, actual, declared)
}

func equal(left, right any) bool {
	if a, ok := left.(json.Number); ok {
		b, ok := right.(json.Number)
		x, okX := new(big.Rat).SetString(a.String())
		y, okY := new(big.Rat).SetString(b.String())
		return ok && okX && okY && x.Cmp(y) == 0
	}
	a, errA := json.Marshal(left)
	b, errB := json.Marshal(right)
	return errA == nil && errB == nil && bytes.Equal(a, b)
}

func bound(s map[string]any, key string) (*big.Rat, bool) {
	number, ok := s[key].(json.Number)
	if !ok {
		return nil, false
	}
	return new(big.Rat).SetString(number.String())
}

func checkString(s map[string]any, value any, at string) error {
	text, ok := value.(string)
	if !ok {
		return nil
	}
	length := big.NewRat(int64(utf8.RuneCountInString(text)), 1)
	if limit, ok := bound(s, "minLength"); ok && length.Cmp(limit) < 0 {
		return fmt.Errorf("%s: string shorter than minLength", at)
	}
	if limit, ok := bound(s, "maxLength"); ok && length.Cmp(limit) > 0 {
		return fmt.Errorf("%s: string longer than maxLength", at)
	}
	if pattern, ok := s["pattern"].(string); ok {
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			return fmt.Errorf("%s: pattern %q: %w", at, pattern, err)
		}
		if !compiled.MatchString(text) {
			return fmt.Errorf("%s: %q does not match %s", at, text, pattern)
		}
	}
	return nil
}

func checkNumber(s map[string]any, value any, at string) error {
	number, ok := value.(json.Number)
	if !ok {
		return nil
	}
	actual, ok := new(big.Rat).SetString(number.String())
	if !ok {
		return fmt.Errorf("%s: invalid number", at)
	}
	if limit, ok := bound(s, "minimum"); ok && actual.Cmp(limit) < 0 {
		return fmt.Errorf("%s: %s below minimum", at, number)
	}
	if limit, ok := bound(s, "maximum"); ok && actual.Cmp(limit) > 0 {
		return fmt.Errorf("%s: %s above maximum", at, number)
	}
	return nil
}

func (r *Registry) checkObject(s map[string]any, root, value any, at string) error {
	object, ok := value.(map[string]any)
	if !ok {
		return nil
	}
	if required, ok := s["required"].([]any); ok {
		for _, name := range required {
			if _, present := object[name.(string)]; !present {
				return fmt.Errorf("%s: required property %v missing", at, name)
			}
		}
	}
	if dependent, ok := s["dependentRequired"].(map[string]any); ok {
		for name, needs := range dependent {
			if _, present := object[name]; !present {
				continue
			}
			for _, need := range needs.([]any) {
				if _, present := object[need.(string)]; !present {
					return fmt.Errorf("%s: %s requires %v", at, name, need)
				}
			}
		}
	}
	properties, _ := s["properties"].(map[string]any)
	for name, member := range object {
		if property, declared := properties[name]; declared {
			if err := r.check(property, root, member, at+"."+name); err != nil {
				return err
			}
			continue
		}
		if additional, ok := s["additionalProperties"]; ok {
			if err := r.check(additional, root, member, at+"."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Registry) checkArray(s map[string]any, root, value any, at string) error {
	items, ok := value.([]any)
	if !ok {
		return nil
	}
	count := big.NewRat(int64(len(items)), 1)
	if limit, ok := bound(s, "minItems"); ok && count.Cmp(limit) < 0 {
		return fmt.Errorf("%s: fewer than minItems", at)
	}
	if limit, ok := bound(s, "maxItems"); ok && count.Cmp(limit) > 0 {
		return fmt.Errorf("%s: more than maxItems", at)
	}
	if unique, _ := s["uniqueItems"].(bool); unique {
		for i := range items {
			for j := i + 1; j < len(items); j++ {
				if equal(items[i], items[j]) {
					return fmt.Errorf("%s: items %d and %d repeat", at, i, j)
				}
			}
		}
	}
	if item, ok := s["items"]; ok {
		for i, element := range items {
			if err := r.check(item, root, element, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	}
	if contains, ok := s["contains"]; ok {
		matched := false
		for _, element := range items {
			matched = matched || r.check(contains, root, element, at) == nil
		}
		if !matched {
			return fmt.Errorf("%s: no item matches contains", at)
		}
	}
	return nil
}

func (r *Registry) checkApplicators(s map[string]any, root, value any, at string) error {
	if all, ok := s["allOf"].([]any); ok {
		for i, sub := range all {
			if err := r.check(sub, root, value, at); err != nil {
				return fmt.Errorf("allOf[%d]: %w", i, err)
			}
		}
	}
	if any_, ok := s["anyOf"].([]any); ok {
		matched := false
		for _, sub := range any_ {
			matched = matched || r.check(sub, root, value, at) == nil
		}
		if !matched {
			return fmt.Errorf("%s: no anyOf branch matches", at)
		}
	}
	if one, ok := s["oneOf"].([]any); ok {
		matches := 0
		for _, sub := range one {
			if r.check(sub, root, value, at) == nil {
				matches++
			}
		}
		if matches != 1 {
			return fmt.Errorf("%s: %d oneOf branches match", at, matches)
		}
	}
	if not, ok := s["not"]; ok && r.check(not, root, value, at) == nil {
		return fmt.Errorf("%s: value matches a not schema", at)
	}
	if condition, ok := s["if"]; ok {
		branch, present := s["else"]
		if r.check(condition, root, value, at) == nil {
			branch, present = s["then"]
		}
		if present {
			if err := r.check(branch, root, value, at); err != nil {
				return err
			}
		}
	}
	return nil
}
