package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPublishedProtocolSchemaReferencesResolveOffline(t *testing.T) {
	documents := map[string]any{}
	root := filepath.Join("..", "..", "schemas")
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			return nil
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var document any
		if err := json.Unmarshal(encoded, &document); err != nil {
			return err
		}
		identity, ok := document.(map[string]any)["$id"].(string)
		if !ok || identity == "" {
			t.Fatalf("schema %s has no identity", path)
		}
		documents[identity] = document
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateSchemaReferences(documents); err != nil {
		t.Fatal(err)
	}
}

func TestSchemaReferenceValidationCoversPointersAndClosedTargets(t *testing.T) {
	firstID := "urn:open-trestle:schema:test:first:v1"
	secondID := "urn:open-trestle:schema:test:second:v1"
	valid := map[string]any{
		firstID: map[string]any{
			"$id": firstID,
			"$defs": map[string]any{
				"value":  map[string]any{"type": "string"},
				"a/b":    map[string]any{"type": "number"},
				"til~de": map[string]any{"type": "boolean"},
				"list":   []any{"zero", "one"},
			},
			"allOf": []any{
				map[string]any{"$ref": "#"},
				map[string]any{"$ref": "#/$defs/value"},
				map[string]any{"$ref": "#/%24defs/value"},
				map[string]any{"$ref": "#/$defs/a~1b"},
				map[string]any{"$ref": "#/$defs/til~0de"},
				map[string]any{"$ref": "#/$defs/list/1"},
				map[string]any{"$ref": secondID},
				map[string]any{"$ref": secondID + "#/$defs/value"},
			},
		},
		secondID: map[string]any{
			"$id":   secondID,
			"$defs": map[string]any{"value": map[string]any{"type": "integer"}},
		},
	}
	if err := validateSchemaReferences(valid); err != nil {
		t.Fatalf("valid references: %v", err)
	}
	nestedIdentity := map[string]any{
		firstID: map[string]any{"$id": firstID, "allOf": []any{map[string]any{"$id": secondID}}},
	}
	if err := validateSchemaReferences(nestedIdentity); err == nil {
		t.Fatal("nested schema identity accepted")
	}
	invalid := []struct {
		name string
		ref  any
	}{
		{"unknown target", "urn:open-trestle:schema:test:missing:v1"},
		{"external target", "https://example.invalid/schema"},
		{"missing fragment", "#/$defs/missing"},
		{"malformed pointer", "#$defs/value"},
		{"invalid escape", "#/$defs/a~2b"},
		{"invalid percent escape", "#/%ZZ"},
		{"empty reference", ""},
		{"noncanonical index", "#/$defs/list/01"},
		{"signed index", "#/$defs/list/+1"},
		{"out of range index", "#/$defs/list/2"},
		{"scalar traversal", "#/$defs/list/0/value"},
		{"non string", float64(1)},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			documents := map[string]any{
				firstID: map[string]any{"$id": firstID, "$defs": valid[firstID].(map[string]any)["$defs"], "$ref": test.ref},
			}
			if err := validateSchemaReferences(documents); err == nil {
				t.Fatal("invalid reference accepted")
			}
		})
	}
}

func validateSchemaReferences(documents map[string]any) error {
	for identity, document := range documents {
		object, ok := document.(map[string]any)
		declared, declaredOK := object["$id"].(string)
		if !ok || !declaredOK || declared != identity || !strings.HasPrefix(identity, "urn:open-trestle:schema:") || strings.Contains(identity, "#") {
			return fmt.Errorf("invalid schema identity %q", identity)
		}
		if err := validateSchemaIdentityScope(document, true); err != nil {
			return fmt.Errorf("schema %q: %w", identity, err)
		}
		if err := walkSchemaReferences(document, func(reference any) error {
			value, ok := reference.(string)
			if !ok || value == "" || strings.Count(value, "#") > 1 {
				return fmt.Errorf("invalid schema reference")
			}
			targetIdentity, fragment, hasFragment := strings.Cut(value, "#")
			if targetIdentity == "" {
				targetIdentity = identity
			} else if !strings.HasPrefix(targetIdentity, "urn:open-trestle:schema:") {
				return fmt.Errorf("external schema reference %q", value)
			}
			target, exists := documents[targetIdentity]
			if !exists {
				return fmt.Errorf("unknown schema reference %q", value)
			}
			if !hasFragment || fragment == "" {
				return nil
			}
			decoded, err := url.PathUnescape(fragment)
			if err != nil || !strings.HasPrefix(decoded, "/") {
				return fmt.Errorf("invalid schema fragment %q", value)
			}
			if _, err := resolveSchemaJSONPointer(target, decoded); err != nil {
				return fmt.Errorf("resolve schema reference %q: %w", value, err)
			}
			return nil
		}); err != nil {
			return fmt.Errorf("schema %q: %w", identity, err)
		}
	}
	return nil
}

func validateSchemaIdentityScope(value any, root bool) error {
	switch current := value.(type) {
	case map[string]any:
		if !root {
			if _, exists := current["$id"]; exists {
				return fmt.Errorf("nested schema identity is not supported")
			}
		}
		for _, child := range current {
			if err := validateSchemaIdentityScope(child, false); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range current {
			if err := validateSchemaIdentityScope(child, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func walkSchemaReferences(value any, visit func(any) error) error {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			if key == "$ref" {
				if err := visit(child); err != nil {
					return err
				}
				continue
			}
			if err := walkSchemaReferences(child, visit); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range current {
			if err := walkSchemaReferences(child, visit); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveSchemaJSONPointer(document any, pointer string) (any, error) {
	current := document
	for _, encoded := range strings.Split(strings.TrimPrefix(pointer, "/"), "/") {
		token, err := decodeSchemaJSONPointerToken(encoded)
		if err != nil {
			return nil, err
		}
		switch container := current.(type) {
		case map[string]any:
			child, exists := container[token]
			if !exists {
				return nil, fmt.Errorf("object key %q not found", token)
			}
			current = child
		case []any:
			if !canonicalSchemaArrayIndex(token) {
				return nil, fmt.Errorf("invalid array index %q", token)
			}
			index, err := strconv.Atoi(token)
			if err != nil || index < 0 || index >= len(container) {
				return nil, fmt.Errorf("array index %q out of range", token)
			}
			current = container[index]
		default:
			return nil, fmt.Errorf("cannot traverse scalar")
		}
	}
	return current, nil
}

func canonicalSchemaArrayIndex(value string) bool {
	if value == "" || len(value) > 1 && value[0] == '0' {
		return false
	}
	for _, digit := range []byte(value) {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	return true
}

func decodeSchemaJSONPointerToken(value string) (string, error) {
	var decoded strings.Builder
	for index := 0; index < len(value); index++ {
		if value[index] != '~' {
			decoded.WriteByte(value[index])
			continue
		}
		if index+1 >= len(value) || value[index+1] != '0' && value[index+1] != '1' {
			return "", fmt.Errorf("invalid JSON Pointer escape")
		}
		index++
		if value[index] == '0' {
			decoded.WriteByte('~')
		} else {
			decoded.WriteByte('/')
		}
	}
	return decoded.String(), nil
}
