package config

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestProtocolDocumentationListsEveryPublishedSchema(t *testing.T) {
	root := filepath.Join("..", "..")
	var expected []string
	err := filepath.WalkDir(filepath.Join(root, "schemas"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		expected = append(expected, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(expected)
	document, err := os.ReadFile(filepath.Join(root, "docs", "protocol-contracts.md"))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateDocumentedSchemaPaths(string(document), expected); err != nil {
		t.Fatal(err)
	}
}

func TestDocumentedSchemaPathValidationRejectsInventoryDrift(t *testing.T) {
	expected := []string{"schemas/a.schema.json", "schemas/nested/b.schema.json"}
	if err := validateDocumentedSchemaPaths("`schemas/nested/b.schema.json`\n`schemas/a.schema.json`\n", expected); err != nil {
		t.Fatalf("valid inventory: %v", err)
	}
	invalid := []struct {
		name, document, want string
	}{
		{"missing", "`schemas/a.schema.json`", "missing documented schema path"},
		{"extra", "`schemas/a.schema.json` `schemas/nested/b.schema.json` `schemas/c.schema.json`", "stale documented schema path"},
		{"duplicate", "`schemas/a.schema.json` `schemas/a.schema.json` `schemas/nested/b.schema.json`", "duplicate documented schema path"},
		{"traversal", "`schemas/a.schema.json` `schemas/../nested/b.schema.json`", "invalid documented schema path"},
		{"absolute", "`schemas/a.schema.json` `/schemas/nested/b.schema.json`", "invalid documented schema path"},
		{"backslash", "`schemas/a.schema.json` `schemas\\nested\\b.schema.json`", "invalid documented schema path"},
		{"malformed", "`schemas/a.schema.json` `schemas/nested/b.json`", "invalid documented schema path"},
		{"unquoted", "`schemas/a.schema.json` schemas/nested/b.schema.json", "missing documented schema path"},
	}
	for _, test := range invalid {
		t.Run(test.name, func(t *testing.T) {
			if test.name == "backslash" && strings.Count(test.document, `\`) != 2 {
				t.Fatal("backslash fixture does not contain two runtime backslashes")
			}
			if err := validateDocumentedSchemaPaths(test.document, expected); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v want %q", err, test.want)
			}
		})
	}
}

var documentedSchemaPathPattern = regexp.MustCompile(`^schemas/(?:[a-z0-9][a-z0-9._-]*/)*[a-z0-9][a-z0-9._-]*\.schema\.json$`)
var markdownCodeTokenPattern = regexp.MustCompile("`([^`\\r\\n]+)`")

func validateDocumentedSchemaPaths(document string, expected []string) error {
	wanted := make(map[string]struct{}, len(expected))
	for _, path := range expected {
		if !validDocumentedSchemaPath(path) {
			return fmt.Errorf("invalid expected schema path %q", path)
		}
		if _, exists := wanted[path]; exists {
			return fmt.Errorf("duplicate expected schema path %q", path)
		}
		wanted[path] = struct{}{}
	}
	documented := make(map[string]struct{}, len(expected))
	for _, match := range markdownCodeTokenPattern.FindAllStringSubmatch(document, -1) {
		token := match[1]
		if !strings.HasPrefix(token, "schemas/") && !strings.Contains(token, ".schema.json") {
			continue
		}
		if !validDocumentedSchemaPath(token) {
			return fmt.Errorf("invalid documented schema path %q", token)
		}
		if _, exists := documented[token]; exists {
			return fmt.Errorf("duplicate documented schema path %q", token)
		}
		documented[token] = struct{}{}
	}
	for path := range wanted {
		if _, exists := documented[path]; !exists {
			return fmt.Errorf("missing documented schema path %q", path)
		}
	}
	for path := range documented {
		if _, exists := wanted[path]; !exists {
			return fmt.Errorf("stale documented schema path %q", path)
		}
	}
	return nil
}

func validDocumentedSchemaPath(value string) bool {
	return !filepath.IsAbs(value) && !strings.Contains(value, `\`) && filepath.ToSlash(filepath.Clean(value)) == value && documentedSchemaPathPattern.MatchString(value)
}
