package secretscan

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestBetterleaksRuleIDsV1MatchPinnedDefaultConfig(t *testing.T) {
	ids := BetterleaksRuleIDsV1()
	if len(ids) != RulesetRuleCount {
		t.Fatalf("got %d rule IDs, want %d", len(ids), RulesetRuleCount)
	}
	if !sort.StringsAreSorted(ids) {
		t.Fatal("rule IDs are not sorted")
	}
	for index := 1; index < len(ids); index++ {
		if ids[index-1] == ids[index] {
			t.Fatalf("duplicate rule ID %q", ids[index])
		}
	}
	digest := sha256.Sum256([]byte(strings.Join(ids, "\n") + "\n"))
	if got := hex.EncodeToString(digest[:]); got != "de5e47aa6bcf8e4379d5ecd85d460aea0d6baf50bdfe6877fbd80052ae237f45" {
		t.Fatalf("unexpected rule ID inventory digest: %s", got)
	}
	ids[0] = "mutated"
	if BetterleaksRuleIDsV1()[0] != "1password-secret-key" {
		t.Fatal("rule ID inventory is mutable through its public accessor")
	}
}

func TestSecretScannerSchemasPinBetterleaksAndDecodedUTF8(t *testing.T) {
	request := readSchema(t, "secret-scan-request-v1.schema.json")
	if !strings.Contains(schemaDescription(t, request), "valid UTF-8") {
		t.Fatal("request schema does not require valid UTF-8 decoded sources")
	}
	requestProperties := schemaProperties(t, request)
	sources := requestProperties["sources"].(map[string]any)
	items := sources["items"].(map[string]any)
	if items["$ref"] != "#/$defs/source" {
		t.Fatal("request sources schema reference changed")
	}
	defs := request["$defs"].(map[string]any)
	source := defs["source"].(map[string]any)
	content := schemaProperties(t, source)["content_base64"].(map[string]any)
	if !strings.Contains(content["description"].(string), "valid UTF-8") {
		t.Fatal("content_base64 description does not require valid UTF-8 decoded bytes")
	}

	response := readSchema(t, "secret-scan-response-v1.schema.json")
	if !strings.Contains(schemaDescription(t, response), "Betterleaks v1.8.1") {
		t.Fatal("response schema does not describe the pinned scanner")
	}
	responseProperties := schemaProperties(t, response)
	want := map[string]string{
		"scanner":          ScannerName,
		"scanner_version":  ScannerVersion,
		"scanner_commit":   ScannerCommit,
		"ruleset_identity": RulesetIdentity,
	}
	for name, value := range want {
		property := responseProperties[name].(map[string]any)
		if property["const"] != value {
			t.Fatalf("response schema %s const = %v, want %q", name, property["const"], value)
		}
		if strings.TrimSpace(property["description"].(string)) == "" {
			t.Fatalf("response schema %s has no description", name)
		}
	}
	buildProfile := responseProperties["build_profile"].(map[string]any)
	if _, pinned := buildProfile["const"]; pinned || !reflect.DeepEqual(buildProfile["enum"], []any{BuildProfile, go12610BuildProfile}) {
		t.Fatalf("response schema build_profile = %v, want exactly the current and recorded go1.26.10 profiles", buildProfile)
	}
	if strings.TrimSpace(buildProfile["description"].(string)) == "" {
		t.Fatal("response schema build_profile has no description")
	}
}

func TestSecretScannerFilesExcludeRetiredIdentity(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	paths := []string{
		"internal/secretscan",
		"schemas/secret-scanner",
		"workers/secret-scanner",
		"docs",
		"THIRD_PARTY_LICENSES/secret-scanner",
		"NOTICE",
	}
	forbidden := []string{
		"ti" + "tus",
		"v1." + "2.10",
		"f2c9e1f5c090c27f43bd" + "eb7b49546b59c86aa508",
		"pure_go_" + "linux_amd64_v1",
	}
	for _, relative := range paths {
		path := filepath.Join(repositoryRoot, relative)
		info, err := os.Stat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() {
			assertFileExcludesRetiredIdentity(t, path, forbidden)
			continue
		}
		err = filepath.WalkDir(path, func(candidate string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			assertFileExcludesRetiredIdentity(t, candidate, forbidden)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func readSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "secret-scanner", name))
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatal(err)
	}
	return schema
}

func schemaDescription(t *testing.T, schema map[string]any) string {
	t.Helper()
	description, ok := schema["description"].(string)
	if !ok {
		t.Fatal("schema has no description")
	}
	return description
}

func schemaProperties(t *testing.T, schema map[string]any) map[string]any {
	t.Helper()
	properties, ok := schema["properties"].(map[string]any)
	if !ok {
		t.Fatal("schema has no properties")
	}
	return properties
}

func assertFileExcludesRetiredIdentity(t *testing.T, path string, forbidden []string) {
	t.Helper()
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(encoded))
	for _, value := range forbidden {
		if strings.Contains(lower, value) {
			t.Errorf("%s contains retired scanner identity %q", path, value)
		}
	}
}
