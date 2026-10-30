package config

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestRuntimePolicyV2NoAuthSchemaFixtures(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "..", "schemas", "runtime", "runtime-policy-v2.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	schema := schemaFixtureObject(t, encoded)
	connections := schemaFixtureMap(t, schemaFixtureMap(t, schema["properties"])["connections"])
	items := schemaFixtureMap(t, connections["items"])
	if items["additionalProperties"] != false {
		t.Fatal("connection schema not closed")
	}
	branches := items["allOf"].([]any)
	branch := schemaFixtureMap(t, branches[0])
	then := schemaFixtureMap(t, branch["then"])
	noEnvironment := schemaFixtureStrings(t, schemaFixtureMap(t, then["not"])["required"])
	if len(noEnvironment) != 1 || noEnvironment[0] != "credential_environment" {
		t.Fatal("none schema permits credential environment presence")
	}
	endpoint := schemaFixtureMap(t, schemaFixtureMap(t, then["properties"])["endpoint"])
	expression := regexp.MustCompile(endpoint["pattern"].(string))
	for _, fixture := range []struct {
		endpoint string
		want     bool
	}{
		{"http://127.0.0.1:11434/v1", true}, {"https://127.2.3.4/v1", true}, {"http://[::1]:1234/v1", true},
		{"https://api.example.test/v1", false}, {"http://localhost:11434/v1", false}, {"http://127.0.0.1.example.test/v1", false}, {"https://192.0.2.1/v1", false},
	} {
		if expression.MatchString(fixture.endpoint) != fixture.want {
			t.Fatalf("none endpoint fixture=%s", fixture.endpoint)
		}
	}
	required := schemaFixtureStrings(t, schemaFixtureMap(t, branch["else"])["required"])
	if len(required) != 1 || required[0] != "credential_environment" {
		t.Fatal("bearer/omitted schema no longer requires environment")
	}

}
