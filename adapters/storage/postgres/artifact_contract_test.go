package postgres

import (
	"regexp"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/artifact"
)

func TestArtifactIndexParsersCoverAllDomainKindsAndOrigins(t *testing.T) {
	for i := 0; i < 256; i++ {
		kind := artifact.Kind(i)
		if kind.String() != "" && parseArtifactKind(kind.String()) != kind {
			t.Errorf("artifact kind parser omits %q", kind.String())
		}
		origin := artifact.Origin(i)
		if origin.String() != "" && parseArtifactOrigin(origin.String()) != origin {
			t.Errorf("artifact origin parser omits %q", origin.String())
		}
	}
	if parseArtifactKind("unknown") != 0 || parseArtifactOrigin("unknown") != 0 {
		t.Fatal("unknown artifact metadata accepted")
	}
}

func TestLatestArtifactConstraintsCoverExactDomainTokens(t *testing.T) {
	latest := map[string]map[string]bool{}
	create := regexp.MustCompile(`(?s)CREATE TABLE open_trestle_artifacts \(.*?;`)
	alter := regexp.MustCompile(`(?s)ALTER TABLE open_trestle_artifacts\s+.*?;`)
	quoted := regexp.MustCompile(`'([^']+)'`)
	for _, name := range orderedMigrations {
		data, err := migrationFiles.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		statements := append(create.FindAllString(string(data), -1), alter.FindAllString(string(data), -1)...)
		for _, statement := range statements {
			for _, column := range []string{"kind", "origin"} {
				pattern := regexp.MustCompile(column + ` IN \(([^)]*)\)`)
				match := pattern.FindStringSubmatch(statement)
				if len(match) == 0 {
					continue
				}
				tokens := map[string]bool{}
				for _, value := range quoted.FindAllStringSubmatch(match[1], -1) {
					tokens[value[1]] = true
				}
				latest[column] = tokens
			}
		}
	}
	expected := map[string]map[string]bool{"kind": {}, "origin": {}}
	for i := 0; i < 256; i++ {
		if value := artifact.Kind(i).String(); value != "" {
			expected["kind"][value] = true
		}
		if value := artifact.Origin(i).String(); value != "" {
			expected["origin"][value] = true
		}
	}
	for column, want := range expected {
		for value := range want {
			if !latest[column][value] {
				t.Errorf("latest SQL %s constraint omits %q", column, value)
			}
		}
		for value := range latest[column] {
			if !want[value] {
				t.Errorf("SQL %s constraint accepts unknown token %q", column, value)
			}
		}
	}
	// The original migration remains an immutable checksum authority.
	original, err := migrationFiles.ReadFile("migrations/0004_artifact_metadata.sql")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(original), "'source_file'") {
		t.Fatal("historical migration rewritten instead of extended")
	}
}
