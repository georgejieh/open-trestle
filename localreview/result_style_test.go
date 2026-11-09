package localreview

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/internal/review"
)

const pythonStyleLine = "style: no declared Python style for 1 changed file; consider PEP 8, enforced with Ruff or Black, and commit its configuration\n"

// styleResultRun runs the real nine-task review over the fixture change, whose
// unchanged go.mod declares the Go style, plus the given root-level files.
func styleResultRun(t *testing.T, name string, options rmModelFixtureOptions, specialist review.ContextSpecialist) Result {
	t.Helper()
	f := newRmModelFixture(t, options)
	sessionOptions := rmOptions(t, f, rmNewClock())
	sessionOptions.ArtifactCapacity = 1024
	var s *Session
	var err error
	if specialist.IsZero() {
		s, err = NewSession(sessionOptions)
	} else {
		s, err = NewSpecialistSession(sessionOptions, specialist)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rmClose(t, s) })
	result, err := s.Run(context.Background(), rmPrepare(t, s, f, "style-result-"+name))
	if err != nil || result.wire.RunStatus != "succeeded" {
		t.Fatalf("review run: %v status=%s", err, result.wire.RunStatus)
	}
	return result
}

func styleTrees(base, head map[string][]byte) rmModelFixtureOptions {
	return rmModelFixtureOptions{extraBase: base, extraHead: head}
}

func TestStyleAdviceRecommendsAStandardOnlyForUndeclaredLanguages(t *testing.T) {
	python := func(content string) map[string][]byte { return map[string][]byte{"tool.py": []byte(content)} }
	with := func(tree map[string][]byte, path, content string) map[string][]byte {
		out := map[string][]byte{path: []byte(content)}
		for key, value := range tree {
			out[key] = value
		}
		return out
	}
	ruff := "line-length = 100\n"
	declared := styleResultRun(t, "declared", styleTrees(with(python("x = 1\n"), "ruff.toml", ruff), with(python("x = 2\n"), "ruff.toml", ruff)), review.ContextSpecialist{})
	if declared.wire.Version != guidanceResultVersion || declared.wire.StyleRecommendations != nil || declared.wire.StyleConfigurationUnread != 0 {
		t.Fatalf("declared style produced style advice: version=%d advice=%v", declared.wire.Version, declared.wire.StyleRecommendations)
	}
	for _, test := range []struct {
		name    string
		options rmModelFixtureOptions
		want    []styleRecommendationWire
	}{
		{"python without declared style", styleTrees(python("x = 1\n"), python("x = 2\n")), []styleRecommendationWire{{"python", 1, "PEP 8, enforced with Ruff or Black"}}},
		{"editorconfig alone", styleTrees(with(python("x = 1\n"), ".editorconfig", "root = true\n"), with(python("x = 2\n"), ".editorconfig", "root = true\n")), []styleRecommendationWire{{"python", 1, "PEP 8, enforced with Ruff or Black"}}},
		{"ruff.toml only in head", styleTrees(python("x = 1\n"), with(python("x = 2\n"), "ruff.toml", ruff)), []styleRecommendationWire{{"python", 1, "PEP 8, enforced with Ruff or Black"}}},
		{"go without go.mod", styleTrees(map[string][]byte{"go.mod": nil}, map[string][]byte{"go.mod": nil}), []styleRecommendationWire{{"go", 1, "gofmt and Effective Go"}}},
		{"java change", styleTrees(map[string][]byte{"Main.java": []byte("class Main {}\n")}, map[string][]byte{"Main.java": []byte("final class Main {}\n")}), nil},
		{"removed python file", styleTrees(python("x = 1\n"), nil), nil},
	} {
		t.Run(test.name, func(t *testing.T) {
			result := styleResultRun(t, strings.ReplaceAll(test.name, " ", "-"), test.options, review.ContextSpecialist{})
			if !reflect.DeepEqual(result.wire.StyleRecommendations, test.want) || result.wire.StyleConfigurationUnread != 0 {
				t.Fatalf("style advice = %+v unread=%d, want %+v", result.wire.StyleRecommendations, result.wire.StyleConfigurationUnread, test.want)
			}
			wantVersion := guidanceResultVersion
			if test.want != nil {
				wantVersion = styleResultVersion
			}
			if result.wire.Version != wantVersion || len(result.wire.Guidance) != len(declared.wire.Guidance) {
				t.Fatalf("version=%d guidance=%d, want version %d with guidance kept", result.wire.Version, len(result.wire.Guidance), wantVersion)
			}
			assertStyleAdviceDoesNotBlock(t, result, declared)
		})
	}
}

// assertStyleAdviceDoesNotBlock compares a result with the same review whose
// base declares its style: status, disposition, every exit code, findings and
// coverage are unchanged, and nothing claims clearance.
func assertStyleAdviceDoesNotBlock(t *testing.T, result, declared Result) {
	t.Helper()
	if result.wire.Status != declared.wire.Status || result.wire.CI != declared.wire.CI || result.wire.RunStatus != declared.wire.RunStatus || result.wire.ComprehensiveClearance ||
		result.diagnostics.CandidateCount() != declared.diagnostics.CandidateCount() || result.diagnostics.VerifiedCount() != declared.diagnostics.VerifiedCount() ||
		len(result.diagnostics.Findings()) != len(declared.diagnostics.Findings()) || !reflect.DeepEqual(result.wire.Limitations, declared.wire.Limitations) {
		t.Fatalf("style advice changed the review outcome: %s/%s vs %s/%s", result.wire.Status, result.wire.CI, declared.wire.Status, declared.wire.CI)
	}
	for _, policy := range []ExitPolicy{ExitPolicyDefault, ExitPolicyFindings, ExitPolicyStrict, ExitPolicyAlwaysZero} {
		if result.ExitCodeFor(policy) != declared.ExitCodeFor(policy) {
			t.Fatalf("style advice changed exit policy %v: %d vs %d", policy, result.ExitCodeFor(policy), declared.ExitCodeFor(policy))
		}
	}
}

func TestStyleAdviceJSONAndTextForms(t *testing.T) {
	t.Run("recommendation", func(t *testing.T) {
		result := styleResultRun(t, "forms", styleTrees(map[string][]byte{"tool.py": []byte("x = 1\n")}, map[string][]byte{"tool.py": []byte("x = 2\n")}), review.ContextSpecialist{})
		encoded, err := EncodeResult(result)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{`"schema_version":5,`, `,"finding_guidance":[`, `,"style_recommendations":[{"language":"python","changed_files":1,"recommendation":"PEP 8, enforced with Ruff or Black"}]}` + "\n"} {
			if !bytes.Contains(encoded, []byte(want)) {
				t.Fatalf("JSON result lacks %s:\n%s", want, encoded)
			}
		}
		if bytes.Contains(encoded, []byte("style_configuration_unread")) {
			t.Fatal("JSON result reported unread style configuration")
		}
		var text bytes.Buffer
		if err := RenderResult(&text, result); err != nil {
			t.Fatal(err)
		}
		rendered := text.String()
		if style, limitations := strings.Index(rendered, pythonStyleLine), strings.Index(rendered, "\nlimitations: "); style < 0 || limitations < style || strings.Count(rendered, "style: ") != 1 {
			t.Fatalf("text result lacks one style line before limitations:\n%s", rendered)
		}
	})
	t.Run("plural", func(t *testing.T) {
		files := map[string][]byte{"tool.py": []byte("x = 1\n"), "util.py": []byte("y = 1\n")}
		changed := map[string][]byte{"tool.py": []byte("x = 2\n"), "util.py": []byte("y = 2\n")}
		var text bytes.Buffer
		if err := RenderResult(&text, styleResultRun(t, "plural", styleTrees(files, changed), review.ContextSpecialist{})); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(text.String(), "style: no declared Python style for 2 changed files; consider PEP 8, enforced with Ruff or Black, and commit its configuration\n") {
			t.Fatalf("text result lacks the plural style line:\n%s", text.String())
		}
	})
	t.Run("unread configuration", func(t *testing.T) {
		oversized := map[string][]byte{"pyproject.toml": []byte("[project]\n" + strings.Repeat("#\n", agentprofile.MaxConfigFileBytes/2))}
		base, head := map[string][]byte{"tool.py": []byte("x = 1\n")}, map[string][]byte{"tool.py": []byte("x = 2\n")}
		for path, content := range oversized {
			base[path], head[path] = content, content
		}
		result := styleResultRun(t, "unread", styleTrees(base, head), review.ContextSpecialist{})
		encoded, err := EncodeResult(result)
		if err != nil || result.wire.Version != styleResultVersion || result.wire.StyleRecommendations != nil || !bytes.HasSuffix(encoded, []byte(`,"style_configuration_unread":1}`+"\n")) {
			t.Fatalf("unread configuration JSON: %v\n%s", err, encoded)
		}
		var text bytes.Buffer
		if err := RenderResult(&text, result); err != nil || !strings.Contains(text.String(), "style: no recommendation; 1 base style configuration file was not read (over 64 KiB, not valid UTF-8, or beyond 256 files)\n") || strings.Contains(text.String(), "no declared") {
			t.Fatalf("unread configuration text:\n%s", text.String())
		}
	})
	t.Run("specialist", func(t *testing.T) {
		specialist, err := review.NewContextSpecialist("bug_hunter")
		if err != nil {
			t.Fatal(err)
		}
		result := styleResultRun(t, "specialist", styleTrees(map[string][]byte{"go.mod": nil}, map[string][]byte{"go.mod": nil}), specialist)
		if result.wire.Version != styleResultVersion || result.wire.Specialist == nil || result.wire.Specialist.ProfileID != "bug_hunter" || len(result.wire.StyleRecommendations) != 1 || len(result.wire.Guidance) == 0 {
			t.Fatalf("version 5 dropped the specialist block or guidance: %+v", result.wire)
		}
	})
}

func TestStyleAdviceResultsImportAndOlderVersionsReadBack(t *testing.T) {
	importable := func(t *testing.T, result Result, version int) []byte {
		t.Helper()
		encoded, err := EncodeResult(result)
		if err != nil || result.wire.Version != version {
			t.Fatalf("result version=%d want %d: %v", result.wire.Version, version, err)
		}
		imported, err := ParseCompletedResult(encoded)
		if err != nil {
			t.Fatalf("version %d result does not import: %v", version, err)
		}
		if _, err := imported.CompletedMetadata(); err != nil {
			t.Fatal(err)
		}
		reencoded, err := EncodeResult(imported)
		if err != nil || !bytes.Equal(reencoded, encoded) {
			t.Fatal("imported result does not re-encode to the same bytes")
		}
		return encoded
	}
	ruff := map[string][]byte{"ruff.toml": []byte("line-length = 100\n"), "tool.py": []byte("x = 1\n")}
	ruffHead := map[string][]byte{"ruff.toml": ruff["ruff.toml"], "tool.py": []byte("x = 2\n")}
	t.Run("version 1", func(t *testing.T) {
		options := styleTrees(ruff, ruffHead)
		options.generationMode = "empty"
		importable(t, styleResultRun(t, "v1", options, review.ContextSpecialist{}), 1)
	})
	t.Run("version 4", func(t *testing.T) {
		importable(t, styleResultRun(t, "v4", styleTrees(ruff, ruffHead), review.ContextSpecialist{}), guidanceResultVersion)
	})
	t.Run("version 5 without guidance", func(t *testing.T) {
		options := styleTrees(map[string][]byte{"tool.py": []byte("x = 1\n")}, map[string][]byte{"tool.py": []byte("x = 2\n")})
		options.generationMode = "empty"
		result := styleResultRun(t, "v5-unguided", options, review.ContextSpecialist{})
		if result.wire.Guidance != nil {
			t.Fatal("empty generation produced guidance")
		}
		importable(t, result, styleResultVersion)
	})
	t.Run("version 5", func(t *testing.T) {
		encoded := importable(t, styleResultRun(t, "v5", styleTrees(map[string][]byte{"tool.py": []byte("x = 1\n")}, map[string][]byte{"tool.py": []byte("x = 2\n")}), review.ContextSpecialist{}), styleResultVersion)
		recommendation := `{"language":"python","changed_files":1,"recommendation":"PEP 8, enforced with Ruff or Black"}`
		for name, tampered := range map[string][]byte{
			"version 4 with style advice": bytes.Replace(encoded, []byte(`"schema_version":5`), []byte(`"schema_version":4`), 1),
			"version 1 with style advice": bytes.Replace(encoded, []byte(`"schema_version":5`), []byte(`"schema_version":1`), 1),
			"edited recommendation":       bytes.Replace(encoded, []byte(`"recommendation":"PEP 8, enforced with Ruff or Black"`), []byte(`"recommendation":"PEP 8"`), 1),
			"language without detector":   bytes.Replace(encoded, []byte(`"language":"python"`), []byte(`"language":"java"`), 1),
			"zero changed files":          bytes.Replace(encoded, []byte(`"changed_files":1`), []byte(`"changed_files":0`), 1),
			"duplicate language":          bytes.Replace(encoded, []byte(recommendation), []byte(recommendation+","+recommendation), 1),
			"unread with recommendation":  bytes.Replace(encoded, []byte(recommendation+"]"), []byte(recommendation+`],"style_configuration_unread":1`), 1),
			"negative unread":             bytes.Replace(encoded, []byte(recommendation+"]"), []byte(recommendation+`],"style_configuration_unread":-1`), 1),
		} {
			if bytes.Equal(tampered, encoded) {
				t.Fatalf("%s fixture did not change the result", name)
			}
			if _, err := ParseCompletedResult(tampered); err == nil {
				t.Fatalf("%s imported", name)
			}
		}
		withoutAdvice := bytes.Replace(encoded, []byte(`,"style_recommendations":[`+recommendation+"]"), nil, 1)
		if bytes.Equal(withoutAdvice, encoded) {
			t.Fatal("version 5 without style advice fixture did not change the result")
		}
		if _, err := ParseCompletedResult(withoutAdvice); err == nil {
			t.Fatal("version 5 without style advice imported")
		}
	})
}
