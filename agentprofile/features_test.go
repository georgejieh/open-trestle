package agentprofile

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/semanticimpact"
)

func TestProfilePathClassification(t *testing.T) {
	for _, test := range []struct {
		path     string
		language Language
		class    FileClass
		signals  []Signal
	}{
		{"internal/gateway/route.go", LanguageGo, FileClassSource, nil},
		{"internal/gateway/route_test.go", LanguageGo, FileClassTest, nil},
		{"web/src/App.tsx", LanguageTypeScript, FileClassSource, nil},
		{"web/src/App.test.tsx", LanguageTypeScript, FileClassTest, nil},
		{"web/styles/site.scss", LanguageCSS, FileClassSource, nil},
		{"docs/agent-profiles.md", LanguageMarkdown, FileClassDocs, nil},
		{"vendor/github.com/x/y.go", LanguageGo, FileClassVendor, nil},
		{"web/node_modules/react/index.js", LanguageJavaScript, FileClassVendor, nil},
		{"api/v1/service.pb.go", LanguageGo, FileClassGenerated, []Signal{SignalHTTP}},
		{"go.mod", "", FileClassDependencyManifest, []Signal{SignalDependencyManifest}},
		{"web/package.json", LanguageJSON, FileClassDependencyManifest, []Signal{SignalDependencyManifest}},
		{".github/workflows/ci.yml", LanguageYAML, FileClassCIBuild, []Signal{SignalCIConfig}},
		{"Dockerfile", "", FileClassCIBuild, []Signal{SignalCIConfig}},
		{"config/app.yaml", LanguageYAML, FileClassConfig, nil},
		{".editorconfig", "", FileClassConfig, nil},
		{"internal/auth/session_store.go", LanguageGo, FileClassSource, []Signal{SignalAuth}},
		{"adapters/storage/postgres/migrations/001.sql", LanguageSQL, FileClassSource, []Signal{SignalSQL}},
		{"webhook/server.go", LanguageGo, FileClassSource, []Signal{SignalHTTP, SignalWebhook}},
		{"internal/crypto/kms.go", LanguageGo, FileClassSource, []Signal{SignalCrypto}},
		{"tools/exec_runner.py", LanguagePython, FileClassSource, []Signal{SignalExec}},
		{"tests/test_parser.py", LanguagePython, FileClassTest, nil},
		{"assets/logo.png", "", FileClassOther, nil},
		{"internal/review/process.go", LanguageGo, FileClassSource, nil},
	} {
		t.Run(test.path, func(t *testing.T) {
			language, hasLanguage := languageForPath(test.path)
			if language != test.language || hasLanguage != (test.language != "") {
				t.Fatalf("language = %q,%t want %q", language, hasLanguage, test.language)
			}
			class := classifyPath(test.path, language, hasLanguage)
			if class != test.class {
				t.Fatalf("class = %q want %q", class, test.class)
			}
			if got := pathSignals(test.path, class); !reflect.DeepEqual(got, test.signals) {
				t.Fatalf("signals = %v want %v", got, test.signals)
			}
		})
	}
}

func TestProfileGlobMatching(t *testing.T) {
	for _, test := range []struct {
		pattern, path string
		want          bool
	}{
		{"**/.env", ".env", true},
		{"**/.env", "deploy/prod/.env", true},
		{"**/.env.*", "deploy/.env.local", true},
		{"**/*.pem", "certs/server.pem", true},
		{"web/**", "web/src/app.ts", true},
		{"web/**", "website/x", false},
		{"src/*.go", "src/a/b.go", false},
		{"src/**/b.go", "src/b.go", true},
	} {
		if err := validateGlob(test.pattern); err != nil {
			t.Fatalf("validateGlob(%q) = %v", test.pattern, err)
		}
		if got := matchGlob(test.pattern, test.path); got != test.want {
			t.Fatalf("matchGlob(%q, %q) = %t", test.pattern, test.path, got)
		}
	}
}

func TestProfileGlobValidationBoundsRecursiveSegments(t *testing.T) {
	for _, pattern := range []string{
		"**/**/secret",
		"src/**/**",
		"**/src/**/secret",
	} {
		if !errors.Is(validateGlob(pattern), ErrInvalidGlob) {
			t.Errorf("validateGlob(%q) accepted multiple recursive segments", pattern)
		}
	}
}

func TestProfileStyleIntentDetection(t *testing.T) {
	for _, test := range []struct {
		name  string
		files []ConfigFile
		want  []StyleIntent
	}{
		{"none", nil, nil},
		{"go module", []ConfigFile{{Path: "go.mod"}}, []StyleIntent{StyleGofmt}},
		{"editorconfig and prettier", []ConfigFile{{Path: ".editorconfig"}, {Path: "web/.prettierrc.json"}}, []StyleIntent{StyleEditorConfig, StylePrettier}},
		{"package.json prettier key", []ConfigFile{{Path: "package.json", Content: `{"prettier":{}}`}}, []StyleIntent{StylePrettier}},
		{"package.json without prettier", []ConfigFile{{Path: "package.json", Content: `{"name":"x"}`}}, nil},
		{"pyproject ruff and black", []ConfigFile{{Path: "pyproject.toml", Content: "[tool.ruff]\n[tool.black]\n"}}, []StyleIntent{StyleBlack, StylePEP8}},
		{"pyproject without tools", []ConfigFile{{Path: "pyproject.toml", Content: "[project]\n"}}, nil},
		{"yapf google", []ConfigFile{{Path: ".style.yapf", Content: "[style]\nbased_on_style = google\n"}}, []StyleIntent{StyleGooglePython}},
		{"clang google", []ConfigFile{{Path: ".clang-format", Content: "BasedOnStyle: Google\n"}}, []StyleIntent{StyleClangFormat, StyleGoogleCPP}},
		{"setup.cfg flake8", []ConfigFile{{Path: "setup.cfg", Content: "[flake8]\nmax-line-length = 100\n"}}, []StyleIntent{StylePEP8}},
		{"eslint flat config", []ConfigFile{{Path: "eslint.config.mjs"}}, []StyleIntent{StyleESLint}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := detectStyleIntents(test.files); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("detectStyleIntents() = %v want %v", got, test.want)
			}
		})
	}
}

const validFeaturesJSON = `{"schema":"open-trestle/agent-profile-change-features","version":1,` +
	`"files":[{"path":"web/src/App.tsx","added_lines":40,"deleted_lines":3},{"path":"internal/auth/session.go","added_lines":12,"deleted_lines":0,"signals":["concurrency"]}],` +
	`"public_api_changes":1,"reference_fan_out":9,"coverage":{"uncovered_changed_lines":30},` +
	`"intent":{"description_present":true,"linked_doc_paths":["docs/auth.md"]},` +
	`"config_files":[{"path":"go.mod"},{"path":".editorconfig","content":"root = true\n"}]}`

func TestProfileParseChangeFeaturesCanonicalRoundTrip(t *testing.T) {
	features, err := ParseChangeFeatures([]byte(validFeaturesJSON))
	if err != nil {
		t.Fatalf("ParseChangeFeatures() error = %v", err)
	}
	if !reflect.DeepEqual(features.StyleIntents(), []StyleIntent{StyleEditorConfig, StyleGofmt}) {
		t.Fatalf("style intents = %v", features.StyleIntents())
	}
	encoded, err := json.Marshal(features)
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := ParseChangeFeatures(encoded)
	if err != nil {
		t.Fatalf("reparse canonical form: %v", err)
	}
	if reparsed.Identity() != features.Identity() {
		t.Fatalf("canonical round trip changed identity: %s vs %s", reparsed.Identity(), features.Identity())
	}
	reordered := strings.Replace(validFeaturesJSON,
		`{"path":"web/src/App.tsx","added_lines":40,"deleted_lines":3},{"path":"internal/auth/session.go","added_lines":12,"deleted_lines":0,"signals":["concurrency"]}`,
		`{"path":"internal/auth/session.go","added_lines":12,"deleted_lines":0,"signals":["concurrency"]},{"path":"web/src/App.tsx","added_lines":40,"deleted_lines":3}`, 1)
	other, err := ParseChangeFeatures([]byte(reordered))
	if err != nil || other.Identity() != features.Identity() {
		t.Fatalf("file order changed identity: %v", err)
	}
	if !strings.Contains(string(encoded), `"signals":["auth","concurrency"]`) {
		t.Fatalf("canonical form lacks merged path signals: %s", encoded)
	}
}

func TestProfileParseChangeFeaturesRejectsInvalidDocuments(t *testing.T) {
	replace := func(old, new string) string {
		if !strings.Contains(validFeaturesJSON, old) {
			t.Fatalf("fixture does not contain %q", old)
		}
		return strings.Replace(validFeaturesJSON, old, new, 1)
	}
	for _, test := range []struct {
		name     string
		document string
		want     error
	}{
		{"empty", ``, ErrInvalidChangeFeatures},
		{"oversize", `{"schema":"` + strings.Repeat("a", MaxChangeFeaturesBytes) + `"}`, ErrChangeFeaturesTooLarge},
		{"unknown field", replace(`"version":1,`, `"version":1,"diff":"x",`), ErrInvalidChangeFeatures},
		{"unknown file field", replace(`"added_lines":40,`, `"added_lines":40,"content":"x",`), ErrInvalidChangeFeatures},
		{"duplicate key", replace(`"version":1,`, `"version":1,"version":1,`), ErrInvalidChangeFeatures},
		{"wrong schema", replace(`change-features`, `change-feature`), ErrInvalidChangeFeatures},
		{"wrong version", replace(`"version":1`, `"version":0`), ErrInvalidChangeFeatures},
		{"no files", replace(`"files":[{"path":"web/src/App.tsx","added_lines":40,"deleted_lines":3},{"path":"internal/auth/session.go","added_lines":12,"deleted_lines":0,"signals":["concurrency"]}]`, `"files":[]`), ErrInvalidChangeFeatures},
		{"duplicate path", replace(`"path":"internal/auth/session.go"`, `"path":"web/src/App.tsx"`), ErrInvalidChangeFeatures},
		{"absolute path", replace(`"path":"web/src/App.tsx"`, `"path":"/etc/passwd"`), ErrInvalidChangeFeatures},
		{"parent path", replace(`"path":"web/src/App.tsx"`, `"path":"../App.tsx"`), ErrInvalidChangeFeatures},
		{"unclean path", replace(`"path":"web/src/App.tsx"`, `"path":"web//src/App.tsx"`), ErrInvalidChangeFeatures},
		{"backslash path", replace(`"path":"web/src/App.tsx"`, `"path":"web\\src\\App.tsx"`), ErrInvalidChangeFeatures},
		{"unknown signal", replace(`["concurrency"]`, `["spooky"]`), ErrInvalidChangeFeatures},
		{"duplicate signal", replace(`["concurrency"]`, `["concurrency","concurrency"]`), ErrInvalidChangeFeatures},
		{"line count too large", replace(`"added_lines":40`, `"added_lines":16777217`), ErrInvalidChangeFeatures},
		{"negative lines", replace(`"added_lines":40`, `"added_lines":-1`), ErrInvalidChangeFeatures},
		{"gap path not changed", replace(`"public_api_changes":1,`, `"semantic_gap_paths":["other.py"],"public_api_changes":1,`), ErrInvalidChangeFeatures},
		{"bad provenance digest", replace(`"public_api_changes":1,`, `"change_identity":"ABC","public_api_changes":1,`), ErrInvalidChangeFeatures},
		{"config too large", replace(`"content":"root = true\n"`, `"content":"`+strings.Repeat("a", maxConfigContentBytes+1)+`"`), ErrInvalidChangeFeatures},
		{"duplicate config", replace(`{"path":"go.mod"}`, `{"path":".editorconfig"}`), ErrInvalidChangeFeatures},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseChangeFeatures([]byte(test.document)); !errors.Is(err, test.want) {
				t.Fatalf("ParseChangeFeatures() error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestProfileChangeFeaturesFromSemanticImpact(t *testing.T) {
	baseAPI := "package lib\nfunc Exported(v int) int { return v }\nfunc removed() {}\n"
	headAPI := "package lib\ntype Public struct{ Value int }\nfunc Exported(v int) int { return v + 1 }\n"
	base := []semanticimpact.File{mustSemanticFile(t, "lib/api.go", baseAPI), mustSemanticFile(t, "lib/api_test.go", "package lib\nfunc TestExported(){ _ = Exported(1) }\n")}
	head := []semanticimpact.File{mustSemanticFile(t, "lib/api.go", headAPI), mustSemanticFile(t, "lib/api_test.go", "package lib\nfunc TestExported(){ _ = Exported(1); _ = Public{} }\n")}
	changedPath, err := semanticimpact.NewChangedPath("lib/api.go")
	if err != nil {
		t.Fatal(err)
	}
	input, err := semanticimpact.NewInput(strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64), []semanticimpact.ChangedPath{changedPath}, base, head)
	if err != nil {
		t.Fatal(err)
	}
	impact, err := semanticimpact.AnalyzeGo(input)
	if err != nil {
		t.Fatal(err)
	}
	fileChange, err := evidence.NewFileChange("lib/api.go", strings.Repeat("1", 64), strings.Repeat("2", 64), []evidence.SourceRange{mustSourceRange(t, "lib/api.go", 2, 3)})
	if err != nil {
		t.Fatal(err)
	}
	hunk, err := evidence.NewHunk(fileChange, 2, 2, 2, 2)
	if err != nil {
		t.Fatal(err)
	}
	lineMap, err := evidence.NewLineMap(fileChange, 3, 3, []evidence.Hunk{hunk})
	if err != nil {
		t.Fatal(err)
	}
	change, err := evidence.NewChange([]evidence.FileChange{fileChange}, []evidence.LineMap{lineMap})
	if err != nil {
		t.Fatal(err)
	}
	features, err := ChangeFeaturesFromSemanticImpact(change, impact, AnalysisHints{
		ConfigFiles: []ConfigFile{{Path: "go.mod"}},
		FileSignals: map[string][]Signal{"lib/api.go": {SignalConcurrency}},
	})
	if err != nil {
		t.Fatalf("ChangeFeaturesFromSemanticImpact() error = %v", err)
	}
	wire := features.wire()
	if len(wire.Files) != 1 || wire.Files[0].AddedLines != 2 || wire.Files[0].DeletedLines != 2 {
		t.Fatalf("line counts = %+v", wire.Files)
	}
	if !reflect.DeepEqual(wire.Files[0].Signals, []string{"concurrency", "http", "public_api"}) {
		t.Fatalf("signals = %v", wire.Files[0].Signals)
	}
	if wire.PublicAPIChanges != uint32(len(impact.PublicAPIChanges())) || wire.ReferenceFanOut != uint32(len(impact.References())) || wire.PublicAPIChanges == 0 || wire.ReferenceFanOut == 0 {
		t.Fatalf("semantic counts = %d/%d", wire.PublicAPIChanges, wire.ReferenceFanOut)
	}
	if wire.ChangeIdentity != change.Identity() || wire.SemanticProfileIdentity != impact.Identity() {
		t.Fatal("provenance identities not recorded")
	}
	if _, err := ChangeFeaturesFromSemanticImpact(change, impact, AnalysisHints{FileSignals: map[string][]Signal{"other.go": {SignalExec}}}); !errors.Is(err, ErrInvalidChangeFeatures) {
		t.Fatalf("hint for unchanged path accepted: %v", err)
	}
	if _, err := ChangeFeaturesFromSemanticImpact(evidence.Change{}, impact, AnalysisHints{}); !errors.Is(err, ErrInvalidChangeFeatures) {
		t.Fatalf("zero change accepted: %v", err)
	}
}

func mustSemanticFile(t *testing.T, path, content string) semanticimpact.File {
	t.Helper()
	file, err := semanticimpact.NewFile(path, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	return file
}

func mustSourceRange(t *testing.T, path string, start, end int) evidence.SourceRange {
	t.Helper()
	sourceRange, err := evidence.NewSourceRange(path, start, end)
	if err != nil {
		t.Fatal(err)
	}
	return sourceRange
}
