package localreview

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/georgejieh/open-trestle/agentprofile"
	sourcehandler "github.com/georgejieh/open-trestle/handlers/source"
	"github.com/georgejieh/open-trestle/internal/sourceoutput"
	"github.com/georgejieh/open-trestle/runtimecatalog"
)

// styleFeaturesRun runs the real nine-task review over the fixture change plus
// the given root-level files, then reads its change features. The artifact
// capacity holds every fixture file of both snapshots.
func styleFeaturesRun(t *testing.T, name string, base, head map[string][]byte) (*Session, runtimecatalog.PreparedReviewRun, agentprofile.ChangeFeatures) {
	t.Helper()
	f := newRmModelFixture(t, rmModelFixtureOptions{extraBase: base, extraHead: head})
	options := rmOptions(t, f, rmNewClock())
	options.ArtifactCapacity = 1024
	s := rmSession(t, options)
	p := rmPrepare(t, s, f, "style-"+name)
	result, err := s.Run(context.Background(), p)
	if err != nil || result.wire.RunStatus != "succeeded" {
		t.Fatalf("review run: %v status=%s", err, result.wire.RunStatus)
	}
	features, _, err := s.ChangeFeatures(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	return s, p, features
}

// TestChangeFeaturesSkipConfigFilesBeyondTheDocumentBound requires base style
// configuration that would push the change-features document past 1 MiB to be
// skipped whole and reported as unread, never truncated.
func TestChangeFeaturesSkipConfigFilesBeyondTheDocumentBound(t *testing.T) {
	files := map[string][]byte{}
	for index := 0; index < 18; index++ {
		files[fmt.Sprintf(".prettierrc.%02d", index)] = []byte(strings.Repeat("a", 58<<10))
	}
	f := newRmModelFixture(t, rmModelFixtureOptions{extraBase: files, extraHead: files})
	options := rmOptions(t, f, rmNewClock())
	// About 1 MiB of configuration in each snapshot needs more than the
	// fixture's 5 s when the whole suite runs in parallel.
	options.ArtifactCapacity, options.Timeout = 1024, 30*time.Second
	s := rmSession(t, options)
	p := rmPrepare(t, s, f, "style-document-bound")
	if result, err := s.Run(context.Background(), p); err != nil || result.wire.RunStatus != "succeeded" {
		t.Fatalf("review run: %v", err)
	}
	features, unread, err := s.ChangeFeatures(context.Background(), p)
	if err != nil || !reflect.DeepEqual(unread, []string{".prettierrc.17"}) {
		t.Fatalf("unread=%v err=%v", unread, err)
	}
	encoded, err := features.MarshalJSON()
	var document struct {
		ConfigFiles []agentprofile.ConfigFile `json:"config_files"`
	}
	if err != nil || len(encoded) > agentprofile.MaxChangeFeaturesBytes || json.Unmarshal(encoded, &document) != nil || len(document.ConfigFiles) != 18 {
		t.Fatalf("features document is %d bytes with %d config files: %v", len(encoded), len(document.ConfigFiles), err)
	}
	for _, file := range document.ConfigFiles {
		if file.Path == ".prettierrc.17" || file.Path != "go.mod" && len(file.Content) != 58<<10 {
			t.Fatalf("config file %s was supplied altered or should have been skipped", file.Path)
		}
	}
	if got := features.StyleIntents(); !reflect.DeepEqual(got, []agentprofile.StyleIntent{agentprofile.StyleGofmt, agentprofile.StylePrettier}) {
		t.Fatalf("style intents = %v", got)
	}
}

// TestChangeFeaturesDetectStyleFromTheBaseTree runs over the fixture's
// unchanged go.mod, so every case also detects gofmt_effective_go.
func TestChangeFeaturesDetectStyleFromTheBaseTree(t *testing.T) {
	ruff := []byte("line-length = 100\n")
	for _, test := range []struct {
		name       string
		base, head map[string][]byte
		want       []agentprofile.StyleIntent
		// languages are the changed languages; a changed TOML config is one.
		languages []string
	}{
		{
			name:      "ruff.toml in base",
			base:      map[string][]byte{"ruff.toml": ruff, "tool.py": []byte("x = 1\n")},
			head:      map[string][]byte{"ruff.toml": ruff, "tool.py": []byte("x = 2\n")},
			want:      []agentprofile.StyleIntent{agentprofile.StyleGofmt, agentprofile.StylePEP8},
			languages: []string{"go", "python"},
		},
		{
			name:      "ruff.toml only in head",
			base:      map[string][]byte{"tool.py": []byte("x = 1\n")},
			head:      map[string][]byte{"ruff.toml": ruff, "tool.py": []byte("x = 2\n")},
			want:      []agentprofile.StyleIntent{agentprofile.StyleGofmt},
			languages: []string{"go", "python", "toml"},
		},
		{
			name:      "pyproject.toml differs between base and head",
			base:      map[string][]byte{"pyproject.toml": []byte("[tool.black]\n"), "tool.py": []byte("x = 1\n")},
			head:      map[string][]byte{"pyproject.toml": []byte("[tool.ruff]\n"), "tool.py": []byte("x = 2\n")},
			want:      []agentprofile.StyleIntent{agentprofile.StyleBlack, agentprofile.StyleGofmt},
			languages: []string{"go", "python", "toml"},
		},
		{
			name:      "ruff.toml deleted in head",
			base:      map[string][]byte{"ruff.toml": ruff, "tool.py": []byte("x = 1\n")},
			head:      map[string][]byte{"tool.py": []byte("x = 2\n")},
			want:      []agentprofile.StyleIntent{agentprofile.StyleGofmt, agentprofile.StylePEP8},
			languages: []string{"go", "python", "toml"},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, _, features := styleFeaturesRun(t, strings.ReplaceAll(test.name, " ", "-"), test.base, test.head)
			if got := features.StyleIntents(); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("style intents = %v, want %v", got, test.want)
			}
			if languages := features.Summary().Languages; !reflect.DeepEqual(languages, test.languages) {
				t.Fatalf("changed languages = %v, want %v", languages, test.languages)
			}
		})
	}
}

func TestBaseStyleConfigFilesSkipOverBoundFilesWhole(t *testing.T) {
	// The ruff marker leads the oversized file, so a truncated read would detect it.
	oversized := append([]byte("[tool.ruff]\n"), []byte(strings.Repeat("#\n", agentprofile.MaxConfigFileBytes/2))...)
	files := map[string][]byte{
		"go.mod":         []byte("module example.test/p\n"),
		"pyproject.toml": oversized,
		"setup.cfg":      []byte("[flake8]\n\xff\n"),
	}
	s, p, features := styleFeaturesRun(t, "over-bound", files, files)
	if got := features.StyleIntents(); !reflect.DeepEqual(got, []agentprofile.StyleIntent{agentprofile.StyleGofmt}) {
		t.Fatalf("style intents = %v, want only gofmt_effective_go", got)
	}
	at := s.options.Clock.Now()
	read, unread, err := s.baseStyleConfigFiles(context.Background(), p.Plan().Scope(), rmTaskArtifact(t, s, p, "source-base", at), at)
	if err != nil || !reflect.DeepEqual(unread, []string{"pyproject.toml", "setup.cfg"}) || len(read) != 1 || read[0].Path != "go.mod" || read[0].Content != "module example.test/p\n" {
		t.Fatalf("read=%v unread=%v err=%v", read, unread, err)
	}
}

func TestBaseStyleConfigFilesStopAtTheFileCountBound(t *testing.T) {
	// Without the fixture's go.mod, every candidate is a Prettier file.
	files := map[string][]byte{"go.mod": nil}
	for index := 0; index <= agentprofile.MaxConfigFiles; index++ {
		files[fmt.Sprintf(".prettierrc.%03d", index)] = []byte("{}\n")
	}
	s, p, features := styleFeaturesRun(t, "count-bound", files, files)
	if got := features.StyleIntents(); !reflect.DeepEqual(got, []agentprofile.StyleIntent{agentprofile.StylePrettier}) {
		t.Fatalf("style intents = %v", got)
	}
	at := s.options.Clock.Now()
	read, unread, err := s.baseStyleConfigFiles(context.Background(), p.Plan().Scope(), rmTaskArtifact(t, s, p, "source-base", at), at)
	if err != nil || len(read) != agentprofile.MaxConfigFiles || !reflect.DeepEqual(unread, []string{fmt.Sprintf(".prettierrc.%03d", agentprofile.MaxConfigFiles)}) || read[len(read)-1].Path != fmt.Sprintf(".prettierrc.%03d", agentprofile.MaxConfigFiles-1) {
		t.Fatalf("read=%d unread=%v err=%v", len(read), unread, err)
	}
}

func TestStyleConfigCandidatesAreRootLevelRecognizedNames(t *testing.T) {
	var references []sourcehandler.FileReference
	for _, path := range []string{".editorconfig", ".github/.editorconfig", "README.md", "a.go", "go.mod", "pyproject.toml", "services/api/ruff.toml", "web/package.json"} {
		references = append(references, sourceoutput.NewFileReference(path, strings.Repeat("a", 64), 1, strings.Repeat("b", 64)))
	}
	var got []string
	for _, reference := range styleConfigCandidates(references) {
		got = append(got, reference.Path())
	}
	if want := []string{".editorconfig", "go.mod", "pyproject.toml"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %v, want %v", got, want)
	}
}
