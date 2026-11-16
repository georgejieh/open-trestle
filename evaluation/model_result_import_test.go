package evaluation

import (
	"errors"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

func TestModelResultCorpusManifestBinding(t *testing.T) {
	corpus, err := loadDeterministicCorpus(deterministicCorpusFiles, corpusRoot)
	if err != nil {
		t.Fatal(err)
	}
	item := corpus.cases[0]
	for _, side := range []string{"base", "head"} {
		content := item.base
		if side == "head" {
			content = item.head
		}
		files := []evidence.RepositoryFile{}
		for path, body := range content {
			file, err := evidence.NewRepositoryFile(path, body)
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, file)
		}
		manifest, err := evidence.NewRepositoryManifest(files)
		if err != nil {
			t.Fatal(err)
		}
		if !modelResultManifestMatches(manifest, item.manifest, side) {
			t.Fatal("exact existing source descriptor refused")
		}
		extra, _ := evidence.NewRepositoryFile("extra.txt", []byte("not in corpus"))
		files = append(files, extra)
		manifest, _ = evidence.NewRepositoryManifest(files)
		if modelResultManifestMatches(manifest, item.manifest, side) {
			t.Fatal("extra source accepted")
		}
		changed := append([]corpusFixtureFile(nil), item.manifest.Files...)
		for i := range changed {
			if changed[i].Side == side {
				changed[i].SHA256 = strings.Repeat("f", 64)
				break
			}
		}
		other := item.manifest
		other.Files = changed
		manifest, _ = evidence.NewRepositoryManifest(files[:len(files)-1])
		if modelResultManifestMatches(manifest, other, side) {
			t.Fatal("changed source digest accepted")
		}
	}
}

func TestModelResultImportRequiresActualSourceExecution(t *testing.T) {
	for _, encoded := range [][]byte{nil, []byte(`{"candidates":[]}`), []byte(`{"diagnostics":{}}`)} {
		if _, err := ImportModelResult(encoded, digestBytes(encoded), "debug_direct_and_multiline", scm.LocalGitChangeExecution{}); !errors.Is(err, ErrInvalidModelResultImport) {
			t.Fatalf("inert source accepted: %v", err)
		}
	}
}
