package scm

import (
	"reflect"
	"sort"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
)

func newContentMapLocalGitChangeFixture(t *testing.T, baseContents, headContents map[string][]byte) (*LocalGitSourceAdapter, evidence.RepositoryAcquisitionRequest, evidence.RepositoryAcquisitionRequest) {
	t.Helper()
	directory, store := newLocalGitObjectStoreFixture(t)
	baseRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, goImpactTreeContent(t, directory, baseContents))
	headRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, goImpactTreeContent(t, directory, headContents))
	adapter := mustLocalGitSourceAdapter(t, store)
	repository := mustRepositoryIdentity(t)
	return adapter,
		mustLocalGitAdapterRequest(t, adapter, repository, baseRevision, evidence.AcquisitionArtifactManifestAndContent),
		mustLocalGitAdapterRequest(t, adapter, repository, headRevision, evidence.AcquisitionArtifactManifestAndContent)
}

func goImpactTreeContent(t *testing.T, directory string, contents map[string][]byte) []byte {
	t.Helper()
	paths := make([]string, 0, len(contents))
	for path := range contents {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	var tree []byte
	for _, path := range paths {
		blob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", contents[path])
		tree = append(tree, localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte(path), blob)...)
	}
	return tree
}

func newSinglePathNamedLocalGitChangeFixture(t *testing.T, name string, baseContent, headContent []byte) (*LocalGitSourceAdapter, evidence.RepositoryAcquisitionRequest, evidence.RepositoryAcquisitionRequest) {
	t.Helper()
	directory, store := newLocalGitObjectStoreFixture(t)
	baseBlob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", baseContent)
	headBlob := writeLooseObject(t, directory, evidence.RevisionAlgorithmSHA1, "blob", headContent)
	baseRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte(name), baseBlob))
	headRevision := writeLocalRevision(t, directory, evidence.RevisionAlgorithmSHA1, localTreeEntry(t, evidence.RevisionAlgorithmSHA1, evidence.GitTreeModeRegular, []byte(name), headBlob))
	adapter := mustLocalGitSourceAdapter(t, store)
	repository := mustRepositoryIdentity(t)
	return adapter,
		mustLocalGitAdapterRequest(t, adapter, repository, baseRevision, evidence.AcquisitionArtifactManifestAndContent),
		mustLocalGitAdapterRequest(t, adapter, repository, headRevision, evidence.AcquisitionArtifactManifestAndContent)
}

func allZeroBytes(content []byte) bool {
	for _, value := range content {
		if value != 0 {
			return false
		}
	}
	return true
}

func assertGoImpactExecutionHasNoRawBytes(t *testing.T, value reflect.Type, path string, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[value] {
		return
	}
	seen[value] = true
	switch value.Kind() {
	case reflect.Pointer, reflect.Interface:
		t.Fatalf("%s retains %s", path, value)
	case reflect.Map:
		assertGoImpactExecutionHasNoRawBytes(t, value.Key(), path+".key", seen)
		assertGoImpactExecutionHasNoRawBytes(t, value.Elem(), path+".value", seen)
	case reflect.Slice, reflect.Array:
		if value.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("%s retains bytes", path)
		}
		assertGoImpactExecutionHasNoRawBytes(t, value.Elem(), path+"[]", seen)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			assertGoImpactExecutionHasNoRawBytes(t, field.Type, path+"."+field.Name, seen)
		}
	}
}
