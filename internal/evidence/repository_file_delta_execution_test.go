package evidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"testing"
)

func TestExecuteRepositoryFileDeltaAccountsForEveryKind(t *testing.T) {
	baseContents := map[string][]byte{"removed": []byte("removed\n"), "modified": []byte("old\n")}
	headContents := map[string][]byte{"added": []byte("added\n"), "modified": []byte("new\n")}
	base := mustManifestFromContents(t, baseContents)
	head := mustManifestFromContents(t, headContents)
	delta, err := NewRepositoryManifestDelta(base, head)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path   string
		base   RepositoryFileDeltaContent
		head   RepositoryFileDeltaContent
		status RepositoryFileDeltaExecutionStatus
		reason RepositoryFileDeltaUnsupportedReason
	}{
		{path: "added", head: RepositoryFileDeltaContent{Present: true, Content: headContents["added"]}, status: RepositoryFileDeltaExecutionStatusSupported, reason: RepositoryFileDeltaUnsupportedReasonNone},
		{path: "modified", base: RepositoryFileDeltaContent{Present: true, Content: baseContents["modified"]}, head: RepositoryFileDeltaContent{Present: true, Content: headContents["modified"]}, status: RepositoryFileDeltaExecutionStatusSupported, reason: RepositoryFileDeltaUnsupportedReasonNone},
		{path: "removed", base: RepositoryFileDeltaContent{Present: true, Content: baseContents["removed"]}, status: RepositoryFileDeltaExecutionStatusUnsupported, reason: RepositoryFileDeltaUnsupportedReasonRemovedFile},
	} {
		t.Run(test.path, func(t *testing.T) {
			entry, _ := delta.Entry(test.path)
			execution, err := ExecuteRepositoryFileDelta(entry, test.base, test.head)
			if err != nil || execution.Identity() == "" || execution.Path() != test.path || execution.RepositoryFileDeltaIdentity() != entry.Identity() || execution.Status() != test.status || execution.Reason() != test.reason || execution.Identity() != expectedRepositoryFileDeltaExecutionIdentity(execution) {
				t.Fatalf("execution = (%#v, %v)", execution, err)
			}
			if test.status == RepositoryFileDeltaExecutionStatusSupported {
				patch, _ := GenerateUnifiedFileDiff(test.path, test.base.Content, test.head.Content)
				fileChange, lineMap, _ := ParseUnifiedFileDiff(test.path, test.base.Content, test.head.Content, patch)
				if execution.FileChange().Identity() != fileChange.Identity() || execution.LineMap().Identity() != lineMap.Identity() {
					t.Fatalf("supported evidence = %#v %#v", execution.FileChange(), execution.LineMap())
				}
			} else if execution.FileChange().Identity() != "" || execution.LineMap().Identity() != "" {
				t.Fatal("unsupported execution includes change evidence")
			}
		})
	}
}

func TestExecuteRepositoryFileDeltaRecordsAddedRefusals(t *testing.T) {
	for _, test := range []struct {
		name    string
		content []byte
		want    RepositoryFileDeltaUnsupportedReason
	}{
		{name: "empty", content: []byte{}, want: RepositoryFileDeltaUnsupportedReasonAddedFile},
		{name: "NUL", content: []byte{'a', 0}, want: RepositoryFileDeltaUnsupportedReasonContent},
		{name: "invalid UTF-8", content: []byte{0xff}, want: RepositoryFileDeltaUnsupportedReasonContent},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := mustManifestFromContents(t, map[string][]byte{})
			head := mustManifestFromContents(t, map[string][]byte{"file": test.content})
			delta, _ := NewRepositoryManifestDelta(base, head)
			entry, _ := delta.Entry("file")
			execution, err := ExecuteRepositoryFileDelta(entry, RepositoryFileDeltaContent{}, RepositoryFileDeltaContent{Present: true, Content: test.content})
			if err != nil || execution.Status() != RepositoryFileDeltaExecutionStatusUnsupported || execution.Reason() != test.want || execution.FileChange().Identity() != "" || execution.LineMap().Identity() != "" {
				t.Fatalf("execution = (%#v, %v)", execution, err)
			}
		})
	}
}

func TestExecuteRepositoryFileDeltaRecordsModifiedRefusals(t *testing.T) {
	for _, test := range []struct {
		name string
		base []byte
		head []byte
		want RepositoryFileDeltaUnsupportedReason
	}{
		{name: "NUL", base: []byte{'a', 0}, head: []byte{'b', 0}, want: RepositoryFileDeltaUnsupportedReasonContent},
		{name: "invalid UTF-8", base: []byte("a"), head: []byte{0xff}, want: RepositoryFileDeltaUnsupportedReasonContent},
		{name: "resource", base: bytes.Repeat([]byte("base\n"), 513), head: bytes.Repeat([]byte("head\n"), 513), want: RepositoryFileDeltaUnsupportedReasonResourceLimit},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := mustManifestFromContents(t, map[string][]byte{"file": test.base})
			head := mustManifestFromContents(t, map[string][]byte{"file": test.head})
			delta, _ := NewRepositoryManifestDelta(base, head)
			entry, _ := delta.Entry("file")
			execution, err := ExecuteRepositoryFileDelta(entry, RepositoryFileDeltaContent{Present: true, Content: test.base}, RepositoryFileDeltaContent{Present: true, Content: test.head})
			if err != nil || execution.Status() != RepositoryFileDeltaExecutionStatusUnsupported || execution.Reason() != test.want || execution.FileChange().Identity() != "" || execution.LineMap().Identity() != "" {
				t.Fatalf("execution = (%#v, %v)", execution, err)
			}
		})
	}
}

func TestExecuteRepositoryFileDeltaBoundsContentBeforeDigestValidation(t *testing.T) {
	oversized := make([]byte, maxUnifiedDiffContentBytes+1)
	empty := mustManifestFromContents(t, map[string][]byte{})
	addedManifest := mustManifestFromContents(t, map[string][]byte{"file": oversized})
	addedDelta, _ := NewRepositoryManifestDelta(empty, addedManifest)
	addedEntry, _ := addedDelta.Entry("file")
	added, err := ExecuteRepositoryFileDelta(addedEntry, RepositoryFileDeltaContent{}, RepositoryFileDeltaContent{Present: true, Content: oversized})
	if err != nil || added.Status() != RepositoryFileDeltaExecutionStatusUnsupported || added.Reason() != RepositoryFileDeltaUnsupportedReasonResourceLimit {
		t.Fatalf("oversized added = (%#v, %v)", added, err)
	}
	wrongSameSize := append([]byte(nil), oversized...)
	wrongSameSize[0] = 1
	forged, err := ExecuteRepositoryFileDelta(addedEntry, RepositoryFileDeltaContent{}, RepositoryFileDeltaContent{Present: true, Content: wrongSameSize})
	if err == nil || forged.Identity() != "" {
		t.Fatalf("wrong same-size added content = (%#v, %v)", forged, err)
	}
	removedDelta, _ := NewRepositoryManifestDelta(addedManifest, empty)
	removedEntry, _ := removedDelta.Entry("file")
	removed, err := ExecuteRepositoryFileDelta(removedEntry, RepositoryFileDeltaContent{Present: true, Content: oversized}, RepositoryFileDeltaContent{})
	if err != nil || removed.Status() != RepositoryFileDeltaExecutionStatusUnsupported || removed.Reason() != RepositoryFileDeltaUnsupportedReasonResourceLimit {
		t.Fatalf("oversized removed = (%#v, %v)", removed, err)
	}
	tiny := mustManifestFromContents(t, map[string][]byte{"file": []byte("tiny")})
	modifiedDelta, _ := NewRepositoryManifestDelta(tiny, mustManifestFromContents(t, map[string][]byte{"file": []byte("other")}))
	modifiedEntry, _ := modifiedDelta.Entry("file")
	wrongSized, err := ExecuteRepositoryFileDelta(modifiedEntry, RepositoryFileDeltaContent{Present: true, Content: oversized}, RepositoryFileDeltaContent{Present: true, Content: []byte("other")})
	if err == nil || wrongSized.Identity() != "" {
		t.Fatalf("wrong-sized content = (%#v, %v)", wrongSized, err)
	}
}

func TestExecuteRepositoryFileDeltaRejectsShapeAndContentMismatch(t *testing.T) {
	baseContent, headContent := []byte("old\n"), []byte("new\n")
	base := mustManifestFromContents(t, map[string][]byte{"file": baseContent})
	head := mustManifestFromContents(t, map[string][]byte{"file": headContent})
	delta, _ := NewRepositoryManifestDelta(base, head)
	entry, _ := delta.Entry("file")
	for _, test := range []struct {
		name string
		base RepositoryFileDeltaContent
		head RepositoryFileDeltaContent
	}{
		{name: "base absent", head: RepositoryFileDeltaContent{Present: true, Content: headContent}},
		{name: "head absent", base: RepositoryFileDeltaContent{Present: true, Content: baseContent}},
		{name: "absent bytes", base: RepositoryFileDeltaContent{Content: []byte("hidden")}, head: RepositoryFileDeltaContent{Present: true, Content: headContent}},
		{name: "base mismatch", base: RepositoryFileDeltaContent{Present: true, Content: []byte("wrong")}, head: RepositoryFileDeltaContent{Present: true, Content: headContent}},
		{name: "head mismatch", base: RepositoryFileDeltaContent{Present: true, Content: baseContent}, head: RepositoryFileDeltaContent{Present: true, Content: []byte("wrong")}},
	} {
		t.Run(test.name, func(t *testing.T) {
			execution, err := ExecuteRepositoryFileDelta(entry, test.base, test.head)
			if err == nil || execution.Identity() != "" {
				t.Fatalf("execution = (%#v, %v)", execution, err)
			}
		})
	}
	var zero RepositoryFileDelta
	if execution, err := ExecuteRepositoryFileDelta(zero, RepositoryFileDeltaContent{}, RepositoryFileDeltaContent{}); err == nil || execution.Identity() != "" {
		t.Fatalf("zero entry execution = (%#v, %v)", execution, err)
	}
}

func TestRepositoryFileDeltaExecutionDoesNotRetainContent(t *testing.T) {
	baseBytes, headBytes := []byte("old\n"), []byte("new\n")
	base := mustManifestFromContents(t, map[string][]byte{"file": baseBytes})
	head := mustManifestFromContents(t, map[string][]byte{"file": headBytes})
	delta, _ := NewRepositoryManifestDelta(base, head)
	entry, _ := delta.Entry("file")
	execution, err := ExecuteRepositoryFileDelta(entry, RepositoryFileDeltaContent{Present: true, Content: baseBytes}, RepositoryFileDeltaContent{Present: true, Content: headBytes})
	if err != nil {
		t.Fatal(err)
	}
	identity := execution.Identity()
	baseBytes[0], headBytes[0] = 'X', 'Y'
	if execution.Identity() != identity {
		t.Fatal("input mutation changed execution")
	}
	assertRepositoryFileDeltaExecutionCompact(t, reflect.TypeOf(RepositoryFileDeltaExecution{}), "RepositoryFileDeltaExecution", map[reflect.Type]bool{})
	var zero RepositoryFileDeltaExecution
	if zero.Identity() != "" || zero.Path() != "" || zero.RepositoryFileDeltaIdentity() != "" || zero.Status() != "" || zero.Reason() != "" || zero.FileChange().Identity() != "" || zero.LineMap().Identity() != "" {
		t.Fatalf("zero execution = %#v", zero)
	}
}

func expectedRepositoryFileDeltaExecutionIdentity(execution RepositoryFileDeltaExecution) string {
	preimage := struct {
		Contract                    string                               `json:"contract"`
		SchemaVersion               int                                  `json:"schema_version"`
		Path                        string                               `json:"path"`
		RepositoryFileDeltaIdentity string                               `json:"repository_file_delta_identity"`
		Status                      RepositoryFileDeltaExecutionStatus   `json:"status"`
		Reason                      RepositoryFileDeltaUnsupportedReason `json:"reason"`
		FileChangeIdentity          string                               `json:"file_change_identity"`
		LineMapIdentity             string                               `json:"line_map_identity"`
	}{"open-trestle/repository-file-delta-execution", 1, execution.Path(), execution.RepositoryFileDeltaIdentity(), execution.Status(), execution.Reason(), execution.FileChange().Identity(), execution.LineMap().Identity()}
	encoded, _ := json.Marshal(preimage)
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func assertRepositoryFileDeltaExecutionCompact(t *testing.T, value reflect.Type, path string, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[value] {
		return
	}
	seen[value] = true
	switch value.Kind() {
	case reflect.Map, reflect.Pointer, reflect.Interface:
		t.Fatalf("%s retains %s", path, value)
	case reflect.Slice, reflect.Array:
		if value.Elem().Kind() == reflect.Uint8 {
			t.Fatalf("%s retains bytes", path)
		}
		assertRepositoryFileDeltaExecutionCompact(t, value.Elem(), path+"[]", seen)
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			field := value.Field(i)
			assertRepositoryFileDeltaExecutionCompact(t, field.Type, path+"."+field.Name, seen)
		}
	}
}
