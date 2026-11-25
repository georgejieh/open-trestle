package buildinfo

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDevelopmentBuildIsUnbound(t *testing.T) {
	var output bytes.Buffer
	if err := Write(&output, "trestle"); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["source_bound"] != false || document["source_revision"] != "" || document["source_tree"] != "" {
		t.Fatalf("development build claimed provenance: %s", output.Bytes())
	}
}

func TestBoundBuildReportsExactSource(t *testing.T) {
	oldRevision, oldTree := sourceRevision, sourceTree
	t.Cleanup(func() { sourceRevision, sourceTree = oldRevision, oldTree })
	sourceRevision, sourceTree = strings.Repeat("a", 40), strings.Repeat("b", 40)
	var output bytes.Buffer
	if err := Write(&output, "trestled"); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["source_bound"] != true || document["source_revision"] != sourceRevision || document["source_tree"] != sourceTree || document["program"] != "trestled" {
		t.Fatalf("wrong provenance: %s", output.Bytes())
	}
}

func TestPartialOrInvalidSourceIsRefused(t *testing.T) {
	oldRevision, oldTree := sourceRevision, sourceTree
	t.Cleanup(func() { sourceRevision, sourceTree = oldRevision, oldTree })
	for _, pair := range [][2]string{{strings.Repeat("a", 40), ""}, {"bad", strings.Repeat("b", 40)}, {strings.Repeat("0", 40), strings.Repeat("b", 40)}, {strings.Repeat("a", 40), strings.Repeat("b", 64)}} {
		sourceRevision, sourceTree = pair[0], pair[1]
		var output bytes.Buffer
		if err := Write(&output, "trestle"); err == nil || output.Len() != 0 {
			t.Fatalf("invalid metadata accepted: %v", pair)
		}
	}
}

type failedWriter struct{}

func (failedWriter) Write([]byte) (int, error) { return 0, errors.New("write failed") }
func TestWriteFailureIsReturned(t *testing.T) {
	if err := Write(failedWriter{}, "trestle"); err == nil {
		t.Fatal("write failure lost")
	}
}

func TestReleaseBuildReportsVersion(t *testing.T) {
	oldRevision, oldTree, oldVersion := sourceRevision, sourceTree, version
	t.Cleanup(func() { sourceRevision, sourceTree, version = oldRevision, oldTree, oldVersion })
	sourceRevision, sourceTree, version = strings.Repeat("a", 40), strings.Repeat("b", 40), "0.1.0-alpha.1"
	var output bytes.Buffer
	if err := Write(&output, "trestle"); err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(output.Bytes(), &document); err != nil {
		t.Fatal(err)
	}
	if document["version"] != "0.1.0-alpha.1" || Version() != "0.1.0-alpha.1" {
		t.Fatalf("wrong version: %s", output.Bytes())
	}
}

func TestInvalidOrUnboundVersionIsRefused(t *testing.T) {
	oldRevision, oldTree, oldVersion := sourceRevision, sourceTree, version
	t.Cleanup(func() { sourceRevision, sourceTree, version = oldRevision, oldTree, oldVersion })
	for _, test := range []struct{ revision, tree, version string }{
		{"", "", "0.1.0"},
		{strings.Repeat("a", 40), strings.Repeat("b", 40), "v0.1.0"},
		{strings.Repeat("a", 40), strings.Repeat("b", 40), "0.1"},
	} {
		sourceRevision, sourceTree, version = test.revision, test.tree, test.version
		var output bytes.Buffer
		if err := Write(&output, "trestle"); err == nil || output.Len() != 0 {
			t.Fatalf("invalid version accepted: %v", test)
		}
		if test.version != "0.1.0" && Version() != "" {
			t.Fatalf("invalid version reported: %v", test)
		}
	}
}
