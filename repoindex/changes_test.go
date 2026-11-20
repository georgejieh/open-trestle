package repoindex

import (
	"fmt"
	"strings"
	"testing"
)

func describeChanges(changes []Change, pairs []DiffPair) string {
	SortChanges(changes)
	lines := []string{}
	for _, c := range changes {
		lines = append(lines, fmt.Sprintf("%s<-%s %s", c.Path, c.BasePath, c.Approximation))
	}
	return strings.Join(lines, "\n") + fmt.Sprintf("\npairs %d", len(pairs))
}

func entries(pairs ...string) []FileEntry {
	out := []FileEntry{}
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, FileEntry{Path: pairs[i], Object: pairs[i+1]})
	}
	return out
}

func TestChangedFilesMatchMovesOneToOne(t *testing.T) {
	base := entries("a/api.go", "A", "dup1.go", "D", "dup2.go", "D", "old/name.go", "N", "x/util.go", "U", "gone.go", "G", "z.go", "Z")
	head := entries("a/api.go", "A", "b/api.go", "A", "dup1.go", "D", "new/name.go", "N", "y/util.go", "U2", "fresh.go", "F", "z.go", "Z2")
	changes, pairs := ChangedFiles(base, head)
	want := strings.Join([]string{
		"<-dup2.go unmatched_move",
		"<-gone.go unmatched_move",
		"b/api.go<- ",
		"fresh.go<- ",
		"y/util.go<-x/util.go ",
		"z.go<-z.go ",
		"pairs 2",
	}, "\n")
	if got := describeChanges(changes, pairs); got != want {
		t.Fatalf("changes:\n%s", got)
	}
	if got := describeChanges(UneditedMoves(base, head), nil); got != "<-old/name.go \npairs 0" {
		t.Fatalf("unedited moves:\n%s", got)
	}
}

func TestChangedFilesKeepAnAmbiguousMoveAsDeleteAndAdd(t *testing.T) {
	changes, pairs := ChangedFiles(entries("a/util.go", "1", "b/util.go", "2"), entries("c/util.go", "3"))
	if got := describeChanges(changes, pairs); got != "<-a/util.go unmatched_move\n<-b/util.go unmatched_move\nc/util.go<- \npairs 0" {
		t.Fatalf("changes:\n%s", got)
	}
}
