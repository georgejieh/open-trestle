package analysis

import (
	"fmt"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/analysiscodec"
)

// budgetLines returns count lines of exactly 1 KiB each.
func budgetLines(count int) []byte {
	return []byte(strings.Repeat(strings.Repeat("r", 1023)+"\n", count))
}

// removedTextByPath groups a result's removed text by path: its bound chunks
// and its removed_lines_limit gaps.
func removedTextByPath(result Result) (map[string][]Item, map[string][]Gap) {
	chunks, limits := map[string][]Item{}, map[string][]Gap{}
	for _, item := range result.RemovedLines() {
		chunks[item.Path()] = append(chunks[item.Path()], item)
	}
	for _, gap := range result.Gaps() {
		if gap.Reason() == analysiscodec.RemovedLinesLimitReason {
			limits[gap.Path()] = append(limits[gap.Path()], gap)
		}
	}
	return chunks, limits
}

// boundBytes sums the bytes of bound chunks.
func boundBytes(chunks []Item) int {
	total := 0
	for _, chunk := range chunks {
		total += chunk.SliceBytes()
	}
	return total
}

// Removed files whose paths sort before the changed files must not take their
// evidence budget. Eleven changed 1000 KiB files under src/ use about 10.7 MiB
// of the 64 MiB evidence budget, and sixty-five removed 1 MiB files sort
// before them. Charged whole, the removed files would leave the changed files
// only resource_limit gaps. Instead every changed file is bound, and removed
// text is charged only the 32 KiB each file binds: even what the changed files
// left would not hold sixty-four whole removed files, yet each binds its first
// 32 KiB. Removed files are read from a separate 64 MiB bound, so the file
// past it is not read and records an explicit whole-entry removed_lines_limit
// gap.
func TestRemovedFilesNeverTakeChangedFilesEvidenceBudget(t *testing.T) {
	baseFiles, headFiles := map[string][]byte{}, map[string][]byte{}
	for index := 0; index < 11; index++ {
		path := fmt.Sprintf("src/m%02d.txt", index)
		content := budgetLines(1000)
		baseFiles[path] = content
		headFiles[path] = append([]byte("changed\n"), content[1024:]...)
	}
	removed := budgetLines(1024)
	for index := 0; index < 65; index++ {
		baseFiles[fmt.Sprintf("a%02d.txt", index)] = removed
	}
	output, change, base, head := deletionAnalysisFixture(t, baseFiles, headFiles)
	result, err := ParseResultArtifact(output, change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	bound := map[string]bool{}
	for _, item := range result.Items() {
		bound[item.Path()] = true
	}
	for _, gap := range result.Gaps() {
		if strings.HasPrefix(gap.Path(), "src/") {
			t.Fatalf("changed %s lost evidence to removed files: %s gap", gap.Path(), gap.Reason())
		}
	}
	if len(bound) != 11 {
		t.Fatalf("%d of 11 changed files were bound", len(bound))
	}
	chunks, limits := removedTextByPath(result)
	for index := 0; index < 64; index++ {
		path := fmt.Sprintf("a%02d.txt", index)
		if boundBytes(chunks[path]) != removedBytesPerEntry || len(limits[path]) != 1 || limits[path][0].StartLine() != 33 || limits[path][0].EndLine() != 1024 {
			t.Fatalf("%s bound %d bytes with limit gaps %v", path, boundBytes(chunks[path]), limits[path])
		}
	}
	if skipped := limits["a64.txt"]; len(chunks["a64.txt"]) != 0 || len(skipped) != 1 || skipped[0].StartLine() != 0 || skipped[0].EndLine() != 0 {
		t.Fatalf("a64.txt past the read bound: %d chunks, limit gaps %v", len(chunks["a64.txt"]), skipped)
	}
}

// A removed binary file binds no removed text and is charged nothing; it keeps
// only its whole-entry removed_file gap, as before removed text was bound.
func TestRemovedBinaryFileBindsNoRemovedText(t *testing.T) {
	output, change, base, head := deletionAnalysisFixture(t, map[string][]byte{"keep.txt": []byte("keep\n"), "image.bin": []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\n")}, map[string][]byte{"keep.txt": []byte("keep\n")})
	result, err := ParseResultArtifact(output, change, base, head)
	if err != nil {
		t.Fatal(err)
	}
	chunks, limits := removedTextByPath(result)
	if len(chunks["image.bin"]) != 0 || len(limits["image.bin"]) != 0 || result.SchemaVersion() == 7 {
		t.Fatalf("binary removed file bound %d chunks, %d limit gaps, version %d", len(chunks["image.bin"]), len(limits["image.bin"]), result.SchemaVersion())
	}
	whole := false
	for _, gap := range result.Gaps() {
		whole = whole || gap.Path() == "image.bin" && gap.Reason() == "removed_file"
	}
	if !whole {
		t.Fatal("binary removed file lost its whole-entry gap")
	}
}
