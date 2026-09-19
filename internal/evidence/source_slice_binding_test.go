package evidence

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestBindSourceSliceVerifiesExactPhysicalLines(t *testing.T) {
	content := []byte("first\r\nsecond\nlast")
	file, _ := NewRepositoryFile("file.go", content)
	sourceRange, _ := NewSourceRange("file.go", 2, 3)
	binding, err := BindSourceSlice(file, content, sourceRange, []byte("second\nlast"))
	if err != nil || binding.Identity() == "" || binding.RepositoryFileIdentity() != file.Identity() || binding.RepositoryFileDigest() != file.Digest() || binding.SourceRange() != sourceRange || binding.SliceDigest() == "" || binding.SliceBytes() != len("second\nlast") || binding.Validate() != nil {
		t.Fatalf("binding=(%#v,%v)", binding, err)
	}
	if strings.Contains(fmt.Sprintf("%#v", binding), "second") {
		t.Fatal("binding formatting leaked content")
	}
	content[0] = 'X'
	if binding.Validate() != nil {
		t.Fatal("input mutation changed binding")
	}
}

func TestBindSourceSliceRejectsMismatchedAndOutOfRangeContent(t *testing.T) {
	content := []byte("first\nsecond\n")
	file, _ := NewRepositoryFile("file.go", content)
	for _, test := range []struct {
		name        string
		sourceRange SourceRange
		slice       []byte
		want        error
	}{
		{"slice", mustSourceSliceRange(t, "file.go", 2, 2), []byte("wrong\n"), ErrSourceSliceMismatch},
		{"path", mustSourceSliceRange(t, "other.go", 1, 1), []byte("first\n"), ErrSourceSliceFileMismatch},
		{"range", mustSourceSliceRange(t, "file.go", 3, 3), []byte(""), ErrSourceSliceRangeOutOfBounds},
	} {
		t.Run(test.name, func(t *testing.T) {
			binding, err := BindSourceSlice(file, content, test.sourceRange, test.slice)
			if !errors.Is(err, test.want) || binding.Identity() != "" {
				t.Fatalf("BindSourceSlice()=(%#v,%v),want %v", binding, err, test.want)
			}
		})
	}
	forgedContent := append([]byte(nil), content...)
	forgedContent[0] = 'X'
	if binding, err := BindSourceSlice(file, forgedContent, mustSourceSliceRange(t, "file.go", 1, 1), []byte("Xirst\n")); !errors.Is(err, ErrSourceSliceFileMismatch) || binding.Identity() != "" {
		t.Fatalf("forged file=(%#v,%v)", binding, err)
	}
}

func mustSourceSliceRange(t *testing.T, path string, start, end int) SourceRange {
	t.Helper()
	value, err := NewSourceRange(path, start, end)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
