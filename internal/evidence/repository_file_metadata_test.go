package evidence

import (
	"strings"
	"testing"
)

func TestNewRecordedRepositoryFileMatchesContentMetadata(t *testing.T) {
	for _, content := range [][]byte{nil, []byte("package p\n"), {0, 1, 255}} {
		file, err := NewRepositoryFile("src/a.go", content)
		if err != nil {
			t.Fatal(err)
		}
		recorded, err := NewRecordedRepositoryFile(file.Path(), file.Digest(), file.SizeBytes())
		if err != nil || recorded != file {
			t.Fatalf("metadata mismatch: %v", err)
		}
	}
	for _, tc := range []struct {
		path, digest string
		size         int
	}{
		{"../unsafe", strings.Repeat("a", 64), 1},
		{"src/a.go", strings.Repeat("A", 64), 1},
		{"src/a.go", strings.Repeat("z", 64), 1},
		{"src/a.go", "", 1},
		{"src/a.go", strings.Repeat("a", 64), -1},
	} {
		if value, err := NewRecordedRepositoryFile(tc.path, tc.digest, tc.size); err == nil || value.Identity() != "" {
			t.Fatalf("invalid metadata accepted: %+v", tc)
		}
	}
}
