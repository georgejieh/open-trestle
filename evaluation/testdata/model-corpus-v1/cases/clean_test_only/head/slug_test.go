package slug

import "testing"

func TestMake(t *testing.T) {
	tests := []struct {
		title string
		want  string
	}{
		{"Hello, World", "hello-world"},
		{"  Go 1.22 release notes ", "go-1-22-release-notes"},
		{"already-slugged", "already-slugged"},
		{"C++ & Go", "c-go"},
		{"", ""},
		{"!!!", ""},
	}
	for _, test := range tests {
		if got := Make(test.title); got != test.want {
			t.Errorf("Make(%q) = %q, want %q", test.title, got, test.want)
		}
	}
}
