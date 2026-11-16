package localownerroot

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestExistingRootPolicyErrorIsOnlyDiagnostic(t *testing.T) {
	parent := t.TempDir()
	private := filepath.Join(parent, "private")
	if err := os.Mkdir(private, 0700); err != nil {
		t.Fatal(err)
	}
	marker := errors.New("caller policy refusal")
	for _, diagnostic := range []error{nil, marker} {
		root, err := ExistingRoot(private, diagnostic)
		if err != nil || root == nil {
			t.Fatalf("private root: %v, %v", root, err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
	}
	public := filepath.Join(parent, "public")
	if err := os.Mkdir(public, 0755); err != nil {
		t.Fatal(err)
	}
	if root, err := ExistingRoot(public, nil); root != nil || err != ErrUnsafePath {
		t.Fatalf("nil diagnostic: root=%v error=%v", root, err)
	}
	if root, err := ExistingRoot(public, marker); root != nil || err != marker {
		t.Fatalf("caller diagnostic: root=%v error=%v", root, err)
	}
}
