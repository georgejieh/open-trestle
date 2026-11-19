package secretscan

import (
	"bytes"
	"os"
	"testing"
)

// The scan helper keeps its own copy of the ACL check, because the scanner
// module cannot import this module. The copies differ only in the package
// name.
func TestScanHelperACLCopiesMatch(t *testing.T) {
	for _, name := range []string{"acl.go", "acl_darwin.go", "acl_other.go", "acl_test.go"} {
		root, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		helper, err := os.ReadFile("../../workers/secret-scanner/internal/scanhelper/" + name)
		if err != nil {
			t.Fatal(err)
		}
		helper = bytes.Replace(helper, []byte("package scanhelper\n"), []byte("package secretscan\n"), 1)
		if !bytes.Equal(root, helper) {
			t.Errorf("root and scan helper copies of %s differ", name)
		}
	}
}
