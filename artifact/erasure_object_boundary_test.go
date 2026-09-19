package artifact

import (
	"strings"
	"testing"
)

func TestErasureObjectBlockedErrorContract(t *testing.T) {
	if ErrErasureBlocked.Error() != "erasure operation blocked" {
		t.Fatal("blocked error differs from frozen contract")
	}
}
func TestErasureObjectInvalidStringsRefuseBeforeCloning(t *testing.T) {
	huge := strings.Repeat("x", 1<<20)
	namespace := strings.Repeat("a", 64)
	cases := []struct {
		name string
		call func() error
	}{
		{"key namespace", func() error { _, err := NewExactObjectKey(huge, "key"); return err }},
		{"key path", func() error { _, err := NewExactObjectKey(namespace, huge); return err }},
		{"version namespace", func() error { _, err := NewObjectVersion(huge, "key", ObjectVersionData, "v"); return err }},
		{"version path", func() error { _, err := NewObjectVersion(namespace, huge, ObjectVersionData, "v"); return err }},
		{"version token", func() error { _, err := NewObjectVersion(namespace, "key", ObjectVersionData, huge); return err }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.call() == nil {
				t.Fatal("oversize metadata accepted")
			}
			// Fixture-specific allocation check for already-owned invalid input strings.
			// It is not a universal RSS or allocation bound for valid inputs.
			if n := testing.AllocsPerRun(5, func() { _ = c.call() }); n > 0 {
				t.Fatalf("invalid bounded metadata allocates copies: %v", n)
			}
		})
	}
}
