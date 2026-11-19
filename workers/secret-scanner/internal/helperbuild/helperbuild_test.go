package helperbuild

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoriesAcceptTheModuleWithEitherLineEnding(t *testing.T) {
	for name, content := range map[string]string{
		"LF":   "module " + modulePath + "\n\ngo 1.25.0\n",
		"CRLF": "module " + modulePath + "\r\n\r\ngo 1.25.0\r\n",
	} {
		module := t.TempDir()
		if err := os.WriteFile(filepath.Join(module, "go.mod"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := directories(module, filepath.Join(t.TempDir(), "out")); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestDirectoriesRefuseAnotherModule(t *testing.T) {
	module := t.TempDir()
	if err := os.WriteFile(filepath.Join(module, "go.mod"), []byte("module "+modulePath+"/other\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := directories(module, filepath.Join(t.TempDir(), "out")); err == nil {
		t.Fatal("another module was accepted")
	}
}
