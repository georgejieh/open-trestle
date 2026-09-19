//go:build unix

package fileauthority

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const protectedWriteSecret = "PROTECTED_WRITE_SECRET_SENTINEL_4295"

func protectedWriteDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestWriteNewProtectedFileCreatesStableExclusive0600(t *testing.T) {
	dir := protectedWriteDir(t)
	path := filepath.Join(dir, "retained-memory-input.json")
	content := []byte(`{"contract":"fixture","text":"` + protectedWriteSecret + `"}`)
	if err := WriteNewProtectedFile(context.Background(), path, content, len(content)); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Mode()&os.ModeSymlink != 0 || info.Size() != int64(len(content)) {
		t.Fatalf("created file authority drift: mode=%v size=%d", info.Mode(), info.Size())
	}
	read, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(read, content) {
		t.Fatal("created bytes are not stable")
	}
	opened, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal("protected read refused newly written file")
	}
	defer opened.Close()
	loaded, err := io.ReadAll(opened)
	if err != nil || !bytes.Equal(loaded, content) {
		t.Fatal("protected read changed newly written content")
	}
	if err := WriteNewProtectedFile(context.Background(), path, []byte("replacement"), 64); !errors.Is(err, ErrProtectedWriteRefused) {
		t.Fatalf("overwrite did not fail closed: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, content) {
		t.Fatal("exclusive create refusal changed existing bytes")
	}
}

func TestWriteNewProtectedFileRefusesBeforeCreateForInvalidRequest(t *testing.T) {
	dir := protectedWriteDir(t)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cases := map[string]struct {
		ctx     context.Context
		path    string
		content []byte
		limit   int
		want    error
	}{
		"nil context":        {nil, filepath.Join(dir, "nil.json"), []byte("x"), 1, ErrProtectedWriteRefused},
		"canceled context":   {canceled, filepath.Join(dir, "canceled.json"), []byte("x"), 1, context.Canceled},
		"empty path":         {context.Background(), "", []byte("x"), 1, ErrProtectedWriteRefused},
		"empty content":      {context.Background(), filepath.Join(dir, "empty.json"), nil, 1, ErrProtectedWriteRefused},
		"zero limit":         {context.Background(), filepath.Join(dir, "zero.json"), []byte("x"), 0, ErrProtectedWriteRefused},
		"over limit":         {context.Background(), filepath.Join(dir, "over.json"), []byte("xx"), 1, ErrProtectedWriteRefused},
		"over max limit":     {context.Background(), filepath.Join(dir, "max.json"), []byte("x"), 65537, ErrProtectedWriteRefused},
		"missing parent":     {context.Background(), filepath.Join(dir, "missing", "x.json"), []byte("x"), 1, ErrProtectedWriteRefused},
		"dot base":           {context.Background(), filepath.Join(dir, "."), []byte("x"), 1, ErrProtectedWriteRefused},
		"parent base":        {context.Background(), filepath.Join(dir, ".."), []byte("x"), 1, ErrProtectedWriteRefused},
		"trailing separator": {context.Background(), filepath.Join(dir, "child") + string(os.PathSeparator), []byte("x"), 1, ErrProtectedWriteRefused},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := WriteNewProtectedFile(tc.ctx, tc.path, tc.content, tc.limit)
			if !errors.Is(err, tc.want) {
				t.Fatalf("refusal=%v want %v", err, tc.want)
			}
			if err != nil && ((tc.path != "" && strings.Contains(err.Error(), tc.path)) || strings.Contains(err.Error(), protectedWriteSecret)) {
				t.Fatal("protected write refusal leaked path or content")
			}
			if tc.path != "" {
				if _, statErr := os.Lstat(tc.path); statErr == nil && name != "dot base" && name != "parent base" && name != "trailing separator" {
					t.Fatal("pre-create refusal created a file")
				}
			}
		})
	}
}

func TestWriteNewProtectedFileRefusesSymlinkAndUnsafeAncestryWithoutMutation(t *testing.T) {
	dir := protectedWriteDir(t)
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := WriteNewProtectedFile(context.Background(), link, []byte("replacement"), 64); !errors.Is(err, ErrProtectedWriteRefused) {
		t.Fatalf("symlink destination was not refused: %v", err)
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "target" {
		t.Fatal("symlink refusal changed target bytes")
	}
	unsafe := filepath.Join(dir, "unsafe")
	if err := os.Mkdir(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(unsafe, "created.json")
	if err := WriteNewProtectedFile(context.Background(), path, []byte("x"), 1); !errors.Is(err, ErrProtectedWriteRefused) {
		t.Fatalf("unsafe ancestry was not refused: %v", err)
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("unsafe ancestry refusal created output")
	}
	parentLink := filepath.Join(dir, "parent-link")
	if err := os.Symlink(unsafe, parentLink); err != nil {
		t.Fatal(err)
	}
	linkedChild := filepath.Join(parentLink, "child.json")
	if err := WriteNewProtectedFile(context.Background(), linkedChild, []byte("x"), 1); !errors.Is(err, ErrProtectedWriteRefused) {
		t.Fatalf("symlink ancestry was not refused: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(unsafe, "child.json")); !os.IsNotExist(err) {
		t.Fatal("symlink ancestry refusal created through link")
	}
}

func TestProtectedWriteSentinelsAreStableAndDistinct(t *testing.T) {
	if ErrProtectedWriteRefused == nil || ErrProtectedWriteIncomplete == nil || ErrProtectedWriteRefused == ErrProtectedWriteIncomplete {
		t.Fatal("protected write sentinels are missing or aliased")
	}
	if errors.Is(ErrProtectedWriteRefused, ErrProtectedWriteIncomplete) || errors.Is(ErrProtectedWriteIncomplete, ErrProtectedWriteRefused) {
		t.Fatal("protected write sentinels wrap each other")
	}
}
