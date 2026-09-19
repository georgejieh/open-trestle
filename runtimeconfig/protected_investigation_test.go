package runtimeconfig

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/fileauthority"
	"github.com/georgejieh/open-trestle/internal/review"
)

func TestProtectedInvestigationPolicyBindsStableImmutableValue(t *testing.T) {
	b, err := os.ReadFile("../internal/review/testdata/investigation-policy-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	want, err := review.ParseInvestigationPolicy(b)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "private-investigation-policy.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadProtectedInvestigationPolicy(context.Background(), path)
	if err != nil || got.Identity() != want.Identity() {
		t.Fatal("protected loader changed policy identity")
	}
	if err := os.WriteFile(path, []byte("changed after immutable load"), 0o600); err != nil {
		t.Fatal(err)
	}
	encoded, err := review.EncodeInvestigationPolicy(got)
	if err != nil || !bytes.Equal(encoded, b) {
		t.Fatal("loaded authority followed mutable file")
	}
}
func TestProtectedInvestigationPolicyRefusesUnsafePathsAndContent(t *testing.T) {
	b, err := os.ReadFile("../internal/review/testdata/investigation-policy-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"symlink", "writable file", "writable ancestor", "directory", "missing", "oversized", "malformed", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "private-policy-sentinel.json")
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "symlink":
				link := path + ".link"
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "writable file":
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			case "writable ancestor":
				if err := os.Chmod(dir, 0o777); err != nil {
					t.Fatal(err)
				}
			case "directory":
				path = dir
			case "missing":
				path += ".missing"
			case "oversized":
				if err := os.WriteFile(path, bytes.Repeat([]byte{' '}, 4097), 0o600); err != nil {
					t.Fatal(err)
				}
			case "malformed":
				if err := os.WriteFile(path, []byte(`{"profile":"shell"}`), 0o600); err != nil {
					t.Fatal(err)
				}
			case "canceled":
				cancel()
			}
			value, err := LoadProtectedInvestigationPolicy(ctx, path)
			if err == nil || value.Identity() != "" {
				t.Fatal("unsafe policy gained authority")
			}
			if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "sentinel") {
				t.Fatal("loader error leaked path")
			}
		})
	}
}

func TestProtectedInvestigationPolicyRechecksDuringReadAndAfterDecode(t *testing.T) {
	b, err := os.ReadFile("../internal/review/testdata/investigation-policy-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"mutate during read", "replace at final recheck"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "private-policy-sentinel.json")
			if err := os.WriteFile(path, b, 0o600); err != nil {
				t.Fatal(err)
			}
			opens := 0
			opener := func(name string) (protectedConfigurationFile, error) {
				opens++
				if mode == "replace at final recheck" && opens == 3 {
					changed := bytes.Replace(b, []byte(`"max_tool_calls":3`), []byte(`"max_tool_calls":2`), 1)
					if err := os.WriteFile(path+".replacement", changed, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Rename(path+".replacement", path); err != nil {
						t.Fatal(err)
					}
				}
				file, err := fileauthority.OpenReadOnly(name)
				if err != nil {
					return nil, err
				}
				if mode == "mutate during read" && opens == 1 {
					return &protectedReadProbe{File: file, afterRead: func() {
						if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
							t.Error(err)
						}
					}}, nil
				}
				return file, nil
			}
			value, err := loadProtectedInvestigationPolicy(context.Background(), path, opener)
			if err == nil || value.Identity() != "" {
				t.Fatal("unstable authority survived protected policy load")
			}
			if mode == "replace at final recheck" && opens < 3 {
				t.Fatal("loader never reached actual post-decode recheck")
			}
			if strings.Contains(err.Error(), dir) || strings.Contains(err.Error(), "sentinel") {
				t.Fatal("unstable load error disclosed authority path")
			}
		})
	}
}
