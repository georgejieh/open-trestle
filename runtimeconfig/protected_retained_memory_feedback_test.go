package runtimeconfig

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

var _ fmt.Formatter = RetainedMemoryFeedback{}
var _ fmt.Stringer = RetainedMemoryFeedback{}
var _ fmt.GoStringer = RetainedMemoryFeedback{}

const rmFeedbackSecret = "OPERATOR_FEEDBACK_SECRET_SENTINEL_6174"

func rmFeedbackFile(t *testing.T, encoded []byte) string {
	t.Helper()
	if !rmaTrustedFileAuthoritySupported() {
		t.Skip("protected feedback loader requires trusted local file ownership")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "feedback.json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadProtectedRetainedMemoryFeedbackAcceptsStrictConvenienceInput(t *testing.T) {
	encoded := bytesForRawJSON(`[{"path":"b/file.go","text":"second note\nwith tab\tallowed"},{"path":"a/file.go","text":"first note"}]`)
	feedback, err := LoadProtectedRetainedMemoryFeedback(context.Background(), rmFeedbackFile(t, encoded))
	if err != nil {
		t.Fatal(err)
	}
	want := []RetainedMemoryFeedback{{Path: "b/file.go", Text: "second note\nwith tab\tallowed"}, {Path: "a/file.go", Text: "first note"}}
	if !reflect.DeepEqual(feedback, want) {
		t.Fatal("feedback loader changed order or content")
	}
	feedback[0].Text = "mutated"
	again, err := LoadProtectedRetainedMemoryFeedback(context.Background(), rmFeedbackFile(t, encoded))
	if err != nil || again[0].Text != want[0].Text {
		t.Fatal("feedback result was not stable across loads")
	}
}

func TestRetainedMemoryFeedbackFormattingRedactsInputAuthority(t *testing.T) {
	value := RetainedMemoryFeedback{Path: "secret/path.go", Text: rmFeedbackSecret}
	for _, format := range []string{"%s", "%v", "%+v", "%q", "%#v", "%x", "%d", "%01000.1s", "%+1000000.1q"} {
		got := fmt.Sprintf(format, value)
		if strings.Contains(got, "secret/path.go") || strings.Contains(got, rmFeedbackSecret) || len(got) > 128 {
			t.Fatalf("feedback format %s leaked path or text: %q", format, got)
		}
	}
}

func TestLoadProtectedRetainedMemoryFeedbackRejectsMalformedAndHostileJSON(t *testing.T) {
	largeUnknown := `[{"path":"a.go","text":"ok","unknown":"` + strings.Repeat("x", 33000) + `"}]`
	tooMany := `[` + strings.TrimRight(strings.Repeat(`{"path":"a.go","text":"ok"},`, 17), ",") + `]`
	cases := map[string][]byte{
		"empty":                  []byte(``),
		"object":                 bytesForRawJSON(`{"path":"a.go","text":"ok"}`),
		"trailing token":         bytesForRawJSON(`[{"path":"a.go","text":"ok"}] {}`),
		"comment":                bytesForRawJSON(`[{"path":"a.go","text":"ok"}] // nope`),
		"bom":                    append([]byte{0xef, 0xbb, 0xbf}, bytesForRawJSON(`[{"path":"a.go","text":"ok"}]`)...),
		"invalid utf8":           []byte{'[', '{', '"', 'p', 'a', 't', 'h', '"', ':', '"', 0xff, '"', ',', '"', 't', 'e', 'x', 't', '"', ':', '"', 'o', 'k', '"', '}', ']'},
		"bad surrogate":          bytesForRawJSON(`[{"path":"a.go","text":"\ud800"}]`),
		"hidden control":         bytesForRawJSON(`[{"path":"a.go","text":"bad\u0001control"}]`),
		"format character":       []byte("[{\"path\":\"a.go\",\"text\":\"bad\u200bformat\"}]"),
		"duplicate key":          bytesForRawJSON(`[{"path":"a.go","path":"b.go","text":"ok"}]`),
		"escaped duplicate key":  bytesForRawJSON(`[{"path":"a.go","p\u0061th":"b.go","text":"ok"}]`),
		"unknown key":            bytesForRawJSON(`[{"path":"a.go","text":"ok","extra":"no"}]`),
		"null path":              bytesForRawJSON(`[{"path":null,"text":"ok"}]`),
		"number text":            bytesForRawJSON(`[{"path":"a.go","text":1}]`),
		"nested text":            bytesForRawJSON(`[{"path":"a.go","text":["ok"]}]`),
		"absolute path":          bytesForRawJSON(`[{"path":"/a.go","text":"ok"}]`),
		"dot path":               bytesForRawJSON(`[{"path":".","text":"ok"}]`),
		"parent path":            bytesForRawJSON(`[{"path":"../a.go","text":"ok"}]`),
		"backslash path":         bytesForRawJSON(`[{"path":"a\\b.go","text":"ok"}]`),
		"duplicate path":         bytesForRawJSON(`[{"path":"a.go","text":"one"},{"path":"a.go","text":"two"}]`),
		"empty text":             bytesForRawJSON(`[{"path":"a.go","text":" \n\t "}]`),
		"too many records":       bytesForRawJSON(tooMany),
		"text over record cap":   bytesForRawJSON(`[{"path":"a.go","text":"` + strings.Repeat("x", 1025) + `"}]`),
		"decoded accounting cap": bytesForRawJSON(largeUnknown),
		"raw cap":                bytesForRawJSON(`[{"path":"a.go","text":"` + strings.Repeat("x", 65536) + `"}]`),
	}
	for name, encoded := range cases {
		t.Run(name, func(t *testing.T) {
			feedback, err := LoadProtectedRetainedMemoryFeedback(context.Background(), rmFeedbackFile(t, encoded))
			if err == nil || len(feedback) != 0 {
				t.Fatal("invalid feedback input was accepted")
			}
			if !errors.Is(err, ErrInvalidRetainedMemoryInput) {
				t.Fatalf("feedback refusal did not use retained-memory sentinel: %v", err)
			}
			if strings.Contains(err.Error(), "a.go") || strings.Contains(err.Error(), "ok") || strings.Contains(err.Error(), rmFeedbackSecret) {
				t.Fatal("feedback refusal leaked input content")
			}
		})
	}
}

func TestLoadProtectedRetainedMemoryFeedbackRejectsUnprotectedFiles(t *testing.T) {
	if !rmaTrustedFileAuthoritySupported() {
		t.Skip("protected feedback loader requires trusted local file ownership")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "feedback.json")
	if err := os.WriteFile(target, bytesForRawJSON(`[{"path":"a.go","text":"ok"}]`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	for name, path := range map[string]string{
		"missing":        filepath.Join(dir, "missing.json"),
		"symlink":        link,
		"world writable": target,
	} {
		t.Run(name, func(t *testing.T) {
			if name == "world writable" {
				if err := os.Chmod(path, 0o666); err != nil {
					t.Fatal(err)
				}
			}
			feedback, err := LoadProtectedRetainedMemoryFeedback(context.Background(), path)
			if err == nil || len(feedback) != 0 || !errors.Is(err, ErrInvalidRetainedMemoryInput) {
				t.Fatal("unprotected feedback file was accepted")
			}
		})
	}
}

func bytesForRawJSON(value string) []byte {
	return []byte(strings.ReplaceAll(value, `\"`, `"`))
}
