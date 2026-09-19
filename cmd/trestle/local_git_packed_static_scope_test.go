package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/internal/scm"
)

func TestLocalGitPackedOptInIsUnknownToStaticParsers(t *testing.T) {
	inspectArgs := localGitInspectArgs("not-opened", evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40))
	changeArgs := localGitChangeArgs("not-opened", evidence.RevisionAlgorithmSHA1, strings.Repeat("1", 40), strings.Repeat("2", 40))
	cases := []struct {
		name  string
		args  []string
		parse func([]string) error
	}{
		{"inspect", inspectArgs, func(args []string) error {
			_, _, _, err := parseLocalGitInspectOptions(args)
			return err
		}},
		{"change", changeArgs, func(args []string) error {
			_, _, _, _, err := parseLocalGitChangeOptions(args)
			return err
		}},
		{"review", changeArgs, func(args []string) error {
			_, _, _, _, _, err := parseLocalGitReviewOptions(args)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The control parses only. It must not open an object root.
			if err := tc.parse(tc.args); err != nil {
				t.Fatalf("valid static control: %v", err)
			}
			args := append([]string(nil), tc.args...)
			if args[0] != "--objects-root" {
				t.Fatal("fixture does not start with the root flag")
			}
			// Preserve the required pair count, isolating unknown-flag rejection
			// from both arity checks and unrelated model-review options.
			args[0] = "--object-store"
			args[1] = string(scm.LocalGitObjectStoreProfileLooseAndPackIndexV1)
			if err := tc.parse(args); err == nil || err.Error() != "unknown flag" {
				t.Fatalf("packed flag parse error = %v, want unknown flag", err)
			}
			var stdout, stderr bytes.Buffer
			if code := run(append([]string{"local-git", tc.name}, args...), &stdout, &stderr); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
				t.Fatalf("packed static dispatch code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}
