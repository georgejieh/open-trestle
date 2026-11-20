package checksandbox

import (
	"strings"
	"testing"
)

func TestSeatbeltProfileDeniesByDefault(t *testing.T) {
	scratch := "/private/var/folders/x/scratch"
	writable := []string{scratch + "/work", scratch + "/home", scratch + "/tmp"}
	profile := seatbeltProfile(scratch, writable, []string{"/opt/homebrew/opt/go/libexec"})
	for _, want := range []string{
		"(version 1)\n(deny default)\n",
		`(allow file-write* (subpath "/private/var/folders/x/scratch/work") (subpath "/private/var/folders/x/scratch/home") (subpath "/private/var/folders/x/scratch/tmp"))`,
		`(subpath "/private/var/folders/x/scratch")`,
		`(subpath "/opt/homebrew/opt/go/libexec")`,
		`(subpath "/usr")`,
		`(literal "/dev/urandom")`,
		"(deny network*)",
		`(global-name "com.apple.system.opendirectoryd.libinfo")`,
	} {
		if !strings.Contains(profile, want) {
			t.Errorf("profile lacks %q:\n%s", want, profile)
		}
	}
	for _, refused := range []string{"(allow network", "ipc-posix", "/dev/tty", `(subpath "/dev")`, "(allow file-write* (subpath \"/usr", "(allow mach-lookup)", "securityd", "/Users"} {
		if strings.Contains(profile, refused) {
			t.Errorf("profile contains %q:\n%s", refused, profile)
		}
	}
	if strings.Count(profile, "file-write*") != 1 {
		t.Errorf("only the scratch's folders may be writable:\n%s", profile)
	}
}

func TestSeatbeltStringEscapes(t *testing.T) {
	if got := seatbeltString(`/a "b" \c`); got != `"/a \"b\" \\c"` {
		t.Fatalf("got %s", got)
	}
	profile := seatbeltProfile("/tmp/s", []string{`/tmp/x") (allow network*) ("`}, nil)
	if !strings.Contains(profile, `(subpath "/tmp/x\") (allow network*) (\""))`) {
		t.Fatalf("a path was not quoted as one string:\n%s", profile)
	}
}
