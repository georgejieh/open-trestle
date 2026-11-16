package update

import (
	"strings"
	"testing"
)

func TestParseVersionAcceptsTheLifecycleGrammar(t *testing.T) {
	for _, text := range []string{"0.0.0", "0.1.0-dev", "0.1.5-dev", "1.2.3-rc.1", "1.2.3-0.a-b.x", "1.2.3+build.7", "1.2.3-alpha+001", "10.20.30"} {
		version, err := ParseVersion(text)
		if err != nil {
			t.Fatalf("%q refused: %v", text, err)
		}
		if version.String() != text {
			t.Fatalf("%q printed as %q", text, version.String())
		}
	}
}

func TestParseVersionRefusesWhatTheLifecycleRefuses(t *testing.T) {
	for _, text := range []string{"", "v1.0.0", "1.0", "1.0.0.0", "01.0.0", "1.01.0", "1.0.01", "1.0.0-", "1.0.0-01", "1.0.0-a..b", "1.0.0+", "1.0.0+a..b", "1.0.0-a_b", " 1.0.0", "1.0.0\n", "18446744073709551616.0.0", strings.Repeat("1", 254) + ".0.0"} {
		if _, err := ParseVersion(text); err == nil {
			t.Fatalf("%q accepted", text)
		}
	}
}

// The order below is the SemVer 2.0.0 example order, which the packaged
// lifecycle's _version_precedence also produces.
func TestCompareFollowsSemVerPrecedence(t *testing.T) {
	ordered := []string{"1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "1.0.1-dev", "1.0.1", "1.1.0", "2.0.0"}
	for i := range ordered {
		for j := range ordered {
			a, b := mustVersion(t, ordered[i]), mustVersion(t, ordered[j])
			want := 0
			if i < j {
				want = -1
			} else if i > j {
				want = 1
			}
			if got := a.Compare(b); got != want {
				t.Fatalf("Compare(%s, %s) = %d, want %d", a, b, got, want)
			}
		}
	}
	if mustVersion(t, "1.0.0+a").Compare(mustVersion(t, "1.0.0+b")) != 0 {
		t.Fatal("build metadata changed precedence")
	}
	huge := "1.0.0-" + strings.Repeat("9", 40)
	if mustVersion(t, huge).Compare(mustVersion(t, "1.0.0-"+strings.Repeat("9", 39))) != 1 {
		t.Fatal("long numeric identifiers are not compared numerically")
	}
}

func TestDevelopmentAndPrereleaseVersions(t *testing.T) {
	for text, want := range map[string][2]bool{
		"0.1.5-dev":      {true, true},
		"0.1.5-dev.3":    {true, true},
		"0.2.0-rc.1-dev": {true, true},
		"0.2.0-rc.1":     {true, false},
		"0.2.0":          {false, false},
		"0.2.0+dev":      {false, false},
	} {
		version := mustVersion(t, text)
		if version.Prerelease() != want[0] || version.Development() != want[1] {
			t.Fatalf("%s: prerelease=%v development=%v, want %v", text, version.Prerelease(), version.Development(), want)
		}
	}
}

func mustVersion(t *testing.T, text string) Version {
	t.Helper()
	version, err := ParseVersion(text)
	if err != nil {
		t.Fatal(err)
	}
	return version
}
