// Package update finds, verifies and prepares updates for the packaged Open
// Trestle Linux amd64 install.
//
// It knows two sources. The release channel is the GitHub Releases of
// georgejieh/open-trestle: a release qualifies only when its archive is signed
// with an Ed25519 key pinned in this build, over a statement that names the
// version, target, tag and the archive's SHA-256 and size. The local channel
// is a folder only this account can open, where a maintainer leaves an
// unsigned development build and its SHA-256 sidecar.
//
// Nothing here installs anything. The package copies a chosen candidate into
// a fresh private folder and verifies the copy; the caller then runs the
// copy's own lifecycle, which enforces the same strictly-newer, same-target
// rule again as root.
package update

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// ErrInvalidVersion is a version outside the grammar the packaged lifecycle
// accepts.
var ErrInvalidVersion = errors.New("version is not valid SemVer")

var (
	versionPattern    = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$`)
	identifierPattern = regexp.MustCompile(`^[0-9A-Za-z-]+$`)
)

// Version is a SemVer 2.0.0 version with the precedence the packaged
// lifecycle (tools/linux_distribution_runtime.py, _version_precedence) uses.
// The lifecycle's integers are unbounded; a major, minor or patch number above
// 2^64-1 is refused here, so such a candidate is never offered.
type Version struct {
	major, minor, patch uint64
	pre                 []string
	text                string
}

// ParseVersion parses text exactly, without a leading "v" or spaces.
func ParseVersion(text string) (Version, error) {
	if len(text) > 255 {
		return Version{}, ErrInvalidVersion
	}
	match := versionPattern.FindStringSubmatch(text)
	if match == nil {
		return Version{}, ErrInvalidVersion
	}
	version := Version{text: text}
	for index, target := range []*uint64{&version.major, &version.minor, &version.patch} {
		value, err := strconv.ParseUint(match[index+1], 10, 64)
		if err != nil {
			return Version{}, ErrInvalidVersion
		}
		*target = value
	}
	if prerelease := match[4]; prerelease != "" {
		version.pre = strings.Split(prerelease, ".")
		for _, identifier := range version.pre {
			if !identifierPattern.MatchString(identifier) || numeric(identifier) && len(identifier) > 1 && identifier[0] == '0' {
				return Version{}, ErrInvalidVersion
			}
		}
	}
	if build := match[5]; build != "" {
		for _, identifier := range strings.Split(build, ".") {
			if !identifierPattern.MatchString(identifier) {
				return Version{}, ErrInvalidVersion
			}
		}
	}
	return version, nil
}

func numeric(identifier string) bool {
	for _, character := range identifier {
		if character < '0' || character > '9' {
			return false
		}
	}
	return identifier != ""
}

// String is the version exactly as parsed.
func (v Version) String() string { return v.text }

// Prerelease reports a version with a prerelease part, such as 0.2.0-rc.1.
func (v Version) Prerelease() bool { return len(v.pre) != 0 }

// Development reports a development version: one whose prerelease part
// contains -dev, such as 0.1.5-dev. Only a development install looks in the
// local update folder by default.
func (v Version) Development() bool {
	return v.Prerelease() && strings.Contains("-"+strings.Join(v.pre, "."), "-dev")
}

// Compare returns -1, 0 or 1 as v has lower, equal or higher precedence than
// other. Build metadata does not count.
func (v Version) Compare(other Version) int {
	for _, pair := range [][2]uint64{{v.major, other.major}, {v.minor, other.minor}, {v.patch, other.patch}} {
		if pair[0] != pair[1] {
			if pair[0] < pair[1] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(v.pre) == 0 && len(other.pre) == 0:
		return 0
	case len(v.pre) == 0:
		return 1
	case len(other.pre) == 0:
		return -1
	}
	for index := 0; index < len(v.pre) && index < len(other.pre); index++ {
		if order := compareIdentifier(v.pre[index], other.pre[index]); order != 0 {
			return order
		}
	}
	switch {
	case len(v.pre) < len(other.pre):
		return -1
	case len(v.pre) > len(other.pre):
		return 1
	}
	return 0
}

// compareIdentifier orders numeric identifiers numerically (of any length,
// since they have no leading zeros) and below alphanumeric ones, which
// compare in ASCII order.
func compareIdentifier(a, b string) int {
	aNumeric, bNumeric := numeric(a), numeric(b)
	switch {
	case aNumeric && bNumeric:
		if len(a) != len(b) {
			if len(a) < len(b) {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	case aNumeric:
		return -1
	case bNumeric:
		return 1
	}
	return strings.Compare(a, b)
}
