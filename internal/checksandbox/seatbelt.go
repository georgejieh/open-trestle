package checksandbox

import (
	"sort"
	"strings"
)

// seatbeltSystemPaths are readable in every macOS sandbox: the system, its
// libraries and configuration.
var seatbeltSystemPaths = []string{"/System", "/usr", "/bin", "/sbin", "/Library/Apple", "/private/etc", "/private/var/db/timezone"}

// seatbeltDevices are the only device files a sandbox may read: the null
// and random devices. Its own descriptors under /dev/fd are allowed too;
// terminals and every other device are not.
var seatbeltDevices = []string{"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"}

// seatbeltServices are the only system services a sandbox may contact:
// logging, user and group lookups, and notifications. The keychain,
// launch services and every network service are absent.
var seatbeltServices = []string{"com.apple.system.logger", "com.apple.system.opendirectoryd.libinfo", "com.apple.system.notification_center"}

// seatbeltProfile returns a sandbox-exec profile that denies everything by
// default, including all network access and POSIX shared memory, whose
// names are shared with the user's other processes. It allows reading the
// system and toolchain folders, a few devices and the scratch, writing only
// inside the writable folders of the scratch, so that nothing can recreate
// the scratch once it is removed, and reading any file's metadata (but not
// its content), which path resolution needs.
func seatbeltProfile(scratch string, writable, readOnly []string) string {
	read := append(append([]string{}, seatbeltSystemPaths...), readOnly...)
	read = append(read, "/dev/fd", scratch)
	sort.Strings(read)
	var profile strings.Builder
	profile.WriteString("(version 1)\n(deny default)\n")
	profile.WriteString("(allow process-fork)\n(allow process-exec)\n(allow signal (target same-sandbox))\n")
	profile.WriteString("(allow sysctl-read)\n(allow file-read-metadata)\n")
	profile.WriteString("(allow mach-lookup")
	for _, service := range seatbeltServices {
		profile.WriteString(" (global-name " + seatbeltString(service) + ")")
	}
	profile.WriteString(")\n(allow file-read*")
	for _, path := range read {
		profile.WriteString(" (subpath " + seatbeltString(path) + ")")
	}
	for _, device := range seatbeltDevices {
		profile.WriteString(" (literal " + seatbeltString(device) + ")")
	}
	profile.WriteString(")\n(allow file-write*")
	for _, path := range writable {
		profile.WriteString(" (subpath " + seatbeltString(path) + ")")
	}
	profile.WriteString(")\n(allow file-write-data (literal \"/dev/null\") (literal \"/dev/zero\"))\n")
	profile.WriteString("(deny network*)\n")
	return profile.String()
}

// seatbeltString quotes text as a profile string literal.
func seatbeltString(text string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(text) + `"`
}
