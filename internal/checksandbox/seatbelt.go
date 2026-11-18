package checksandbox

import (
	"sort"
	"strings"
)

// seatbeltSystemPaths are readable in every macOS sandbox: the system,
// its libraries and configuration, and the device files.
var seatbeltSystemPaths = []string{"/System", "/usr", "/bin", "/sbin", "/Library/Apple", "/private/etc", "/private/var/db/timezone", "/dev"}

// seatbeltServices are the only system services a sandbox may contact:
// logging, user and group lookups, and notifications. The keychain,
// launch services and every network service are absent.
var seatbeltServices = []string{"com.apple.system.logger", "com.apple.system.opendirectoryd.libinfo", "com.apple.system.notification_center"}

// seatbeltProfile returns a sandbox-exec profile that denies everything by
// default, including all network access and POSIX shared memory, whose
// names are shared with the user's other processes, and allows reading the system
// and toolchain folders, reading and writing scratch, and reading any
// file's metadata (but not its content), which path resolution needs.
func seatbeltProfile(scratch string, readOnly []string) string {
	read := append(append([]string{}, seatbeltSystemPaths...), readOnly...)
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
	profile.WriteString(")\n(allow file-read* file-write* (subpath " + seatbeltString(scratch) + "))\n")
	profile.WriteString("(allow file-write-data (literal \"/dev/null\") (literal \"/dev/zero\"))\n")
	profile.WriteString("(deny network*)\n")
	return profile.String()
}

// seatbeltString quotes text as a profile string literal.
func seatbeltString(text string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(text) + `"`
}
