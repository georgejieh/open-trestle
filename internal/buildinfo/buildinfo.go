// Package buildinfo reports source identities embedded by the protected packager.
package buildinfo

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
)

var (
	sourceRevision string
	sourceTree     string
	// version is set only for a release archive build.
	version string
)

var versionPattern = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$`)

type information struct {
	Contract       string `json:"contract"`
	SchemaVersion  int    `json:"schema_version"`
	Program        string `json:"program"`
	Version        string `json:"version,omitempty"`
	SourceBound    bool   `json:"source_bound"`
	SourceRevision string `json:"source_revision"`
	SourceTree     string `json:"source_tree"`
}

func validObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 || strings.Trim(value, "0") == "" {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

// Version is the release version embedded in a release archive build, or ""
// for any other build.
func Version() string {
	if !versionPattern.MatchString(version) {
		return ""
	}
	return version
}

// Revision is the embedded source revision, or "" when the build is not bound
// to its source.
func Revision() string {
	if !validObjectID(sourceRevision) {
		return ""
	}
	return sourceRevision
}

// Write emits build identity, not publisher authenticity or release approval.
func Write(output io.Writer, program string) error {
	bound := sourceRevision != "" || sourceTree != ""
	if bound && (!validObjectID(sourceRevision) || !validObjectID(sourceTree) || len(sourceRevision) != len(sourceTree)) {
		return fmt.Errorf("invalid embedded source identity")
	}
	if version != "" && (!bound || !versionPattern.MatchString(version)) {
		return fmt.Errorf("invalid embedded version")
	}
	return json.NewEncoder(output).Encode(information{
		Contract: "open-trestle/build-info", SchemaVersion: 1, Program: program, Version: version,
		SourceBound: bound, SourceRevision: sourceRevision, SourceTree: sourceTree,
	})
}
