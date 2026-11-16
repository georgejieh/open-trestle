// Package buildinfo reports source identities embedded by the protected packager.
package buildinfo

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

var (
	sourceRevision string
	sourceTree     string
)

type information struct {
	Contract       string `json:"contract"`
	SchemaVersion  int    `json:"schema_version"`
	Program        string `json:"program"`
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

// Write emits build identity, not publisher authenticity or release approval.
func Write(output io.Writer, program string) error {
	bound := sourceRevision != "" || sourceTree != ""
	if bound && (!validObjectID(sourceRevision) || !validObjectID(sourceTree) || len(sourceRevision) != len(sourceTree)) {
		return fmt.Errorf("invalid embedded source identity")
	}
	return json.NewEncoder(output).Encode(information{
		Contract: "open-trestle/build-info", SchemaVersion: 1, Program: program,
		SourceBound: bound, SourceRevision: sourceRevision, SourceTree: sourceTree,
	})
}
