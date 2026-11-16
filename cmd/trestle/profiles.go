package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/agentprofile"
	"github.com/georgejieh/open-trestle/internal/review"
)

// runProfiles implements the planning-only `trestle profiles` commands. It
// makes no model call, network request, or source change.
func runProfiles(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeProfilesUsage(stderr)
		return 2
	}
	switch args[0] {
	case "list":
		format, ok := parseProfilesListFormat(args[1:])
		if !ok {
			writeProfilesUsage(stderr)
			return 2
		}
		return runProfilesList(format, stdout, stderr)
	case "plan":
		return runProfilesPlan(args[1:], stdout, stderr)
	default:
		writeProfilesUsage(stderr)
		return 2
	}
}

// parseProfilesListFormat accepts no arguments (text) or one `--format text|json` pair.
func parseProfilesListFormat(args []string) (string, bool) {
	switch {
	case len(args) == 0:
		return "text", true
	case len(args) == 2 && args[0] == "--format" && (args[1] == "text" || args[1] == "json"):
		return args[1], true
	}
	return "", false
}

func runProfilesList(format string, stdout, stderr io.Writer) int {
	catalog, err := agentprofile.DefaultCatalog()
	if err != nil {
		fmt.Fprintf(stderr, "load profile catalog: %v\n", err)
		return 1
	}
	if format == "json" {
		return writeProfilesJSON(catalog, stdout, stderr)
	}
	return writeProfilesOutput(renderProfilesText(catalog, review.ContextSpecialistProfileIDs()), stdout, stderr)
}

// renderProfilesText prints one line per profile: its ID, when it calls a
// model, whether local-git model-review accepts it as a specialist, and its
// purpose. The catalog names no provider or model; assignments bind those per
// tier in `trestle profiles plan`.
func renderProfilesText(catalog agentprofile.Catalog, reviewProfiles []string) []byte {
	accepted := make(map[string]bool, len(reviewProfiles))
	for _, id := range reviewProfiles {
		accepted[id] = true
	}
	profiles := catalog.Profiles()
	rows := [][4]string{{"PROFILE", "MODEL", "REVIEW", "PURPOSE"}}
	for _, profile := range profiles {
		use := "plan only"
		if accepted[string(profile.ID())] {
			use = "--profile"
		}
		rows = append(rows, [4]string{string(profile.ID()), string(profile.ModelCall()), use, profile.Purpose()})
	}
	var widths [3]int
	for _, row := range rows {
		for column := range widths {
			widths[column] = max(widths[column], len(row[column]))
		}
	}
	var buffer bytes.Buffer
	for _, row := range rows {
		fmt.Fprintf(&buffer, "%-*s  %-*s  %-*s  %s\n", widths[0], row[0], widths[1], row[1], widths[2], row[2], row[3])
	}
	fmt.Fprintf(&buffer, "%d profiles, catalog version %d, identity %s\n", len(profiles), catalog.Version(), catalog.Identity())
	fmt.Fprintln(&buffer, "REVIEW --profile: local-git model-review accepts it in --profile and --specialists.")
	fmt.Fprintln(&buffer, "Models are assigned per tier by trestle profiles plan; --format json prints the full catalog.")
	return buffer.Bytes()
}

func runProfilesPlan(args []string, stdout, stderr io.Writer) int {
	var assignmentsPath, featuresPath string
	for index := 0; index < len(args); index += 2 {
		if index+1 >= len(args) || args[index+1] == "" {
			writeProfilesUsage(stderr)
			return 2
		}
		switch args[index] {
		case "--assignments":
			if assignmentsPath != "" {
				writeProfilesUsage(stderr)
				return 2
			}
			assignmentsPath = args[index+1]
		case "--features":
			if featuresPath != "" {
				writeProfilesUsage(stderr)
				return 2
			}
			featuresPath = args[index+1]
		default:
			writeProfilesUsage(stderr)
			return 2
		}
	}
	if assignmentsPath == "" || featuresPath == "" {
		writeProfilesUsage(stderr)
		return 2
	}
	catalog, err := agentprofile.DefaultCatalog()
	if err != nil {
		fmt.Fprintf(stderr, "load profile catalog: %v\n", err)
		return 1
	}
	assignmentsBytes, err := readRegularBoundedFile(assignmentsPath, agentprofile.MaxAssignmentsBytes)
	if err != nil {
		fmt.Fprintf(stderr, "read assignments: %v\n", err)
		return 1
	}
	assignments, err := agentprofile.ParseAssignments(catalog, assignmentsBytes)
	if err != nil {
		fmt.Fprintf(stderr, "parse assignments: %v\n", err)
		return 1
	}
	featuresBytes, err := readRegularBoundedFile(featuresPath, agentprofile.MaxChangeFeaturesBytes)
	if err != nil {
		fmt.Fprintf(stderr, "read features: %v\n", err)
		return 1
	}
	features, err := agentprofile.ParseChangeFeatures(featuresBytes)
	if err != nil {
		fmt.Fprintf(stderr, "parse features: %v\n", err)
		return 1
	}
	plan, err := agentprofile.Plan(catalog, assignments, features)
	if err != nil {
		fmt.Fprintf(stderr, "plan profiles: %v\n", err)
		return 1
	}
	return writeProfilesJSON(plan, stdout, stderr)
}

func writeProfilesJSON(value any, stdout, stderr io.Writer) int {
	encoded, err := json.Marshal(value)
	if err != nil {
		fmt.Fprintf(stderr, "encode result: %v\n", err)
		return 1
	}
	return writeProfilesOutput(append(encoded, '\n'), stdout, stderr)
}

func writeProfilesOutput(encoded []byte, stdout, stderr io.Writer) int {
	if written, err := stdout.Write(encoded); err != nil || written != len(encoded) {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}

func writeProfilesUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle profiles list [--format text|json]")
	fmt.Fprintln(stderr, "       trestle profiles plan --assignments PATH --features PATH")
}
