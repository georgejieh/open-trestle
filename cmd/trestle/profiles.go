package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/agentprofile"
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
		if len(args) != 1 {
			writeProfilesUsage(stderr)
			return 2
		}
		return runProfilesList(stdout, stderr)
	case "plan":
		return runProfilesPlan(args[1:], stdout, stderr)
	default:
		writeProfilesUsage(stderr)
		return 2
	}
}

func runProfilesList(stdout, stderr io.Writer) int {
	catalog, err := agentprofile.DefaultCatalog()
	if err != nil {
		fmt.Fprintf(stderr, "load profile catalog: %v\n", err)
		return 1
	}
	return writeProfilesJSON(catalog, stdout, stderr)
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
	encoded = append(encoded, '\n')
	if written, err := stdout.Write(encoded); err != nil || written != len(encoded) {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}

func writeProfilesUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle profiles list")
	fmt.Fprintln(stderr, "       trestle profiles plan --assignments PATH --features PATH")
}
