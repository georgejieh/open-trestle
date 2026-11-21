package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"time"

	setupcore "github.com/georgejieh/open-trestle/setup"
)

type setupClock interface{ Now() time.Time }
type systemSetupClock struct{}

func (systemSetupClock) Now() time.Time { return time.Now().UTC() }

func runSetup(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		writeSetupUsage(stderr)
		return 2
	}
	switch args[0] {
	case "bootstrap":
		return runSetupBootstrap(args[1:], stdout, stderr)
	case "inspect":
		return runSetupInspect(args[1:], stdout, stderr)
	case "backup":
		return runSetupBackup(args[1:], stdout, stderr)
	default:
		writeSetupUsage(stderr)
		return 2
	}
}

func runSetupInspect(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("trestle setup inspect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	state := flags.String("state", "", "private setup state file")
	expectedRoot := flags.String("expected-root-identity", "", "expected initial setup plan identity")
	if flags.Parse(args) != nil || flags.NArg() != 0 || *state == "" || (*expectedRoot != "" && !validAdminDigest(*expectedRoot)) {
		writeSetupUsage(stderr)
		return 2
	}
	plan, err := setupcore.InspectStateFile(context.Background(), *state)
	if err == nil && *expectedRoot != "" && plan.RootIdentity() != *expectedRoot {
		err = setupcore.ErrStateConflict
	}
	if err != nil {
		fmt.Fprintln(stderr, "setup inspection failed")
		return 1
	}
	canonical, _ := setupcore.EncodePlan(plan)
	if _, err = stdout.Write(append(canonical, '\n')); err != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}

func runSetupBackup(args []string, stdout, stderr io.Writer) int {
	if len(args) < 1 {
		writeSetupUsage(stderr)
		return 2
	}
	var plan setupcore.Plan
	var err error
	status := ""
	switch args[0] {
	case "create":
		flags := flag.NewFlagSet("trestle setup backup create", flag.ContinueOnError)
		flags.SetOutput(stderr)
		state := flags.String("state", "", "protected setup state file")
		destination := flags.String("destination", "", "new protected backup snapshot")
		expected := flags.String("expected-plan-identity", "", "exact current setup plan identity")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *state == "" || *destination == "" || !validAdminDigest(*expected) {
			writeSetupUsage(stderr)
			return 2
		}
		plan, err = setupcore.CreateBackupSnapshot(context.Background(), *state, *destination, *expected)
		status = "backup_created"
	case "restore":
		flags := flag.NewFlagSet("trestle setup backup restore", flag.ContinueOnError)
		flags.SetOutput(stderr)
		snapshot := flags.String("snapshot", "", "protected setup backup snapshot")
		destination := flags.String("destination", "", "new protected setup state file")
		expectedRoot := flags.String("expected-root-identity", "", "expected initial setup plan identity")
		expectedPlan := flags.String("expected-plan-identity", "", "expected backed-up plan identity")
		if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *snapshot == "" || *destination == "" || !validAdminDigest(*expectedRoot) || !validAdminDigest(*expectedPlan) {
			writeSetupUsage(stderr)
			return 2
		}
		plan, err = setupcore.RestoreBackupSnapshot(context.Background(), *snapshot, *destination, *expectedRoot, *expectedPlan)
		status = "backup_restored"
	default:
		writeSetupUsage(stderr)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "setup backup failed")
		return 1
	}
	result := struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		PlanIdentity  string `json:"plan_identity"`
		Revision      uint64 `json:"revision"`
		Ready         bool   `json:"ready"`
	}{"open-trestle/setup-command-result", 1, status, plan.Identity(), plan.Revision(), plan.Ready()}
	if json.NewEncoder(stdout).Encode(result) != nil {
		fmt.Fprintln(stderr, "write result failed")
		return 1
	}
	return 0
}

func writeSetupUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: trestle setup bootstrap init|check|inspect (local-first protected configuration and first-review commands)")
	fmt.Fprintln(writer, "       trestle setup inspect --state PATH [--expected-root-identity HEX64]")
	fmt.Fprintln(writer, "       trestle setup backup create --state PATH --destination PATH --expected-plan-identity HEX64")
	fmt.Fprintln(writer, "       trestle setup backup restore --snapshot PATH --destination PATH --expected-root-identity HEX64 --expected-plan-identity HEX64")
}
