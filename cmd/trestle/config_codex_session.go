package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/adapters/providers/codexsession"
)

func runConfigCodexSession(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || args[0] != "status" {
		writeConfigCodexSessionUsage(stderr)
		return 2
	}
	result := struct {
		Contract      string `json:"contract"`
		SchemaVersion int    `json:"schema_version"`
		Status        string `json:"status"`
		codexsession.ProfileStatus
		Reason      string   `json:"reason"`
		Limitations []string `json:"limitations"`
	}{"open-trestle/codex-chatgpt-session-status", 1, "blocked", codexsession.Status(), codexsession.RuntimeAdmission().Error(), []string{"Status inspection does not authenticate an account or qualify a provider.", "No token exchange, session persistence, or model dispatch is implemented.", "Hard output and spend admission remains unavailable; client cancellation is not a server billing bound."}}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, "write Codex session status: failed")
		return 1
	}
	return 0
}

func writeConfigCodexSessionUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle config codex-session status")
}
