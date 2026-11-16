package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/evaluation"
)

func runEvaluateAdjudication(args []string, stdout, stderr io.Writer) int {
	values, ok := parseEvaluateAdjudicationArgs(args)
	if !ok || stdout == nil || stderr == nil {
		if stderr != nil {
			writeEvaluateAdjudicationUsage(stderr)
		}
		return 2
	}
	adjudication, err := readRegularBoundedFile(values["--adjudication"], 1<<20)
	if err != nil {
		fmt.Fprintln(stderr, "read adjudication input failed")
		return 1
	}
	observed, err := readRegularBoundedFile(values["--observed"], (1<<20)+1)
	if err != nil {
		fmt.Fprintln(stderr, "read observed input failed")
		return 1
	}
	encoded, err := evaluation.EvaluateAdjudication(adjudication, observed, values["--adjudication-sha256"])
	if err != nil {
		fmt.Fprintln(stderr, "evaluate adjudication failed")
		return 1
	}
	var result struct {
		ExecutionStatus string `json:"execution_status"`
	}
	if json.Unmarshal(encoded, &result) != nil {
		fmt.Fprintln(stderr, "evaluate adjudication failed")
		return 1
	}
	written, err := stdout.Write(append(encoded, '\n'))
	if err != nil || written != len(encoded)+1 {
		fmt.Fprintln(stderr, "write adjudication result failed")
		return 1
	}
	if result.ExecutionStatus == "mismatch" {
		return 3
	}
	return 4
}

func parseEvaluateAdjudicationArgs(args []string) (map[string]string, bool) {
	if len(args) != 6 {
		return nil, false
	}
	values := make(map[string]string, 3)
	for index := 0; index < len(args); index += 2 {
		key, value := args[index], args[index+1]
		switch key {
		case "--adjudication", "--adjudication-sha256", "--observed":
		default:
			return nil, false
		}
		if _, exists := values[key]; exists || value == "" {
			return nil, false
		}
		values[key] = value
	}
	return values, true
}

func writeEvaluateAdjudicationUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: trestle evaluate adjudication --adjudication PATH --adjudication-sha256 SHA256 --observed PATH")
}
