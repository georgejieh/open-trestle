package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/georgejieh/open-trestle/runtimecatalog"

	"github.com/georgejieh/open-trestle/modelcatalog"
)

func runConfigModels(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || (args[0] != "refresh" && args[0] != "apply") {
		writeConfigModelsUsage(stderr)
		return 2
	}
	flags := flag.NewFlagSet("trestle config models "+args[0], flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	sources := flags.String("sources", "", "protected source manifest")
	current := flags.String("current", "", "current metadata catalog (may be absent)")
	proposal := flags.String("proposal", "", "protected proposal path")
	var remote bool
	var expectedProposal, expectedCurrent string
	if args[0] == "refresh" {
		flags.BoolVar(&remote, "allow-remote", false, "allow explicit remote HTTPS metadata GETs")
	} else {
		flags.StringVar(&expectedProposal, "expected-proposal", "", "reviewed proposal SHA-256")
		flags.StringVar(&expectedCurrent, "expected-current", "", "reviewed current SHA-256 or absent")
	}
	if flags.Parse(args[1:]) != nil || flags.NArg() != 0 || *sources == "" || *current == "" || *proposal == "" || (args[0] == "apply" && (expectedProposal == "" || expectedCurrent == "")) {
		writeConfigModelsUsage(stderr)
		return 2
	}
	var result any
	if args[0] == "refresh" {
		resolver, _ := runtimecatalog.NewEnvironmentOpenAICredentialResolver(os.Getenv)
		review, err := modelcatalog.RefreshWithCredentials(context.Background(), *sources, *current, *proposal, remote, resolver)
		if err != nil {
			fmt.Fprintf(stderr, "model catalog refresh: %v\n", err)
			return 1
		}
		result = review
	} else {
		if err := modelcatalog.Apply(context.Background(), *sources, *current, *proposal, expectedProposal, expectedCurrent); err != nil {
			fmt.Fprintf(stderr, "model catalog apply: %v\n", err)
			return 1
		}
		result = struct {
			Status string `json:"status"`
		}{"applied"}
	}
	if err := json.NewEncoder(stdout).Encode(result); err != nil {
		fmt.Fprintln(stderr, "write model catalog result failed")
		return 1
	}
	return 0
}
func writeConfigModelsUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: trestle config models refresh --sources PATH --current PATH --proposal NEW_PATH [--allow-remote]")
	fmt.Fprintln(writer, "       trestle config models apply --sources PATH --current PATH --proposal PATH --expected-proposal SHA256 --expected-current SHA256|absent")
}
