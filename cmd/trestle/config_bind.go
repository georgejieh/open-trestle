package main

import (
	"context"
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/runtimeconfig"
)

func runConfigBind(args []string, stdout, stderr io.Writer) int {
	values, ok := parseConfigBindArgs(args)
	if !ok {
		writeConfigBindUsage(stderr)
		return 2
	}
	encoded, err := runtimeconfig.BindProtectedRuntimePolicy(context.Background(), values["--route-inventory"], values["--runtime-policy-template"], values["--generation-adapter"], values["--verification-adapter"])
	if err != nil {
		fmt.Fprintln(stderr, "bind runtime policy failed")
		return 1
	}
	encoded = append(encoded, '\n')
	if written, err := stdout.Write(encoded); err != nil || written != len(encoded) {
		fmt.Fprintln(stderr, "write bound runtime policy failed")
		return 1
	}
	return 0
}

func parseConfigBindArgs(args []string) (map[string]string, bool) {
	if len(args) != 8 {
		return nil, false
	}
	values := make(map[string]string, 4)
	for index := 0; index < len(args); index += 2 {
		key, value := args[index], args[index+1]
		switch key {
		case "--route-inventory", "--runtime-policy-template", "--generation-adapter", "--verification-adapter":
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

func writeConfigBindUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: trestle config bind --route-inventory PATH --runtime-policy-template PATH --generation-adapter ID --verification-adapter ID")
}
