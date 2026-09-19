package main

import (
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/evaluation"
)

type staticDebugEvaluationRunner func() ([]byte, bool, error)

func runEvaluate(args []string, stdout, stderr io.Writer) int {
	return runEvaluateWithRunner(args, stdout, stderr, runStaticDebugEvaluation)
}

func runEvaluateWithRunner(args []string, stdout, stderr io.Writer, runner staticDebugEvaluationRunner) int {
	if len(args) != 1 || args[0] != "static-debug" || stdout == nil || stderr == nil || runner == nil {
		writeEvaluateUsage(stderr)
		return 2
	}
	encoded, passed, err := runner()
	if err != nil {
		fmt.Fprintln(stderr, "static-debug evaluation failed")
		return 1
	}
	written, err := stdout.Write(append(encoded, '\n'))
	if err != nil || written != len(encoded)+1 {
		fmt.Fprintln(stderr, "write evaluation result failed")
		return 1
	}
	if !passed {
		return 3
	}
	return 0
}

func runStaticDebugEvaluation() ([]byte, bool, error) {
	report, err := evaluation.EvaluateStaticDebug()
	if err != nil {
		return nil, false, err
	}
	encoded, err := evaluation.EncodeStaticDebugReport(report)
	return encoded, report.Passed(), err
}

func writeEvaluateUsage(stderr io.Writer) {
	fmt.Fprintln(stderr, "usage: trestle evaluate static-debug")
}
