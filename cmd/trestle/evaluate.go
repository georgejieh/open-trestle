package main

import (
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/evaluation"
)

type staticDebugEvaluationRunner func() ([]byte, bool, error)
type deterministicCorpusCandidateRunner func() ([]byte, string, error)

func runEvaluate(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "adjudication" {
		return runEvaluateAdjudication(args[1:], stdout, stderr)
	}
	if len(args) == 1 && args[0] == "model-contract-candidate" {
		return runModelContractCandidate(stdout, stderr)
	}
	if len(args) == 1 && args[0] == "deterministic-corpus-candidate" {
		return runDeterministicCorpusCandidate(stdout, stderr, runDeterministicCorpusCandidateEvaluation)
	}
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

func runDeterministicCorpusCandidate(stdout, stderr io.Writer, runner deterministicCorpusCandidateRunner) int {
	if stdout == nil || stderr == nil || runner == nil {
		writeEvaluateUsage(stderr)
		return 2
	}
	encoded, status, err := runner()
	if err != nil {
		fmt.Fprintln(stderr, "deterministic corpus candidate evaluation failed")
		return 1
	}
	written, err := stdout.Write(append(encoded, '\n'))
	if err != nil || written != len(encoded)+1 {
		fmt.Fprintln(stderr, "write evaluation result failed")
		return 1
	}
	switch status {
	case "mismatch":
		return 3
	case "matched":
		return 4
	default:
		fmt.Fprintln(stderr, "deterministic corpus candidate evaluation failed")
		return 1
	}
}

func runStaticDebugEvaluation() ([]byte, bool, error) {
	report, err := evaluation.EvaluateStaticDebug()
	if err != nil {
		return nil, false, err
	}
	encoded, err := evaluation.EncodeStaticDebugReport(report)
	return encoded, report.Passed(), err
}

func runDeterministicCorpusCandidateEvaluation() ([]byte, string, error) {
	report, err := evaluation.EvaluateDeterministicCorpusCandidate()
	if err != nil {
		return nil, "", err
	}
	encoded, err := evaluation.EncodeDeterministicCorpusReport(report)
	return encoded, report.ExecutionStatus(), err
}

func runModelContractCandidate(stdout, stderr io.Writer) int {
	if stdout == nil || stderr == nil {
		return 2
	}
	encoded, err := evaluation.EvaluateModelContractCandidate()
	if err != nil {
		fmt.Fprintln(stderr, "model contract candidate evaluation failed")
		return 1
	}
	written, err := stdout.Write(append(encoded, '\n'))
	if err != nil || written != len(encoded)+1 {
		fmt.Fprintln(stderr, "write evaluation result failed")
		return 1
	}
	return 4
}

func writeEvaluateUsage(stderr io.Writer) {
	writeEvaluateAdjudicationUsage(stderr)
	fmt.Fprintln(stderr, "usage: trestle evaluate static-debug | deterministic-corpus-candidate | model-contract-candidate")
}
