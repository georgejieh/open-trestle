package syntaxworker

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"io"

	"github.com/georgejieh/open-trestle/internal/syntaxwasm"
	"github.com/georgejieh/open-trestle/semanticimpact"
	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// Serve answers requests from in on out until in ends. abandoned reports
// the analyzer's abandoned guest calls, which each response carries. A
// malformed request or a failed write ends Serve with an error.
func Serve(ctx context.Context, in io.Reader, out io.Writer, analyzer syntaxanalysis.Analyzer, abandoned func() int) error {
	reader := bufio.NewReaderSize(in, 1<<16)
	writer := bufio.NewWriterSize(out, 1<<16)
	for {
		payload, err := readFrame(reader)
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		q, err := decodeRequest(payload)
		if err != nil {
			return err
		}
		answer := response{id: q.id, status: statusInvalidInput}
		if source, err := syntaxanalysis.NewSource(q.path, q.language, q.content); err == nil {
			analysis, err := analyzer.Analyze(ctx, source)
			if err != nil {
				return err
			}
			encoded, err := syntaxanalysis.EncodeBinary(analysis)
			if err != nil {
				return err
			}
			answer.status, answer.analysis = statusAnalysed, encoded
		}
		if n := abandoned(); n > 0 {
			answer.abandoned = uint64(n)
		}
		if err := writeFrame(writer, answer.encode()); err != nil {
			return err
		}
		if err := writer.Flush(); err != nil {
			return err
		}
	}
}

// Run is the worker program: it analyses Go with go/parser and every other
// language with the WebAssembly grammars, one file at a time. The only
// argument is --cache-directory, a private directory for compiled modules,
// which syntaxwasm.Config describes. It returns the process exit code.
func Run(ctx context.Context, args []string, in io.Reader, out io.Writer) int {
	flags := flag.NewFlagSet("syntax worker", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cache := flags.String("cache-directory", "", "")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return 2
	}
	limits := syntaxanalysis.DefaultLimits()
	goAnalyzer, err := semanticimpact.NewGoSyntaxAnalyzer(limits)
	if err != nil {
		return 1
	}
	wasm, err := syntaxwasm.New(ctx, syntaxwasm.Config{CacheDirectory: *cache, Limits: limits, InstancesPerFamily: 1})
	if err != nil {
		return 1
	}
	defer wasm.Close(context.Background())
	if Serve(ctx, in, out, syntaxanalysis.NewDispatcher(goAnalyzer, wasm), wasm.AbandonedCalls) != nil {
		return 1
	}
	return 0
}
