package main

import (
	"flag"
	"io"
	"os"
)

const (
	defaultDisplayWidth = 100
	minimumDisplayWidth = 60
	maximumDisplayWidth = 240
)

// terminalColumns reports the column count of a terminal file, or 0 when it
// cannot be determined. It is a variable so tests can supply a size.
var terminalColumns = func(file *os.File) int { return queryTerminalColumns(file) }

// resolveDisplayWidth keeps an explicit --width, and otherwise fits an
// interactive terminal. Plain, dumb-terminal and non-terminal output keeps the
// fixed default so captured logs stay stable.
func resolveDisplayWidth(flags *flag.FlagSet, width int, plain bool, stdout io.Writer) int {
	explicit := false
	flags.Visit(func(f *flag.Flag) {
		if f.Name == "width" {
			explicit = true
		}
	})
	if explicit || plain || os.Getenv("TERM") == "dumb" {
		return width
	}
	file, ok := stdout.(*os.File)
	if !ok {
		return width
	}
	if information, err := file.Stat(); err != nil || information.Mode()&os.ModeCharDevice == 0 {
		return width
	}
	columns := terminalColumns(file)
	if columns <= 0 {
		return width
	}
	return min(max(columns, minimumDisplayWidth), maximumDisplayWidth)
}
