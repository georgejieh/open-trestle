package main

import (
	"bytes"
	"flag"
	"os"
	"testing"
)

func widthFlags(t *testing.T, args ...string) (*flag.FlagSet, *int, *bool) {
	t.Helper()
	flags := flag.NewFlagSet("test", flag.ContinueOnError)
	width := flags.Int("width", 100, "")
	plain := flags.Bool("plain", false, "")
	if err := flags.Parse(args); err != nil {
		t.Fatal(err)
	}
	return flags, width, plain
}

func TestResolveDisplayWidth(t *testing.T) {
	// /dev/null is a character device, which stands in for a terminal here.
	device, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Skip("character device unavailable")
	}
	defer device.Close()
	original := terminalColumns
	defer func() { terminalColumns = original }()
	reported := 0
	terminalColumns = func(*os.File) int { return reported }
	t.Setenv("TERM", "xterm-256color")
	for _, tc := range []struct {
		name     string
		args     []string
		columns  int
		term     string
		terminal bool
		want     int
	}{
		{"terminal width is used", nil, 72, "", true, 72},
		{"narrow terminal clamps up", nil, 30, "", true, 60},
		{"wide terminal clamps down", nil, 500, "", true, 240},
		{"unknown size keeps default", nil, 0, "", true, 100},
		{"explicit width wins", []string{"--width", "80"}, 72, "", true, 80},
		{"explicit default value still wins", []string{"--width", "100"}, 72, "", true, 100},
		{"plain keeps default", []string{"--plain"}, 72, "", true, 100},
		{"dumb terminal keeps default", nil, 72, "dumb", true, 100},
		{"non-terminal writer keeps default", nil, 72, "", false, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.term != "" {
				t.Setenv("TERM", tc.term)
			}
			reported = tc.columns
			flags, width, plain := widthFlags(t, tc.args...)
			var output interface{ Write([]byte) (int, error) } = &bytes.Buffer{}
			if tc.terminal {
				output = device
			}
			if got := resolveDisplayWidth(flags, *width, *plain, output); got != tc.want {
				t.Fatalf("width=%d want %d", got, tc.want)
			}
		})
	}
}
