// Package checksandbox runs one command from a reviewed repository in an
// isolated, bounded sandbox: no network, no access to the user's home
// folder, credentials or other repositories, read-only toolchains and a
// writable scratch copy of the tree only. Linux uses unprivileged
// namespaces, Windows an AppContainer inside a job object, and macOS a
// sandbox-exec profile.
package checksandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Limits bound one run.
type Limits struct {
	// Time is the wall clock limit; the whole process tree is killed when it
	// passes.
	Time time.Duration
	// MemoryBytes is the memory limit: per process on Linux, for the whole
	// tree on Windows. macOS has no limit a user can set.
	MemoryBytes uint64
	// Processes bounds the processes that may exist at once; on Linux each
	// thread counts as one.
	Processes int
	// OutputBytes bounds standard output and standard error, each.
	OutputBytes int
	// DiskBytes bounds the writable scratch, including the copy of the tree.
	DiskBytes int64
}

// DefaultLimits are the limits for one repository check.
func DefaultLimits() Limits {
	return Limits{
		Time:        3 * time.Minute,
		MemoryBytes: 4 << 30,
		Processes:   1024,
		OutputBytes: 8 << 20,
		DiskBytes:   2 << 30,
	}
}

// reportLimit bounds the report file the runner writes.
const reportLimit = 16 << 20

// Spec describes one run.
type Spec struct {
	// Tree is a host directory holding the tree to check. It is copied into
	// a fresh scratch for the run and never written.
	Tree string
	// Dir is the working directory, relative to the tree.
	Dir string
	// Args is the command. Args[0] is looked up in Path unless it is
	// absolute.
	Args []string
	// Path lists the host directories searched for programs, in order. Only
	// programs inside ReadOnly or the system directories are visible.
	Path []string
	// ReadOnly lists host directories made readable, at the same paths, for
	// toolchains and their dependency caches.
	ReadOnly []string
	// Env holds extra KEY=VALUE entries. In values, and in Args after the
	// program, $HOME, $TMPDIR and $WORK expand to the sandbox's private
	// home, temporary folder and tree copy.
	Env []string
	// HomeSeed, when set, is a host folder whose contents are copied into
	// the private home before the run, such as a prebuilt build cache. The
	// run changes only its own copy.
	HomeSeed string
	// Report, when set, is a file path relative to the scratch's temporary
	// folder that the runner writes its structured results to. Its content
	// is returned in Result.Report.
	Report string
	Limits Limits
}

// Result is the outcome of a command that ran.
type Result struct {
	// ExitCode is the command's exit status, or -1 when a signal ended it.
	ExitCode int
	// TimedOut reports that the time limit killed the process tree.
	TimedOut bool
	// OutputExceeded reports that output passed its limit and the process
	// tree was killed.
	OutputExceeded bool
	// DiskExceeded reports that the scratch filled up or passed its limit.
	DiskExceeded bool
	Stdout       []byte
	Stderr       []byte
	// Report is the report file's content, or nil when it was not written.
	Report   []byte
	Duration time.Duration
	// Leftover names the scratch folder when it could not be removed after
	// the run, such as when a process the run left is still writing to it.
	// SweepStale tries again later.
	Leftover string
}

// Succeeded reports that the command ran to completion with status zero.
func (r Result) Succeeded() bool {
	return r.ExitCode == 0 && !r.TimedOut && !r.OutputExceeded && !r.DiskExceeded
}

// Unavailable is the error for a command that could not run: the sandbox
// could not be set up, or the command could not be started in it. It is
// never returned for a command that ran and failed.
type Unavailable struct {
	Reason string
}

func (e *Unavailable) Error() string {
	return "the check sandbox could not run the command: " + e.Reason
}

func unavailable(format string, values ...any) error {
	return &Unavailable{Reason: fmt.Sprintf(format, values...)}
}

// IsUnavailable reports whether err means the command could not run.
func IsUnavailable(err error) bool {
	var target *Unavailable
	return errors.As(err, &target)
}

// Available reports, without running anything, whether this system has
// what the sandbox needs. A run can still report Unavailable.
func Available() error { return available() }

// Run runs spec in the sandbox. A non-nil error is always *Unavailable; it
// means nothing ran. The command is never run without the sandbox.
func Run(ctx context.Context, spec Spec) (Result, error) {
	if err := spec.validate(); err != nil {
		return Result{}, err
	}
	return run(ctx, spec)
}

func (spec Spec) validate() error {
	if len(spec.Args) == 0 || spec.Args[0] == "" {
		return unavailable("no command was given")
	}
	if !filepath.IsAbs(spec.Tree) {
		return unavailable("the tree path is not absolute")
	}
	if info, err := os.Stat(spec.Tree); err != nil || !info.IsDir() {
		return unavailable("the tree is not a folder")
	}
	if !localPath(spec.Dir) || spec.Report != "" && !localPath(spec.Report) {
		return unavailable("a relative path leaves the scratch")
	}
	for _, path := range append(append([]string{}, spec.ReadOnly...), spec.Path...) {
		if !filepath.IsAbs(path) {
			return unavailable("a toolchain path is not absolute")
		}
	}
	if spec.HomeSeed != "" && !filepath.IsAbs(spec.HomeSeed) {
		return unavailable("the home seed path is not absolute")
	}
	for _, entry := range spec.Env {
		if key, _, ok := strings.Cut(entry, "="); !ok || key == "" {
			return unavailable("an environment entry has no name")
		}
	}
	limits := spec.Limits
	if limits.Time <= 0 || limits.MemoryBytes == 0 || limits.Processes <= 0 || limits.OutputBytes <= 0 || limits.DiskBytes <= 0 {
		return unavailable("a limit is missing")
	}
	return refuseHome(spec.ReadOnly)
}

// refuseHome refuses a read-only path that would show the whole home
// folder; a toolchain or cache inside it is fine.
func refuseHome(paths []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	for _, path := range paths {
		if within(path, home) {
			return unavailable("%s would show the whole home folder", path)
		}
	}
	return nil
}

// within reports whether path is base or lies inside it.
func within(base, path string) bool {
	relative, err := filepath.Rel(filepath.Clean(base), filepath.Clean(path))
	return err == nil && (relative == "." || filepath.IsLocal(relative))
}

// localPath reports whether path is empty or relative and stays inside its
// base.
func localPath(path string) bool {
	return path == "" || filepath.IsLocal(path)
}

// sandboxPaths are the sandbox's own folders, as the command sees them.
type sandboxPaths struct {
	home, temporary, work string
}

// expand replaces $HOME, $TMPDIR and $WORK in text.
func (paths sandboxPaths) expand(text string) string {
	values := map[string]string{"HOME": paths.home, "TMPDIR": paths.temporary, "WORK": paths.work}
	return os.Expand(text, func(name string) string {
		if value, ok := values[name]; ok {
			return value
		}
		return "$" + name
	})
}

// ExpandEnv expands $HOME and $TMPDIR in the values of entries as a run
// does, for a host command that must see the same environment.
func ExpandEnv(entries []string, home, temporary string) []string {
	return sandboxPaths{home: home, temporary: temporary}.env(entries)
}

// env expands the values of entries.
func (paths sandboxPaths) env(entries []string) []string {
	expanded := make([]string, 0, len(entries))
	for _, entry := range entries {
		key, value, _ := strings.Cut(entry, "=")
		expanded = append(expanded, key+"="+paths.expand(value))
	}
	return expanded
}

// args expands every argument after the program.
func (paths sandboxPaths) args(args []string) []string {
	expanded := append([]string{}, args...)
	for index := 1; index < len(expanded); index++ {
		expanded[index] = paths.expand(expanded[index])
	}
	return expanded
}
