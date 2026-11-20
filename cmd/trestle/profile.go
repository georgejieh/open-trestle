package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/internal/evidence"
	"github.com/georgejieh/open-trestle/repoindex"
	"github.com/georgejieh/open-trestle/repoprofile"
)

// `trestle profile` describes the repository of the checkout in the current
// directory: its languages, test frameworks and layout, and the checks its
// own CI enforces, apart from those it merely configures. It reads the commit
// from the Git object store through the repository index.

func writeProfileUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: trestle profile [--commit REF] [--directory PATH] [--json]   (languages, tests and the checks the repository's CI enforces)")
}

func runProfile(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	var f indexFlags
	var asJSON bool
	flags := flag.NewFlagSet("trestle profile", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&f.directory, "directory", "", "")
	flags.StringVar(&f.commit, "commit", "HEAD", "")
	flags.BoolVar(&asJSON, "json", false, "")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		writeProfileUsage(stderr)
		return 2
	}
	s, err := openIndexSession(ctx, f)
	if err != nil {
		return profileFail(stderr, 1, "%v", err)
	}
	defer s.close()
	revision, err := s.commit(ctx, f.commit)
	if err != nil {
		return profileFail(stderr, 2, "--commit: %v", err)
	}
	graph, err := s.ensureIndexed(ctx, revision, stderr)
	if err != nil {
		return profileFail(stderr, 1, "%v", err)
	}
	profile, err := repositoryProfile(ctx, s, graph)
	if err != nil {
		return profileFail(stderr, 1, "%v", err)
	}
	if asJSON {
		return writeIndexJSON(stdout, stderr, profile)
	}
	writeProfileText(stdout, profile)
	return 0
}

func profileFail(stderr io.Writer, code int, format string, values ...any) int {
	fmt.Fprintf(stderr, "trestle profile: "+format+"\n", values...)
	return code
}

// repositoryProfile describes the commit of a graph. It reads the
// configuration files from the object store; a file that cannot be read is
// left out. Test frameworks come from the imports the index recorded.
func repositoryProfile(ctx context.Context, s *indexSession, graph *repoindex.Graph) (repoprofile.Profile, error) {
	files := graph.Files()
	objects := make(map[string]string, len(files))
	for _, f := range files {
		objects[f.Path] = f.Object
	}
	paths := repoprofile.ConfigPaths(files)
	revision, err := evidence.NewRevisionIdentity(evidence.RevisionKindGitCommit, evidence.RevisionAlgorithm(s.algorithm), graph.Coverage().Commit)
	if err != nil {
		return repoprofile.Profile{}, err
	}
	tree, err := repoindex.NewGitTree(s.store, revision)
	if err != nil {
		return repoprofile.Profile{}, err
	}
	contents := map[string][]byte{}
	read, next := 0, 0
	err = tree.ReadBlobs(ctx, func() (string, bool) {
		if next >= len(paths) {
			return "", false
		}
		next++
		return objects[paths[next-1]], true
	}, func(content []byte, err error) error {
		path := paths[read]
		read++
		if err == nil && len(content) <= repoprofile.MaxFileBytes {
			contents[path] = slices.Clone(content)
		}
		return nil
	})
	if err != nil {
		return repoprofile.Profile{}, fmt.Errorf("the repository profile could not be read: %w", err)
	}
	imports := func(path string) []string {
		sources, _ := graph.ImportSources(path)
		return sources
	}
	return repoprofile.Detect(files, imports, contents), nil
}

func writeProfileText(w io.Writer, p repoprofile.Profile) {
	var languages []string
	for _, l := range p.Languages {
		languages = append(languages, fmt.Sprintf("%s %d%%", l.Language, l.Percent))
	}
	fmt.Fprintf(w, "Languages: %s\n", orNone(languages))
	fmt.Fprintf(w, "Tests: %d files; frameworks: %s; layout: %s\n", p.Tests.Files, orNone(p.Tests.Frameworks), orNone(p.Tests.Layouts))
	var enforced, configured []repoprofile.Check
	enforcedTools := map[string]bool{}
	for _, c := range p.Checks {
		if c.Enforced {
			enforced = append(enforced, c)
			enforcedTools[c.Tool] = true
		}
	}
	for _, c := range p.Checks {
		if !c.Enforced && !enforcedTools[c.Tool] {
			configured = append(configured, c)
		}
	}
	if len(enforced) == 0 {
		fmt.Fprintln(w, "Checks the repository's CI enforces: none found")
	} else {
		fmt.Fprintln(w, "Checks the repository's CI enforces:")
		writeChecksByClass(w, enforced)
	}
	if len(configured) > 0 {
		fmt.Fprintln(w, "Also configured (not run by CI on changes):")
		writeChecksByClass(w, configured)
	}
}

// writeChecksByClass prints the tools of checks, which are sorted by class,
// one line per class.
func writeChecksByClass(w io.Writer, checks []repoprofile.Check) {
	var classes []string
	tools := map[string][]string{}
	for _, c := range checks {
		if _, ok := tools[c.Class]; !ok {
			classes = append(classes, c.Class)
		}
		if label := c.Tool + " (" + c.Source + ")"; !slices.Contains(tools[c.Class], label) {
			tools[c.Class] = append(tools[c.Class], label)
		}
	}
	for _, class := range classes {
		fmt.Fprintf(w, "  %s: %s\n", class, strings.Join(tools[class], ", "))
	}
}

func orNone(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, ", ")
}
