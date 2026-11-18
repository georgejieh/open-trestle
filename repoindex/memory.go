package repoindex

import (
	"context"
	"path"
	"slices"

	"github.com/georgejieh/open-trestle/syntaxanalysis"
)

// MemoryGraph analyses files a caller already holds in memory, such as the
// snapshots a review loaded, and returns their graph. It stores nothing.
// Files in a language the analyzer does not support are listed as not
// analysed, and analyses that fail as failed, which the coverage reports.
func MemoryGraph(ctx context.Context, commit string, files map[string][]byte, analyzer syntaxanalysis.Analyzer) (*Graph, error) {
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	slices.Sort(paths)
	s := Snapshot{Commit: commit, Files: make([]FileEntry, len(paths)), Modules: []GoModule{}}
	analyses := make([]*syntaxanalysis.FileAnalysis, len(paths))
	for i, p := range paths {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		content := files[p]
		f := newFileEntry(TreeEntry{Path: p, Kind: EntryFile})
		if path.Base(p) == "go.mod" && f.Role != RoleVendored {
			if module := goModulePath(content); module != "" {
				s.Modules = append(s.Modules, GoModule{Dir: path.Dir(p), Path: module})
			}
		}
		switch {
		case f.Status != "":
		case !analyzer.Supports(f.Language):
			f.Status = StatusNotAnalysed
		default:
			f, analyses[i] = analyseInMemory(ctx, f, content, analyzer)
		}
		s.Files[i] = f
	}
	slices.SortStableFunc(s.Modules, func(a, b GoModule) int { return len(b.Path) - len(a.Path) })
	g := newGraph(s)
	for i, f := range s.Files {
		g.add(f, analyses[i])
	}
	g.finish()
	return g, ctx.Err()
}

func analyseInMemory(ctx context.Context, f FileEntry, content []byte, analyzer syntaxanalysis.Analyzer) (FileEntry, *syntaxanalysis.FileAnalysis) {
	if isGeneratedContent(content) && f.Role != RoleVendored {
		f.Role = RoleGenerated
	}
	if isBinaryContent(content) {
		f.Status = StatusBinary
		return f, nil
	}
	source, err := syntaxanalysis.NewSource(f.Path, f.Language, content)
	if err != nil {
		f.Status = StatusUnavailable
		return f, nil
	}
	analysis, err := analyzer.Analyze(ctx, source)
	if err != nil || failedAsAWhole(analysis) {
		f.Status = StatusFailed
		return f, nil
	}
	f.Status = StatusIndexed
	return f, &analysis
}

// ChangeOf is the change of one file between two contents a caller holds:
// headPath or basePath is empty for a file the head or the base does not
// have. A modified file's lines come from a diff, or cover the whole file
// when the diff cannot represent it.
func ChangeOf(headPath, basePath string, base, head []byte) Change {
	c := Change{Path: headPath, BasePath: basePath}
	switch {
	case basePath == "":
		c.HeadLines = WholeFile
	case headPath == "":
		c.BaseLines = WholeFile
	default:
		lines, ok := diffLines(headPath, base, head)
		if !ok {
			c.HeadLines, c.BaseLines, c.Approximation = WholeFile, WholeFile, ApproximationDiffUnavailable
			break
		}
		c.HeadLines, c.BaseLines, c.DeletionPoints = lines.HeadLines, lines.BaseLines, lines.DeletionPoints
	}
	return c
}
