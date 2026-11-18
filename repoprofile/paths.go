package repoprofile

import (
	"path"
	"slices"
	"strings"

	"github.com/georgejieh/open-trestle/repoindex"
)

const (
	maxConfigPaths = 64
)

// rootSources maps the root-level files that are read as text to their source.
var rootSources = map[string]string{
	".gitlab-ci.yml": SourceCIOther, "azure-pipelines.yml": SourceCIOther, "Jenkinsfile": SourceCIOther,
	"Makefile": SourceTaskRunner, "makefile": SourceTaskRunner, "GNUmakefile": SourceTaskRunner,
	"justfile": SourceTaskRunner, "Justfile": SourceTaskRunner, "Taskfile.yml": SourceTaskRunner,
	"Taskfile.yaml": SourceTaskRunner, "package.json": SourceTaskRunner, "tox.ini": SourceTaskRunner,
	"noxfile.py":              SourceTaskRunner,
	".pre-commit-config.yaml": SourcePreCommit, "lefthook.yml": SourcePreCommit,
	"tsconfig.json": SourceConfig, "pyproject.toml": SourceConfig,
}

// sourceOf returns how a repository path is read, or "" when it is not read.
func sourceOf(p string) string {
	dir, base := path.Split(p)
	switch dir {
	case "":
		if source, ok := rootSources[base]; ok {
			return source
		}
		if configTool(base) != "" {
			return SourceConfig
		}
	case ".github/workflows/":
		if ext := path.Ext(base); ext == ".yml" || ext == ".yaml" {
			return SourceCI
		}
	case ".circleci/":
		if base == "config.yml" {
			return SourceCIOther
		}
	case ".buildkite/":
		if base == "pipeline.yml" {
			return SourceCIOther
		}
	case ".husky/":
		if !strings.HasPrefix(base, "_") {
			return SourcePreCommit
		}
	}
	return ""
}

// ConfigPaths returns, in path order, the files of a snapshot that Detect
// reads: CI workflow, task-runner, pre-commit and hook, and linter,
// formatter and type-check configuration files. At most 64.
func ConfigPaths(files []repoindex.FileEntry) []string {
	var paths []string
	for _, f := range files {
		if f.Object != "" && f.Status != repoindex.StatusSymlink && f.Status != repoindex.StatusSubmodule && sourceOf(f.Path) != "" {
			paths = append(paths, f.Path)
		}
	}
	slices.Sort(paths)
	return paths[:min(len(paths), maxConfigPaths)]
}

func isAnalysedTest(f repoindex.FileEntry) bool {
	return f.Role == repoindex.RoleTest && f.Status == repoindex.StatusIndexed && f.Language != ""
}
