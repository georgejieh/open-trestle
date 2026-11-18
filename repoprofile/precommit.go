package repoprofile

import (
	"slices"
	"strings"
)

const maxHooks = 500

// hook is a hook of a pre-commit configuration.
type hook struct {
	id     string
	stages []string
	entry  string // the command of a local hook
}

var stageNames = map[string]string{"commit": "pre-commit", "push": "pre-push", "merge-commit": "pre-merge-commit"}

func stageName(stage string) string {
	if full, ok := stageNames[stage]; ok {
		return full
	}
	return stage
}

func parsePreCommit(text string) []hook {
	doc := parseYAML(text)
	defaults := stageList(doc.get("default_stages"))
	var hooks []hook
	for _, repo := range doc.get("repos").seq() {
		for _, h := range repo.get("hooks").seq() {
			id := h.get("id").str()
			if id == "" || len(hooks) >= maxHooks {
				continue
			}
			stages := stageList(h.get("stages"))
			if len(stages) == 0 {
				stages = defaults
			}
			hooks = append(hooks, hook{id: id, stages: stages, entry: h.get("entry").str()})
		}
	}
	return hooks
}

func stageList(n *yamlNode) []string {
	var stages []string
	for _, item := range n.seq() {
		stages = append(stages, stageName(item.str()))
	}
	return stages
}

// runs reports whether "pre-commit run [id] [--hook-stage stage]" runs the
// hook. Without a stage option, pre-commit runs the pre-commit stage.
func (h hook) runs(id, stage string) bool {
	if stage == "" {
		stage = "pre-commit"
	}
	return (id == "" || h.id == id) && (len(h.stages) == 0 || slices.Contains(h.stages, stageName(stage)))
}

// addHook records the tool of a hook, and the commands of a local hook.
func (s *scanner) addHook(h hook, enforced bool) {
	if tool, ok := hookTools[h.id]; ok {
		s.add(SourcePreCommit, s.hookRef, tool, enforced)
	}
	s.script(h.entry, s.hookRef, SourcePreCommit, maxDepth, enforced)
}

var preCommitValued = map[string]bool{
	"-c": true, "--config": true, "--from-ref": true, "--to-ref": true, "-s": true, "--source": true,
	"-o": true, "--origin": true, "--color": true, "--files": true, "--commit-msg-filename": true,
}

// runPreCommit records as enforced the hooks that a pre-commit command runs.
func (s *scanner) runPreCommit(args []string) {
	if len(args) == 0 || args[0] != "run" {
		return
	}
	id, stage := "", ""
	for i := 1; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--hook-stage" && i+1 < len(args):
			stage = args[i+1]
			i++
		case strings.HasPrefix(a, "--hook-stage="):
			stage = strings.TrimPrefix(a, "--hook-stage=")
		case preCommitValued[a]:
			i++
		case a != "" && a[0] == '-':
		case id == "":
			id = a
		}
	}
	for _, h := range s.hooks {
		if h.runs(id, stage) {
			s.addHook(h, true)
		}
	}
}

// yamlRuns returns the values of the "run" keys of a YAML document.
func yamlRuns(n *yamlNode, depth int) []string {
	if n == nil || depth > maxYAMLDepth {
		return nil
	}
	var runs []string
	for i, item := range n.items {
		if n.kind == yamlMapping && n.keys[i] == "run" && item.kind == yamlScalar {
			runs = append(runs, item.value)
		}
		runs = append(runs, yamlRuns(item, depth+1)...)
	}
	return runs
}
