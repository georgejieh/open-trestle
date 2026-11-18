package repoprofile

import "strings"

// changeEvents are the workflow triggers that run on proposed changes.
var changeEvents = map[string]bool{"push": true, "pull_request": true, "pull_request_target": true, "merge_group": true}

// workflow records the checks of a GitHub Actions workflow. A step is
// enforced when its workflow runs on changes and neither its job nor the
// step is disabled with "if: false" or allowed to fail with
// "continue-on-error".
func (s *scanner) workflow(path, text string) {
	doc := parseYAML(text)
	jobs := doc.get("jobs")
	if jobs == nil || jobs.kind != yamlMapping {
		return
	}
	onChange := runsOnChange(doc.get("on"))
	for _, job := range jobs.items {
		jobCounts := onChange && stepCounts(job)
		for _, step := range job.get("steps").seq() {
			enforced := jobCounts && stepCounts(step)
			if run := step.get("run").str(); run != "" {
				s.script(run, path, SourceCI, 0, enforced)
			}
			if uses := step.get("uses").str(); uses != "" {
				s.action(uses, path, enforced)
			}
		}
	}
}

func runsOnChange(on *yamlNode) bool {
	if on == nil {
		return false
	}
	switch on.kind {
	case yamlScalar:
		return changeEvents[on.value]
	case yamlSequence:
		for _, event := range on.items {
			if changeEvents[event.str()] {
				return true
			}
		}
	case yamlMapping:
		for _, event := range on.keys {
			if changeEvents[event] {
				return true
			}
		}
	}
	return false
}

// stepCounts reports whether a job or step can fail the workflow.
func stepCounts(n *yamlNode) bool {
	if v := n.get("continue-on-error"); v != nil && expression(v.str()) != "false" {
		return false
	}
	if v := n.get("if"); v != nil && expression(v.str()) == "false" {
		return false
	}
	return true
}

// expression returns a condition without its "${{ }}" wrapper, lower case.
func expression(s string) string {
	s = strings.TrimSpace(s)
	if inner, ok := strings.CutPrefix(s, "${{"); ok {
		s = strings.TrimSuffix(strings.TrimSpace(inner), "}}")
	}
	return strings.ToLower(strings.TrimSpace(s))
}
