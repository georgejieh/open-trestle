package localreview

// FailureDetailModelOutputExhausted records that a model route finished with
// a length stop and no answer: the model spent its whole output allowance,
// typically on reasoning, before writing the requested document.
const FailureDetailModelOutputExhausted = "model_output_exhausted"

// failureHints are plain-language explanations of each run failure class.
// They describe what the class usually means; they are not diagnoses.
var failureHints = map[string]string{
	"policy":         "a runtime policy, authorization or budget rule refused the work",
	"resource_limit": "a configured size, token, time or cost limit was reached",
	"transient":      "the model route failed temporarily (network, rate limit or provider error); a later retry may succeed",
	"invalid_input":  "a recorded input did not match its expected shape or identity",
	"canceled":       "the run was canceled or its time limit expired",
	"dependency":     "a task this one depends on did not complete",
	"internal":       "a model response could not be accepted (for example malformed or truncated output) or an internal check failed",
}

// taskFailureHints refine a class hint for a specific failing task.
var taskFailureHints = map[[2]string]string{
	{"policy", "context"}:         "usually no changed source could be supplied to the model (every source was omitted, unsupported, or not authorized); see the context task's source omissions",
	{"resource_limit", "context"}: "usually the changed source did not fit the context packet budget",
}

var failureDetailHints = map[string]string{
	FailureDetailModelOutputExhausted: "the model used its whole output allowance (reasoning) before answering; choose a non-reasoning model for this role or raise the review output allowance (setup bootstrap init --max-output-tokens)",
}

// failureTask returns the key of the first task, in plan order, that failed.
func (r Result) failureTask() string {
	for _, task := range r.wire.Tasks {
		if task.Status == "failed" {
			return task.Key
		}
	}
	return ""
}

// failureSummary returns the failure class, failing task and one-line hint of
// a run that did not succeed. It is empty for a run without a recorded failure.
func (r Result) failureSummary() (class, task, detail, hint string) {
	if r.wire.RunStatus == "succeeded" || r.wire.Failure == "" {
		return "", "", "", ""
	}
	class, task, detail = r.wire.Failure, r.failureTask(), r.wire.FailureDetail
	hint = failureHints[class]
	if value, ok := taskFailureHints[[2]string{class, task}]; ok {
		hint = value
	}
	if value, ok := failureDetailHints[detail]; ok {
		hint = value
	}
	return class, task, detail, hint
}

// FailureLine renders "class (task key)" with the detail when one was
// observed, for example "internal (task verification): model_output_exhausted".
func FailureLine(class, task, detail string) string {
	line := class
	if task != "" {
		line += " (task " + task + ")"
	}
	if detail != "" {
		line += ": " + detail
	}
	return line
}
