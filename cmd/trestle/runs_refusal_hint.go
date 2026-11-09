package main

import (
	"fmt"
	"io"

	"github.com/georgejieh/open-trestle/controlplane"
	"github.com/georgejieh/open-trestle/diagnostics"
	"github.com/georgejieh/open-trestle/internal/routehint"
)

// receiptRefusalHint names the first context route refusal a receipt records,
// with the same hint as the local review, or returns "".
func receiptRefusalHint(receipt controlplane.ReviewRunReceipt) string {
	for _, task := range receipt.Tasks() {
		switch task.FailureReason() {
		case controlplane.TaskFailureReasonRouteContextInsufficient:
			s, _ := task.ContextShortfall()
			return refusalHintText(task.Key(), task.FailureReason().String(), routehint.RouteContextInsufficient, routehint.ContextShortfall(s.RequiredTokens, s.EstimatedInputTokens, s.MaxOutputTokens, s.DeclaredContextTokens))
		case controlplane.TaskFailureReasonNoEligibleRoute:
			return refusalHintText(task.Key(), task.FailureReason().String(), routehint.NoEligibleRoute, "")
		}
	}
	return ""
}

// setRefusalHint names the context refusal a final result set records, and
// whether the result was recorded after its evidence expired, or returns "".
func setRefusalHint(set diagnostics.Set) string {
	expired := ""
	if set.EvidenceExpired() {
		expired = "runs status: " + diagnostics.EvidenceExpiredText + "\n"
	}
	refusal, ok := set.ContextRefusal()
	if !ok {
		return expired
	}
	return contextRefusalHint(refusal) + expired
}

func contextRefusalHint(refusal diagnostics.ContextRefusal) string {
	if refusal.Reason == diagnostics.ContextRefusalRouteContextInsufficient {
		return refusalHintText("context", string(refusal.Reason), routehint.RouteContextInsufficient, routehint.ContextShortfall(refusal.RequiredTokens, refusal.EstimatedInputTokens, refusal.MaxOutputTokens, refusal.DeclaredContextTokens))
	}
	return refusalHintText("context", string(refusal.Reason), routehint.NoEligibleRoute, "")
}

func refusalHintText(task, reason, text, hint string) string {
	line := fmt.Sprintf("runs status: task %s refused: %s (%s)\n", task, reason, text)
	if hint != "" {
		line += "hint: " + hint + "\n"
	}
	return line
}

// writeRefusalHint keeps stdout machine-readable and names a refusal on stderr.
func writeRefusalHint(stderr io.Writer, hint string) {
	if hint != "" {
		_, _ = io.WriteString(stderr, hint)
	}
}
