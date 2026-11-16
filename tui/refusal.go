package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/georgejieh/open-trestle/audit"
	"github.com/georgejieh/open-trestle/webhook"
)

// RefusalService is optionally implemented by a Service that can read the
// refusal intake recorded for a webhook delivery whose run was never opened.
type RefusalService interface {
	GetDeliveryRefusal(context.Context, audit.ReviewScope) (webhook.RefusalRecord, error)
}

// refusal returns the recorded refusal of the scope's delivery, if the
// service can read one.
func (i *Interface) refusal(ctx context.Context) (webhook.RefusalRecord, bool) {
	reader, ok := i.service.(RefusalService)
	if !ok {
		return webhook.RefusalRecord{}, false
	}
	record, err := reader.GetDeliveryRefusal(ctx, i.options.Scope)
	if err != nil || record.Validate() != nil || record.Scope().TenantID() != i.options.Scope.TenantID() || record.Scope().RepositoryID() != i.options.Scope.RepositoryID() || "webhook-"+record.DeduplicationKey() != i.options.Scope.ReviewRunID() {
		return webhook.RefusalRecord{}, false
	}
	return record, true
}

func (i *Interface) renderRefusal(record webhook.RefusalRecord) error {
	var builder strings.Builder
	if !i.options.Plain {
		builder.WriteString("\x1b[H\x1b[2J")
	} else {
		builder.WriteString("---\n")
	}
	width := i.options.Width
	builder.WriteString("OPEN TRESTLE\n")
	writeAmbassadorBridgeMark(&builder)
	scope := i.options.Scope
	fmt.Fprintf(&builder, "Scope       %s\n", truncateTerminalText(fmt.Sprintf("%s / %s / %s", scope.TenantID(), scope.RepositoryID(), scope.ReviewRunID()), width-12))
	builder.WriteString("Run         not opened\n")
	fmt.Fprintf(&builder, "Refusal     %s\n", truncateTerminalText(record.Reason()+" ("+webhook.RefusalExplanation(record.Reason())+")", width-12))
	fmt.Fprintf(&builder, "Refused     %s\n", record.RefusedAt().Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(&builder, "Delivery    %s\n", truncateTerminalText(record.DeliveryIdentity(), width-12))
	fmt.Fprintf(&builder, "Planner     %s\n", truncateTerminalText(record.PlannerIdentity(), width-12))
	builder.WriteString("\nIntake recorded this refusal instead of opening a review run. No review result exists.\n")
	_, err := i.output.Write([]byte(builder.String()))
	return err
}
